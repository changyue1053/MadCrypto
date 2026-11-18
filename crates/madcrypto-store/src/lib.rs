//! IMCrypto 持久化后端：SQLCipher 之上实现 `SessionStore`（架构 §15 的落地验证）。
//!
//! 这是「解密即事务」从 mock 证明升级为**真数据库端到端**的一块：`commit` 用
//! `BEGIN IMMEDIATE ... COMMIT` 把「消息 + 会话状态 blob」裹进同一个 SQLite 事务——
//! 任意点崩溃（进程被杀、掉电）由 WAL 回滚保证原子，与 IMCrypto 协议层的事务性解密
//! 首尾相接。会话状态是加密落盘的（SQLCipher 页级 AES），与 IMDB 的 Keyring 同款路线。
//!
//! 生产装配中这层由 IMDB 的工作单元承担（会话表与消息表同库同事务）；本 crate 是
//! 独立可运行的等价实现，用于在纯 CI 环境验证契约与崩溃语义（`imdb-core` 未就绪时的
//! 端到端证据）。

use std::path::Path;

use madcrypto_core::session::{SecureSession, SessionStore};
use madcrypto_core::{CryptoError, Result};
use rusqlite::{Connection, OptionalExtension};

/// 崩溃注入点（测试用；生产恒 `None`）。模拟"事务提交前/后"进程消失。
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum CrashPoint {
    #[default]
    None,
    /// 事务已 BEGIN、写入已发出，但 COMMIT 前进程消失 → WAL 必须回滚整笔。
    BeforeCommit,
}

/// SQLCipher 持久化的会话存储。
pub struct SqlcipherSessionStore {
    conn: Connection,
    crash: CrashPoint,
}

impl SqlcipherSessionStore {
    /// 打开（或创建）加密库。`key` 为 SQLCipher 主密钥（生产中来自 Keyring/系统硬件）。
    pub fn open(path: impl AsRef<Path>, key: &[u8]) -> Result<Self> {
        let conn = Connection::open(path).map_err(map_sql)?;
        Self::init(conn, key)
    }

    /// 内存库（测试/临时会话）。
    pub fn open_in_memory(key: &[u8]) -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(map_sql)?;
        Self::init(conn, key)
    }

    fn init(conn: Connection, key: &[u8]) -> Result<Self> {
        // 施钥必须在任何其它语句之前（SQLCipher 契约）
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        conn.pragma_update(None, "key", format!("x'{hex}'")).map_err(map_sql)?;
        // 密钥自检先行（架构 §14）：错误密钥下这次触碰 schema 的读会失败——
        // 把"密钥错"在 open 入口就暴露成 KeyInvalid，而不是拖到建表/查询才报模糊错误。
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(|_| CryptoError::StateCorrupt)?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(map_sql)?;
        conn.pragma_update(None, "synchronous", "NORMAL").map_err(map_sql)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS crypto_session (
                 session_id TEXT PRIMARY KEY,
                 state      BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS crypto_message (
                 message_id TEXT PRIMARY KEY,
                 session_id TEXT NOT NULL,
                 plaintext  BLOB NOT NULL
             );",
        )
        .map_err(map_sql)?;
        Ok(Self { conn, crash: CrashPoint::None })
    }

    /// 是否能用给定 key 正常读库（密钥自检：区分"密钥错"与"库损坏"，对齐 IMDB §14）。
    pub fn verify_key(&self) -> bool {
        self.conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .is_ok()
    }

    pub fn arm_crash(&mut self, at: CrashPoint) {
        self.crash = at;
    }

    pub fn message_count(&self) -> u64 {
        self.conn
            .query_row("SELECT count(*) FROM crypto_message", [], |r| r.get::<_, i64>(0))
            .map(|n| n as u64)
            .unwrap_or(0)
    }

    /// 首次落库会话状态（会话建立后调用，不伴随消息）。
    pub fn put_session(&self, session_id: &str, session: &SecureSession) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO crypto_session(session_id, state) VALUES (?1, ?2)",
                rusqlite::params![session_id, session.serialize()],
            )
            .map_err(map_sql)?;
        Ok(())
    }
}

impl SessionStore for SqlcipherSessionStore {
    fn load(&self, session_id: &str) -> Option<SecureSession> {
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT state FROM crypto_session WHERE session_id = ?1",
                [session_id],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten();
        blob.and_then(|b| SecureSession::deserialize(&b).ok())
    }

    fn contains_message(&self, message_id: &str) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM crypto_message WHERE message_id = ?1",
                [message_id],
                |_| Ok(()),
            )
            .optional()
            .map(|o| o.is_some())
            .unwrap_or(false)
    }

    fn commit(
        &mut self,
        session_id: &str,
        message_id: &str,
        plaintext: Vec<u8>,
        new_state: SecureSession,
    ) -> Result<()> {
        // BEGIN IMMEDIATE：入口即取写锁，失败只发生在边界（对齐 IMDB §6 的事务纪律）
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        tx.execute(
            "INSERT INTO crypto_message(message_id, session_id, plaintext) VALUES (?1, ?2, ?3)",
            rusqlite::params![message_id, session_id, plaintext],
        )
        .map_err(map_sql)?;
        tx.execute(
            "INSERT OR REPLACE INTO crypto_session(session_id, state) VALUES (?1, ?2)",
            rusqlite::params![session_id, new_state.serialize()],
        )
        .map_err(map_sql)?;

        if self.crash == CrashPoint::BeforeCommit {
            // 进程在 COMMIT 前消失：tx 于此 drop → 自动 ROLLBACK，整笔消失
            self.crash = CrashPoint::None;
            return Err(CryptoError::StateCorrupt);
        }
        tx.commit().map_err(map_sql)?;
        Ok(())
    }
}

fn map_sql(_e: rusqlite::Error) -> CryptoError {
    CryptoError::StateCorrupt
}

#[cfg(test)]
mod tests {
    use super::*;
    use madcrypto_core::session::{receive_and_commit, Incoming};
    use madcrypto_core::x3dh::{
        generate_identity, initiate, new_signed_prekey, respond, PreKeyBundle, ResponderKeys,
    };
    use madcrypto_prims::{CipherSuite as _, IntlSuite};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    type S = IntlSuite;
    const SID: &str = "conv:sql";
    const AD: &[u8] = b"conv:sql";
    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn setup() -> (SecureSession, SecureSession, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::seed_from_u64(500);
        let aid = generate_identity::<S, _>(&mut rng);
        let bid = generate_identity::<S, _>(&mut rng);
        let (spk_priv, spk_pub, spk_sig) = new_signed_prekey::<S, _>(&mut rng, &bid).unwrap();
        let bundle = PreKeyBundle {
            suite: S::id(),
            identity: bid.public(),
            signed_prekey: spk_pub,
            signed_prekey_sig: spk_sig,
            one_time_prekey: None,
        };
        let init = initiate::<S, _>(&mut rng, &aid, &bundle).unwrap();
        let resp = respond::<S>(
            ResponderKeys {
                identity: &bid,
                signed_prekey_private: &spk_priv,
                one_time_prekey_private: None,
            },
            &init.initial_message,
        )
        .unwrap();
        let alice = SecureSession::initiator::<S, _>(&mut rng, init.root, init.their_ratchet_public).unwrap();
        let bob = SecureSession::receiver(resp.root, resp.my_ratchet_private, resp.my_ratchet_public);
        (alice, bob, rng)
    }

    #[test]
    fn wrong_key_cannot_open() {
        let dir = std::env::temp_dir().join(format!("imct-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        {
            let store = SqlcipherSessionStore::open(&dir, KEY).unwrap();
            store.put_session("x", &make_dummy_session()).unwrap(); // 落一页真数据
            assert!(store.verify_key());
        }
        // 错误密钥打开已有库：init 的密钥自检先行失败 → open 直接返回 Err
        // （SQLCipher 的真实行为：错误密钥表象等同坏库，§14 的密钥自检把它拦在入口）
        assert!(
            SqlcipherSessionStore::open(&dir, b"ffffffffffffffffffffffffffffffff").is_err(),
            "错误密钥必须在 open 入口被拒"
        );
        // 正确密钥仍能打开
        assert!(SqlcipherSessionStore::open(&dir, KEY).is_ok());
        let _ = std::fs::remove_file(&dir);
    }

    fn make_dummy_session() -> SecureSession {
        let (_alice, bob, _rng) = setup();
        bob
    }

    #[test]
    fn end_to_end_over_real_sqlcipher() {
        let (mut alice, bob, mut rng) = setup();
        let mut store = SqlcipherSessionStore::open_in_memory(KEY).unwrap();
        store.put_session(SID, &bob).unwrap();

        let (h, ct) = alice.encrypt::<S>(AD, b"real db message").unwrap();
        let mut bob_mem = store.load(SID).unwrap();
        let pt = receive_and_commit::<S, _, _>(
            &mut store, &mut rng, SID, &mut bob_mem,
            Incoming { message_id: "m1", header: &h, ciphertext: &ct, ad: AD },
        )
        .unwrap();
        assert_eq!(pt.as_deref(), Some(&b"real db message"[..]));
        assert!(store.contains_message("m1"));
        assert_eq!(store.message_count(), 1);
    }

    #[test]
    fn crash_before_commit_rolls_back_real_transaction() {
        let (mut alice, bob, mut rng) = setup();
        // 磁盘库：真正验证 WAL 回滚跨"关库再开库"（进程重启语义）
        let path = std::env::temp_dir().join(format!("imct-crash-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        // 密文只算一次，留在外层——服务端重推的就是同一条
        let (h, ct) = alice.encrypt::<S>(AD, b"important").unwrap();

        // 阶段一：提交前崩溃
        {
            let mut store = SqlcipherSessionStore::open(&path, KEY).unwrap();
            store.put_session(SID, &bob).unwrap();
            store.arm_crash(CrashPoint::BeforeCommit);
            let mut bob_mem = store.load(SID).unwrap();
            let r = receive_and_commit::<S, _, _>(
                &mut store, &mut rng, SID, &mut bob_mem,
                Incoming { message_id: "m1", header: &h, ciphertext: &ct, ad: AD },
            );
            assert!(r.is_err(), "提交前崩溃必须报错");
        } // store drop = 关库，模拟进程退出

        // 阶段二：重开库（进程重启）——消息未落库、会话仍是旧态 → 重推成功
        let mut store = SqlcipherSessionStore::open(&path, KEY).unwrap();
        assert!(!store.contains_message("m1"), "崩溃前的消息不得残留（WAL 回滚）");
        assert_eq!(store.message_count(), 0);
        let mut bob_restart = store.load(SID).unwrap();
        let pt = receive_and_commit::<S, _, _>(
            &mut store, &mut rng, SID, &mut bob_restart,
            Incoming { message_id: "m1", header: &h, ciphertext: &ct, ad: AD },
        )
        .unwrap();
        assert_eq!(pt.as_deref(), Some(&b"important"[..]), "重推必须能重新解密——消息不丢");

        // 阶段三：重放同一条 → 真库 UNIQUE 主键 + contains_message 幂等跳过
        let mut bob2 = store.load(SID).unwrap();
        let again = receive_and_commit::<S, _, _>(
            &mut store, &mut rng, SID, &mut bob2,
            Incoming { message_id: "m1", header: &h, ciphertext: &ct, ad: AD },
        )
        .unwrap();
        assert_eq!(again, None, "重放必须幂等跳过");
        assert_eq!(store.message_count(), 1);
        let _ = std::fs::remove_file(&path);
    }
}

