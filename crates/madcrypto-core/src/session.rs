//! 会话组装 + 存储契约 + 「解密即事务」（架构 §1 压舱石 / §15 / 实施 P2）。
//!
//! 核心不变量：**解密是写操作**。棘轮解密推进的是内存中的乐观状态，只有当消息与新会话
//! 状态作为一个整体在存储层原子提交后才算数。崩溃发生在提交前，整体未发生，消息重推可
//! 重新解密；崩溃发生在提交后，整体完成，消息重推被幂等层拒绝，棘轮密钥绝不二次消耗。
//!
//! The host supplies an atomic SessionStore. madcrypto-store is an optional
//! SQLCipher reference backend; no MadDB/IMDB bridge is required or implemented.

use std::collections::HashMap;

use madcrypto_prims::CipherSuite;
use rand_core::{CryptoRng, RngCore};

use crate::error::{CryptoError, Result};
use crate::keys::{DhPrivate, DhPublic, RootKey};
use crate::ratchet::{Header, Ratchet};

/// 已建立的安全会话（密聊单聊）。封装双棘轮，对外只暴露加解密与快照。
pub struct SecureSession {
    ratchet: Ratchet,
}

impl SecureSession {
    /// 由 X3DH 发起方结果建立（Alice，可立即发送）。
    pub fn initiator<S: CipherSuite, R: RngCore + CryptoRng>(
        rng: &mut R,
        root: RootKey,
        their_ratchet_public: DhPublic,
    ) -> Result<Self> {
        Ok(Self {
            ratchet: Ratchet::init_initiator::<S, R>(rng, root, their_ratchet_public)?,
        })
    }

    /// 由 X3DH 接收方结果建立（Bob，收到首条后可回复）。
    pub fn receiver(root: RootKey, my_private: DhPrivate, my_public: DhPublic) -> Self {
        Self {
            ratchet: Ratchet::init_receiver(root, my_private, my_public),
        }
    }

    pub fn encrypt<S: CipherSuite>(&mut self, ad: &[u8], pt: &[u8]) -> Result<(Header, Vec<u8>)> {
        self.ratchet.encrypt::<S>(ad, pt)
    }

    pub fn decrypt<S: CipherSuite, R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        header: &Header,
        ct: &[u8],
        ad: &[u8],
    ) -> Result<Vec<u8>> {
        self.ratchet.decrypt::<S, R>(rng, header, ct, ad)
    }

    /// 会话状态快照（深拷贝）。等价于生产中序列化后 `put_session_state` 的落库值。
    pub fn snapshot(&self) -> Self {
        Self {
            ratchet: self.ratchet.dup(),
        }
    }

    /// 序列化为字节 blob——真持久化后端（madcrypto-store → IMDB）落库的会话状态本体（§15）。
    pub fn serialize(&self) -> Vec<u8> {
        self.ratchet.serialize()
    }

    /// 从字节 blob 恢复会话（崩溃后从存储重建）。坏字节报 `StateCorrupt`。
    pub fn deserialize(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            ratchet: crate::ratchet::Ratchet::deserialize(bytes)?,
        })
    }
}

/// Atomic storage port. Host implementations must serialize each session and
/// scope message IDs by account. Reference store is optional, not a DB bridge.
pub trait SessionStore {
    /// 加载会话状态（返回独立副本，供内存乐观推进）。
    fn load(&self, session_id: &str) -> Option<SecureSession>;
    /// 消息幂等锚点是否已存在（对应 IMDB 的 client_msg_id 唯一索引，架构 §15）。
    fn contains_message(&self, message_id: &str) -> bool;
    /// **原子**提交：消息 + 会话新状态。要么都落库，要么都不（同一 SQLCipher 事务）。
    fn commit(
        &mut self,
        session_id: &str,
        message_id: &str,
        plaintext: Vec<u8>,
        new_state: SecureSession,
    ) -> Result<()>;
}

/// 内存 mock store，带崩溃注入。生产替换为 IMDB 后端，测试集在真实现上复用。
#[derive(Default)]
pub struct MemoryStore {
    sessions: HashMap<String, SecureSession>,
    messages: HashMap<String, Vec<u8>>,
    /// 崩溃注入：为 true 时下一次 commit 在写入前失败（模拟提交前掉电）。
    crash_before_commit: bool,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn put_initial(&mut self, session_id: &str, session: SecureSession) {
        self.sessions.insert(session_id.to_string(), session);
    }
    pub fn arm_crash(&mut self) {
        self.crash_before_commit = true;
    }
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }
}

impl SessionStore for MemoryStore {
    fn load(&self, session_id: &str) -> Option<SecureSession> {
        self.sessions.get(session_id).map(SecureSession::snapshot)
    }

    fn contains_message(&self, message_id: &str) -> bool {
        self.messages.contains_key(message_id)
    }

    fn commit(
        &mut self,
        session_id: &str,
        message_id: &str,
        plaintext: Vec<u8>,
        new_state: SecureSession,
    ) -> Result<()> {
        if self.crash_before_commit {
            // 掉电：事务未提交，消息与会话状态<b>都不落库</b>
            self.crash_before_commit = false;
            return Err(CryptoError::StateCorrupt);
        }
        // 原子：两个写入在真实后端是同一事务，mock 里保证一起发生
        self.messages.insert(message_id.to_string(), plaintext);
        self.sessions.insert(session_id.to_string(), new_state);
        Ok(())
    }
}

/// 一条入站密文（幂等锚点 + 棘轮头 + 密文 + 关联数据）。
pub struct Incoming<'a> {
    pub message_id: &'a str,
    pub header: &'a Header,
    pub ciphertext: &'a [u8],
    pub ad: &'a [u8],
}

/// 「收一条密聊消息」的事务性编排（架构 §15 链路的协议侧）。
///
/// 返回 `Ok(Some(pt))`=首次成功解密并落库；`Ok(None)`=幂等跳过（消息已处理）；
/// `Err`: decryption or commit failed; caller state is unchanged.
/// Store MUST fail atomically: an error means no durable commit. Ambiguous durable
/// outcomes require store recovery and reloading before any further operation.
pub fn receive_and_commit<S: CipherSuite, R: RngCore + CryptoRng, St: SessionStore>(
    store: &mut St,
    rng: &mut R,
    session_id: &str,
    session: &mut SecureSession,
    incoming: Incoming<'_>,
) -> Result<Option<Vec<u8>>> {
    // 幂等：已处理过的消息直接跳过——绝不二次消耗棘轮密钥（架构 §15）
    if store.contains_message(incoming.message_id) {
        return Ok(None);
    }
    // 解密推进内存乐观状态
    let mut candidate = session.snapshot();
    let plaintext = candidate.decrypt::<S, R>(rng, incoming.header, incoming.ciphertext, incoming.ad)?;
    // 原子提交：消息 + 会话新状态。崩溃在此 → 整体回滚
    store.commit(
        session_id,
        incoming.message_id,
        plaintext.clone(),
        candidate.snapshot(),
    )?;
    *session = candidate;
    Ok(Some(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x3dh::{generate_identity, initiate, new_signed_prekey, respond, PreKeyBundle, ResponderKeys};
    use madcrypto_prims::IntlSuite;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    type S = IntlSuite;
    const SID: &str = "conv:42";
    const AD: &[u8] = b"conv:42";

    /// 建立 Alice/Bob 会话，返回 (alice_session, bob_session, rng)。
    fn setup() -> (SecureSession, SecureSession, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::seed_from_u64(100);
        let alice_id = generate_identity::<S, _>(&mut rng);
        let bob_id = generate_identity::<S, _>(&mut rng);
        let (spk_priv, spk_pub, spk_sig) = new_signed_prekey::<S, _>(&mut rng, &bob_id).unwrap();
        let bundle = PreKeyBundle {
            suite: S::id(),
            identity: bob_id.public(),
            signed_prekey: spk_pub,
            signed_prekey_sig: spk_sig,
            one_time_prekey: None,
        };
        let init = initiate::<S, _>(&mut rng, &alice_id, &bundle).unwrap();
        let resp = respond::<S>(
            ResponderKeys {
                identity: &bob_id,
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
    fn happy_path_receive_and_commit() {
        let (mut alice, bob, mut rng) = setup();
        let mut store = MemoryStore::new();
        store.put_initial(SID, bob);

        let (h, ct) = alice.encrypt::<S>(AD, b"hello").unwrap();
        let mut bob_mem = store.load(SID).unwrap();
        let inc = Incoming { message_id: "a1", header: &h, ciphertext: &ct, ad: AD };
        let pt = receive_and_commit::<S, _, _>(&mut store, &mut rng, SID, &mut bob_mem, inc).unwrap();
        assert_eq!(pt.as_deref(), Some(&b"hello"[..]));
        assert!(store.contains_message("a1"));
        assert_eq!(store.message_count(), 1);
    }

    #[test]
    fn crash_before_commit_loses_nothing() {
        let (mut alice, bob, mut rng) = setup();
        let mut store = MemoryStore::new();
        store.put_initial(SID, bob);
        let (h, ct) = alice.encrypt::<S>(AD, b"important").unwrap();

        // 掉电于提交前：内存会话已推进，但 store 事务回滚
        store.arm_crash();
        let mut bob_mem = store.load(SID).unwrap();
        let before = bob_mem.serialize();
        let inc = Incoming { message_id: "a1", header: &h, ciphertext: &ct, ad: AD };
        let r = receive_and_commit::<S, _, _>(&mut store, &mut rng, SID, &mut bob_mem, inc);
        assert!(r.is_err(), "提交前崩溃必须报错");
        assert!(!store.contains_message("a1"), "消息不得落库");
        assert_eq!(bob_mem.serialize(), before, "failed commit must not advance caller state");
        // Retry the SAME in-memory session; no reload needed after definite rollback.
        let inc = Incoming { message_id: "a1", header: &h, ciphertext: &ct, ad: AD };
        assert_eq!(receive_and_commit::<S, _, _>(&mut store, &mut rng, SID, &mut bob_mem, inc).unwrap().as_deref(), Some(&b"important"[..]));
        // Preserve the original restart test separately by resetting fixture.
        let (mut alice, bob, mut rng) = setup();
        let mut store = MemoryStore::new();
        store.put_initial(SID, bob);
        let (h, ct) = alice.encrypt::<S>(AD, b"important").unwrap();

        // 重启：从 store 重新加载【旧】会话状态，服务端重推同一条消息
        let mut bob_restart = store.load(SID).unwrap();
        let inc = Incoming { message_id: "a1", header: &h, ciphertext: &ct, ad: AD };
        let pt = receive_and_commit::<S, _, _>(&mut store, &mut rng, SID, &mut bob_restart, inc).unwrap();
        assert_eq!(pt.as_deref(), Some(&b"important"[..]), "重推必须能重新解密——消息不丢");
        assert!(store.contains_message("a1"));
    }

    #[test]
    fn replay_after_commit_is_idempotent() {
        let (mut alice, bob, mut rng) = setup();
        let mut store = MemoryStore::new();
        store.put_initial(SID, bob);
        let (h, ct) = alice.encrypt::<S>(AD, b"once").unwrap();

        // 正常提交
        let mut bob_mem = store.load(SID).unwrap();
        let inc = Incoming { message_id: "a1", header: &h, ciphertext: &ct, ad: AD };
        receive_and_commit::<S, _, _>(&mut store, &mut rng, SID, &mut bob_mem, inc).unwrap();

        // 提交后 ACK 前崩溃 → 服务端重推同一条。幂等层拦截，密钥不二次消耗
        let mut bob_restart = store.load(SID).unwrap();
        let inc = Incoming { message_id: "a1", header: &h, ciphertext: &ct, ad: AD };
        let pt = receive_and_commit::<S, _, _>(&mut store, &mut rng, SID, &mut bob_restart, inc).unwrap();
        assert_eq!(pt, None, "重放必须被幂等跳过，不再解密");
        assert_eq!(store.message_count(), 1, "消息不得重复落库");
    }

    #[test]
    fn serialize_survives_roundtrip_and_continues() {
        let (mut alice, mut bob, mut rng) = setup();
        // 先跑几条（含乱序，制造非空 skipped 缓存），再序列化 Bob
        let (h0, c0) = alice.encrypt::<S>(AD, b"m0").unwrap();
        let (h1, c1) = alice.encrypt::<S>(AD, b"m1").unwrap();
        assert_eq!(bob.decrypt::<S, _>(&mut rng, &h1, &c1, AD).unwrap(), b"m1"); // 先收 1，跳过 0

        let blob = bob.serialize();
        // 确定性：再序列化一次字节一致
        assert_eq!(blob, bob.serialize());

        // 从 blob 重建，继续解密——skipped 缓存也要一并恢复
        let mut restored = SecureSession::deserialize(&blob).unwrap();
        assert_eq!(restored.decrypt::<S, _>(&mut rng, &h0, &c0, AD).unwrap(), b"m0"); // 用恢复的 skipped 解 0
        let (h2, c2) = alice.encrypt::<S>(AD, b"m2").unwrap();
        assert_eq!(restored.decrypt::<S, _>(&mut rng, &h2, &c2, AD).unwrap(), b"m2");

        // 坏字节必报 StateCorrupt，不 panic
        assert!(SecureSession::deserialize(&blob[..blob.len() - 1]).is_err());
        assert!(SecureSession::deserialize(&[]).is_err());
    }

    #[test]
    fn without_idempotency_replay_would_desync() {
        // 反证：绕过幂等层直接对同一条消息二次解密 → 棘轮已前进 → 失步。
        // 这正是 store 幂等锚点（contains_message）不可或缺的原因（架构 §15）。
        let (mut alice, mut bob, mut rng) = setup();
        let (h, ct) = alice.encrypt::<S>(AD, b"once").unwrap();
        assert_eq!(bob.decrypt::<S, _>(&mut rng, &h, &ct, AD).unwrap(), b"once");
        let err = bob.decrypt::<S, _>(&mut rng, &h, &ct, AD).err().unwrap();
        assert_eq!(err, CryptoError::DecryptDesync, "无幂等保护的重放会导致失步");
    }
}

