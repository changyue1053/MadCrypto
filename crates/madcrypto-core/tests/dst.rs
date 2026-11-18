//! 协议 DST——确定性模拟测试（实施 P9.1/9.2，方法论继承 IMDB §21：
//! 种子驱动、任意失败 100% 可复现、不变量零违例）。
//!
//! 每个种子生成一条随机操作流：发送 / 乱序交付 / **解密后提交前掉电** / 已提交消息重放 /
//! 无故障重启，全程断言四条不变量：
//!   I1 凡发出的消息最终恰好提交一次（不丢、不重）；
//!   I2 掉电回滚后重推可解（密钥未被白白消耗）；
//!   I3 已提交消息重放被幂等层跳过（密钥绝不二次消耗）；
//!   I4 任意时刻从存储重启都能继续（提交过的状态永远可恢复），结尾新往返成功（收敛）。
//!
//! 发送侧不注入崩溃：发送的崩溃语义由 IMDB 的 outbox「先落库再发网络」承诺（其 §17），
//! 本 DST 聚焦接收路径——这正是"解密即事务"的主战场。
//!
//! 运行：默认 150 种子（debug 友好）；全量 `IMCRYPTO_DST_SEEDS=1000 cargo test --release --test dst`；
//! 复现单种子 `IMCRYPTO_DST_SEED=<n>`。

use madcrypto_core::ratchet::Header;
use madcrypto_core::session::{receive_and_commit, Incoming, MemoryStore, SecureSession, SessionStore};
use madcrypto_core::x3dh::{
    generate_identity, initiate, new_signed_prekey, respond, PreKeyBundle, ResponderKeys,
};
use madcrypto_prims::{CipherSuite as _, IntlSuite};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

type S = IntlSuite;
const SID: &str = "conv:dst";
const AD: &[u8] = b"conv:dst";
const STEPS: usize = 40;

struct Msg {
    mid: String,
    header: Header,
    ct: Vec<u8>,
    pt: Vec<u8>,
}

fn establish(rng: &mut ChaCha20Rng) -> (SecureSession, SecureSession) {
    let alice_id = generate_identity::<S, _>(rng);
    let bob_id = generate_identity::<S, _>(rng);
    let (spk_priv, spk_pub, spk_sig) = new_signed_prekey::<S, _>(rng, &bob_id).unwrap();
    let bundle = PreKeyBundle {
        suite: S::id(),
        identity: bob_id.public(),
        signed_prekey: spk_pub,
        signed_prekey_sig: spk_sig,
        one_time_prekey: None,
    };
    let init = initiate::<S, _>(rng, &alice_id, &bundle).unwrap();
    let resp = respond::<S>(
        ResponderKeys {
            identity: &bob_id,
            signed_prekey_private: &spk_priv,
            one_time_prekey_private: None,
        },
        &init.initial_message,
    )
    .unwrap();
    let alice = SecureSession::initiator::<S, _>(rng, init.root, init.their_ratchet_public).unwrap();
    let bob = SecureSession::receiver(resp.root, resp.my_ratchet_private, resp.my_ratchet_public);
    (alice, bob)
}

fn run_seed(seed: u64) -> Result<(), String> {
    let mut crypto_rng = ChaCha20Rng::seed_from_u64(seed);
    let mut script = ChaCha20Rng::seed_from_u64(seed ^ 0x5EED_5EED_5EED_5EED);

    let (mut alice, bob0) = establish(&mut crypto_rng);
    let mut store = MemoryStore::new();
    store.put_initial(SID, bob0);
    // 进程内存中的 Bob（乐观状态）：崩溃/重启即丢弃，从 store 重建
    let mut bob = store.load(SID).ok_or("初始加载失败")?;

    let mut inflight: Vec<Msg> = Vec::new();
    let mut committed: Vec<Msg> = Vec::new();
    let mut sent = 0usize;

    // 事后可读的操作日志：失败时随错误一起输出（复现的第一现场）
    let mut oplog: Vec<String> = Vec::new();

    for step in 0..STEPS {
        match script.next_u32() % 100 {
            // 35%：Alice 发送一条
            0..=34 => {
                let mid = format!("m{sent}");
                let pt = format!("payload-{sent}").into_bytes();
                let (header, ct) = alice.encrypt::<S>(AD, &pt).map_err(|e| format!("发送失败: {e}"))?;
                inflight.push(Msg { mid: mid.clone(), header, ct, pt });
                sent += 1;
                oplog.push(format!("{step}: send {mid}"));
            }
            // 30%：正常交付一条（随机取 → 天然乱序）
            35..=64 if !inflight.is_empty() => {
                let idx = (script.next_u32() as usize) % inflight.len();
                let m = inflight.swap_remove(idx);
                let got = receive_and_commit::<S, _, _>(
                    &mut store, &mut crypto_rng, SID, &mut bob,
                    Incoming { message_id: &m.mid, header: &m.header, ciphertext: &m.ct, ad: AD },
                )
                .map_err(|e| format!("正常交付 {} 失败: {e}\n{}", m.mid, oplog.join("\n")))?;
                // I1/I2：首次交付必须解出且明文一致
                if got.as_deref() != Some(m.pt.as_slice()) {
                    return Err(format!("交付 {} 明文不符\n{}", m.mid, oplog.join("\n")));
                }
                oplog.push(format!("{step}: deliver {}", m.mid));
                committed.push(m);
            }
            // 10%：解密后、提交前掉电 → 消息留在网络，进程重启
            65..=74 if !inflight.is_empty() => {
                let idx = (script.next_u32() as usize) % inflight.len();
                store.arm_crash();
                {
                    let m = &inflight[idx];
                    let r = receive_and_commit::<S, _, _>(
                        &mut store, &mut crypto_rng, SID, &mut bob,
                        Incoming { message_id: &m.mid, header: &m.header, ciphertext: &m.ct, ad: AD },
                    );
                    if r.is_ok() {
                        return Err(format!("掉电注入未生效于 {}\n{}", m.mid, oplog.join("\n")));
                    }
                    if store.contains_message(&m.mid) {
                        return Err(format!("掉电后消息 {} 竟然落库（事务未回滚）\n{}", m.mid, oplog.join("\n")));
                    }
                    oplog.push(format!("{step}: crash-during {}", m.mid));
                }
                // 进程重启：丢弃被污染的内存态，从存储恢复（消息仍在 inflight，稍后重推）
                bob = store.load(SID).ok_or("崩溃后加载失败")?;
            }
            // 10%：服务端重推已提交消息（ACK 丢失场景）→ 幂等层必须跳过
            75..=84 if !committed.is_empty() => {
                let idx = (script.next_u32() as usize) % committed.len();
                let m = &committed[idx];
                let got = receive_and_commit::<S, _, _>(
                    &mut store, &mut crypto_rng, SID, &mut bob,
                    Incoming { message_id: &m.mid, header: &m.header, ciphertext: &m.ct, ad: AD },
                )
                .map_err(|e| format!("重放 {} 报错（应幂等跳过）: {e}\n{}", m.mid, oplog.join("\n")))?;
                // I3：重放必须返回 None（跳过），绝不重新解密
                if got.is_some() {
                    return Err(format!("重放 {} 被二次解密\n{}", m.mid, oplog.join("\n")));
                }
                oplog.push(format!("{step}: replay {}", m.mid));
            }
            // 15%：无故障重启（杀进程再拉起）→ 已提交状态必须可恢复
            _ => {
                bob = store.load(SID).ok_or("重启加载失败")?;
                oplog.push(format!("{step}: restart"));
            }
        }
    }

    // 收尾：网络把滞留消息全部吐出（随机序、无故障）——I1 的"最终恰好一次"
    while !inflight.is_empty() {
        let idx = (script.next_u32() as usize) % inflight.len();
        let m = inflight.swap_remove(idx);
        let got = receive_and_commit::<S, _, _>(
            &mut store, &mut crypto_rng, SID, &mut bob,
            Incoming { message_id: &m.mid, header: &m.header, ciphertext: &m.ct, ad: AD },
        )
        .map_err(|e| format!("收尾交付 {} 失败: {e}\n{}", m.mid, oplog.join("\n")))?;
        if got.as_deref() != Some(m.pt.as_slice()) {
            return Err(format!("收尾交付 {} 明文不符", m.mid));
        }
        committed.push(m);
    }

    // I1：不丢不重——存储中消息数 == 实际发出数
    if store.message_count() != sent {
        return Err(format!(
            "计数违例：发出 {sent} 条，落库 {} 条\n{}",
            store.message_count(),
            oplog.join("\n")
        ));
    }

    // I4：收敛——重启后新往返成功
    bob = store.load(SID).ok_or("终局加载失败")?;
    let (h, ct) = alice.encrypt::<S>(AD, b"dst-final").map_err(|e| e.to_string())?;
    let got = receive_and_commit::<S, _, _>(
        &mut store, &mut crypto_rng, SID, &mut bob,
        Incoming { message_id: "final", header: &h, ciphertext: &ct, ad: AD },
    )
    .map_err(|e| format!("终局往返失败: {e}"))?;
    if got.as_deref() != Some(&b"dst-final"[..]) {
        return Err("终局明文不符".into());
    }
    Ok(())
}

#[test]
fn dst_seeded_operation_streams() {
    // 单种子复现优先（失败排查的第一入口）
    if let Ok(s) = std::env::var("IMCRYPTO_DST_SEED") {
        let seed: u64 = s.parse().expect("IMCRYPTO_DST_SEED 需为整数");
        if let Err(e) = run_seed(seed) {
            panic!("DST 失败 seed={seed}\n{e}");
        }
        return;
    }
    let n: u64 = std::env::var("IMCRYPTO_DST_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(150);
    for seed in 0..n {
        if let Err(e) = run_seed(seed) {
            panic!("DST 失败 seed={seed}（复现：IMCRYPTO_DST_SEED={seed} cargo test --test dst）\n{e}");
        }
    }
}

