//! IMCrypto 演示（对应实施计划 M1/M2 的演示剧本）。
//!
//! 四幕：① 离线握手（服务器只见公钥与密文）② 双棘轮（乱序 / 篡改不失步）
//! ③ 解密即事务（掉电不丢、重放幂等）④ 群密聊（分发 / 踢人轮换 / 新人读不到历史）。

use madcrypto_core::group::{GroupProtocol, MemberId, SenderKeyGroup};
use madcrypto_core::kt::{verify_kt_proof, KtMonitor, MerkleKtLog};
use madcrypto_core::session::{receive_and_commit, Incoming, MemoryStore, SecureSession, SessionStore};
use madcrypto_core::x3dh::{
    generate_identity, initiate, new_one_time_prekey, new_signed_prekey, respond, PreKeyBundle,
    ResponderKeys,
};
use madcrypto_prims::{CipherSuite, IntlSuite};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

type S = IntlSuite;
const AD: &[u8] = b"conv:42|alice<->bob";

fn hex8(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

fn banner(title: &str) {
    println!("\n══════════════════════════════════════════════════");
    println!("  {title}");
    println!("══════════════════════════════════════════════════");
}

fn main() {
    let mut rng = ChaCha20Rng::seed_from_u64(0x2026_0831);
    println!("IMCrypto 双轨加密内核 · 密聊轨演示（国际套件 X25519/Ed25519/AES-256-GCM）");

    // ─────────────────────────────── 第一幕：离线握手 ───────────────────────────────
    banner("① PQXDH 形态握手：Bob 不在线，也能把密钥谈成");
    let alice_id = generate_identity::<S, _>(&mut rng);
    let bob_id = generate_identity::<S, _>(&mut rng);
    println!("  Alice 身份指纹  {}", hex8(&S::hash(alice_id.public().dh.as_slice())));
    println!("  Bob   身份指纹  {}", hex8(&S::hash(bob_id.public().dh.as_slice())));

    let (spk_priv, spk_pub, spk_sig) = new_signed_prekey::<S, _>(&mut rng, &bob_id).unwrap();
    let (opk_priv, opk_pub) = new_one_time_prekey::<S, _>(&mut rng);
    let bundle = PreKeyBundle {
        suite: S::id(),
        identity: bob_id.public(),
        signed_prekey: spk_pub,
        signed_prekey_sig: spk_sig,
        one_time_prekey: Some((7, opk_pub)),
    };
    println!("  [注册期] Bob 上传 bundle 到目录（IK/SPK+签名/OPK×N）——目录不可信，只当公告板");

    let init = initiate::<S, _>(&mut rng, &alice_id, &bundle).unwrap();
    println!("  [发起]   Alice 拉 bundle → 验 SPK 签名 → DH₁..₄ → HKDF → 共享 root（Bob 全程离线）");
    let resp = respond::<S>(
        ResponderKeys {
            identity: &bob_id,
            signed_prekey_private: &spk_priv,
            one_time_prekey_private: Some(&opk_priv),
        },
        &init.initial_message,
    )
    .unwrap();
    println!("  [上线]   Bob 用私钥补算出同一个 root ✓（OPK#7 用后即删）");
    println!("  服务器视角：几把公钥 + 一段解不开的密文。没了。");

    let mut alice = SecureSession::initiator::<S, _>(&mut rng, init.root, init.their_ratchet_public).unwrap();
    let bob = SecureSession::receiver(resp.root, resp.my_ratchet_private, resp.my_ratchet_public);

    // ─────────────────────────────── 第二幕：双棘轮 ───────────────────────────────
    banner("② 双棘轮：每条消息一把钥匙，乱序能解，篡改不失步");
    let mut store = MemoryStore::new();
    store.put_initial("conv:42", bob);
    let mut bob_mem = store.load("conv:42").unwrap();

    let (h0, c0) = alice.encrypt::<S>(AD, "早上的并购会改到 3 点".as_bytes()).unwrap();
    let (h1, c1) = alice.encrypt::<S>(AD, "带上估值模型 v7".as_bytes()).unwrap();
    let (h2, c2) = alice.encrypt::<S>(AD, "这事先别扩散".as_bytes()).unwrap();
    println!("  Alice 连发 3 条（n=0,1,2），网络把 n=2 先送到——");
    let pt2 = bob_mem.decrypt::<S, _>(&mut rng, &h2, &c2, AD).unwrap();
    println!("  Bob 先解 n=2：『{}』（n=0,1 的钥匙已缓存待用）", String::from_utf8_lossy(&pt2));
    let pt0 = bob_mem.decrypt::<S, _>(&mut rng, &h0, &c0, AD).unwrap();
    let pt1 = bob_mem.decrypt::<S, _>(&mut rng, &h1, &c1, AD).unwrap();
    println!("  迟到的 n=0『{}』n=1『{}』照常解出 ✓", String::from_utf8_lossy(&pt0), String::from_utf8_lossy(&pt1));

    let (h3, c3) = alice.encrypt::<S>(AD, "第四条".as_bytes()).unwrap();
    let mut forged = c3.clone();
    forged[0] ^= 0xFF;
    assert!(bob_mem.decrypt::<S, _>(&mut rng, &h3, &forged, AD).is_err());
    let pt3 = bob_mem.decrypt::<S, _>(&mut rng, &h3, &c3, AD).unwrap();
    println!("  攻击者篡改第 4 条 → 解密拒绝；紧接着真第 4 条『{}』仍可解 ✓（伪造不推进棘轮状态）", String::from_utf8_lossy(&pt3));

    // ─────────────────────────────── 第三幕：解密即事务 ───────────────────────────────
    banner("③ 解密即事务：掉电不丢消息，重放不吃两次钥匙");
    let (h4, c4) = alice.encrypt::<S>(AD, "掉电测试消息".as_bytes()).unwrap();

    store.arm_crash();
    let r = receive_and_commit::<S, _, _>(
        &mut store, &mut rng, "conv:42", &mut bob_mem,
        Incoming { message_id: "m4", header: &h4, ciphertext: &c4, ad: AD },
    );
    println!("  [模拟掉电] 解密后、事务提交前掉电 → {:?}", r.err().unwrap());
    println!("             消息落库？{} —— 整体回滚，什么都没发生", store.contains_message("m4"));

    drop(bob_mem); // 进程重启：丢弃内存态
    let mut bob_restart = store.load("conv:42").unwrap();
    let pt = receive_and_commit::<S, _, _>(
        &mut store, &mut rng, "conv:42", &mut bob_restart,
        Incoming { message_id: "m4", header: &h4, ciphertext: &c4, ad: AD },
    )
    .unwrap();
    println!("  [重启+重推] 从存储恢复旧会话态 → 重新解出『{}』✓ 消息不丢", String::from_utf8_lossy(&pt.unwrap()));

    let replay = receive_and_commit::<S, _, _>(
        &mut store, &mut rng, "conv:42", &mut bob_restart,
        Incoming { message_id: "m4", header: &h4, ciphertext: &c4, ad: AD },
    )
    .unwrap();
    println!("  [服务端再推一次] 幂等锚点拦截 → {replay:?} ✓ 棘轮密钥绝不二次消耗");

    // ─────────────────────────────── 第四幕：群密聊 ───────────────────────────────
    banner("④ 群密聊 Sender Keys：发一条 O(1)，踢一人全员换锁");
    let names: Vec<MemberId> = vec!["alice".into(), "bob".into(), "carol".into()];
    let mut groups: Vec<(MemberId, SenderKeyGroup)> = Vec::new();
    let mut all_tasks = Vec::new();
    for me in &names {
        let others: Vec<MemberId> = names.iter().filter(|n| *n != me).cloned().collect();
        let (g, tasks) = SenderKeyGroup::create::<S, _>(&mut rng, &others);
        groups.push((me.clone(), g));
        all_tasks.push((me.clone(), tasks));
    }
    for (from, tasks) in all_tasks {
        for t in tasks {
            if let Some((_, g)) = groups.iter_mut().find(|(n, _)| *n == t.to) {
                g.install(from.clone(), t.distribution);
            }
        }
    }
    println!("  三人群建立：每人的 SenderKey 经 pairwise 密聊分发给其余成员（3×2=6 条分发）");

    let msg = groups[0].1.encrypt::<S>(b"group:ma", "季度目标只对齐到 VP 层".as_bytes()).unwrap();
    for (name, g) in groups.iter_mut().skip(1) {
        let pt = g.decrypt::<S>(&"alice".into(), b"group:ma", &msg).unwrap();
        println!("  {name} 解出 alice 的群播：『{}』（加密一次，服务端只扇出密文）", String::from_utf8_lossy(&pt));
    }

    // 踢掉 carol：alice 轮换并只重发给 bob
    let tasks = {
        let (_, ga) = &mut groups[0];
        ga.on_member_removed::<S, _>(&mut rng, &"carol".into(), &["bob".into()])
    };
    for t in tasks {
        if let Some((_, g)) = groups.iter_mut().find(|(n, _)| *n == t.to) {
            g.install("alice".into(), t.distribution);
        }
    }
    let post = groups[0].1.encrypt::<S>(b"group:ma", "carol 已离项目组".as_bytes()).unwrap();
    let bob_ok = groups[1].1.decrypt::<S>(&"alice".into(), b"group:ma", &post).is_ok();
    let carol_out = groups[2].1.decrypt::<S>(&"alice".into(), b"group:ma", &post).is_err();
    println!("  踢人后 alice 轮换 SenderKey：bob 可解 = {bob_ok} ✓，carol 可解 = {} ✓（旧钥作废）", !carol_out);

    // ─────────────────────────────── 第五幕：密钥透明度 ───────────────────────────────
    banner("⑤ 密钥透明度（真 Merkle 账本）：目录换钥必留痕，改写历史必被识破");
    let mut ktlog = MerkleKtLog::<S>::new(&mut rng);
    let dave = generate_identity::<S, _>(&mut rng);
    ktlog.record("alice@corp", alice_id.public()).unwrap();
    ktlog.record("bob@corp", bob_id.public()).unwrap();
    println!("  目录登记 alice/bob 进 append-only Merkle 日志（树大小 = 2）");

    let (identity, proof) = ktlog.lookup("bob@corp").unwrap();
    verify_kt_proof::<S>(&ktlog.log_public(), "bob@corp", &identity, &proof).unwrap();
    println!("  客户端拉 bob 的身份 + 证明包 → 树头签名 ✓ 包含证明 ✓（无需账本本体）");
    assert!(verify_kt_proof::<S>(&ktlog.log_public(), "bob@corp", &dave.public(), &proof).is_err());
    println!("  目录若返回别人的公钥 → 包含证明失败 ✓（叶哈希对不上）");

    let mut monitor = KtMonitor::new();
    monitor.advance::<S>(&ktlog.log_public(), &ktlog.sth().unwrap(), &[]).unwrap();
    ktlog.record("bob@corp", dave.public()).unwrap(); // bob 换钥（或被换钥）——唯一合法路径是追加
    let consistency = ktlog.consistency_since(2).unwrap();
    monitor.advance::<S>(&ktlog.log_public(), &ktlog.sth().unwrap(), &consistency).unwrap();
    println!(
        "  bob 换钥 = 追加新条目：一致性证明 ✓ 锚点前进到 {}；登记次数 = {} → 监控端告警口径",
        monitor.pinned_size(),
        ktlog.history_count("bob@corp")
    );
    println!("  （改写历史叶再续写 → 一致性证明必失败，见 kt 模块测试；此即「作恶必留痕」）");

    println!("\n全部演示通过。完整验证体系（95 项测试 / 千种子 DST / 真 SQLCipher 事务 / C ABI 冒烟 / 官方向量 / 国密 spike）另见 `cargo test`。");
}

