//! 属性测试（实施 P4.4 / P6.6，架构 §17 L2）：把乱序/重复/轮换的语义形式化成
//! "对任意输入成立"的不变量，随机剧本由 proptest 生成并在失败时自动最小化。
//!
//! 不变量清单：
//! 1. 双方会话：任意轮次、任意批量、任意送达顺序——凡真实发出的消息必可解且明文一致；
//! 2. 重复投递（重放）必被拒绝，且**不破坏**后续合法消息的解密（事务性解密的推论）；
//! 3. 全部延迟消息消化后，会话仍健康（新一轮往返成功）——双端状态收敛；
//! 4. 群：任意条数、任意送达顺序全部可解；轮换后旧接收态必不可解、新分发后恢复。

use madcrypto_core::group::{GroupReceiver, GroupSender};
use madcrypto_core::ratchet::Header;
use madcrypto_core::session::SecureSession;
use madcrypto_core::x3dh::{
    generate_identity, initiate, new_signed_prekey, respond, PreKeyBundle, ResponderKeys,
};
use madcrypto_prims::{CipherSuite as _, IntlSuite};
use proptest::prelude::*;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

type S = IntlSuite;
const AD: &[u8] = b"conv:prop";

fn establish(seed: u64) -> (SecureSession, SecureSession, ChaCha20Rng) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
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

fn shuffle<T>(v: &mut [T], rng: &mut ChaCha20Rng) {
    for i in (1..v.len()).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        v.swap(i, j);
    }
}

struct Delayed {
    to_bob: bool,
    header: Header,
    ct: Vec<u8>,
    expected: Vec<u8>,
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// 不变量 1+2+3：多轮双向会话，任意送达顺序 + 重放注入，全部收敛。
    #[test]
    fn pairwise_any_interleaving_converges(
        rounds in prop::collection::vec((1usize..=4, 1usize..=4), 1..=3),
        crypto_seed in any::<u64>(),
        shuffle_seed in any::<u64>(),
    ) {
        let (mut alice, mut bob, mut rng) = establish(crypto_seed);
        let mut sh = ChaCha20Rng::seed_from_u64(shuffle_seed);
        let mut delayed: Vec<Delayed> = Vec::new();
        let mut consumed: Vec<Delayed> = Vec::new(); // 已送达的，供重放注入

        for (r, (n_a, n_b)) in rounds.iter().enumerate() {
            // Alice 发一批：第一条立即送达（维持协议因果），其余延迟
            for k in 0..*n_a {
                let pt = format!("a:{r}:{k}").into_bytes();
                let (h, ct) = alice.encrypt::<S>(AD, &pt).unwrap();
                if k == 0 {
                    prop_assert_eq!(bob.decrypt::<S, _>(&mut rng, &h, &ct, AD).unwrap(), pt.clone());
                    consumed.push(Delayed { to_bob: true, header: h, ct, expected: pt });
                } else {
                    delayed.push(Delayed { to_bob: true, header: h, ct, expected: pt });
                }
            }
            // Bob 回一批：同上
            for k in 0..*n_b {
                let pt = format!("b:{r}:{k}").into_bytes();
                let (h, ct) = bob.encrypt::<S>(AD, &pt).unwrap();
                if k == 0 {
                    prop_assert_eq!(alice.decrypt::<S, _>(&mut rng, &h, &ct, AD).unwrap(), pt.clone());
                    consumed.push(Delayed { to_bob: false, header: h, ct, expected: pt });
                } else {
                    delayed.push(Delayed { to_bob: false, header: h, ct, expected: pt });
                }
            }
        }

        // 网络把全部滞留消息以任意顺序吐出来——每一条都必须解出原文
        shuffle(&mut delayed, &mut sh);
        for d in delayed {
            let got = if d.to_bob {
                bob.decrypt::<S, _>(&mut rng, &d.header, &d.ct, AD).unwrap()
            } else {
                alice.decrypt::<S, _>(&mut rng, &d.header, &d.ct, AD).unwrap()
            };
            prop_assert_eq!(got, d.expected.clone());
            consumed.push(d);
        }

        // 不变量 2：重放已消费的消息（任取三分之一）必被拒绝，且不破坏状态
        shuffle(&mut consumed, &mut sh);
        for d in consumed.iter().take(consumed.len().div_ceil(3)) {
            let r = if d.to_bob {
                bob.decrypt::<S, _>(&mut rng, &d.header, &d.ct, AD)
            } else {
                alice.decrypt::<S, _>(&mut rng, &d.header, &d.ct, AD)
            };
            prop_assert!(r.is_err(), "重放必须被拒绝");
        }

        // 不变量 3：会话仍健康——新一轮完整往返
        let (h, ct) = alice.encrypt::<S>(AD, b"final-a").unwrap();
        prop_assert_eq!(bob.decrypt::<S, _>(&mut rng, &h, &ct, AD).unwrap(), b"final-a");
        let (h, ct) = bob.encrypt::<S>(AD, b"final-b").unwrap();
        prop_assert_eq!(alice.decrypt::<S, _>(&mut rng, &h, &ct, AD).unwrap(), b"final-b");
    }

    /// 单方向大批量的更强洗牌覆盖：N ≤ 30 条任意顺序全部可解。
    #[test]
    fn one_direction_full_permutation(
        n in 1usize..=30,
        crypto_seed in any::<u64>(),
        shuffle_seed in any::<u64>(),
    ) {
        let (mut alice, mut bob, mut rng) = establish(crypto_seed);
        let mut sh = ChaCha20Rng::seed_from_u64(shuffle_seed);
        let mut msgs: Vec<(Header, Vec<u8>, Vec<u8>)> = (0..n)
            .map(|k| {
                let pt = format!("m{k}").into_bytes();
                let (h, ct) = alice.encrypt::<S>(AD, &pt).unwrap();
                (h, ct, pt)
            })
            .collect();
        shuffle(&mut msgs, &mut sh);
        for (h, ct, pt) in msgs {
            prop_assert_eq!(bob.decrypt::<S, _>(&mut rng, &h, &ct, AD).unwrap(), pt);
        }
    }

    /// 不变量 4：群消息任意乱序全部可解；重复必拒；轮换语义正确。
    #[test]
    fn group_any_order_and_rotation(
        n in 1usize..=20,
        crypto_seed in any::<u64>(),
        shuffle_seed in any::<u64>(),
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(crypto_seed);
        let mut sh = ChaCha20Rng::seed_from_u64(shuffle_seed);
        let mut sender = GroupSender::new::<S, _>(&mut rng);
        let mut receiver = GroupReceiver::from_distribution(sender.distribution());

        let mut msgs: Vec<(madcrypto_core::group::GroupMessage, Vec<u8>)> = (0..n)
            .map(|k| {
                let pt = format!("g{k}").into_bytes();
                (sender.encrypt::<S>(AD, &pt).unwrap(), pt)
            })
            .collect();
        shuffle(&mut msgs, &mut sh);
        for (m, pt) in &msgs {
            prop_assert_eq!(&receiver.decrypt::<S>(AD, m).unwrap(), pt);
        }
        // 重放任一条必拒
        prop_assert!(receiver.decrypt::<S>(AD, &msgs[0].0).is_err());

        // 轮换：旧接收态对新消息必不可解；安装新分发后恢复
        sender = GroupSender::new::<S, _>(&mut rng);
        let fresh = sender.encrypt::<S>(AD, b"rotated").unwrap();
        prop_assert!(receiver.decrypt::<S>(AD, &fresh).is_err());
        let mut receiver2 = GroupReceiver::from_distribution(sender.distribution());
        prop_assert!(receiver2.decrypt::<S>(AD, &fresh).is_err(), "分发晚于消息 = 读不到历史");
        let next = sender.encrypt::<S>(AD, b"after-dist").unwrap();
        prop_assert_eq!(receiver2.decrypt::<S>(AD, &next).unwrap(), b"after-dist");
    }
}

