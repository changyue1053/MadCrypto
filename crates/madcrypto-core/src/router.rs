//! 多设备 pairwise 路由编排（架构 §10 / 实施计划 P5 残余回填）。
//!
//! "给张三发一条密信" = 对扇出计划里的每台设备各跑一条 pairwise 双棘轮：
//! - 缺会话的设备**就地 X3DH 建立**，该设备的首只信封携带首包头（对端凭它建响应侧会话）；
//! - 每台设备独立密文——不存在共享组密钥，单设备失陷不波及其他设备的前向保密；
//! - 设备被撤销（MDM 收权）→ 会话当场剔除：新建被 sesame 挡（不在扇出计划），存量在此收口；
//! - 新设备**结构性读不到历史**（pairwise 从加入起点开始）——历史补齐是"老设备重新加密直传"，
//!   本模块产出待办清单，搬运走业务消息通道（密文对服务器仍不透明）。

use std::collections::{HashMap, HashSet};

use madcrypto_prims::CipherSuite;
use rand_core::{CryptoRng, RngCore};

use crate::error::{CryptoError, Result};
use crate::keys::IdentityKeyPair;
use crate::ratchet::Header;
use crate::sesame::{fanout_plan, DeviceChange, DeviceRecord};
use crate::session::SecureSession;
use crate::x3dh::{initiate, respond, InitialMessage, PreKeyBundle, ResponderKeys};

fn addr(user: &str, device: &str) -> String {
    format!("{user}/{device}")
}

/// 目录抽象：按设备取 prekey bundle。生产为目录服务（上游必须先过 kt::verify_directory_entry
/// 三层验证）；测试为内存目录。
pub trait BundleDirectory {
    fn bundle_for(&self, user: &str, device_id: &str) -> Result<PreKeyBundle>;
}

/// 发给单台设备的信封。`initial` 仅在与该设备的首条消息上携带。
pub struct DeviceEnvelope {
    pub user: String,
    pub device_id: String,
    pub initial: Option<InitialMessage>,
    pub header: Header,
    pub ciphertext: Vec<u8>,
}

/// 历史直传待办：新设备加入后由本方老设备重新加密历史并直传（业务层消费与搬运）。
#[derive(Debug, PartialEq, Eq)]
pub struct HistoryHandoff {
    pub user: String,
    pub device_id: String,
}

/// 每设备一条 pairwise 会话的路由器（单个本机设备视角）。
pub struct DeviceRouter {
    my_user: String,
    my_device: String,
    sessions: HashMap<String, SecureSession>,
    pending_handoffs: Vec<HistoryHandoff>,
}

impl DeviceRouter {
    pub fn new(my_user: &str, my_device: &str) -> Self {
        Self {
            my_user: my_user.to_string(),
            my_device: my_device.to_string(),
            sessions: HashMap::new(),
            pending_handoffs: Vec::new(),
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn has_session(&self, user: &str, device: &str) -> bool {
        self.sessions.contains_key(&addr(user, device))
    }

    /// 扇出加密：计划 = 对端全部设备 + 自己其他设备（sesame::fanout_plan）。
    /// 缺会话的设备就地 X3DH；全部信封使用同一 AD（policy 的规范构造）与同一明文。
    #[allow(clippy::too_many_arguments)] // 编排入口：参数即协作方清单，收拢成 struct 反而藏依赖
    pub fn encrypt_fanout<S: CipherSuite, R: RngCore + CryptoRng, D: BundleDirectory>(
        &mut self,
        rng: &mut R,
        my_identity: &IdentityKeyPair,
        directory: &D,
        my_devices: &[DeviceRecord],
        peer_user: &str,
        peer_devices: &[DeviceRecord],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<DeviceEnvelope>> {
        let plan = fanout_plan(&self.my_device, my_devices, peer_devices);
        let peer_ids: HashSet<&str> = peer_devices.iter().map(|d| d.device_id.as_str()).collect();
        let mut out = Vec::with_capacity(plan.len());
        for dev in plan {
            let user = if peer_ids.contains(dev.device_id.as_str()) {
                peer_user
            } else {
                self.my_user.as_str()
            };
            let key = addr(user, &dev.device_id);
            let mut initial = None;
            if !self.sessions.contains_key(&key) {
                let bundle = directory.bundle_for(user, &dev.device_id)?;
                let init = initiate::<S, _>(rng, my_identity, &bundle)?;
                let session = SecureSession::initiator::<S, _>(rng, init.root, init.their_ratchet_public)?;
                self.sessions.insert(key.clone(), session);
                initial = Some(init.initial_message);
            }
            let session = self.sessions.get_mut(&key).expect("session just ensured");
            let (header, ciphertext) = session.encrypt::<S>(ad, plaintext)?;
            out.push(DeviceEnvelope {
                user: user.to_string(),
                device_id: dev.device_id.clone(),
                initial,
                header,
                ciphertext,
            });
        }
        Ok(out)
    }

    /// 收方入口：与发方设备无会话时，信封必须带首包头（且调用方提供本设备响应私钥）。
    pub fn decrypt_from<S: CipherSuite, R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        from_user: &str,
        from_device: &str,
        responder: Option<ResponderKeys<'_>>,
        envelope: &DeviceEnvelope,
        ad: &[u8],
    ) -> Result<Vec<u8>> {
        let key = addr(from_user, from_device);
        if !self.sessions.contains_key(&key) {
            let init = envelope
                .initial
                .as_ref()
                .ok_or(CryptoError::Handshake("无既有会话且信封缺少首包头"))?;
            let keys = responder.ok_or(CryptoError::Handshake("缺少响应方 prekey 私钥"))?;
            let resp = respond::<S>(keys, init)?;
            self.sessions.insert(
                key.clone(),
                SecureSession::receiver(resp.root, resp.my_ratchet_private, resp.my_ratchet_public),
            );
        }
        let session = self.sessions.get_mut(&key).expect("session just ensured");
        session.decrypt::<S, R>(rng, &envelope.header, &envelope.ciphertext, ad)
    }

    /// 设备列表变更钩子（sesame::DeviceRegistry::update 的产物接到这里）：
    /// 撤销 → 存量会话当场剔除；新增 → 历史直传待办登记（本机设备除外）。
    pub fn apply_device_change(&mut self, user: &str, change: &DeviceChange) {
        for removed in &change.removed {
            self.sessions.remove(&addr(user, removed));
        }
        for added in &change.added {
            if !(user == self.my_user && added == &self.my_device) {
                self.pending_handoffs.push(HistoryHandoff {
                    user: user.to_string(),
                    device_id: added.clone(),
                });
            }
        }
    }

    /// 取走历史直传待办（业务层消费后编排老设备直传）。
    pub fn take_handoffs(&mut self) -> Vec<HistoryHandoff> {
        std::mem::take(&mut self.pending_handoffs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{DhPrivate, DhPublic};
    use crate::sesame::{sign_device_list, DeviceRegistry};
    use crate::x3dh::{generate_identity, new_signed_prekey};
    use madcrypto_prims::IntlSuite;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    type S = IntlSuite;
    const AD: &[u8] = b"conv:77|secret-track|intl";

    /// 测试目录：每台设备一份 bundle + 响应私钥（模拟各设备的本地 prekey 库存）。
    struct TestDirectory {
        bundles: HashMap<String, PreKeyBundle>,
        spk_privs: HashMap<String, DhPrivate>,
        identities: HashMap<String, crate::keys::IdentityKeyPair>,
    }

    impl TestDirectory {
        fn new() -> Self {
            Self { bundles: HashMap::new(), spk_privs: HashMap::new(), identities: HashMap::new() }
        }
        /// 注册一台设备（设备级身份 + SPK），返回其 DeviceRecord。
        fn register(&mut self, rng: &mut ChaCha20Rng, user: &str, device: &str) -> DeviceRecord {
            let identity = generate_identity::<S, _>(rng);
            let (spk_priv, spk_pub, spk_sig) = new_signed_prekey::<S, _>(rng, &identity).unwrap();
            let key = addr(user, device);
            self.bundles.insert(
                key.clone(),
                PreKeyBundle {
                    suite: S::id(),
                    identity: identity.public(),
                    signed_prekey: spk_pub.clone(),
                    signed_prekey_sig: spk_sig,
                    one_time_prekey: None,
                },
            );
            self.spk_privs.insert(key.clone(), spk_priv);
            self.identities.insert(key, identity);
            DeviceRecord { device_id: device.to_string(), dh_public: DhPublic::new(spk_pub.as_slice().to_vec()) }
        }
        fn responder_keys(&self, user: &str, device: &str) -> ResponderKeys<'_> {
            let key = addr(user, device);
            ResponderKeys {
                identity: &self.identities[&key],
                signed_prekey_private: &self.spk_privs[&key],
                one_time_prekey_private: None,
            }
        }
    }

    impl BundleDirectory for TestDirectory {
        fn bundle_for(&self, user: &str, device_id: &str) -> Result<PreKeyBundle> {
            self.bundles
                .get(&addr(user, device_id))
                .cloned()
                .ok_or(CryptoError::Handshake("目录无此设备"))
        }
    }

    #[test]
    fn fanout_is_pairwise_and_every_device_decrypts() {
        let mut rng = ChaCha20Rng::seed_from_u64(80);
        let mut dir = TestDirectory::new();
        let alice_id = generate_identity::<S, _>(&mut rng);

        let a_phone = dir.register(&mut rng, "alice", "a-phone");
        let a_desk = dir.register(&mut rng, "alice", "a-desk");
        let b_phone = dir.register(&mut rng, "bob", "b-phone");
        let b_desk = dir.register(&mut rng, "bob", "b-desk");
        let my_devices = vec![a_phone, a_desk];
        let peer_devices = vec![b_phone, b_desk];

        let mut sender = DeviceRouter::new("alice", "a-phone");
        let envs = sender
            .encrypt_fanout::<S, _, _>(&mut rng, &alice_id, &dir, &my_devices, "bob", &peer_devices, AD, b"m1")
            .unwrap();
        // 扇出 = bob 两台 + 自己桌面；首轮全部携带首包头
        let ids: Vec<&str> = envs.iter().map(|e| e.device_id.as_str()).collect();
        assert_eq!(ids, vec!["b-phone", "b-desk", "a-desk"]);
        assert!(envs.iter().all(|e| e.initial.is_some()));
        // pairwise：同一明文在不同设备的密文不同（各自独立棘轮）
        assert_ne!(envs[0].ciphertext, envs[1].ciphertext);

        // 每台收方设备各自建会话并解出同一明文
        for e in &envs {
            let mut receiver = DeviceRouter::new(&e.user, &e.device_id);
            let pt = receiver
                .decrypt_from::<S, _>(
                    &mut rng,
                    "alice",
                    "a-phone",
                    Some(dir.responder_keys(&e.user, &e.device_id)),
                    e,
                    AD,
                )
                .unwrap();
            assert_eq!(pt, b"m1");
        }

        // 第二条：会话已缓存，不再携带首包头，也不再查目录
        let envs2 = sender
            .encrypt_fanout::<S, _, _>(&mut rng, &alice_id, &dir, &my_devices, "bob", &peer_devices, AD, b"m2")
            .unwrap();
        assert!(envs2.iter().all(|e| e.initial.is_none()));
        assert_eq!(sender.session_count(), 3);
    }

    #[test]
    fn revoked_device_is_evicted_from_sessions_and_fanout() {
        let mut rng = ChaCha20Rng::seed_from_u64(81);
        let mut dir = TestDirectory::new();
        let alice_id = generate_identity::<S, _>(&mut rng);
        let bob_id = generate_identity::<S, _>(&mut rng);

        let a_phone = dir.register(&mut rng, "alice", "a-phone");
        let b_phone = dir.register(&mut rng, "bob", "b-phone");
        let b_desk = dir.register(&mut rng, "bob", "b-desk");
        let my_devices = vec![a_phone];

        let mut bob_reg = DeviceRegistry::new(bob_id.public().sign);
        bob_reg
            .update::<S>(sign_device_list::<S>(&bob_id, 1, vec![b_phone.clone(), b_desk.clone()]).unwrap())
            .unwrap();

        let mut sender = DeviceRouter::new("alice", "a-phone");
        sender
            .encrypt_fanout::<S, _, _>(&mut rng, &alice_id, &dir, &my_devices, "bob", bob_reg.devices(), AD, b"m1")
            .unwrap();
        assert!(sender.has_session("bob", "b-desk"));

        // MDM 收权：v2 列表剔除 b-desk → 注册表产出 change → 路由器剔除存量会话
        let change = bob_reg
            .update::<S>(sign_device_list::<S>(&bob_id, 2, vec![b_phone.clone()]).unwrap())
            .unwrap();
        sender.apply_device_change("bob", &change);
        assert!(!sender.has_session("bob", "b-desk"), "被撤销设备的存量会话必须当场剔除");

        // 后续扇出结构性不含被撤销设备（新建被 sesame 挡，存量已收口——两把闸门都到位）
        let envs = sender
            .encrypt_fanout::<S, _, _>(&mut rng, &alice_id, &dir, &my_devices, "bob", bob_reg.devices(), AD, b"m2")
            .unwrap();
        assert!(envs.iter().all(|e| e.device_id != "b-desk"));
        assert!(!sender.has_session("bob", "b-desk"));
    }

    #[test]
    fn new_device_reads_nothing_before_join_and_gets_handoff() {
        let mut rng = ChaCha20Rng::seed_from_u64(82);
        let mut dir = TestDirectory::new();
        let alice_id = generate_identity::<S, _>(&mut rng);
        let bob_id = generate_identity::<S, _>(&mut rng);

        let a_phone = dir.register(&mut rng, "alice", "a-phone");
        let b_phone = dir.register(&mut rng, "bob", "b-phone");
        let my_devices = vec![a_phone];

        let mut bob_reg = DeviceRegistry::new(bob_id.public().sign);
        bob_reg
            .update::<S>(sign_device_list::<S>(&bob_id, 1, vec![b_phone.clone()]).unwrap())
            .unwrap();

        let mut sender = DeviceRouter::new("alice", "a-phone");
        let m1 = sender
            .encrypt_fanout::<S, _, _>(&mut rng, &alice_id, &dir, &my_devices, "bob", bob_reg.devices(), AD, b"history")
            .unwrap();
        // 历史消息的信封集合里结构性不存在未来设备
        assert!(m1.iter().all(|e| e.device_id != "b-tablet"));

        // 新设备加入 → 路由器登记历史直传待办（老设备重新加密直传，业务层搬运）
        let b_tablet = dir.register(&mut rng, "bob", "b-tablet");
        let change = bob_reg
            .update::<S>(sign_device_list::<S>(&bob_id, 2, vec![b_phone.clone(), b_tablet.clone()]).unwrap())
            .unwrap();
        sender.apply_device_change("bob", &change);
        assert_eq!(
            sender.take_handoffs(),
            vec![HistoryHandoff { user: "bob".into(), device_id: "b-tablet".into() }]
        );
        assert!(sender.take_handoffs().is_empty(), "待办取走即清");

        // 新消息正常送达新设备（含首包头），且新设备解不出任何"历史"——它根本没有历史信封
        let m2 = sender
            .encrypt_fanout::<S, _, _>(&mut rng, &alice_id, &dir, &my_devices, "bob", bob_reg.devices(), AD, b"fresh")
            .unwrap();
        let tablet_env = m2.iter().find(|e| e.device_id == "b-tablet").unwrap();
        assert!(tablet_env.initial.is_some());
        let mut tablet = DeviceRouter::new("bob", "b-tablet");
        let pt = tablet
            .decrypt_from::<S, _>(&mut rng, "alice", "a-phone", Some(dir.responder_keys("bob", "b-tablet")), tablet_env, AD)
            .unwrap();
        assert_eq!(pt, b"fresh");
    }

    #[test]
    fn missing_initial_without_session_is_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(83);
        let mut dir = TestDirectory::new();
        let alice_id = generate_identity::<S, _>(&mut rng);
        let a_phone = dir.register(&mut rng, "alice", "a-phone");
        let b_phone = dir.register(&mut rng, "bob", "b-phone");

        let mut sender = DeviceRouter::new("alice", "a-phone");
        let mut envs = sender
            .encrypt_fanout::<S, _, _>(&mut rng, &alice_id, &dir, &[a_phone], "bob", &[b_phone], AD, b"x")
            .unwrap();
        // 剥掉首包头模拟丢失/恶意剔除：无会话的收方必须显式拒绝（而不是 panic 或误建会话）
        envs[0].initial = None;
        let mut receiver = DeviceRouter::new("bob", "b-phone");
        let err = receiver
            .decrypt_from::<S, _>(&mut rng, "alice", "a-phone", Some(dir.responder_keys("bob", "b-phone")), &envs[0], AD)
            .err()
            .unwrap();
        assert_eq!(err, CryptoError::Handshake("无既有会话且信封缺少首包头"));
    }
}

