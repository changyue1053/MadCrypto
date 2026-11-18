//! 多设备 Sesame（架构 §10）：设备注册表 + 扇出计划 + 撤销语义。
//!
//! 员工必然手机 + 桌面并用。每台设备独立密钥对，"给张三发密信"= 给张三全部设备
//! 和自己其他设备各跑一次 pairwise 棘轮。设备列表由**身份签名密钥**背书且版本单调——
//! 目录服务器静默塞一台"影子设备"进列表 = 伪造签名，做不到；回滚旧列表 = 版本倒退，拒收。
//! 撤销（离职一键收权，MDM 联动）= 发布不含该设备的新版本列表，扇出计划即刻剔除。

use madcrypto_prims::CipherSuite;

use crate::error::{CryptoError, Result};
use crate::keys::{DhPublic, IdentityKeyPair, SignPublic};

/// 设备记录：设备号 + 该设备的棘轮引导公钥（prekey bundle 仍按设备从目录拉取）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DeviceRecord {
    pub device_id: String,
    pub dh_public: DhPublic,
}

/// 由身份签名密钥背书的设备列表。版本单调递增（防回滚），签名覆盖版本 + 全部设备。
#[derive(Clone)]
pub struct SignedDeviceList {
    pub version: u64,
    pub devices: Vec<DeviceRecord>,
    pub signature: Vec<u8>,
}

fn signing_bytes(version: u64, devices: &[DeviceRecord]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 * devices.len() + 8);
    out.extend_from_slice(b"IMCrypto/v1/device-list");
    out.extend_from_slice(&version.to_be_bytes());
    for d in devices {
        let id = d.device_id.as_bytes();
        out.extend_from_slice(&(id.len() as u16).to_be_bytes());
        out.extend_from_slice(id);
        let pk = d.dh_public.as_slice();
        out.extend_from_slice(&(pk.len() as u16).to_be_bytes());
        out.extend_from_slice(pk);
    }
    out
}

/// 本人侧：用身份密钥签发新版本设备列表（增删设备都走这里）。
pub fn sign_device_list<S: CipherSuite>(
    identity: &IdentityKeyPair,
    version: u64,
    devices: Vec<DeviceRecord>,
) -> Result<SignedDeviceList> {
    let signature = S::sign(identity.sign_private.expose(), &signing_bytes(version, &devices))?;
    Ok(SignedDeviceList {
        version,
        devices,
        signature,
    })
}

/// 设备变更摘要：抛给业务层做"对方设备列表已变化"的会话内提示（架构 §10）。
#[derive(Debug, PartialEq, Eq)]
pub struct DeviceChange {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

/// 对某个联系人的设备注册表：只接受签名合法且版本更新的列表。
pub struct DeviceRegistry {
    identity_sign: SignPublic,
    current: Option<SignedDeviceList>,
}

impl DeviceRegistry {
    pub fn new(identity_sign: SignPublic) -> Self {
        Self {
            identity_sign,
            current: None,
        }
    }

    /// 应用一份新设备列表。拒绝：签名非法（影子设备攻击）/ 版本回退（回滚攻击）。
    pub fn update<S: CipherSuite>(&mut self, list: SignedDeviceList) -> Result<DeviceChange> {
        if !S::verify(
            self.identity_sign.as_slice(),
            &signing_bytes(list.version, &list.devices),
            &list.signature,
        ) {
            return Err(CryptoError::Handshake("设备列表签名非法（疑似目录塞入影子设备）"));
        }
        if let Some(cur) = &self.current {
            if list.version <= cur.version {
                return Err(CryptoError::Handshake("设备列表版本回退（疑似回滚攻击）"));
            }
        }
        let change = self.diff(&list);
        self.current = Some(list);
        Ok(change)
    }

    pub fn devices(&self) -> &[DeviceRecord] {
        self.current.as_ref().map(|l| l.devices.as_slice()).unwrap_or(&[])
    }

    fn diff(&self, new: &SignedDeviceList) -> DeviceChange {
        let old_ids: Vec<&str> = self
            .current
            .as_ref()
            .map(|l| l.devices.iter().map(|d| d.device_id.as_str()).collect())
            .unwrap_or_default();
        let new_ids: Vec<&str> = new.devices.iter().map(|d| d.device_id.as_str()).collect();
        DeviceChange {
            added: new_ids
                .iter()
                .filter(|id| !old_ids.contains(id))
                .map(|s| s.to_string())
                .collect(),
            removed: old_ids
                .iter()
                .filter(|id| !new_ids.contains(id))
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

/// 扇出计划：一条密聊消息要加密给哪些设备（架构 §10）。
/// = 收件人全部设备 + 自己除本机外的其他设备（多端同步已读自己的消息）。
pub fn fanout_plan(
    my_device_id: &str,
    my_devices: &[DeviceRecord],
    peer_devices: &[DeviceRecord],
) -> Vec<DeviceRecord> {
    let mut plan = Vec::with_capacity(my_devices.len() + peer_devices.len());
    plan.extend(peer_devices.iter().cloned());
    plan.extend(
        my_devices
            .iter()
            .filter(|d| d.device_id != my_device_id)
            .cloned(),
    );
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x3dh::generate_identity;
    use madcrypto_prims::IntlSuite;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    type S = IntlSuite;

    fn dev(rng: &mut ChaCha20Rng, id: &str) -> DeviceRecord {
        let kp = S::dh_keypair(rng);
        DeviceRecord {
            device_id: id.to_string(),
            dh_public: DhPublic::new(kp.public),
        }
    }

    #[test]
    fn signed_list_roundtrip_and_diff() {
        let mut rng = ChaCha20Rng::seed_from_u64(40);
        let id = generate_identity::<S, _>(&mut rng);
        let mut reg = DeviceRegistry::new(id.public().sign);

        let v1 = sign_device_list::<S>(&id, 1, vec![dev(&mut rng, "phone")]).unwrap();
        let c1 = reg.update::<S>(v1).unwrap();
        assert_eq!(c1.added, vec!["phone"]);

        // 加桌面端：v2
        let v2 = sign_device_list::<S>(&id, 2, vec![dev(&mut rng, "phone"), dev(&mut rng, "desktop")]).unwrap();
        let c2 = reg.update::<S>(v2).unwrap();
        assert_eq!(c2.added, vec!["desktop"]);
        assert!(c2.removed.is_empty());
        assert_eq!(reg.devices().len(), 2);
    }

    #[test]
    fn shadow_device_injection_is_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(41);
        let id = generate_identity::<S, _>(&mut rng);
        let mut reg = DeviceRegistry::new(id.public().sign);

        // 目录（或入侵者）想塞一台影子设备：改列表但签名对不上
        let mut list = sign_device_list::<S>(&id, 1, vec![dev(&mut rng, "phone")]).unwrap();
        list.devices.push(dev(&mut rng, "shadow-device"));
        let err = reg.update::<S>(list).err().unwrap();
        assert_eq!(err, CryptoError::Handshake("设备列表签名非法（疑似目录塞入影子设备）"));
    }

    #[test]
    fn version_rollback_is_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let id = generate_identity::<S, _>(&mut rng);
        let mut reg = DeviceRegistry::new(id.public().sign);

        let v2 = sign_device_list::<S>(&id, 2, vec![dev(&mut rng, "phone"), dev(&mut rng, "desktop")]).unwrap();
        reg.update::<S>(v2).unwrap();

        // 重放旧的 v1（试图让"已撤销设备"复活）→ 拒绝
        let v1_replay = sign_device_list::<S>(&id, 1, vec![dev(&mut rng, "stolen-laptop")]).unwrap();
        let err = reg.update::<S>(v1_replay).err().unwrap();
        assert_eq!(err, CryptoError::Handshake("设备列表版本回退（疑似回滚攻击）"));
    }

    #[test]
    fn revocation_removes_device_from_fanout() {
        let mut rng = ChaCha20Rng::seed_from_u64(43);
        let alice_id = generate_identity::<S, _>(&mut rng);
        let bob_id = generate_identity::<S, _>(&mut rng);

        // Alice 两台设备；Bob 两台设备
        let a_phone = dev(&mut rng, "a-phone");
        let a_desk = dev(&mut rng, "a-desktop");
        let b_phone = dev(&mut rng, "b-phone");
        let b_desk = dev(&mut rng, "b-desktop");

        let mut bob_reg = DeviceRegistry::new(bob_id.public().sign);
        bob_reg
            .update::<S>(sign_device_list::<S>(&bob_id, 1, vec![b_phone.clone(), b_desk.clone()]).unwrap())
            .unwrap();
        let mut alice_reg = DeviceRegistry::new(alice_id.public().sign);
        alice_reg
            .update::<S>(sign_device_list::<S>(&alice_id, 1, vec![a_phone.clone(), a_desk.clone()]).unwrap())
            .unwrap();

        // Alice 手机端发消息：扇出 = Bob 两台 + Alice 桌面（不含本机）
        let plan = fanout_plan("a-phone", alice_reg.devices(), bob_reg.devices());
        let ids: Vec<&str> = plan.iter().map(|d| d.device_id.as_str()).collect();
        assert_eq!(ids, vec!["b-phone", "b-desktop", "a-desktop"]);

        // MDM 撤销 Bob 桌面（离职收权）：新版本列表不含它 → 扇出即刻剔除
        let change = bob_reg
            .update::<S>(sign_device_list::<S>(&bob_id, 2, vec![b_phone.clone()]).unwrap())
            .unwrap();
        assert_eq!(change.removed, vec!["b-desktop"]);
        let plan2 = fanout_plan("a-phone", alice_reg.devices(), bob_reg.devices());
        let ids2: Vec<&str> = plan2.iter().map(|d| d.device_id.as_str()).collect();
        assert_eq!(ids2, vec!["b-phone", "a-desktop"], "被撤销设备不得再出现在扇出计划中");
    }
}

