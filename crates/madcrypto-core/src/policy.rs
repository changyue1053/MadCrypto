//! 租户策略引擎 + 防降级（架构 §12 §13 / 实施 P7.4/7.5）。
//!
//! 两件事：① 策略判定——密聊开关按租户/角色、套件强制、群上限（**租户配置而非常量**，
//! 实施 R4）；② 规范 AD 构造——轨道 / 套件 / 会话 / TTL 全部进 AEAD 关联数据，
//! "密聊消息塞进普通轨通道""静默降级套件""篡改阅后即焚时长"在密码学层直接解不开，
//! 而不是靠 UI 自觉（架构 §13 表格的代码化）。

use madcrypto_prims::SuiteId;

use crate::error::{CryptoError, Result};

/// 轨道标记：双轨在 AD 层不可混流（架构 §1/§13）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Track {
    Cloud = 1,
    Secret = 2,
}

/// 租户策略（管理后台下发，架构 §12 解法 1「管理开关」）。
pub struct TenantPolicy {
    /// 密聊总开关。
    pub secret_chat_enabled: bool,
    /// 高危岗位黑名单（内幕信息接触者等）——禁用密聊。
    pub blocked_roles: Vec<String>,
    /// 允许的密码套件（国密租户可强制 [Sm]）。
    pub allowed_suites: Vec<SuiteId>,
    /// 密聊群人数上限（决策门④的出口：上限是配置不是常量）。
    pub secret_group_limit: usize,
}

impl Default for TenantPolicy {
    fn default() -> Self {
        Self {
            secret_chat_enabled: true,
            blocked_roles: Vec::new(),
            allowed_suites: vec![SuiteId::Intl],
            secret_group_limit: 500,
        }
    }
}

impl TenantPolicy {
    /// 会话建立前的策略闸门：开关 → 角色 → 套件，全过才允许握手。
    pub fn check_secret_session(&self, role: &str, suite: SuiteId) -> Result<()> {
        if !self.secret_chat_enabled {
            return Err(CryptoError::PolicyRejected);
        }
        if self.blocked_roles.iter().any(|r| r == role) {
            return Err(CryptoError::PolicyRejected);
        }
        if !self.allowed_suites.contains(&suite) {
            return Err(CryptoError::PolicyRejected);
        }
        Ok(())
    }

    /// 密聊群人数闸门（建群与加人时都要过）。
    pub fn check_secret_group_size(&self, member_count: usize) -> Result<()> {
        if member_count > self.secret_group_limit {
            return Err(CryptoError::PolicyRejected);
        }
        Ok(())
    }
}

/// 规范 AD 构造：会话全部加解密必须使用本函数的输出，禁止手拼（防漏字段）。
/// 覆盖：域前缀 ‖ 轨道 ‖ 套件 ‖ 会话 ‖ TTL——任一字段被改，AEAD 直接拒绝。
pub fn session_ad(track: Track, suite: SuiteId, conv_id: &str, ttl_secs: Option<u32>) -> Vec<u8> {
    let mut v = Vec::with_capacity(conv_id.len() + 16);
    v.extend_from_slice(b"IMCrypto/ad/v1|");
    v.push(track as u8);
    v.push(suite.as_u8());
    v.extend_from_slice(&(conv_id.len() as u16).to_be_bytes());
    v.extend_from_slice(conv_id.as_bytes());
    match ttl_secs {
        Some(t) => {
            v.push(1);
            v.extend_from_slice(&t.to_be_bytes());
        }
        None => v.push(0),
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SecureSession;
    use crate::x3dh::{generate_identity, initiate, new_signed_prekey, respond, PreKeyBundle, ResponderKeys};
    use madcrypto_prims::{CipherSuite as _, IntlSuite};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    type S = IntlSuite;

    #[test]
    fn policy_gates() {
        let mut p = TenantPolicy::default();
        assert!(p.check_secret_session("engineer", SuiteId::Intl).is_ok());

        // ① 租户关闭密聊
        p.secret_chat_enabled = false;
        assert_eq!(
            p.check_secret_session("engineer", SuiteId::Intl).err().unwrap(),
            CryptoError::PolicyRejected
        );
        p.secret_chat_enabled = true;

        // ② 高危岗位黑名单
        p.blocked_roles = vec!["insider-trader-desk".into()];
        assert!(p.check_secret_session("insider-trader-desk", SuiteId::Intl).is_err());
        assert!(p.check_secret_session("engineer", SuiteId::Intl).is_ok());

        // ③ 套件强制（国密租户禁国际套件）
        p.allowed_suites = vec![SuiteId::Sm];
        assert!(p.check_secret_session("engineer", SuiteId::Intl).is_err());

        // ④ 群上限是租户配置
        let p2 = TenantPolicy { secret_group_limit: 300, ..Default::default() };
        assert!(p2.check_secret_group_size(300).is_ok());
        assert!(p2.check_secret_group_size(301).is_err());
    }

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

    /// 防降级用例集（实施 P7.5）：架构 §13 表格逐行翻译成密码学断言。
    #[test]
    fn downgrade_attacks_all_fail() {
        let (mut alice, mut bob, mut rng) = establish(70);
        let ad = session_ad(Track::Secret, SuiteId::Intl, "conv:42", Some(60));
        let (h, ct) = alice.encrypt::<S>(&ad, b"burn after reading").unwrap();

        // ① 轨道错配：密聊消息塞进普通轨通道 → 解不开
        let cloud_ad = session_ad(Track::Cloud, SuiteId::Intl, "conv:42", Some(60));
        assert!(bob.decrypt::<S, _>(&mut rng, &h, &ct, &cloud_ad).is_err());

        // ② 套件声明降级 → 解不开
        let sm_ad = session_ad(Track::Secret, SuiteId::Sm, "conv:42", Some(60));
        assert!(bob.decrypt::<S, _>(&mut rng, &h, &ct, &sm_ad).is_err());

        // ③ 篡改阅后即焚 TTL（60s → 1h）→ 解不开（TTL 在 AD 里，改了就是另一条消息）
        let ttl_ad = session_ad(Track::Secret, SuiteId::Intl, "conv:42", Some(3600));
        assert!(bob.decrypt::<S, _>(&mut rng, &h, &ct, &ttl_ad).is_err());

        // ④ 会话移植 → 解不开
        let conv_ad = session_ad(Track::Secret, SuiteId::Intl, "conv:99", Some(60));
        assert!(bob.decrypt::<S, _>(&mut rng, &h, &ct, &conv_ad).is_err());

        // 正确 AD 一次通过（且前四次失败未污染状态——事务性解密的又一佐证）
        assert_eq!(bob.decrypt::<S, _>(&mut rng, &h, &ct, &ad).unwrap(), b"burn after reading");
    }
}

