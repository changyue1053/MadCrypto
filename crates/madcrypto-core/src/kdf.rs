//! KDF 域分隔（架构 §14 / 实施 P1.2）。全部密钥派生收敛到本模块带 label 的封装，
//! 跨上下文密钥重用在入口处灭绝。label 常量表即 `docs/kdf-labels.md` 的代码化。

use madcrypto_prims::CipherSuite;
use zeroize::Zeroize;

use crate::keys::{ChainKey, MessageKey, RootKey};

/// 域分隔标签：每个用途一个唯一 label，进 HKDF 的 info 参数。
pub mod label {
    pub const X3DH_ROOT: &[u8] = b"IMCrypto/v1/x3dh-root";
    pub const ROOT_CHAIN: &[u8] = b"IMCrypto/v1/root-chain";
    pub const CHAIN_STEP: &[u8] = b"IMCrypto/v1/chain-step";
    pub const MSG_KEY: &[u8] = b"IMCrypto/v1/msg-key";
    pub const SENDER_STEP: &[u8] = b"IMCrypto/v1/sender-step";
    pub const SENDER_MSG: &[u8] = b"IMCrypto/v1/sender-msg";
    pub const CLOUD_DEK: &[u8] = b"IMCrypto/v1/cloud-dek";
}

/// X3DH/PQXDH：把拼接的 DH（+ KEM）输出派生为初始 root key（架构 §6 汇合点）。
pub fn kdf_x3dh<S: CipherSuite>(dh_concat: &[u8]) -> RootKey {
    let mut okm = [0u8; 32];
    S::hkdf(&[0u8; 32], dh_concat, label::X3DH_ROOT, &mut okm);
    let rk = RootKey::new(okm);
    okm.zeroize();
    rk
}

/// DH 棘轮步进：root_key + dh_out → (新 root_key, 新 chain_key)（架构 §7）。
pub fn kdf_rk<S: CipherSuite>(root: &RootKey, dh_out: &[u8; 32]) -> (RootKey, ChainKey) {
    let mut okm = [0u8; 64];
    S::hkdf(root.expose(), dh_out, label::ROOT_CHAIN, &mut okm);
    let mut rk = [0u8; 32];
    let mut ck = [0u8; 32];
    rk.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    okm.zeroize();
    let out = (RootKey::new(rk), ChainKey::new(ck));
    rk.zeroize();
    ck.zeroize();
    out
}

/// 对称棘轮步进：chain_key → (下一 chain_key, message_key)（架构 §7，前向保密来源）。
pub fn kdf_ck<S: CipherSuite>(ck: &ChainKey) -> (ChainKey, MessageKey) {
    step::<S>(ck, label::CHAIN_STEP, label::MSG_KEY)
}

/// Sender Key 对称步进（群密聊，架构 §8）。与单聊对称棘轮同构，仅 label 不同。
pub fn kdf_sender<S: CipherSuite>(ck: &ChainKey) -> (ChainKey, MessageKey) {
    step::<S>(ck, label::SENDER_STEP, label::SENDER_MSG)
}

fn step<S: CipherSuite>(
    ck: &ChainKey,
    step_label: &[u8],
    msg_label: &[u8],
) -> (ChainKey, MessageKey) {
    let mut next = [0u8; 32];
    S::hkdf(&[], ck.expose(), step_label, &mut next);

    let mut mk = [0u8; 44]; // 32B AEAD key + 12B IV
    S::hkdf(&[], ck.expose(), msg_label, &mut mk);
    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    key.copy_from_slice(&mk[..32]);
    iv.copy_from_slice(&mk[32..]);

    let out = (ChainKey::new(next), MessageKey::new(key, iv));
    next.zeroize();
    mk.zeroize();
    key.zeroize();
    iv.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use madcrypto_prims::IntlSuite;
    use subtle::ConstantTimeEq;

    #[test]
    fn chain_step_is_forward_secret_and_deterministic() {
        let ck0 = ChainKey::new([1u8; 32]);
        let (ck1, _mk1) = kdf_ck::<IntlSuite>(&ck0);
        let (ck1_again, _mk1b) = kdf_ck::<IntlSuite>(&ck0);
        // 确定性：同一 ck 步进结果一致
        assert!(bool::from(ck1.ct_eq(&ck1_again)));
        // 单向：下一链密钥不等于上一把（无法反推）
        assert!(!bool::from(ck1.ct_eq(&ck0)));
    }

    #[test]
    fn single_and_group_ratchets_are_domain_separated() {
        let ck = ChainKey::new([5u8; 32]);
        let (single_next, _) = kdf_ck::<IntlSuite>(&ck);
        let (group_next, _) = kdf_sender::<IntlSuite>(&ck);
        // 同一 ck 在单聊/群棘轮下必须派生不同链密钥（label 域分隔）
        assert!(!bool::from(single_next.ct_eq(&group_next)));
    }

    #[test]
    fn rk_step_changes_root_and_yields_chain() {
        let rk0 = RootKey::new([0u8; 32]);
        let dh = [7u8; 32];
        let (rk1, _ck) = kdf_rk::<IntlSuite>(&rk0, &dh);
        assert!(!bool::from(rk1.ct_eq(&rk0)), "根密钥必须随棘轮前进而改变");
    }
}

