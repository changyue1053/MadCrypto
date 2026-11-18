//! 普通轨（云端加密）端侧原语（架构 §4）。
//!
//! 服务器持钥 ≠ 随便做：每消息 DEK 由带版本的会话密钥 CK 派生（不落盘、不入表），
//! AAD 绑定 tenant/conv/msg/key_version——密文跨会话、跨租户移植必失败。
//! **crypto-shredding**：销毁某版本 CK = 该版本加密的全部消息（含万人群的所有扇出副本）
//! 同时不可读——GDPR/个保法删除权在海量副本下唯一工程可行的实现（架构 §4）。

use madcrypto_prims::CipherSuite;
use zeroize::Zeroize;

use crate::error::{CryptoError, Result};
use crate::kdf::label;
use crate::keys::ConvKey;

/// 信封：密钥版本 + 密文。版本进 AAD，指错版本的钥匙开不了箱。
pub struct Envelope {
    pub key_version: u32,
    pub ciphertext: Vec<u8>,
}

fn aad(tenant: &str, conv_id: &str, msg_id: u64, key_version: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(tenant.len() + conv_id.len() + 32);
    v.extend_from_slice(b"IMCrypto/cloud/v1|");
    v.extend_from_slice(&(tenant.len() as u16).to_be_bytes());
    v.extend_from_slice(tenant.as_bytes());
    v.extend_from_slice(&(conv_id.len() as u16).to_be_bytes());
    v.extend_from_slice(conv_id.as_bytes());
    v.extend_from_slice(&msg_id.to_be_bytes());
    v.extend_from_slice(&key_version.to_be_bytes());
    v
}

/// 每消息 DEK + IV 派生：HKDF(CK, msg_id ‖ key_version)——msg_id 会话内唯一，故 (DEK, IV) 唯一。
fn derive<S: CipherSuite>(ck: &ConvKey, msg_id: u64, key_version: u32) -> ([u8; 32], [u8; 12]) {
    let mut info = Vec::with_capacity(label::CLOUD_DEK.len() + 12);
    info.extend_from_slice(label::CLOUD_DEK);
    info.extend_from_slice(&msg_id.to_be_bytes());
    info.extend_from_slice(&key_version.to_be_bytes());
    let mut okm = [0u8; 44];
    S::hkdf(&[], ck.expose(), &info, &mut okm);
    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    iv.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (key, iv)
}

/// 信封加密（服务端消息服务/端侧增强档共用同一原语）。
pub fn seal<S: CipherSuite>(
    ck: &ConvKey,
    key_version: u32,
    tenant: &str,
    conv_id: &str,
    msg_id: u64,
    plaintext: &[u8],
) -> Envelope {
    let (mut key, iv) = derive::<S>(ck, msg_id, key_version);
    let ct = S::aead_seal(&key, &iv, &aad(tenant, conv_id, msg_id, key_version), plaintext);
    key.zeroize();
    Envelope {
        key_version,
        ciphertext: ct,
    }
}

/// 信封解密。调用方按 `envelope.key_version` 取对应版本的 CK——版本钥匙已销毁即 crypto-shredded。
pub fn open<S: CipherSuite>(
    ck: &ConvKey,
    tenant: &str,
    conv_id: &str,
    msg_id: u64,
    envelope: &Envelope,
) -> Result<Vec<u8>> {
    let (mut key, iv) = derive::<S>(ck, msg_id, envelope.key_version);
    let r = S::aead_open(
        &key,
        &iv,
        &aad(tenant, conv_id, msg_id, envelope.key_version),
        &envelope.ciphertext,
    )
    .map_err(|_| CryptoError::DecryptDesync);
    key.zeroize();
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use madcrypto_prims::IntlSuite;

    type S = IntlSuite;

    fn ck(byte: u8) -> ConvKey {
        ConvKey::new([byte; 32])
    }

    #[test]
    fn roundtrip_ok() {
        let k = ck(1);
        let env = seal::<S>(&k, 1, "tenant-a", "conv-1", 42, b"quarterly numbers");
        assert_eq!(open::<S>(&k, "tenant-a", "conv-1", 42, &env).unwrap(), b"quarterly numbers");
    }

    #[test]
    fn transplant_is_rejected() {
        let k = ck(2);
        let env = seal::<S>(&k, 1, "tenant-a", "conv-1", 42, b"secret");
        // 跨会话 / 跨租户 / 改消息号移植密文，AAD 绑定全部拦截
        assert!(open::<S>(&k, "tenant-a", "conv-2", 42, &env).is_err());
        assert!(open::<S>(&k, "tenant-b", "conv-1", 42, &env).is_err());
        assert!(open::<S>(&k, "tenant-a", "conv-1", 43, &env).is_err());
    }

    #[test]
    fn key_rotation_and_crypto_shredding() {
        let k_v1 = ck(3);
        let k_v2 = ck(4);
        let old = seal::<S>(&k_v1, 1, "t", "c", 1, b"before rotation");
        let new = seal::<S>(&k_v2, 2, "t", "c", 2, b"after rotation");

        // 轮换不重加密：历史消息用旧版本钥匙照常可读（架构 §4）
        assert_eq!(open::<S>(&k_v1, "t", "c", 1, &old).unwrap(), b"before rotation");
        assert_eq!(open::<S>(&k_v2, "t", "c", 2, &new).unwrap(), b"after rotation");

        // crypto-shredding：v1 钥匙销毁后，拿 v2 钥匙开 v1 信封必失败——
        // 一把钥匙作废 = 该版本全部副本（含万人群扇出）同时不可读
        assert!(open::<S>(&k_v2, "t", "c", 1, &old).is_err());
    }

    #[test]
    fn per_message_dek_uniqueness() {
        // 同一 CK 下不同 msg_id 的密文必不相同（每消息独立 DEK/IV，无 nonce 复用面）
        let k = ck(5);
        let a = seal::<S>(&k, 1, "t", "c", 1, b"same body");
        let b = seal::<S>(&k, 1, "t", "c", 2, b"same body");
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}

