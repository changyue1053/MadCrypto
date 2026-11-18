//! 国际套件：X25519 / Ed25519 / AES-256-GCM / HKDF-SHA-256。
//! 全部来自 RustCrypto / dalek 生态（多年审计史），本模块只做接线，不含自研算法。

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::suite::{arr32, CipherSuite, DhKeyPair, PrimError, SignKeyPair, SuiteId};

/// 国际套件的零尺寸标记类型。协议层以 `<S: CipherSuite>` 泛型持有它。
pub struct IntlSuite;

fn arr64(b: &[u8]) -> Result<[u8; 64], PrimError> {
    b.try_into().map_err(|_| PrimError::BadSignature)
}

impl CipherSuite for IntlSuite {
    fn id() -> SuiteId {
        SuiteId::Intl
    }

    fn dh_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> DhKeyPair {
        let sk = StaticSecret::random_from_rng(&mut *rng);
        let pk = PublicKey::from(&sk);
        DhKeyPair {
            private: sk.to_bytes().to_vec(),
            public: pk.to_bytes().to_vec(),
        }
    }

    fn dh_public(private: &[u8]) -> Result<Vec<u8>, PrimError> {
        let sk = StaticSecret::from(arr32(private)?);
        Ok(PublicKey::from(&sk).to_bytes().to_vec())
    }

    fn dh(private: &[u8], public: &[u8]) -> Result<[u8; 32], PrimError> {
        let sk = StaticSecret::from(arr32(private)?);
        let pk = PublicKey::from(arr32(public)?);
        Ok(sk.diffie_hellman(&pk).to_bytes())
    }

    fn sign_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> SignKeyPair {
        let sk = SigningKey::generate(&mut *rng);
        SignKeyPair {
            private: sk.to_bytes().to_vec(),
            public: sk.verifying_key().to_bytes().to_vec(),
        }
    }

    fn sign(private: &[u8], msg: &[u8]) -> Result<Vec<u8>, PrimError> {
        let sk = SigningKey::from_bytes(&arr32(private)?);
        Ok(sk.sign(msg).to_bytes().to_vec())
    }

    fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let Ok(pk_bytes) = arr32(public) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk_bytes) else {
            return false;
        };
        let Ok(sig_bytes) = arr64(sig) else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        vk.verify(msg, &signature).is_ok()
    }

    fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(key.into());
        cipher
            .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
            .expect("AES-GCM 加密只在长度溢出时失败，消息长度受上层约束")
    }

    fn aead_open(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PrimError> {
        let cipher = Aes256Gcm::new(key.into());
        cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
            .map_err(|_| PrimError::AeadAuth)
    }

    fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
        let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
        hk.expand(info, out)
            .expect("HKDF 仅在 out 长度 > 255*HashLen 时失败，本库派生长度受控");
    }

    fn hash(data: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0xC0FFEE)
    }

    #[test]
    fn dh_agrees_both_directions() {
        let mut r = rng();
        let a = IntlSuite::dh_keypair(&mut r);
        let b = IntlSuite::dh_keypair(&mut r);
        let ab = IntlSuite::dh(&a.private, &b.public).unwrap();
        let ba = IntlSuite::dh(&b.private, &a.public).unwrap();
        assert_eq!(ab, ba, "双向 DH 必须得到同一共享密钥");
    }

    #[test]
    fn dh_public_matches_keypair() {
        let mut r = rng();
        let a = IntlSuite::dh_keypair(&mut r);
        assert_eq!(IntlSuite::dh_public(&a.private).unwrap(), a.public);
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let mut r = rng();
        let kp = IntlSuite::sign_keypair(&mut r);
        let msg = b"transfer 100 to bob";
        let sig = IntlSuite::sign(&kp.private, msg).unwrap();
        assert!(IntlSuite::verify(&kp.public, msg, &sig));
        // 篡改消息 / 篡改签名 / 换公钥都必须验签失败
        assert!(!IntlSuite::verify(&kp.public, b"transfer 900 to eve", &sig));
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(!IntlSuite::verify(&kp.public, msg, &bad));
    }

    #[test]
    fn aead_seal_open_and_aad_binding() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let pt = b"secret body";
        let ct = IntlSuite::aead_seal(&key, &nonce, b"conv:42", pt);
        assert_ne!(&ct[..], &pt[..], "密文不得等于明文");
        assert_eq!(
            IntlSuite::aead_open(&key, &nonce, b"conv:42", &ct).unwrap(),
            pt
        );
        // AAD 不匹配（跨会话移植密文）必须失败——这是防降级/防重放的基石
        assert_eq!(
            IntlSuite::aead_open(&key, &nonce, b"conv:99", &ct),
            Err(PrimError::AeadAuth)
        );
        // 篡改密文任一字节必失败
        let mut tampered = ct.clone();
        tampered[0] ^= 1;
        assert_eq!(
            IntlSuite::aead_open(&key, &nonce, b"conv:42", &tampered),
            Err(PrimError::AeadAuth)
        );
    }

    #[test]
    fn hkdf_is_deterministic_and_domain_separated() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        IntlSuite::hkdf(b"salt", b"ikm", b"label-A", &mut a);
        IntlSuite::hkdf(b"salt", b"ikm", b"label-B", &mut b);
        assert_ne!(a, b, "不同 info label 必须派生不同密钥（域分隔）");
        let mut a2 = [0u8; 32];
        IntlSuite::hkdf(b"salt", b"ikm", b"label-A", &mut a2);
        assert_eq!(a, a2, "同输入必须确定性可复现");
    }
}

