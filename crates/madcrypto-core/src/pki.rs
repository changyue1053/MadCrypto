//! 企业 PKI（架构 §11 L1）：工牌证书消灭 TOFU。
//!
//! 消费级 E2EE 的软肋是首次信任（安全码没人比对）；企业有统一身份源与 MDM，
//! 可以让企业 CA 为员工身份公钥签发证书——**首次会话即强验证，TOFU 窗口不存在**。
//! 目录服务器发假钥（教科书 MITM）在这里被"工牌"拦下：bundle 里的身份必须与证书绑定一致。

use madcrypto_prims::CipherSuite;
use rand_core::{CryptoRng, RngCore};

use crate::error::{CryptoError, Result};
use crate::keys::{IdentityPublic, SignPrivate, SignPublic};
use crate::x3dh::PreKeyBundle;

/// 员工身份证书：把身份公钥（DH + 签名两截）绑定到组织内主体，由企业 CA 背书。
#[derive(Clone)]
pub struct Certificate {
    pub subject: String,
    pub identity: IdentityPublic,
    pub issuer: String,
    /// 过期时间（Unix 秒）。轮换走重新签发；吊销由 MDM/目录下发吊销列表（P8 接入）。
    pub not_after: u64,
    pub signature: Vec<u8>,
}

fn tbs_bytes(subject: &str, identity: &IdentityPublic, issuer: &str, not_after: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(128);
    v.extend_from_slice(b"IMCrypto/v1/cert|");
    for field in [subject.as_bytes(), issuer.as_bytes()] {
        v.extend_from_slice(&(field.len() as u16).to_be_bytes());
        v.extend_from_slice(field);
    }
    for key in [identity.dh.as_slice(), identity.sign.as_slice()] {
        v.extend_from_slice(&(key.len() as u16).to_be_bytes());
        v.extend_from_slice(key);
    }
    v.extend_from_slice(&not_after.to_be_bytes());
    v
}

/// 测试证书工厂（实施 P7.2）：mock CA。生产中签发在企业 CA 侧，客户端只做验证。
pub struct MockCa {
    pub name: String,
    sign_private: SignPrivate,
    sign_public: SignPublic,
}

impl MockCa {
    pub fn new<S: CipherSuite, R: RngCore + CryptoRng>(rng: &mut R, name: &str) -> Self {
        let kp = S::sign_keypair(rng);
        Self {
            name: name.to_string(),
            sign_private: SignPrivate::new(kp.private),
            sign_public: SignPublic::new(kp.public),
        }
    }

    pub fn public(&self) -> SignPublic {
        self.sign_public.clone()
    }

    pub fn issue<S: CipherSuite>(
        &self,
        subject: &str,
        identity: IdentityPublic,
        not_after: u64,
    ) -> Result<Certificate> {
        let signature = S::sign(
            self.sign_private.expose(),
            &tbs_bytes(subject, &identity, &self.name, not_after),
        )?;
        Ok(Certificate {
            subject: subject.to_string(),
            identity,
            issuer: self.name.clone(),
            not_after,
            signature,
        })
    }
}

/// 验证证书：CA 签名 + 有效期。
pub fn verify_certificate<S: CipherSuite>(
    ca_public: &SignPublic,
    cert: &Certificate,
    now: u64,
) -> Result<()> {
    if now > cert.not_after {
        return Err(CryptoError::Handshake("证书已过期"));
    }
    if !S::verify(
        ca_public.as_slice(),
        &tbs_bytes(&cert.subject, &cert.identity, &cert.issuer, cert.not_after),
        &cert.signature,
    ) {
        return Err(CryptoError::Handshake("证书签名非法"));
    }
    Ok(())
}

// ================= 证书吊销（实施 P7 残余回填）：MDM 离职收权的密码学收口 =================

/// 吊销列表：CA 签名背书 + 版本单调。离职/设备失陷 → 主体进列表 → 新会话握手即拒。
/// （已建会话的收权由 sesame 设备撤销负责——两把闸门分别锁"新建"与"存量"。）
#[derive(Clone)]
pub struct RevocationList {
    pub issuer: String,
    /// 单调版本：客户端 pin 最新版本，旧列表重放（隐藏新吊销）被拒。
    pub version: u64,
    /// 已吊销主体（排序去重，作为签名输入的规范形）。
    pub revoked: Vec<String>,
    pub signature: Vec<u8>,
}

fn crl_tbs(issuer: &str, version: u64, revoked: &[String]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + revoked.len() * 24);
    v.extend_from_slice(b"IMCrypto/v1/crl|");
    v.extend_from_slice(&(issuer.len() as u16).to_be_bytes());
    v.extend_from_slice(issuer.as_bytes());
    v.extend_from_slice(&version.to_be_bytes());
    v.extend_from_slice(&(revoked.len() as u32).to_be_bytes());
    for s in revoked {
        v.extend_from_slice(&(s.len() as u16).to_be_bytes());
        v.extend_from_slice(s.as_bytes());
    }
    v
}

/// 验证 CRL 的 CA 签名（列表内容与版本一体背书，改一个字节即失效）。
pub fn verify_revocation_list<S: CipherSuite>(ca_public: &SignPublic, crl: &RevocationList) -> Result<()> {
    if !S::verify(
        ca_public.as_slice(),
        &crl_tbs(&crl.issuer, crl.version, &crl.revoked),
        &crl.signature,
    ) {
        return Err(CryptoError::Handshake("吊销列表签名非法"));
    }
    Ok(())
}

/// 主体是否被吊销（列表为规范排序形，二分查找）。
pub fn check_not_revoked(crl: &RevocationList, subject: &str) -> Result<()> {
    if crl.revoked.binary_search_by(|s| s.as_str().cmp(subject)).is_ok() {
        return Err(CryptoError::Handshake("证书已吊销（MDM 收权）"));
    }
    Ok(())
}

/// 客户端 CRL 锚点：版本只进不退——重放旧列表以"复活"被吊销者，在此被拒。
#[derive(Default, Clone)]
pub struct CrlPin {
    version: u64,
}

impl CrlPin {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    /// 接受一份已验签的 CRL：版本必须 ≥ 已 pin 版本。
    pub fn accept(&mut self, crl: &RevocationList) -> Result<()> {
        if crl.version < self.version {
            return Err(CryptoError::Handshake("吊销列表版本回滚"));
        }
        self.version = crl.version;
        Ok(())
    }
}

impl MockCa {
    /// 签发吊销列表（生产中由企业 CA/MDM 侧签发下发；客户端只验签 + pin 版本）。
    pub fn issue_revocations<S: CipherSuite>(
        &self,
        version: u64,
        subjects: &[&str],
    ) -> Result<RevocationList> {
        let mut revoked: Vec<String> = subjects.iter().map(|s| s.to_string()).collect();
        revoked.sort();
        revoked.dedup();
        let signature = S::sign(self.sign_private.expose(), &crl_tbs(&self.name, version, &revoked))?;
        Ok(RevocationList { issuer: self.name.clone(), version, revoked, signature })
    }
}

/// L1 防线主入口：用工牌证书验证 prekey bundle 的身份——目录发假钥在此被拦（架构 §11）。
pub fn verify_bundle_with_certificate<S: CipherSuite>(
    ca_public: &SignPublic,
    cert: &Certificate,
    expected_subject: &str,
    bundle: &PreKeyBundle,
    now: u64,
) -> Result<()> {
    verify_certificate::<S>(ca_public, cert, now)?;
    if cert.subject != expected_subject {
        return Err(CryptoError::Handshake("证书主体与会话对象不符"));
    }
    if cert.identity != bundle.identity {
        // 目录返回的身份公钥 ≠ 证书绑定的公钥 = 目录在发假钥（MITM）
        return Err(CryptoError::Handshake("bundle 身份与证书不符（疑似目录发假钥）"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x3dh::{generate_identity, new_signed_prekey};
    use madcrypto_prims::IntlSuite;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    type S = IntlSuite;
    const NOW: u64 = 1_760_000_000;

    fn bundle_for(rng: &mut ChaCha20Rng, identity: &crate::keys::IdentityKeyPair) -> PreKeyBundle {
        let (_spk_priv, spk_pub, spk_sig) = new_signed_prekey::<S, _>(rng, identity).unwrap();
        PreKeyBundle {
            suite: S::id(),
            identity: identity.public(),
            signed_prekey: spk_pub,
            signed_prekey_sig: spk_sig,
            one_time_prekey: None,
        }
    }

    #[test]
    fn valid_certificate_verifies_bundle() {
        let mut rng = ChaCha20Rng::seed_from_u64(50);
        let ca = MockCa::new::<S, _>(&mut rng, "corp-ca");
        let bob = generate_identity::<S, _>(&mut rng);
        let cert = ca.issue::<S>("bob@corp", bob.public(), NOW + 86400).unwrap();
        let bundle = bundle_for(&mut rng, &bob);
        verify_bundle_with_certificate::<S>(&ca.public(), &cert, "bob@corp", &bundle, NOW).unwrap();
    }

    #[test]
    fn negative_samples_all_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(51);
        let ca = MockCa::new::<S, _>(&mut rng, "corp-ca");
        let rogue_ca = MockCa::new::<S, _>(&mut rng, "rogue-ca");
        let bob = generate_identity::<S, _>(&mut rng);
        let cert = ca.issue::<S>("bob@corp", bob.public(), NOW + 86400).unwrap();

        // ① 过期
        assert_eq!(
            verify_certificate::<S>(&ca.public(), &cert, cert.not_after + 1).err().unwrap(),
            CryptoError::Handshake("证书已过期")
        );
        // ② 篡改主体
        let mut tampered = cert.clone();
        tampered.subject = "eve@corp".into();
        assert_eq!(
            verify_certificate::<S>(&ca.public(), &tampered, NOW).err().unwrap(),
            CryptoError::Handshake("证书签名非法")
        );
        // ③ 错 CA（自签冒充）
        let forged = rogue_ca.issue::<S>("bob@corp", bob.public(), NOW + 86400).unwrap();
        assert_eq!(
            verify_certificate::<S>(&ca.public(), &forged, NOW).err().unwrap(),
            CryptoError::Handshake("证书签名非法")
        );
        // ④ 主体与会话对象不符
        let bundle = bundle_for(&mut rng, &bob);
        assert_eq!(
            verify_bundle_with_certificate::<S>(&ca.public(), &cert, "alice@corp", &bundle, NOW)
                .err()
                .unwrap(),
            CryptoError::Handshake("证书主体与会话对象不符")
        );
    }

    #[test]
    fn revocation_list_signature_and_lookup() {
        let mut rng = ChaCha20Rng::seed_from_u64(53);
        let ca = MockCa::new::<S, _>(&mut rng, "corp-ca");
        let rogue = MockCa::new::<S, _>(&mut rng, "corp-ca");  // 同名不同钥：伪造 CA
        let crl = ca.issue_revocations::<S>(3, &["eve@corp", "bob@corp"]).unwrap();

        verify_revocation_list::<S>(&ca.public(), &crl).unwrap();
        // 伪造者签的列表被拒
        let forged = rogue.issue_revocations::<S>(4, &["alice@corp"]).unwrap();
        assert_eq!(
            verify_revocation_list::<S>(&ca.public(), &forged).err().unwrap(),
            CryptoError::Handshake("吊销列表签名非法")
        );
        // 篡改列表内容（偷偷移出被吊销者）→ 签名失效
        let mut tampered = crl.clone();
        tampered.revoked.retain(|s| s != "bob@corp");
        assert_eq!(
            verify_revocation_list::<S>(&ca.public(), &tampered).err().unwrap(),
            CryptoError::Handshake("吊销列表签名非法")
        );
        // 吊销判定
        assert_eq!(
            check_not_revoked(&crl, "bob@corp").err().unwrap(),
            CryptoError::Handshake("证书已吊销（MDM 收权）")
        );
        check_not_revoked(&crl, "alice@corp").unwrap();
    }

    #[test]
    fn crl_version_rollback_is_rejected() {
        // 攻击：重放旧版本 CRL"复活"已被吊销的账号——版本 pin 拦下
        let mut rng = ChaCha20Rng::seed_from_u64(54);
        let ca = MockCa::new::<S, _>(&mut rng, "corp-ca");
        let v5 = ca.issue_revocations::<S>(5, &[]).unwrap();
        let v9 = ca.issue_revocations::<S>(9, &["bob@corp"]).unwrap();

        let mut pin = CrlPin::new();
        pin.accept(&v5).unwrap();
        pin.accept(&v9).unwrap();
        assert_eq!(pin.version(), 9);
        assert_eq!(
            pin.accept(&v5).err().unwrap(),
            CryptoError::Handshake("吊销列表版本回滚")
        );
        // 同版本重复下发是合法的（幂等分发）
        pin.accept(&v9).unwrap();
    }

    #[test]
    fn directory_serving_fake_key_is_caught() {
        let mut rng = ChaCha20Rng::seed_from_u64(52);
        let ca = MockCa::new::<S, _>(&mut rng, "corp-ca");
        let bob = generate_identity::<S, _>(&mut rng);
        let cert = ca.issue::<S>("bob@corp", bob.public(), NOW + 86400).unwrap();

        // 目录被入侵：返回的 bundle 里是攻击者的身份公钥（教科书 MITM）
        let attacker = generate_identity::<S, _>(&mut rng);
        let fake_bundle = bundle_for(&mut rng, &attacker);

        let err = verify_bundle_with_certificate::<S>(&ca.public(), &cert, "bob@corp", &fake_bundle, NOW)
            .err()
            .unwrap();
        assert_eq!(
            err,
            CryptoError::Handshake("bundle 身份与证书不符（疑似目录发假钥）"),
            "工牌证书必须拦下目录发的假钥——TOFU 在企业形态下不存在"
        );
    }
}

