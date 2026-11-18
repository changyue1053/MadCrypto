//! 密钥透明度（架构 §11 L2）：目录静默换钥在数学上必留痕。
//!
//! 公钥目录写进 append-only Merkle 日志（`merkle` 模块）：
//! - 客户端每次取 bundle 验证**包含证明**（这条身份确实登记在日志里）；
//! - 客户端锚定树头，用**一致性证明**推进锚点——日志方改写历史必被识破；
//! - 换钥的唯一合法路径是**追加新条目**：同一主体出现第二条即留痕，监控端可见。
//!
//! `MockKt` 保留为轻量测试替身；`MerkleKtLog` 是真账本形态（私有化装置/测试服务端），
//! 客户端只消费 `KtProof`（STH + 包含证明），不需要账本本体。

use madcrypto_prims::CipherSuite;
use std::collections::HashMap;
use std::marker::PhantomData;

use crate::error::{CryptoError, Result};
use crate::keys::{IdentityPublic, SignPrivate, SignPublic};
use crate::merkle::{leaf_hash, verify_consistency, verify_inclusion, MerkleLog};
use crate::pki::{check_not_revoked, verify_bundle_with_certificate, Certificate, RevocationList};
use crate::x3dh::PreKeyBundle;

/// KT 客户端接口。产品 P1 落真实现（inclusion/consistency 证明验证）。
pub trait KeyTransparency {
    /// 验证"目录返回的身份"确实登记在透明日志中。
    fn verify_inclusion(&self, subject: &str, identity: &IdentityPublic) -> Result<()>;
}

/// mock KT：用账本 HashMap 模拟透明日志。目录返回的身份 ≠ 账本记录 = 换钥告警。
#[derive(Default)]
pub struct MockKt {
    ledger: HashMap<String, IdentityPublic>,
}

impl MockKt {
    pub fn new() -> Self {
        Self::default()
    }
    /// 身份登记进透明日志（生产中由注册流程写入 + 全网审计）。
    pub fn record(&mut self, subject: &str, identity: IdentityPublic) {
        self.ledger.insert(subject.to_string(), identity);
    }
}

impl KeyTransparency for MockKt {
    fn verify_inclusion(&self, subject: &str, identity: &IdentityPublic) -> Result<()> {
        match self.ledger.get(subject) {
            Some(recorded) if recorded == identity => Ok(()),
            Some(_) => Err(CryptoError::Handshake("KT：目录身份与透明日志不符（换钥必留痕）")),
            None => Err(CryptoError::Handshake("KT：身份未登记于透明日志")),
        }
    }
}

// ================= 真 KT：Merkle 账本 + 签名树头 + 客户端验证（实施 P7 残余回填） =================

/// 签名树头（STH）：日志方对 (size, root) 的签名承诺。伪造树头 = 伪造签名。
#[derive(Clone, Debug)]
pub struct SignedTreeHead {
    pub tree_size: u64,
    pub root: [u8; 32],
    pub signature: Vec<u8>,
}

fn sth_tbs(tree_size: u64, root: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(b"IMCrypto/v1/kt-sth|");
    v.extend_from_slice(&tree_size.to_be_bytes());
    v.extend_from_slice(root);
    v
}

/// KT 叶的规范序列化：主体 + 身份公钥（DH/签名两截），长度前缀防拼接歧义。
pub fn kt_leaf_bytes(subject: &str, identity: &IdentityPublic) -> Vec<u8> {
    let mut v = Vec::with_capacity(128);
    v.extend_from_slice(b"IMCrypto/v1/kt-leaf|");
    for field in [subject.as_bytes(), identity.dh.as_slice(), identity.sign.as_slice()] {
        v.extend_from_slice(&(field.len() as u16).to_be_bytes());
        v.extend_from_slice(field);
    }
    v
}

/// 目录查询返回给客户端的证明包：凭它即可无账本验证。
#[derive(Clone, Debug)]
pub struct KtProof {
    pub leaf_index: u64,
    pub inclusion: Vec<[u8; 32]>,
    pub sth: SignedTreeHead,
}

/// 客户端验证：STH 签名 + 叶包含证明。任一不过即拒绝会话建立。
pub fn verify_kt_proof<S: CipherSuite>(
    log_public: &SignPublic,
    subject: &str,
    identity: &IdentityPublic,
    proof: &KtProof,
) -> Result<()> {
    if !S::verify(
        log_public.as_slice(),
        &sth_tbs(proof.sth.tree_size, &proof.sth.root),
        &proof.sth.signature,
    ) {
        return Err(CryptoError::Handshake("KT：树头签名非法"));
    }
    let leaf = leaf_hash::<S>(&kt_leaf_bytes(subject, identity));
    if !verify_inclusion::<S>(&proof.sth.root, proof.sth.tree_size, proof.leaf_index, &leaf, &proof.inclusion)
    {
        return Err(CryptoError::Handshake("KT：包含证明验证失败"));
    }
    Ok(())
}

/// 客户端监控锚点：pin 住已验证的树头，只沿一致性证明前进——历史改写在此被识破。
#[derive(Default, Clone, Debug)]
pub struct KtMonitor {
    pinned_size: u64,
    pinned_root: [u8; 32],
}

impl KtMonitor {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn pinned_size(&self) -> u64 {
        self.pinned_size
    }
    /// 推进锚点：验证新 STH 签名 + 与旧锚点的一致性。树头回缩（append-only 被违反）同样拒绝。
    pub fn advance<S: CipherSuite>(
        &mut self,
        log_public: &SignPublic,
        new_sth: &SignedTreeHead,
        consistency: &[[u8; 32]],
    ) -> Result<()> {
        if !S::verify(
            log_public.as_slice(),
            &sth_tbs(new_sth.tree_size, &new_sth.root),
            &new_sth.signature,
        ) {
            return Err(CryptoError::Handshake("KT：树头签名非法"));
        }
        if new_sth.tree_size < self.pinned_size {
            return Err(CryptoError::Handshake("KT：树头回缩（append-only 被违反）"));
        }
        if !verify_consistency::<S>(
            &self.pinned_root,
            self.pinned_size,
            &new_sth.root,
            new_sth.tree_size,
            consistency,
        ) {
            return Err(CryptoError::Handshake("KT：一致性证明失败（疑似历史被改写）"));
        }
        self.pinned_size = new_sth.tree_size;
        self.pinned_root = new_sth.root;
        Ok(())
    }
}

/// 真账本（服务端形态，私有化装置与测试用；客户端永远只见 `KtProof`）。
pub struct MerkleKtLog<S: CipherSuite> {
    log: MerkleLog,
    entries: Vec<(String, IdentityPublic)>,
    latest: HashMap<String, u64>,   // subject → 最新叶索引
    history: HashMap<String, u64>,  // subject → 登记次数（换钥留痕的量化口径）
    sign_private: SignPrivate,
    sign_public: SignPublic,
    _suite: PhantomData<S>,
}

impl<S: CipherSuite> MerkleKtLog<S> {
    pub fn new<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let kp = S::sign_keypair(rng);
        Self {
            log: MerkleLog::new(),
            entries: Vec::new(),
            latest: HashMap::new(),
            history: HashMap::new(),
            sign_private: SignPrivate::new(kp.private),
            sign_public: SignPublic::new(kp.public),
            _suite: PhantomData,
        }
    }

    pub fn log_public(&self) -> SignPublic {
        self.sign_public.clone()
    }

    /// 登记身份（注册/换钥同一入口——换钥只能追加，这正是"必留痕"的机制本体）。
    pub fn record(&mut self, subject: &str, identity: IdentityPublic) -> Result<u64> {
        let index = self.log.append(leaf_hash::<S>(&kt_leaf_bytes(subject, &identity)));
        self.entries.push((subject.to_string(), identity));
        self.latest.insert(subject.to_string(), index);
        *self.history.entry(subject.to_string()).or_insert(0) += 1;
        Ok(index)
    }

    /// 同一主体的登记次数：> 1 即发生过换钥（监控端告警口径）。
    pub fn history_count(&self, subject: &str) -> u64 {
        self.history.get(subject).copied().unwrap_or(0)
    }

    pub fn sth(&self) -> Result<SignedTreeHead> {
        let root = self.log.root::<S>();
        let tree_size = self.log.size();
        let signature = S::sign(self.sign_private.expose(), &sth_tbs(tree_size, &root))?;
        Ok(SignedTreeHead { tree_size, root, signature })
    }

    /// 目录查询：返回主体最新身份 + 可独立验证的证明包。
    pub fn lookup(&self, subject: &str) -> Result<(IdentityPublic, KtProof)> {
        let index = *self
            .latest
            .get(subject)
            .ok_or(CryptoError::Handshake("KT：身份未登记于透明日志"))?;
        let identity = self.entries[index as usize].1.clone();
        let inclusion = self
            .log
            .inclusion_proof::<S>(index)
            .ok_or(CryptoError::Handshake("KT：包含证明生成失败"))?;
        Ok((identity, KtProof { leaf_index: index, inclusion, sth: self.sth()? }))
    }

    /// 监控端点：自旧锚点以来的一致性证明。
    pub fn consistency_since(&self, old_size: u64) -> Result<Vec<[u8; 32]>> {
        self.log
            .consistency_proof::<S>(old_size)
            .ok_or(CryptoError::Handshake("KT：一致性证明生成失败"))
    }
}

/// 真账本同样实现挂点 trait：编排层（`verify_directory_entry`）接 mock 还是真 KT 透明。
impl<S: CipherSuite> KeyTransparency for MerkleKtLog<S> {
    fn verify_inclusion(&self, subject: &str, identity: &IdentityPublic) -> Result<()> {
        let (recorded, proof) = self.lookup(subject)?;
        if &recorded != identity {
            return Err(CryptoError::Handshake("KT：目录身份与透明日志不符（换钥必留痕）"));
        }
        verify_kt_proof::<S>(&self.sign_public, subject, identity, &proof)
    }
}

/// 三层验证的结论：告诉产品层这条会话的身份保障级别（架构 §11 三层防线表）。
#[derive(Debug, PartialEq, Eq)]
pub enum Assurance {
    /// L1 证书 + L2 KT 双验通过——企业内默认路径。
    CertificateAndTransparency,
    /// 仅 L1 证书（租户未启用 KT）。
    CertificateOnly,
    /// 无证书可用（跨企业联邦等）——降级到 L3：UI 必须引导安全码人工比对。
    ManualVerificationRequired,
}

/// 目录条目验证编排：L1 工牌（含吊销检查）→ L2 透明日志 → L3 人工兜底标记。
/// 有证书必须验过，有 CRL 必须查过，有 KT 必须查过——任何一层显式失败都终止会话建立。
pub fn verify_directory_entry<S: CipherSuite, K: KeyTransparency>(
    ca_public: Option<&SignPublic>,
    certificate: Option<&Certificate>,
    crl: Option<&RevocationList>,
    kt: Option<&K>,
    subject: &str,
    bundle: &PreKeyBundle,
    now: u64,
) -> Result<Assurance> {
    let cert_verified = match (ca_public, certificate) {
        (Some(ca), Some(cert)) => {
            verify_bundle_with_certificate::<S>(ca, cert, subject, bundle, now)?;
            if let Some(crl) = crl {
                check_not_revoked(crl, subject)?; // MDM 收权：吊销即拒新会话
            }
            true
        }
        _ => false,
    };

    if let Some(kt) = kt {
        kt.verify_inclusion(subject, &bundle.identity)?;
        if cert_verified {
            return Ok(Assurance::CertificateAndTransparency);
        }
    }

    if cert_verified {
        Ok(Assurance::CertificateOnly)
    } else {
        Ok(Assurance::ManualVerificationRequired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::MockCa;
    use crate::x3dh::{generate_identity, new_signed_prekey};
    use madcrypto_prims::IntlSuite;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    type S = IntlSuite;
    const NOW: u64 = 1_760_000_000;

    fn setup(
        rng: &mut ChaCha20Rng,
    ) -> (MockCa, Certificate, PreKeyBundle, MockKt, crate::keys::IdentityKeyPair) {
        let ca = MockCa::new::<S, _>(rng, "corp-ca");
        let bob = generate_identity::<S, _>(rng);
        let cert = ca.issue::<S>("bob@corp", bob.public(), NOW + 86400).unwrap();
        let (_sp, spk_pub, spk_sig) = new_signed_prekey::<S, _>(rng, &bob).unwrap();
        let bundle = PreKeyBundle {
            suite: S::id(),
            identity: bob.public(),
            signed_prekey: spk_pub,
            signed_prekey_sig: spk_sig,
            one_time_prekey: None,
        };
        let mut kt = MockKt::new();
        kt.record("bob@corp", bob.public());
        (ca, cert, bundle, kt, bob)
    }

    #[test]
    fn full_assurance_when_cert_and_kt_pass() {
        let mut rng = ChaCha20Rng::seed_from_u64(60);
        let (ca, cert, bundle, kt, _bob) = setup(&mut rng);
        let a = verify_directory_entry::<S, _>(
            Some(&ca.public()),
            Some(&cert),
            None,
            Some(&kt),
            "bob@corp",
            &bundle,
            NOW,
        )
        .unwrap();
        assert_eq!(a, Assurance::CertificateAndTransparency);
    }

    #[test]
    fn silent_key_swap_is_flagged_by_kt() {
        let mut rng = ChaCha20Rng::seed_from_u64(61);
        let (ca, _cert, _bundle, kt, _bob) = setup(&mut rng);

        // 目录被入侵后静默换钥：新身份连同一张"新证书"一起伪造（假设 CA 也被骗签）。
        // L1 过了，L2 透明日志上记录的还是旧身份——换钥必留痕。
        let attacker = generate_identity::<S, _>(&mut rng);
        let fake_cert = ca.issue::<S>("bob@corp", attacker.public(), NOW + 86400).unwrap();
        let (_sp, spk_pub, spk_sig) = new_signed_prekey::<S, _>(&mut rng, &attacker).unwrap();
        let fake_bundle = PreKeyBundle {
            suite: S::id(),
            identity: attacker.public(),
            signed_prekey: spk_pub,
            signed_prekey_sig: spk_sig,
            one_time_prekey: None,
        };

        let err = verify_directory_entry::<S, _>(
            Some(&ca.public()),
            Some(&fake_cert),
            None,
            Some(&kt),
            "bob@corp",
            &fake_bundle,
            NOW,
        )
        .err()
        .unwrap();
        assert_eq!(err, CryptoError::Handshake("KT：目录身份与透明日志不符（换钥必留痕）"));
    }

    #[test]
    fn no_cert_no_kt_falls_back_to_manual() {
        let mut rng = ChaCha20Rng::seed_from_u64(62);
        let (_ca, _cert, bundle, _kt, _bob) = setup(&mut rng);
        // 跨企业联邦：没有对方组织的 CA 与 KT → L3 兜底，UI 引导安全码比对
        let a = verify_directory_entry::<S, MockKt>(None, None, None, None, "bob@corp", &bundle, NOW)
            .unwrap();
        assert_eq!(a, Assurance::ManualVerificationRequired);
    }

    #[test]
    fn revoked_subject_is_rejected_at_orchestration() {
        // MDM 离职收权：主体进 CRL → 新会话在编排层即拒（存量会话由 sesame 撤销收口）
        let mut rng = ChaCha20Rng::seed_from_u64(63);
        let (ca, cert, bundle, kt, _bob) = setup(&mut rng);
        let crl = ca.issue_revocations::<S>(7, &["bob@corp", "mallory@corp"]).unwrap();
        crate::pki::verify_revocation_list::<S>(&ca.public(), &crl).unwrap();
        let err = verify_directory_entry::<S, _>(
            Some(&ca.public()),
            Some(&cert),
            Some(&crl),
            Some(&kt),
            "bob@corp",
            &bundle,
            NOW,
        )
        .err()
        .unwrap();
        assert_eq!(err, CryptoError::Handshake("证书已吊销（MDM 收权）"));
        // 未被吊销者不受影响
        let clean = ca.issue_revocations::<S>(8, &["mallory@corp"]).unwrap();
        let a = verify_directory_entry::<S, _>(
            Some(&ca.public()),
            Some(&cert),
            Some(&clean),
            Some(&kt),
            "bob@corp",
            &bundle,
            NOW,
        )
        .unwrap();
        assert_eq!(a, Assurance::CertificateAndTransparency);
    }

    // ================= 真 KT（Merkle 账本）=================

    #[test]
    fn real_ledger_proof_verifies_client_side() {
        let mut rng = ChaCha20Rng::seed_from_u64(70);
        let mut log = MerkleKtLog::<S>::new(&mut rng);
        let alice = generate_identity::<S, _>(&mut rng);
        let bob = generate_identity::<S, _>(&mut rng);
        log.record("alice@corp", alice.public()).unwrap();
        log.record("bob@corp", bob.public()).unwrap();

        // 客户端拿证明包独立验证（无账本本体）
        let (identity, proof) = log.lookup("bob@corp").unwrap();
        assert_eq!(identity, bob.public());
        verify_kt_proof::<S>(&log.log_public(), "bob@corp", &identity, &proof).unwrap();

        // 目录声称的身份 ≠ 日志登记：包含证明必然失败（叶哈希不同）
        let attacker = generate_identity::<S, _>(&mut rng);
        let err = verify_kt_proof::<S>(&log.log_public(), "bob@corp", &attacker.public(), &proof)
            .err()
            .unwrap();
        assert_eq!(err, CryptoError::Handshake("KT：包含证明验证失败"));

        // 伪造树头（换 root）：签名验证失败
        let mut forged = proof.clone();
        forged.sth.root[0] ^= 1;
        let err = verify_kt_proof::<S>(&log.log_public(), "bob@corp", &identity, &forged).err().unwrap();
        assert_eq!(err, CryptoError::Handshake("KT：树头签名非法"));
    }

    #[test]
    fn monitor_detects_history_rewrite_by_log_operator() {
        // 攻击模型：日志运营方（持真树头签名钥）改写历史再续写——锚定客户端必识破。
        // 同种子 → 同签名密钥对，模拟"同一运营方"。
        let build = |swap_early: bool| {
            let mut rng = ChaCha20Rng::seed_from_u64(71);
            let mut log = MerkleKtLog::<S>::new(&mut rng);
            let a = generate_identity::<S, _>(&mut rng);
            let b = generate_identity::<S, _>(&mut rng);
            let evil = generate_identity::<S, _>(&mut rng);
            log.record("alice@corp", a.public()).unwrap();
            log.record("bob@corp", if swap_early { evil.public() } else { b.public() }).unwrap();
            log
        };

        let honest = build(false);
        let mut monitor = KtMonitor::new();
        // 首次锚定（old_size=0 合法空证明）
        monitor.advance::<S>(&honest.log_public(), &honest.sth().unwrap(), &[]).unwrap();
        assert_eq!(monitor.pinned_size(), 2);

        // 诚实续写：一致性证明通过，锚点前进
        let mut grown = build(false);
        let mut rng2 = ChaCha20Rng::seed_from_u64(72);
        let carol = generate_identity::<S, _>(&mut rng2);
        grown.record("carol@corp", carol.public()).unwrap();
        let proof = grown.consistency_since(2).unwrap();
        monitor.advance::<S>(&grown.log_public(), &grown.sth().unwrap(), &proof).unwrap();
        assert_eq!(monitor.pinned_size(), 3);

        // 改写历史后续写：树头签名合法（同一运营方！），但一致性证明必然失败
        let mut rewritten = build(true);
        let dave = generate_identity::<S, _>(&mut rng2);
        rewritten.record("carol@corp", carol.public()).unwrap();
        rewritten.record("dave@corp", dave.public()).unwrap();
        let mut fresh_monitor = KtMonitor::new();
        fresh_monitor.advance::<S>(&honest.log_public(), &honest.sth().unwrap(), &[]).unwrap();
        let bad = rewritten.consistency_since(2).unwrap();
        let err = fresh_monitor
            .advance::<S>(&rewritten.log_public(), &rewritten.sth().unwrap(), &bad)
            .err()
            .unwrap();
        assert_eq!(err, CryptoError::Handshake("KT：一致性证明失败（疑似历史被改写）"));
        // 树头回缩同样被拒（append-only 的另一半承诺）：锚定 size=3 后收到 size=2 的旧树头
        let mut m2 = KtMonitor::new();
        m2.advance::<S>(&grown.log_public(), &grown.sth().unwrap(), &[]).unwrap(); // 锚定 size=3
        let shrink = honest.sth().unwrap(); // size=2 < 3
        let err = m2.advance::<S>(&honest.log_public(), &shrink, &[]).err().unwrap();
        assert_eq!(err, CryptoError::Handshake("KT：树头回缩（append-only 被违反）"));
    }

    #[test]
    fn key_rotation_must_leave_trace() {
        let mut rng = ChaCha20Rng::seed_from_u64(73);
        let mut log = MerkleKtLog::<S>::new(&mut rng);
        let bob_v1 = generate_identity::<S, _>(&mut rng);
        let bob_v2 = generate_identity::<S, _>(&mut rng);
        log.record("bob@corp", bob_v1.public()).unwrap();
        assert_eq!(log.history_count("bob@corp"), 1);

        // 换钥的唯一合法路径 = 追加 → 留痕（监控端告警口径：登记次数 > 1）
        log.record("bob@corp", bob_v2.public()).unwrap();
        assert_eq!(log.history_count("bob@corp"), 2);
        let (latest, proof) = log.lookup("bob@corp").unwrap();
        assert_eq!(latest, bob_v2.public());
        verify_kt_proof::<S>(&log.log_public(), "bob@corp", &latest, &proof).unwrap();
    }

    #[test]
    fn orchestration_accepts_real_ledger_as_kt_backend() {
        // 挂点透明性：编排层接 mock 与真账本行为一致（架构 §11 "对协议层透明"承诺）
        let mut rng = ChaCha20Rng::seed_from_u64(74);
        let ca = MockCa::new::<S, _>(&mut rng, "corp-ca");
        let bob = generate_identity::<S, _>(&mut rng);
        let cert = ca.issue::<S>("bob@corp", bob.public(), NOW + 86400).unwrap();
        let (_sp, spk_pub, spk_sig) = new_signed_prekey::<S, _>(&mut rng, &bob).unwrap();
        let bundle = PreKeyBundle {
            suite: S::id(),
            identity: bob.public(),
            signed_prekey: spk_pub,
            signed_prekey_sig: spk_sig,
            one_time_prekey: None,
        };
        let mut log = MerkleKtLog::<S>::new(&mut rng);
        log.record("bob@corp", bob.public()).unwrap();
        let a = verify_directory_entry::<S, _>(
            Some(&ca.public()),
            Some(&cert),
            None,
            Some(&log),
            "bob@corp",
            &bundle,
            NOW,
        )
        .unwrap();
        assert_eq!(a, Assurance::CertificateAndTransparency);
    }
}

