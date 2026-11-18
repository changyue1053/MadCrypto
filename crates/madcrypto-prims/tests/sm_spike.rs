//! 国密套件 spike（实施 P0.3 / 决策门①）：libsm 0.6.1 实测，dev 依赖不进发布树。
//!
//! # Spike 结论（写入 README「国密 spike 结论」，决策门①出口）
//!
//! **可直接用的三件**（纸面风险被推翻的部分）：
//! - SM3：API 简洁，国标示例向量逐字节对齐（下方测试）；
//! - SM2 签名/验签：可用，可作 CipherSuite 的 sign/verify 后端；
//! - **SM4-GCM 原生存在**（`CipherMode::Gcm`，encrypt 原生带 AAD）——
//!   架构 §5 与风险 R1 中「SM4-GCM 需自行组合」的假设**不成立**，风险降级。
//!
//! **真正的缺口**（比纸面预估的更深，坐实决策门①）：
//! - SM2 密钥交换是**四步交互式协议**（GB/T 32918.3：exchange1→4，混入双方身份 ID
//!   与确认哈希）——与 X3DH 需要的非交互 raw DH（离线 bundle 上做 DH₁..₄）**不同构**，
//!   不能作为 `CipherSuite::dh()` 的直接后端；
//! - libsm 0.6.1 的交换 API **无协商密钥 getter**（k_a/k_b 私有）——确认流程能跑通，
//!   会话密钥取不出来，集成需 fork 或上游 PR。
//!
//! **结论**：国密轨的「握手」是设计问题而非编码问题（离线建密 × 交互式国标协议的矛盾
//! 需要方案评审），工作量 > 2d → 触发决策门①：**国密移 v1.1，v1.0 保持 `SuiteId::Sm`
//! 接口位；SM3/SM2 签名/SM4-GCM 三件可随时接入**。铜锁（认证模块路线）的对照评估
//! 因涉及 C FFI 绑定，随 v1.1 国密专项执行。

use libsm::sm2::exchange::{ExchangeCtxA, ExchangeCtxB};
use libsm::sm2::signature::SigCtx;
use libsm::sm3::hash::Sm3Hash;
use libsm::sm4::cipher_mode::{CipherMode, Sm4CipherMode};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// 上游随机性伪影的重试壳（spike 可靠性纪律）：
/// - **只重试上游 Err 伪影**（随机密钥相关的罕见失败），连续两次仍失败才判失败；
/// - **安全断言永不重试**（篡改被判合法之类直接 panic）——重试不允许掩盖安全回归。
///
/// 背景：全量并行测试中 sm_spike 出现过一次未复现的 1/4 失败（复跑 ×7 + release
/// 压测 2×200 轮零复现，复现工具见 `sm_stress.rs`）。最可疑根因：对篡改输入的验签
/// 曾用 `.expect()`——libsm 对部分罕见输入以 `Err` 而非 `Ok(false)` 拒绝，语义上
/// 两者都是"拒绝"，测试已改为统一接受。**间歇性本身已记入国密 spike 结论：
/// libsm 的错误边界不整洁，坐实 v1.1 国密专项需铜锁对照评估。**
fn with_upstream_retry(name: &str, f: impl Fn() -> Result<(), String>) {
    let mut last = String::new();
    for _ in 0..2 {
        match f() {
            Ok(()) => return,
            Err(e) => last = e,
        }
    }
    panic!("{name}: 上游连续两次失败（非偶发伪影）: {last}");
}

/// SM3 国标（GB/T 32905）示例 1："abc"。
#[test]
fn sm3_gbt32905_vector() {
    let digest = Sm3Hash::new(b"abc").get_hash();
    assert_eq!(
        digest.to_vec(),
        unhex("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
    );
}

/// SM2 签名/验签：可作 CipherSuite 签名后端（往返 + 篡改拒绝）。
#[test]
fn sm2_sign_verify_roundtrip_and_tamper() {
    with_upstream_retry("sm2 sign/verify", || {
        let ctx = SigCtx::new();
        let (pk, sk) = ctx.new_keypair().map_err(|e| format!("keypair: {e:?}"))?;
        let msg = b"imcrypto sm spike";
        let sig = ctx.sign(msg, &sk, &pk).map_err(|e| format!("sign: {e:?}"))?;
        match ctx.verify(msg, &pk, &sig) {
            Ok(true) => {}
            other => return Err(format!("合法签名未通过验证: {other:?}")),
        }
        // 拒绝语义：Ok(false) 与 Err 都算拒绝（libsm 对罕见输入以 Err 拒绝，边界不整洁）
        if let Ok(true) = ctx.verify(b"tampered message", &pk, &sig) {
            panic!("篡改消息被判合法——安全性缺陷，不进重试"); // 安全断言：立即失败
        }
        Ok(())
    });
}

/// SM4-GCM：原生可用，AAD 绑定与篡改拒绝语义齐全——「需自行组合 GCM」的纸面风险不成立。
/// 适配点（spike 发现）：libsm 接口层强制 **16 字节 IV**（`iv.len() != 16` 直接拒），
/// 与本库 CipherSuite 的 12 字节 nonce 约定不一致——接入时 nonce 长度需按套件参数化。
#[test]
fn sm4_gcm_native_with_aad_binding() {
    let key = [0x42u8; 16]; // SM4 128-bit
    let iv = [7u8; 16]; // libsm 强制 16B（12B 会被接口层拒绝）
    let cipher = Sm4CipherMode::new(&key, CipherMode::Gcm).expect("gcm mode");

    let ct = cipher.encrypt(b"conv:42", b"secret body", &iv).expect("seal");
    assert_ne!(&ct[..11], b"secret body");
    let pt = cipher.decrypt(b"conv:42", &ct, &iv).expect("open");
    assert_eq!(pt, b"secret body");

    // AAD 错配（跨会话移植）必须失败
    assert!(cipher.decrypt(b"conv:99", &ct, &iv).is_err());
    // 篡改密文必须失败
    let mut tampered = ct.clone();
    tampered[0] ^= 1;
    assert!(cipher.decrypt(b"conv:42", &tampered, &iv).is_err());
}

/// SM2 密钥交换：四步交互式协议能跑通（exchange4 确认 = 双方密钥一致），
/// 但形态与 X3DH 不同构、且 API 无密钥 getter——国密握手需单独设计（见模块头结论）。
#[test]
fn sm2_exchange_is_interactive_and_has_no_key_getter() {
    with_upstream_retry("sm2 exchange", || {
        let ctx = SigCtx::new();
        let (pk_a, sk_a) = ctx.new_keypair().map_err(|e| format!("A keypair: {e:?}"))?;
        let (pk_b, sk_b) = ctx.new_keypair().map_err(|e| format!("B keypair: {e:?}"))?;

        // 注意签名：协议要求双方身份 ID 参与 Z 值计算——身份混入协议本体，
        // 这与 X3DH「身份密钥只做 DH 输入」的结构完全不同。
        let mut a = ExchangeCtxA::new(16, "alice@corp", "bob@corp", pk_a, pk_b, sk_a)
            .map_err(|e| format!("ctx A: {e:?}"))?;
        let mut b = ExchangeCtxB::new(16, "alice@corp", "bob@corp", pk_a, pk_b, sk_b)
            .map_err(|e| format!("ctx B: {e:?}"))?;

        let r_a = a.exchange1().map_err(|e| format!("step1: {e:?}"))?; // A → B：R_A
        let (r_b, s_b) = b.exchange2(&r_a).map_err(|e| format!("step2: {e:?}"))?; // B → A：R_B + S_B
        let s_a = a.exchange3(&r_b, s_b).map_err(|e| format!("step3: {e:?}"))?; // A 验 S_B，回 S_A
        let confirmed = b.exchange4(s_a, &r_a).map_err(|e| format!("step4: {e:?}"))?; // B 验 S_A
        if !confirmed {
            return Err("exchange4 confirmed=false（确认哈希不一致）".into());
        }
        // 但 k_a / k_b 为私有字段且无 getter：密钥取不出来——集成硬伤，见模块头结论。
        Ok(())
    });
}

