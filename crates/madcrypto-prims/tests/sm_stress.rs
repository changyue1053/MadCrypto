//! 国密 spike 的可靠性压测（排查 CI 间歇失败用，默认 ignore）：
//!   cargo test --release -p madcrypto-prims --test sm_stress -- --ignored --nocapture
//!
//! 目的：全量跑 workspace 时 sm_spike 出现过一次 1/4 失败（随机密钥相关，复跑即过）。
//! 本文件用大样本把"哪个操作、哪种失败形态（Err vs Ok(false)）、概率量级"钉死——
//! 结论回填 sm_spike 模块头与 README 国密风险表（spike 的意义就是拿数据说话）。

use libsm::sm2::exchange::{ExchangeCtxA, ExchangeCtxB};
use libsm::sm2::signature::SigCtx;

const ITERS: usize = 200;

#[test]
#[ignore]
fn sm2_sign_verify_stress() {
    let ctx = SigCtx::new();
    let mut verify_err_on_valid = 0usize;
    let mut false_on_valid = 0usize;
    let mut err_on_tampered = 0usize; // Err（而非 Ok(false)）拒绝篡改：语义不整洁但可接受
    for i in 0..ITERS {
        let (pk, sk) = ctx.new_keypair().unwrap_or_else(|e| panic!("iter {i}: keypair failed: {e:?}"));
        let msg = format!("stress message {i}");
        let sig = ctx.sign(msg.as_bytes(), &sk, &pk).unwrap_or_else(|e| panic!("iter {i}: sign failed: {e:?}"));
        match ctx.verify(msg.as_bytes(), &pk, &sig) {
            Ok(true) => {}
            Ok(false) => false_on_valid += 1,
            Err(_) => verify_err_on_valid += 1,
        }
        match ctx.verify(b"tampered", &pk, &sig) {
            Ok(true) => panic!("iter {i}: tampered message verified as VALID — 安全性缺陷"),
            Ok(false) => {}
            Err(_) => err_on_tampered += 1,
        }
    }
    println!(
        "sign/verify stress: {ITERS} iters | valid→Err {verify_err_on_valid} | valid→false {false_on_valid} | tampered→Err {err_on_tampered}"
    );
    assert_eq!(false_on_valid, 0, "合法签名被判 false：签名后端不可用级缺陷");
    assert_eq!(verify_err_on_valid, 0, "合法签名验证报 Err：签名后端不可用级缺陷");
}

#[test]
#[ignore]
fn sm2_exchange_stress() {
    let ctx = SigCtx::new();
    let mut failures = Vec::new();
    for i in 0..ITERS {
        let r = (|| -> Result<bool, String> {
            let (pk_a, sk_a) = ctx.new_keypair().map_err(|e| format!("keypair A: {e:?}"))?;
            let (pk_b, sk_b) = ctx.new_keypair().map_err(|e| format!("keypair B: {e:?}"))?;
            let mut a = ExchangeCtxA::new(16, "alice@corp", "bob@corp", pk_a, pk_b, sk_a)
                .map_err(|e| format!("ctx A: {e:?}"))?;
            let mut b = ExchangeCtxB::new(16, "alice@corp", "bob@corp", pk_a, pk_b, sk_b)
                .map_err(|e| format!("ctx B: {e:?}"))?;
            let r_a = a.exchange1().map_err(|e| format!("step1: {e:?}"))?;
            let (r_b, s_b) = b.exchange2(&r_a).map_err(|e| format!("step2: {e:?}"))?;
            let s_a = a.exchange3(&r_b, s_b).map_err(|e| format!("step3: {e:?}"))?;
            b.exchange4(s_a, &r_a).map_err(|e| format!("step4: {e:?}"))
        })();
        match r {
            Ok(true) => {}
            Ok(false) => failures.push(format!("iter {i}: exchange4 confirmed=false")),
            Err(e) => failures.push(format!("iter {i}: {e}")),
        }
    }
    println!("exchange stress: {ITERS} iters, {} failures", failures.len());
    for f in &failures {
        println!("  {f}");
    }
    // 概率性失败在此显形：断言收紧到 0，任何非零都要进 spike 结论表
    assert!(failures.is_empty(), "SM2 交换存在概率性失败：{failures:?}");
}

