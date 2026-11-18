//! IMCrypto C ABI 骨架（架构 §14 / 实施 P8.1）。
//!
//! 四条 FFI 铁律（对齐 IMLink / IMDB）：
//! 1. **panic 不得越境**：每个导出函数经 `guard` 包裹——捕获 → 线程局部 last_error →
//!    返回 `MADCRYPTO_ERR_PANIC`，是否 abort 交宿主决定（跨 FFI 的 unwind 是未定义行为）；
//! 2. **密钥永不过界**：导出面只有错误码、版本号、密文/明文 buffer——私钥与链密钥
//!    没有任何序列化出口（完整会话句柄面随 P8 主体，同样只传句柄）；
//! 3. 所有权单向：跨界只传值；buffer 由调用方分配，Rust 只写入；
//! 4. 本 crate 是全 workspace **唯一 unsafe 区**（`deny(unsafe_code)` 白名单，
//!    unsafe 仅一处：向调用方 buffer 拷贝错误消息）。

mod handles;
pub use handles::*;

use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// 成功。
pub const MADCRYPTO_OK: i32 = 0;
/// 业务错误（详情经 `madcrypto_last_error` 取回）。
pub const MADCRYPTO_ERR: i32 = -1;
/// 内部 panic 被防火墙捕获（未跨越 FFI 边界）。
pub const MADCRYPTO_ERR_PANIC: i32 = -2;

thread_local! {
    static LAST_ERROR: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn set_error(msg: &str) {
    LAST_ERROR.with(|e| {
        let mut e = e.borrow_mut();
        e.clear();
        e.extend_from_slice(msg.as_bytes());
    });
}

/// panic 防火墙：所有导出函数的唯一出口。
///
/// `AssertUnwindSafe` 论证：闭包内触碰的全局状态只有注册表 Mutex——panic 导致的
/// 锁中毒经 `into_inner` 解毒；操作以"整函数持锁"为粒度，HashMap 自身一致性由
/// Rust 保证，协议路径另有禁 panic 纪律（P1.5）。
pub(crate) fn guard<F>(f: F) -> i32
where
    F: FnOnce() -> Result<i32, String>,
{
    set_error("");
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(code)) => code,
        Ok(Err(msg)) => {
            set_error(&msg);
            MADCRYPTO_ERR
        }
        Err(_) => {
            set_error("internal panic captured by firewall (did not cross FFI)");
            MADCRYPTO_ERR_PANIC
        }
    }
}

/// 返回句柄（i64 正数）的导出函数用的防火墙变体：负数即错误码。
pub(crate) fn guard_i64<F>(f: F) -> i64
where
    F: FnOnce() -> Result<i64, String>,
{
    set_error("");
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => v,
        Ok(Err(msg)) => {
            set_error(&msg);
            MADCRYPTO_ERR as i64
        }
        Err(_) => {
            set_error("internal panic captured by firewall (did not cross FFI)");
            MADCRYPTO_ERR_PANIC as i64
        }
    }
}

/// ABI 版本（语义化：major<<16 | minor<<8 | patch）。C 侧启动时校验。
#[no_mangle]
pub extern "C" fn madcrypto_abi_version() -> u32 {
    0x00_01_00
}

/// 取回线程局部错误消息（UTF-8，不含 NUL 约定——长度显式返回，架构 §14 FFI 铁律）。
/// 返回完整消息长度；最多向 `buf` 写入 `cap` 字节。`buf` 可为 NULL（只探长度）。
///
/// # Safety
/// 调用方必须保证：`buf` 为 NULL，或指向至少 `cap` 字节的可写内存。
/// 本函数绝不写超 `cap` 字节（内部 `n = len.min(cap)` 约束）。
#[no_mangle]
pub unsafe extern "C" fn madcrypto_last_error(buf: *mut u8, cap: usize) -> i32 {
    LAST_ERROR.with(|e| {
        let msg = e.borrow();
        let n = msg.len().min(cap);
        if n > 0 && !buf.is_null() {
            // 全 workspace 唯一 unsafe 操作：受 n ≤ cap 且 buf 非空约束的单向拷贝
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr(), buf, n);
            }
        }
        msg.len() as i32
    })
}

/// 内核自检：在进程内完整跑一遍握手 → 双棘轮往返 → 防降级 → 群密聊 → 信封。
/// 端侧集成后的第一件事就是调它——链接、原语、协议三层一次验明。
#[no_mangle]
pub extern "C" fn madcrypto_selftest() -> i32 {
    guard(|| selftest_impl().map(|_| MADCRYPTO_OK))
}

fn selftest_impl() -> Result<(), String> {
    use madcrypto_core::cloud;
    use madcrypto_core::group::{GroupReceiver, GroupSender};
    use madcrypto_core::keys::ConvKey;
    use madcrypto_core::policy::{session_ad, Track};
    use madcrypto_core::session::SecureSession;
    use madcrypto_core::x3dh::{
        generate_identity, initiate, new_signed_prekey, respond, PreKeyBundle, ResponderKeys,
    };
    use madcrypto_prims::{CipherSuite, IntlSuite, SuiteId};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    type S = IntlSuite;
    let e = |m: &str| m.to_string();
    let mut rng = ChaCha20Rng::seed_from_u64(0x5E1F);

    // 握手
    let alice_id = generate_identity::<S, _>(&mut rng);
    let bob_id = generate_identity::<S, _>(&mut rng);
    let (spk_priv, spk_pub, spk_sig) =
        new_signed_prekey::<S, _>(&mut rng, &bob_id).map_err(|_| e("spk"))?;
    let bundle = PreKeyBundle {
        suite: S::id(),
        identity: bob_id.public(),
        signed_prekey: spk_pub,
        signed_prekey_sig: spk_sig,
        one_time_prekey: None,
    };
    let init = initiate::<S, _>(&mut rng, &alice_id, &bundle).map_err(|_| e("initiate"))?;
    let resp = respond::<S>(
        ResponderKeys {
            identity: &bob_id,
            signed_prekey_private: &spk_priv,
            one_time_prekey_private: None,
        },
        &init.initial_message,
    )
    .map_err(|_| e("respond"))?;

    // 双棘轮往返 + 防降级
    let mut alice = SecureSession::initiator::<S, _>(&mut rng, init.root, init.their_ratchet_public)
        .map_err(|_| e("session"))?;
    let mut bob = SecureSession::receiver(resp.root, resp.my_ratchet_private, resp.my_ratchet_public);
    let ad = session_ad(Track::Secret, SuiteId::Intl, "selftest", None);
    let (h, ct) = alice.encrypt::<S>(&ad, b"selftest").map_err(|_| e("encrypt"))?;
    let wrong_ad = session_ad(Track::Cloud, SuiteId::Intl, "selftest", None);
    if bob.decrypt::<S, _>(&mut rng, &h, &ct, &wrong_ad).is_ok() {
        return Err(e("downgrade guard failed"));
    }
    let pt = bob.decrypt::<S, _>(&mut rng, &h, &ct, &ad).map_err(|_| e("decrypt"))?;
    if pt != b"selftest" {
        return Err(e("plaintext mismatch"));
    }

    // 群密聊
    let mut sender = GroupSender::new::<S, _>(&mut rng);
    let mut receiver = GroupReceiver::from_distribution(sender.distribution());
    let gm = sender.encrypt::<S>(b"g", b"group").map_err(|_| e("group encrypt"))?;
    if receiver.decrypt::<S>(b"g", &gm).map_err(|_| e("group decrypt"))? != b"group" {
        return Err(e("group mismatch"));
    }

    // 普通轨信封
    let ck = ConvKey::new([9u8; 32]);
    let env = cloud::seal::<S>(&ck, 1, "t", "c", 1, b"cloud");
    if cloud::open::<S>(&ck, "t", "c", 1, &env).map_err(|_| e("envelope"))? != b"cloud" {
        return Err(e("envelope mismatch"));
    }
    Ok(())
}

/// 仅供集成方验证防火墙的调试导出：内部故意 panic，必须返回 `MADCRYPTO_ERR_PANIC` 而非崩溃。
#[cfg(test)]
#[no_mangle]
pub extern "C" fn madcrypto_debug_trigger_panic() -> i32 {
    guard(|| -> Result<i32, String> { panic!("deliberate panic for firewall verification") })
}

// C 冒烟入口：由 build.rs 用真 clang 编译 tests/c_smoke.c 链接进本 crate。
// 声明在 lib 内 → 本 crate 单测构建自动带上 build 脚本的 native-lib 链接。
#[cfg(all(test, feature = "c-test-fixtures"))]
extern "C" {
    fn madcrypto_c_smoke_main() -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C ABI 端到端：真 clang 编译的 C 程序驱动完整密聊往返——手写 imcrypto.h 与 Rust 导出
    /// 逐符号一致（消除"手写头从未被 C 编译器验证过"的盲区，IMDB §23）。
    #[cfg(feature = "c-test-fixtures")]
    #[test]
    fn c_abi_full_roundtrip() {
        let rc = unsafe { madcrypto_c_smoke_main() };
        assert_eq!(rc, 0, "C 冒烟失败（返回码 {rc}）——见 stderr 的 C-smoke FAIL 行");
    }

    #[test]
    fn selftest_passes() {
        assert_eq!(madcrypto_selftest(), MADCRYPTO_OK);
    }

    #[test]
    fn firewall_catches_panic_and_reports() {
        // panic 被捕获 → 错误码，进程不死、不跨界 unwind
        assert_eq!(madcrypto_debug_trigger_panic(), MADCRYPTO_ERR_PANIC);
        let mut buf = [0u8; 256];
        let n = unsafe { madcrypto_last_error(buf.as_mut_ptr(), buf.len()) };
        assert!(n > 0, "错误消息必须可取回");
        let msg = std::str::from_utf8(&buf[..n as usize]).unwrap();
        assert!(msg.contains("firewall"));
        // 防火墙之后 FFI 仍可用（线程未被污染）
        assert_eq!(madcrypto_selftest(), MADCRYPTO_OK);
    }

    #[test]
    fn error_buffer_length_probe() {
        assert_eq!(madcrypto_debug_trigger_panic(), MADCRYPTO_ERR_PANIC);
        // NULL buffer 探长度
        let need = unsafe { madcrypto_last_error(std::ptr::null_mut(), 0) };
        assert!(need > 0);
        // 截断拷贝不越界
        let mut small = [0u8; 4];
        let n = unsafe { madcrypto_last_error(small.as_mut_ptr(), small.len()) };
        assert_eq!(n, need, "返回值恒为完整长度");
    }

    #[test]
    fn abi_version_is_stable() {
        assert_eq!(madcrypto_abi_version(), 0x00_01_00);
    }
}


pub mod store_adapter;
