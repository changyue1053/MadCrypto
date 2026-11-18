//! 会话句柄面（实施 P8 主体）：C 侧经句柄驱动完整密聊流程。
//!
//! 三条设计纪律：
//! - **密钥不过界**：导出面只有句柄、公钥 bundle、线格式密文、明文——私钥与会话状态
//!   永远留在注册表内，没有任何序列化出口（持久化由宿主 Rust SessionStore 负责；没有默认数据库 bridge）。
//! - **pending-take 模式**：凡产生字节的操作（首包/密文/明文）都推进了棘轮状态，
//!   绝不能为"探长"重算——操作执行一次、结果暂存 pending 槽，`madcrypto_take_pending`
//!   两段式取走（cap 不足只报总长、不清槽，重试安全；取走即清）。
//! - 每个导出函数过 panic 防火墙（`guard`/`guard_i64`），错误经 `madcrypto_last_error` 取回。
//!
//! v1 边界（如实标注）：句柄面提供协议操作，会话为内存态；「解密即事务」的持久化编排
//! 通过 Rust SessionStore 接口由宿主实现；本阶段未实现产品数据库 bridge。

use std::collections::{HashMap, VecDeque};
use zeroize::Zeroizing;
use std::sync::{Mutex, MutexGuard, OnceLock};

use madcrypto_core::keys::{DhPrivate, IdentityKeyPair};
use madcrypto_core::session::SecureSession;
use madcrypto_core::wire;
use madcrypto_core::x3dh::{
    generate_identity, initiate, new_one_time_prekey, new_signed_prekey, respond, PreKeyBundle,
    ResponderKeys,
};
use madcrypto_prims::{CipherSuite, IntlSuite};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::{guard, guard_i64, MADCRYPTO_OK};

type S = IntlSuite;

/// Bob 侧已发布 bundle 的私钥槽（等待 accept；OPK 用后即删）。
struct BundleSlot {
    spk_private: DhPrivate,
    opk_private: Option<DhPrivate>,
    opk_id: u32,
}

#[derive(Default)]
struct Registry {
    next: u64,
    identities: HashMap<u64, IdentityKeyPair>,
    bundles: HashMap<u64, BundleSlot>, // keyed by 身份句柄（覆盖式：一个活跃 bundle）
    sessions: HashMap<u64, SecureSession>,
    pending: HashMap<u64, Zeroizing<Vec<u8>>>, // keyed by 任意句柄：待取输出
    rng: Option<ChaCha20Rng>,
    observers: HashMap<u64, Observation>,
}

fn registry() -> MutexGuard<'static, Registry> {
    static REG: OnceLock<Mutex<Registry>> = OnceLock::new();
    let m = REG.get_or_init(|| Mutex::new(Registry::default()));
    // 防火墙捕获 panic 后锁可能中毒；操作以"取出-操作-放回"为粒度，数据结构保持一致，解毒继续
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 字段拆借入口：deref 一次拿 `&mut Registry`，此后 identities/sessions 与 rng 各借各的字段。
fn rng_of(reg: &mut Registry) -> &mut ChaCha20Rng {
    reg.rng.get_or_insert_with(ChaCha20Rng::from_entropy)
}

/// 输入边界：C 指针 + 长度 → 切片。NULL 且 len>0 = 拒绝。
///
/// # Safety
/// 调用方保证 `ptr` 为 NULL 或指向至少 `len` 字节的可读内存。
unsafe fn in_slice<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], String> {
    if len > isize::MAX as usize { return Err("input length exceeds slice limit".into()); }
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err("输入指针为 NULL".into());
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

fn err<T>(msg: &str) -> Result<T, String> {
    Err(msg.to_string())
}

// ================= 身份与 bundle =================

/// 生成身份密钥对，返回句柄（>0）；失败返回负错误码。
#[no_mangle]
pub extern "C" fn madcrypto_identity_new() -> i64 {
    guard_i64(|| {
        let mut g = registry();
        let reg = &mut *g;
        let identity = generate_identity::<S, _>(rng_of(reg));
        reg.next += 1;
        let h = reg.next;
        reg.identities.insert(h, identity);
        Ok(h as i64)
    })
}

#[no_mangle]
pub extern "C" fn madcrypto_identity_free(handle: u64) -> i32 {
    guard(move || {
        let mut g = registry();
        if g.sessions.contains_key(&handle) { return err("wrong handle type: expected identity"); }
        g.identities.remove(&handle);
        g.bundles.remove(&handle);
        g.pending.remove(&handle);
        Ok(MADCRYPTO_OK)
    })
}

/// 发布 prekey bundle：生成 SPK(+签名) + OPK，私钥留槽等待 accept；
/// 公钥 bundle 线格式进 pending[身份句柄]，经 `madcrypto_take_pending` 取走交给目录。
#[no_mangle]
pub extern "C" fn madcrypto_bundle_publish(identity_handle: u64) -> i32 {
    guard(move || {
        let mut g = registry();
        let reg = &mut *g;
        if reg.pending.contains_key(&identity_handle) { return err("pending output must be consumed first"); }
        let Some(identity) = reg.identities.get(&identity_handle) else {
            return err("身份句柄非法");
        };
        let rng = reg.rng.get_or_insert_with(ChaCha20Rng::from_entropy);
        let (spk_private, spk_public, spk_sig) =
            new_signed_prekey::<S, _>(rng, identity).map_err(|e| e.to_string())?;
        let (opk_private, opk_public) = new_one_time_prekey::<S, _>(rng);

        let bundle = PreKeyBundle {
            suite: S::id(),
            identity: identity.public(),
            signed_prekey: spk_public,
            signed_prekey_sig: spk_sig,
            one_time_prekey: Some((1, opk_public)),
        };
        let bytes = wire::encode_bundle(&bundle);
        reg.bundles.insert(
            identity_handle,
            BundleSlot { spk_private, opk_private: Some(opk_private), opk_id: 1 },
        );
        reg.pending.insert(identity_handle, Zeroizing::new(bytes));
        Ok(MADCRYPTO_OK)
    })
}

// ================= 会话建立 =================

/// 发起方：目录来的 bundle 字节 + 首条明文 + AD → 会话句柄（>0）；
/// 首包（PreKeyMessage 线格式）进 pending[会话句柄]。
///
/// # Safety
/// 指针参数遵循 `in_slice` 契约（NULL 或至少 len 字节可读）。
#[no_mangle]
pub unsafe extern "C" fn madcrypto_session_initiate(
    identity_handle: u64,
    bundle_ptr: *const u8,
    bundle_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    ad_ptr: *const u8,
    ad_len: usize,
) -> i64 {
    guard_i64(move || {
        if plaintext_len > 65472 { return err("plaintext exceeds v1 Intl wire limit"); }
        let bundle_bytes = unsafe { in_slice(bundle_ptr, bundle_len)? };
        let plaintext = unsafe { in_slice(plaintext_ptr, plaintext_len)? };
        let ad = unsafe { in_slice(ad_ptr, ad_len)? };
        let bundle = wire::decode_bundle(bundle_bytes).map_err(|e| e.to_string())?;
        if bundle.one_time_prekey.is_none() { return err("C ABI requires an OPK; persistent no-OPK replay protection is not provided"); }

        let mut g = registry();
        let reg = &mut *g;
        let Some(identity) = reg.identities.get(&identity_handle) else {
            return err("身份句柄非法");
        };
        let rng = reg.rng.get_or_insert_with(ChaCha20Rng::from_entropy);

        let init = initiate::<S, _>(rng, identity, &bundle).map_err(|e| e.to_string())?;
        let mut session = SecureSession::initiator::<S, _>(rng, init.root, init.their_ratchet_public)
            .map_err(|e| e.to_string())?;
        let (header, ct) = session.encrypt::<S>(ad, plaintext).map_err(|e| e.to_string())?;
        let inner = wire::encode_message(S::id(), &header, &ct);
        let outer = wire::encode_prekey_message(&init.initial_message, &inner);

        reg.next += 1;
        let h = reg.next;
        reg.sessions.insert(h, session);
        reg.pending.insert(h, Zeroizing::new(outer));
        Ok(h as i64)
    })
}

/// 接收方：吃首包（PreKeyMessage）→ 会话句柄（>0）；首条明文进 pending[会话句柄]。
/// OPK 用后即删：同一首包重放会因 OPK 已消费而被拒（重放防御的组成部分）。
///
/// # Safety
/// 指针参数遵循 `in_slice` 契约。
#[no_mangle]
pub unsafe extern "C" fn madcrypto_session_accept(
    identity_handle: u64,
    message_ptr: *const u8,
    message_len: usize,
    ad_ptr: *const u8,
    ad_len: usize,
) -> i64 {
    guard_i64(move || {
        let msg_bytes = unsafe { in_slice(message_ptr, message_len)? };
        let ad = unsafe { in_slice(ad_ptr, ad_len)? };
        let (im, inner) = wire::decode_prekey_message(msg_bytes).map_err(|e| e.to_string())?;
        if im.one_time_prekey_id.is_none() { return err("C ABI requires an OPK; no-OPK first packets are rejected"); }
        let (suite, header, ct) = wire::decode_message(&inner).map_err(|e| e.to_string())?;
        if suite != S::id() {
            return err("套件不符");
        }

        let mut g = registry();
        let reg = &mut *g;
        let Some(identity) = reg.identities.get(&identity_handle) else {
            return err("身份句柄非法");
        };
        let Some(slot) = reg.bundles.get_mut(&identity_handle) else {
            return err("未发布 bundle 或已失效");
        };
        // OPK 一致性 + 用后即删
        let opk_private = match im.one_time_prekey_id {
            None => None,
            Some(id) if id == slot.opk_id => match slot.opk_private.as_ref() {
                Some(p) => Some(p),
                None => return err("OPK 已被消费（疑似首包重放）"),
            },
            Some(_) => return err("OPK id 未知"),
        };
        let resp = respond::<S>(
            ResponderKeys {
                identity,
                signed_prekey_private: &slot.spk_private,
                one_time_prekey_private: opk_private,
            },
            &im,
        )
        .map_err(|e| e.to_string())?;

        let mut session =
            SecureSession::receiver(resp.root, resp.my_ratchet_private, resp.my_ratchet_public);
        let rng = reg.rng.get_or_insert_with(ChaCha20Rng::from_entropy);
        let plaintext = session
            .decrypt::<S, _>(rng, &header, &ct, ad)
            .map_err(|e| e.to_string())?;

        // Authentication succeeded: now consume the OPK, never on forged input.
        if im.one_time_prekey_id.is_some() { slot.opk_private.take(); }
        reg.next += 1;
        let h = reg.next;
        reg.sessions.insert(h, session);
        reg.pending.insert(h, Zeroizing::new(plaintext));
        Ok(h as i64)
    })
}

// ================= 消息收发 =================

/// 加密一条消息：线格式密文进 pending[会话句柄]。
///
/// # Safety
/// 指针参数遵循 `in_slice` 契约。
#[no_mangle]
pub unsafe extern "C" fn madcrypto_session_encrypt(
    session_handle: u64,
    ad_ptr: *const u8,
    ad_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
) -> i32 {
    guard(move || {
        if plaintext_len > 65520 { return err("plaintext exceeds v1 Intl wire limit"); }
        let ad = unsafe { in_slice(ad_ptr, ad_len)? };
        let plaintext = unsafe { in_slice(plaintext_ptr, plaintext_len)? };
        let mut g = registry();
        let reg = &mut *g;
        if reg.pending.contains_key(&session_handle) { return err("pending output must be consumed first"); }
        let Some(session) = reg.sessions.get_mut(&session_handle) else {
            return err("会话句柄非法");
        };
        let (header, ct) = session.encrypt::<S>(ad, plaintext).map_err(|e| e.to_string())?;
        let bytes = wire::encode_message(S::id(), &header, &ct);
        reg.pending.insert(session_handle, Zeroizing::new(bytes));
        if let Some(obs) = reg.observers.get_mut(&session_handle) { obs.record(1); }
        Ok(MADCRYPTO_OK)
    })
}

/// 解密一条线格式消息：明文进 pending[会话句柄]。
///
/// # Safety
/// 指针参数遵循 `in_slice` 契约。
#[no_mangle]
pub unsafe extern "C" fn madcrypto_session_decrypt(
    session_handle: u64,
    ad_ptr: *const u8,
    ad_len: usize,
    message_ptr: *const u8,
    message_len: usize,
) -> i32 {
    guard(move || {
        let ad = unsafe { in_slice(ad_ptr, ad_len)? };
        let msg = unsafe { in_slice(message_ptr, message_len)? };
        let (suite, header, ct) = wire::decode_message(msg).map_err(|e| e.to_string())?;
        if suite != S::id() {
            return err("套件不符");
        }
        let mut g = registry();
        let reg = &mut *g;
        if reg.pending.contains_key(&session_handle) { return err("pending output must be consumed first"); }
        let Some(session) = reg.sessions.get_mut(&session_handle) else {
            return err("会话句柄非法");
        };
        let rng = reg.rng.get_or_insert_with(ChaCha20Rng::from_entropy);
        let plaintext = session
            .decrypt::<S, _>(rng, &header, &ct, ad)
            .map_err(|e| e.to_string())?;
        reg.pending.insert(session_handle, Zeroizing::new(plaintext));
        if let Some(obs) = reg.observers.get_mut(&session_handle) { obs.record(2); }
        Ok(MADCRYPTO_OK)
    })
}

#[no_mangle]
pub extern "C" fn madcrypto_session_free(handle: u64) -> i32 {
    guard(move || {
        let mut g = registry();
        if g.identities.contains_key(&handle) { return err("wrong handle type: expected session"); }
        g.sessions.remove(&handle);
        g.observers.remove(&handle);
        g.pending.remove(&handle);
        Ok(MADCRYPTO_OK)
    })
}

// ================= pending-take =================

/// 两段式取待取字节：返回总长度；cap ≥ 总长时写入并清槽，否则只报长、不清槽（重试安全）。
/// `buf` 可为 NULL 仅探长。
///
/// # Safety
/// `buf` 为 NULL 或指向至少 `cap` 字节可写内存；本函数绝不写超 `cap` 字节。
#[no_mangle]
pub unsafe extern "C" fn madcrypto_take_pending(handle: u64, buf: *mut u8, cap: usize) -> i64 {
    guard_i64(move || {
        let mut g = registry();
        let Some(bytes) = g.pending.get(&handle) else {
            return err("该句柄无待取数据");
        };
        let n = bytes.len();
        if buf.is_null() || cap < n {
            return Ok(n as i64); // 探长：不清槽
        }
        if n > 0 {
            if buf.is_null() {
                return err("输出指针为 NULL");
            }
            unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n) };
        }
        g.pending.remove(&handle);
        Ok(n as i64)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AD: &[u8] = b"conv:ffi";

    /// pending-take 两段式取字节。
    fn take(handle: u64) -> Vec<u8> {
        let need = unsafe { madcrypto_take_pending(handle, std::ptr::null_mut(), 0) };
        assert!(need >= 0, "探长失败");
        let mut buf = vec![0u8; need as usize];
        let n = unsafe { madcrypto_take_pending(handle, buf.as_mut_ptr(), buf.len()) };
        assert_eq!(n, need);
        buf
    }

    #[test]
    fn full_secret_chat_over_c_abi() {
        let alice = madcrypto_identity_new();
        let bob = madcrypto_identity_new();
        assert!(alice > 0 && bob > 0);

        // Bob 发布 bundle（字节交给目录）
        assert_eq!(madcrypto_bundle_publish(bob as u64), MADCRYPTO_OK);
        assert!(madcrypto_bundle_publish(bob as u64) < 0, "unconsumed bundle must not be replaced");
        assert!(madcrypto_session_free(bob as u64) < 0, "wrong handle type must retain bundle");
        let bundle = take(bob as u64);

        // C facade does not silently downgrade to a replay-unprotected no-OPK flow.
        let mut no_opk = wire::decode_bundle(&bundle).unwrap();
        no_opk.one_time_prekey = None;
        let no_opk_bytes = wire::encode_bundle(&no_opk);
        assert!(unsafe { madcrypto_session_initiate(alice as u64, no_opk_bytes.as_ptr(), no_opk_bytes.len(), b"x".as_ptr(), 1, AD.as_ptr(), AD.len()) } < 0);
        // Construct an AUTHENTIC no-OPK packet via the low-level Rust protocol.
        // Unlike flipping an existing OPK flag, its KDF/root genuinely match.
        let mut test_rng = ChaCha20Rng::seed_from_u64(42);
        let rust_alice = generate_identity::<S, _>(&mut test_rng);
        let rust_init = initiate::<S, _>(&mut test_rng, &rust_alice, &no_opk).unwrap();
        let mut rust_session = SecureSession::initiator::<S, _>(&mut test_rng, rust_init.root, rust_init.their_ratchet_public).unwrap();
        let (rust_header, rust_ct) = rust_session.encrypt::<S>(AD, b"valid no-opk").unwrap();
        let rust_inner = wire::encode_message(S::id(), &rust_header, &rust_ct);
        let valid_no_opk = wire::encode_prekey_message(&rust_init.initial_message, &rust_inner);
        assert!(unsafe { madcrypto_session_accept(bob as u64, valid_no_opk.as_ptr(), valid_no_opk.len(), AD.as_ptr(), AD.len()) } < 0);
        // Alice 拉 bundle 发起会话（附首条明文）
        let text = b"hello over ffi";
        let sa = unsafe {
            madcrypto_session_initiate(
                alice as u64,
                bundle.as_ptr(),
                bundle.len(),
                text.as_ptr(),
                text.len(),
                AD.as_ptr(),
                AD.len(),
            )
        };
        assert!(sa > 0);
        assert!(madcrypto_identity_free(sa as u64) < 0, "wrong handle type must retain first packet");
        let first_packet = take(sa as u64);

        let (mut initial, inner) = wire::decode_prekey_message(&first_packet).unwrap();
        initial.one_time_prekey_id = None;
        let downgraded = wire::encode_prekey_message(&initial, &inner);
        assert!(unsafe { madcrypto_session_accept(bob as u64, downgraded.as_ptr(), downgraded.len(), AD.as_ptr(), AD.len()) } < 0);
        // A forged first packet must not burn Bob's one-time prekey.
        let mut forged = first_packet.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(unsafe { madcrypto_session_accept(bob as u64, forged.as_ptr(), forged.len(), AD.as_ptr(), AD.len()) } < 0);
        // Bob 收首包：建会话 + 解出首条明文
        let sb = unsafe {
            madcrypto_session_accept(bob as u64, first_packet.as_ptr(), first_packet.len(), AD.as_ptr(), AD.len())
        };
        assert!(sb > 0);
        assert!(unsafe { madcrypto_session_encrypt(sb as u64, AD.as_ptr(), AD.len(), b"lost".as_ptr(), 4) } < 0);
        assert_eq!(take(sb as u64), text);
        assert_eq!(madcrypto_poll_event(sb as u64), 0);
        assert_eq!(madcrypto_observe(sb as u64, 1), MADCRYPTO_OK);

        // Bob 回复 → Alice 解（双向棘轮经 C ABI 走通）
        assert_eq!(
            unsafe { madcrypto_session_encrypt(sb as u64, AD.as_ptr(), AD.len(), b"reply".as_ptr(), 5) },
            MADCRYPTO_OK
        );
        assert!(unsafe { madcrypto_session_encrypt(sb as u64, AD.as_ptr(), AD.len(), b"lost".as_ptr(), 4) } < 0);
        let msg = take(sb as u64);
        assert_eq!(madcrypto_poll_event(sb as u64), 1);
        assert_eq!(madcrypto_poll_event(sb as u64), 0);
        assert_eq!(
            unsafe { madcrypto_session_decrypt(sa as u64, AD.as_ptr(), AD.len(), msg.as_ptr(), msg.len()) },
            MADCRYPTO_OK
        );
        assert!(unsafe { madcrypto_session_decrypt(sa as u64, AD.as_ptr(), AD.len(), msg.as_ptr(), msg.len()) } < 0);
        assert_eq!(take(sa as u64), b"reply");
        // Empty plaintext: repeated NULL probes do not consume the slot.
        assert_eq!(unsafe { madcrypto_session_encrypt(sb as u64, AD.as_ptr(), AD.len(), std::ptr::null(), 0) }, MADCRYPTO_OK);
        let empty = take(sb as u64);
        assert_eq!(unsafe { madcrypto_session_decrypt(sa as u64, AD.as_ptr(), AD.len(), empty.as_ptr(), empty.len()) }, MADCRYPTO_OK);
        assert_eq!(unsafe { madcrypto_take_pending(sa as u64, std::ptr::null_mut(), 0) }, 0);
        assert_eq!(unsafe { madcrypto_take_pending(sa as u64, std::ptr::null_mut(), 0) }, 0);
        assert!(take(sa as u64).is_empty());

        // 首包重放：OPK 用后即删 → 必拒
        let replay = unsafe {
            madcrypto_session_accept(bob as u64, first_packet.as_ptr(), first_packet.len(), AD.as_ptr(), AD.len())
        };
        assert!(replay < 0, "首包重放必须被拒（OPK 已消费）");

        assert_eq!(madcrypto_session_free(sa as u64), MADCRYPTO_OK);
        assert_eq!(madcrypto_session_free(sb as u64), MADCRYPTO_OK);
        assert_eq!(madcrypto_identity_free(alice as u64), MADCRYPTO_OK);
        assert_eq!(madcrypto_identity_free(bob as u64), MADCRYPTO_OK);
    }

    #[test]
    fn wire_limits_reject_without_advancing_and_accept_exact_boundaries() {
        let alice = madcrypto_identity_new() as u64;
        let bob = madcrypto_identity_new() as u64;
        assert_eq!(madcrypto_bundle_publish(bob), 0);
        let bundle = take(bob);
        let too_big = vec![0x61u8; 65_473];
        assert!(unsafe { madcrypto_session_initiate(alice, bundle.as_ptr(), bundle.len(), too_big.as_ptr(), too_big.len(), AD.as_ptr(), AD.len()) } < 0);
        let sa = unsafe { madcrypto_session_initiate(alice, bundle.as_ptr(), bundle.len(), too_big.as_ptr(), 65_472, AD.as_ptr(), AD.len()) };
        assert!(sa > 0);
        let first = take(sa as u64);
        let sb = unsafe { madcrypto_session_accept(bob, first.as_ptr(), first.len(), AD.as_ptr(), AD.len()) };
        assert!(sb > 0);
        assert_eq!(take(sb as u64).len(), 65_472);
        let big = vec![0x62u8; 65_521];
        assert!(unsafe { madcrypto_session_encrypt(sa as u64, AD.as_ptr(), AD.len(), big.as_ptr(), big.len()) } < 0);
        assert_eq!(unsafe { madcrypto_session_encrypt(sa as u64, AD.as_ptr(), AD.len(), big.as_ptr(), 65_520) }, 0);
        let packet = take(sa as u64);
        assert_eq!(unsafe { madcrypto_session_decrypt(sb as u64, AD.as_ptr(), AD.len(), packet.as_ptr(), packet.len()) }, 0);
        assert_eq!(take(sb as u64).len(), 65_520);
        madcrypto_session_free(sa as u64); madcrypto_session_free(sb as u64);
        madcrypto_identity_free(alice); madcrypto_identity_free(bob);
    }

    #[test]
    fn invalid_handles_error_cleanly() {
        assert!(unsafe { madcrypto_session_encrypt(999_999, AD.as_ptr(), AD.len(), b"x".as_ptr(), 1) } < 0);
        let mut buf = [0u8; 256];
        let n = unsafe { crate::madcrypto_last_error(buf.as_mut_ptr(), buf.len()) };
        assert!(n > 0, "错误消息必须可取回");
        assert!(unsafe { madcrypto_take_pending(999_999, std::ptr::null_mut(), 0) } < 0);
    }

    #[test]
    fn probe_does_not_consume_pending() {
        let id = madcrypto_identity_new();
        assert_eq!(madcrypto_bundle_publish(id as u64), MADCRYPTO_OK);
        // 连续探长：槽不清
        let n1 = unsafe { madcrypto_take_pending(id as u64, std::ptr::null_mut(), 0) };
        let n2 = unsafe { madcrypto_take_pending(id as u64, std::ptr::null_mut(), 0) };
        assert!(n1 > 0 && n1 == n2);
        // 真取后槽空
        let mut buf = vec![0u8; n1 as usize];
        assert_eq!(unsafe { madcrypto_take_pending(id as u64, buf.as_mut_ptr(), buf.len()) }, n1);
        assert!(unsafe { madcrypto_take_pending(id as u64, std::ptr::null_mut(), 0) } < 0);
        madcrypto_identity_free(id as u64);
    }
}


/// Bounded numeric observation: no callback executes on a protocol thread.
#[derive(Default)]
struct Observation { events: VecDeque<u32>, dropped: u64 }
impl Observation {
    fn record(&mut self, event: u32) {
        if self.events.len() == 32 { self.dropped = self.dropped.saturating_add(1); }
        else { self.events.push_back(event); }
    }
}
/// Opt in/out per session. Repeated enable preserves the queue; disable clears it.
#[no_mangle]
pub extern "C" fn madcrypto_observe(session: u64, enabled: u32) -> i32 {
    guard(|| {
        let mut reg = registry();
        if !reg.sessions.contains_key(&session) || enabled > 1 { return err("invalid session or flag"); }
        if enabled == 1 { reg.observers.entry(session).or_default(); }
        else { reg.observers.remove(&session); }
        Ok(MADCRYPTO_OK)
    })
}
/// Poll one event: 0=empty/disabled, 1=encrypt, 2=decrypt, negative=invalid handle.
#[no_mangle]
pub extern "C" fn madcrypto_poll_event(session: u64) -> i32 {
    guard(|| {
        let mut reg = registry();
        if !reg.sessions.contains_key(&session) { return err("invalid session"); }
        Ok(reg.observers.get_mut(&session).and_then(|o| o.events.pop_front()).unwrap_or(0) as i32)
    })
}
/// Returns the saturating queue-overflow count; -1 on invalid session.
#[no_mangle]
pub extern "C" fn madcrypto_observation_drops(session: u64) -> i64 {
    guard_i64(|| {
        let reg = registry();
        if !reg.sessions.contains_key(&session) { return err("invalid session"); }
        Ok(reg.observers.get(&session).map(|o| o.dropped.min(i64::MAX as u64)).unwrap_or(0) as i64)
    })
}
#[cfg(test)]
mod observation_tests {
    use super::*;
    #[test]
    fn bounded_observation_drops_instead_of_growing() {
        let mut obs = Observation::default();
        for _ in 0..100 { obs.record(1); }
        assert_eq!(obs.events.len(), 32);
        assert_eq!(obs.dropped, 68);
    }
}
