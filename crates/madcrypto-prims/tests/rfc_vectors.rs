//! L1 官方向量回放（实施 P0.4 / 架构 §17）。
//!
//! 密码学代码唯一可信的「对」的定义：与官方参考向量逐字节一致。本文件装载
//! IETF RFC 与 GCM 原始论文（McGrew–Viega）的公开已知答案，**红灯不可 override**。

use madcrypto_prims::{CipherSuite, IntlSuite};

type S = IntlSuite;

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex 长度必须为偶数");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("非法 hex"))
        .collect()
}

/// RFC 7748 §6.1：X25519 的 Alice/Bob Diffie-Hellman 官方向量。
#[test]
fn x25519_rfc7748_section_6_1() {
    let alice_priv = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_pub = unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_priv = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_pub = unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    // 公钥派生与 RFC 一致
    assert_eq!(S::dh_public(&alice_priv).unwrap(), alice_pub);
    assert_eq!(S::dh_public(&bob_priv).unwrap(), bob_pub);
    // 双向 DH 均得到 RFC 给定的共享密钥
    assert_eq!(S::dh(&alice_priv, &bob_pub).unwrap().to_vec(), shared);
    assert_eq!(S::dh(&bob_priv, &alice_pub).unwrap().to_vec(), shared);
}

/// RFC 8032 §7.1 TEST 1：Ed25519 确定性签名官方向量（空消息）。
#[test]
fn ed25519_rfc8032_test_1() {
    let secret = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let expected_sig = unhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    let sig = S::sign(&secret, b"").unwrap();
    assert_eq!(sig, expected_sig, "Ed25519 签名必须与 RFC 8032 逐字节一致（确定性签名）");
    assert!(S::verify(&public, b"", &sig));
}

/// RFC 5869 附录 A.1：HKDF-SHA-256 官方向量。
#[test]
fn hkdf_rfc5869_case_1() {
    let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = unhex("000102030405060708090a0b0c");
    let info = unhex("f0f1f2f3f4f5f6f7f8f9");
    let expected = unhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );

    let mut okm = vec![0u8; 42];
    S::hkdf(&salt, &ikm, &info, &mut okm);
    assert_eq!(okm, expected);
}

/// SHA-256 已知答案（FIPS 180 附录示例）。
#[test]
fn sha256_known_answers() {
    assert_eq!(
        S::hash(b"").to_vec(),
        unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(
        S::hash(b"abc").to_vec(),
        unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

/// AES-256-GCM：McGrew–Viega GCM 规范测试用例 13/14（零密钥/零 IV）。
/// 本库 seal 输出 = 密文 ‖ tag(16B)。
#[test]
fn aes256gcm_mcgrew_viega_tc13_tc14() {
    let key = [0u8; 32];
    let iv = [0u8; 12];

    // TC13：空明文 → 输出即 16 字节 tag
    let out = S::aead_seal(&key, &iv, b"", b"");
    assert_eq!(out, unhex("530f8afbc74536b9a963b4f1c4cb738b"));

    // TC14：16 字节零明文
    let out = S::aead_seal(&key, &iv, b"", &[0u8; 16]);
    assert_eq!(out[..16].to_vec(), unhex("cea7403d4d606b6e074ec5d3baf39d18"), "密文部分");
    assert_eq!(out[16..].to_vec(), unhex("d0d1c8a799996bf0265b98b5d48ab919"), "认证 tag");
}

