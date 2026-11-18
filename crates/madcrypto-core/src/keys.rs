//! 密钥 newtype 体系（架构 §14「类型系统白拿的东西」的工程落地）。
//!
//! 纪律，全部由类型强制、非靠自觉：
//! - 私钥/对称秘密 **不实现 `Clone`**（复制路径在类型层不存在）；
//! - 全部 `ZeroizeOnDrop`（离开作用域即擦除内存）；
//! - `Debug` 手动打码（日志泄露面封死）；
//! - 秘密相等性只暴露 **常时比较**（`ct_eq`），不实现 `==`（时序侧信道在 API 层灭掉）；
//! - 跨类型混用（拿 RootKey 当 ChainKey）编译不过。

use core::fmt;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 生成一个 32 字节定长对称秘密 newtype：无 Clone、Zeroize、Debug 打码、常时比较。
macro_rules! secret32 {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
            /// 仅 crate 内部读取原始字节（喂给原语层），不对外导出。
            pub(crate) fn expose(&self) -> &[u8; 32] {
                &self.0
            }
            /// 受控复制：仅用于棘轮"试算副本、验签成功才提交"的事务性解密（§7）。
            /// 对外不实现 `Clone`——复制路径不进业务代码。并非所有密钥类型都触发（如 ConvKey）。
            #[allow(dead_code)]
            pub(crate) fn clone_secret(&self) -> Self {
                Self(self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(****)"))
            }
        }

        impl ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.0[..].ct_eq(&other.0[..])
            }
        }
    };
}

secret32!(RootKey, "棘轮根密钥：每次 DH 棘轮更新（架构 §7）。");
secret32!(ChainKey, "链密钥：对称棘轮单向前进，前向保密的来源（架构 §7）。");
secret32!(ConvKey, "普通轨会话密钥 CK：信封加密的每消息 DEK 派生源，带版本轮换（架构 §4）。");

/// 消息密钥：AEAD 密钥 + IV，每条消息一把，用后即毁（架构 §7）。
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MessageKey {
    key: [u8; 32],
    iv: [u8; 12],
}

impl MessageKey {
    pub fn new(key: [u8; 32], iv: [u8; 12]) -> Self {
        Self { key, iv }
    }
    pub(crate) fn key(&self) -> &[u8; 32] {
        &self.key
    }
    pub(crate) fn iv(&self) -> &[u8; 12] {
        &self.iv
    }
    pub(crate) fn clone_secret(&self) -> Self {
        Self {
            key: self.key,
            iv: self.iv,
        }
    }
}

impl fmt::Debug for MessageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MessageKey(****)")
    }
}

/// 生成一个变长私钥 newtype（适配套件：X25519 32B / SM2 不同长）：无 Clone、Zeroize、打码。
macro_rules! secret_vec {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name(Vec<u8>);

        impl $name {
            pub fn new(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
            pub(crate) fn expose(&self) -> &[u8] {
                &self.0
            }
            // 供事务性快照/会话持久化使用；并非所有私钥类型都会触发（如 SignPrivate）。
            #[allow(dead_code)]
            pub(crate) fn clone_secret(&self) -> Self {
                Self(self.0.clone())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(****)"))
            }
        }
    };
}

secret_vec!(DhPrivate, "DH 私钥（棘轮/临时/预共享私钥）。");
secret_vec!(SignPrivate, "签名私钥（身份签名、Sender Key 签名）。");

/// 生成一个变长公钥 newtype：可 Clone、可比较、可序列化传输（公开值无秘密纪律）。
macro_rules! public_vec {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub struct $name(Vec<u8>);

        impl $name {
            pub fn new(bytes: Vec<u8>) -> Self {
                Self(bytes)
            }
            pub fn as_slice(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                // 公钥可打印（非秘密），但截断避免日志噪声
                write!(f, "{}({}B)", stringify!($name), self.0.len())
            }
        }
    };
}

public_vec!(DhPublic, "DH 公钥。");
public_vec!(SignPublic, "签名公钥（= 身份公钥的签名部分，KT 与证书绑定锚点）。");

/// 身份密钥对：DH 部分（X3DH 用）+ 签名部分（SPK 签名、证书绑定）。私钥不可复制。
pub struct IdentityKeyPair {
    pub dh_private: DhPrivate,
    pub dh_public: DhPublic,
    pub sign_private: SignPrivate,
    pub sign_public: SignPublic,
}

impl IdentityKeyPair {
    /// 对外身份公钥（DH + 签名两截），用于分发进 bundle 与 KT 登记。
    pub fn public(&self) -> IdentityPublic {
        IdentityPublic {
            dh: self.dh_public.clone(),
            sign: self.sign_public.clone(),
        }
    }
}

/// 对端身份公钥（可分发、可比对指纹）。
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IdentityPublic {
    pub dh: DhPublic,
    pub sign: SignPublic,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let rk = RootKey::new([1u8; 32]);
        let mk = MessageKey::new([2u8; 32], [3u8; 12]);
        let dp = DhPrivate::new(vec![4u8; 32]);
        // 日志泄露面：Debug 输出不得包含任何密钥字节
        assert_eq!(format!("{rk:?}"), "RootKey(****)");
        assert_eq!(format!("{mk:?}"), "MessageKey(****)");
        assert_eq!(format!("{dp:?}"), "DhPrivate(****)");
    }

    #[test]
    fn secret_constant_time_eq() {
        let a = ChainKey::new([9u8; 32]);
        let b = ChainKey::new([9u8; 32]);
        let c = ChainKey::new([8u8; 32]);
        assert!(bool::from(a.ct_eq(&b)));
        assert!(!bool::from(a.ct_eq(&c)));
    }

    #[test]
    fn public_key_is_clonable_and_comparable() {
        let p = DhPublic::new(vec![1, 2, 3]);
        assert_eq!(p.clone(), p);
    }
}

