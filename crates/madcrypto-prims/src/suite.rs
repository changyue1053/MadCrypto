//! CipherSuite 抽象：协议层与原语层的唯一对话协议（架构 §3 绿条）。
//!
//! 六能力：DH / 签名 / AEAD / HKDF / hash / 随机数。协议状态机对套件无感——
//! 双棘轮、Sender Keys 的结构与具体算法无关，换套件是换一个 trait 实现（架构 §5）。

use rand_core::{CryptoRng, RngCore};

/// 套件标识：进握手关联数据（AD），中间人改套件声明即握手失败（防降级，架构 §5）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SuiteId {
    /// 国际套件：X25519 / Ed25519 / AES-256-GCM / HKDF-SHA-256。
    Intl = 1,
    /// 国密套件：SM2 / SM4-GCM / HKDF-SM3（双后端：libsm 纯 Rust / 铜锁认证模块）。
    Sm = 2,
}

impl SuiteId {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
    /// 线格式解码入口（非法值返回 None，由上层报「报文格式非法」）。
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(SuiteId::Intl),
            2 => Some(SuiteId::Sm),
            _ => None,
        }
    }
}

/// DH 密钥对。私钥为敏感字节，公钥可公开。core 层再包一层 newtype 纪律（§14）。
pub struct DhKeyPair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

/// 签名密钥对。
pub struct SignKeyPair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

/// 原语层错误。刻意粗粒度：不向调用方泄漏失败细节（防 oracle）。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PrimError {
    #[error("密钥编码非法")]
    BadKey,
    #[error("签名编码非法")]
    BadSignature,
    #[error("AEAD 认证失败")]
    AeadAuth,
    #[error("输出长度非法")]
    BadLength,
}

/// 一套密码学套件。所有方法无状态（纯函数），状态由协议层持有。
pub trait CipherSuite {
    fn id() -> SuiteId;

    // ---- DH（X25519 / SM2 密钥交换）----
    fn dh_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> DhKeyPair;
    /// 由私钥导出公钥（多设备扇出、测试构造用）。
    fn dh_public(private: &[u8]) -> Result<Vec<u8>, PrimError>;
    /// 统一输出 32 字节共享密钥（X25519 天然 32；SM2 交换后 KDF 收敛到 32）。
    fn dh(private: &[u8], public: &[u8]) -> Result<[u8; 32], PrimError>;

    // ---- 签名（Ed25519 / SM2 签名）----
    fn sign_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> SignKeyPair;
    fn sign(private: &[u8], msg: &[u8]) -> Result<Vec<u8>, PrimError>;
    fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool;

    // ---- AEAD（AES-256-GCM / SM4-GCM）----
    fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8>;
    fn aead_open(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PrimError>;

    // ---- KDF / hash（HKDF-SHA-256 / HKDF-SM3、SHA-256 / SM3）----
    fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]);
    fn hash(data: &[u8]) -> [u8; 32];
}

/// 字节切片转定长数组（协议层与原语层边界的统一校验入口）。
pub(crate) fn arr32(b: &[u8]) -> Result<[u8; 32], PrimError> {
    b.try_into().map_err(|_| PrimError::BadKey)
}

