//! IMCrypto 原语层。
//!
//! 纪律（架构 §1「不发明密码学」）：本 crate 只做被审计实现的接线与套件抽象，
//! 不包含任何自研密码学算法。国密位（`SuiteId::Sm`）预留双后端：
//! libsm（纯 Rust）/ 铜锁认证模块（密评租户，C FFI 限定在本 crate 内，架构 §5）。
#![forbid(unsafe_code)]

mod intl;
mod suite;

pub use intl::IntlSuite;
pub use suite::{CipherSuite, DhKeyPair, PrimError, SignKeyPair, SuiteId};

