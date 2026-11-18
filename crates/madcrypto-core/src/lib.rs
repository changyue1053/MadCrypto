//! IMCrypto 协议层（纯 Rust，不依赖平台头）。
//!
//! 压舱石（架构 §1）：不发明密码学（原语在 `madcrypto-prims`）、服务器不可信化、
//! 解密即事务（`session` 输出 `StateDelta`，由调用方与消息落库同事务提交）。
#![forbid(unsafe_code)]

pub mod cloud;
pub mod error;
pub mod group;
pub mod kdf;
pub mod keys;
pub mod kt;
pub mod merkle;
pub mod pki;
pub mod policy;
pub mod ratchet;
pub mod router;
pub mod sesame;
pub mod session;
pub mod wire;
pub mod x3dh;

pub use error::{CryptoError, Result};


pub mod persistence;
