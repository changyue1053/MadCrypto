//! 错误分类（架构 §14 / 实施 P1.5）。刻意五类，粒度对应不同的<b>恢复动作</b>：
//! 可重试解密 → 等补发；失步 → 触发重握手（§20-Q6）；状态损坏 → 走存储修复；
//! 套件不符 / 策略拒绝 → 防降级命中，安全事件上报。

use madcrypto_prims::PrimError;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    /// 握手失败（bundle 校验不过、签名非法、并发发起冲突未收敛）。
    #[error("握手失败: {0}")]
    Handshake(&'static str),

    /// 解密失败但<b>可重试</b>：消息乱序尚未越过 skipped 上限，等待补发即可。
    #[error("解密可重试（乱序/暂缺）")]
    DecryptRetryable,

    /// 解密失败且<b>已失步</b>：状态无法继续，触发自动重握手（不弹窗）。
    #[error("会话失步，需重握手")]
    DecryptDesync,

    /// 会话状态损坏（版本回滚、反序列化失败）——走存储修复路径。
    #[error("会话状态损坏")]
    StateCorrupt,

    /// 套件声明与会话锁定不符——降级攻击命中（架构 §5）。
    #[error("密码套件不匹配")]
    SuiteMismatch,

    /// 租户策略拒绝（轨道错配、密聊转普通、TTL 篡改，架构 §13）。
    #[error("策略拒绝")]
    PolicyRejected,

    /// 线格式非法（截断/长度字段越界/未知版本或套件）——解码入口的统一出口，绝不 panic。
    #[error("报文格式非法")]
    Malformed,

    /// 原语层错误透传。
    #[error("原语错误: {0}")]
    Prim(#[from] PrimError),
}

pub type Result<T> = core::result::Result<T, CryptoError>;

