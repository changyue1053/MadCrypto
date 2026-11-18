/*
 * IMCrypto C ABI（实施 P8）。
 *
 * ★ 本文件由 cbindgen 从 crates/madcrypto-ffi/src 生成，禁止手改（FAM-5）。
 *   再生成：IMSDK/scripts/gen_headers.sh；文档注释请改 Rust 源的 /// doc。
 *
 * 约定（架构 §14 FFI 铁律）：
 *  - 字符串/字节一律 UTF-8 + 显式长度，不依赖 NUL 结尾；
 *  - 产字节的操作把结果暂存 pending 槽，用 madcrypto_take_pending 两段式取回；
 *  - 返回 i32：0 = 成功；负 = 错误（详情 madcrypto_last_error）。返回 i64：正 = 句柄；负 = 错误码。
 *  - 密钥永不过界：导出面只有句柄、公钥 bundle、密文、明文。
 */

#ifndef MADCRYPTO_H
#define MADCRYPTO_H
/* Mad C facade requires OPK for initiate/accept. Authentic no-OPK packets are
 * rejected (behavior tightening; wire format unchanged). No persistent replay
 * store is provided. First plaintext <=65472, later plaintext <=65520 bytes. */

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/*
 成功。
 */
#define MADCRYPTO_OK 0

/*
 业务错误（详情经 `madcrypto_last_error` 取回）。
 */
#define MADCRYPTO_ERR -1

/*
 内部 panic 被防火墙捕获（未跨越 FFI 边界）。
 */
#define MADCRYPTO_ERR_PANIC -2

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/*
 ABI 版本（语义化：major<<16 | minor<<8 | patch）。C 侧启动时校验。
 */
uint32_t madcrypto_abi_version(void);

/*
 取回线程局部错误消息（UTF-8，不含 NUL 约定——长度显式返回，架构 §14 FFI 铁律）。
 返回完整消息长度；最多向 `buf` 写入 `cap` 字节。`buf` 可为 NULL（只探长度）。

 # Safety
 调用方必须保证：`buf` 为 NULL，或指向至少 `cap` 字节的可写内存。
 本函数绝不写超 `cap` 字节（内部 `n = len.min(cap)` 约束）。
 */
int32_t madcrypto_last_error(uint8_t *buf,
                        size_t cap);

/*
 内核自检：在进程内完整跑一遍握手 → 双棘轮往返 → 防降级 → 群密聊 → 信封。
 端侧集成后的第一件事就是调它——链接、原语、协议三层一次验明。
 */
int32_t madcrypto_selftest(void);

/*
 仅供集成方验证防火墙的调试导出：内部故意 panic，必须返回 `MADCRYPTO_ERR_PANIC` 而非崩溃。
 */
/* Test-only panic trigger is not exported in distributable builds. */

/*
 生成身份密钥对，返回句柄（>0）；失败返回负错误码。
 */
int64_t madcrypto_identity_new(void);

int32_t madcrypto_identity_free(uint64_t handle);

/*
 发布 prekey bundle：生成 SPK(+签名) + OPK，私钥留槽等待 accept；
 公钥 bundle 线格式进 pending[身份句柄]，经 `madcrypto_take_pending` 取走交给目录。
 */
int32_t madcrypto_bundle_publish(uint64_t identity_handle);

/*
 发起方：目录来的 bundle 字节 + 首条明文 + AD → 会话句柄（>0）；
 首包（PreKeyMessage 线格式）进 pending[会话句柄]。

 # Safety
 指针参数遵循 `in_slice` 契约（NULL 或至少 len 字节可读）。
 */
int64_t madcrypto_session_initiate(uint64_t identity_handle,
                              const uint8_t *bundle_ptr,
                              size_t bundle_len,
                              const uint8_t *plaintext_ptr,
                              size_t plaintext_len,
                              const uint8_t *ad_ptr,
                              size_t ad_len);

/*
 接收方：吃首包（PreKeyMessage）→ 会话句柄（>0）；首条明文进 pending[会话句柄]。
 OPK 用后即删：同一首包重放会因 OPK 已消费而被拒（重放防御的组成部分）。

 # Safety
 指针参数遵循 `in_slice` 契约。
 */
int64_t madcrypto_session_accept(uint64_t identity_handle,
                            const uint8_t *message_ptr,
                            size_t message_len,
                            const uint8_t *ad_ptr,
                            size_t ad_len);

/*
 加密一条消息：线格式密文进 pending[会话句柄]。

 # Safety
 指针参数遵循 `in_slice` 契约。
 */
int32_t madcrypto_session_encrypt(uint64_t session_handle,
                             const uint8_t *ad_ptr,
                             size_t ad_len,
                             const uint8_t *plaintext_ptr,
                             size_t plaintext_len);

/*
 解密一条线格式消息：明文进 pending[会话句柄]。

 # Safety
 指针参数遵循 `in_slice` 契约。
 */
int32_t madcrypto_session_decrypt(uint64_t session_handle,
                             const uint8_t *ad_ptr,
                             size_t ad_len,
                             const uint8_t *message_ptr,
                             size_t message_len);

int32_t madcrypto_session_free(uint64_t handle);

/*
 两段式取待取字节：返回总长度；cap ≥ 总长时写入并清槽，否则只报长、不清槽（重试安全）。
 `buf` 可为 NULL 仅探长。

 # Safety
 `buf` 为 NULL 或指向至少 `cap` 字节可写内存；本函数绝不写超 `cap` 字节。
 */
int64_t madcrypto_take_pending(uint64_t handle,
                          uint8_t *buf,
                          size_t cap);

/* Optional observation is disabled by default. No callbacks or MadObs dependency.
 * Host polls bounded numeric events outside SDK locks, optionally forwards to MadObs.
 * 1=encrypt completed, 2=decrypt completed; no payload, identity or key attributes. */
int32_t madcrypto_observe(uint64_t session, uint32_t enabled);
int32_t madcrypto_poll_event(uint64_t session);
int64_t madcrypto_observation_drops(uint64_t session);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  /* MADCRYPTO_H */

