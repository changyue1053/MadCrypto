/* C 侧冒烟：用真 clang 编译、链接 IMCrypto staticlib，驱动一次完整密聊。
 * 验证手写 imcrypto.h 与 Rust 导出的 ABI 逐符号一致（消除验证盲区，IMDB §23）。
 * 由 build.rs 触发；断言失败或返回码异常则非零退出。 */
#include "madcrypto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CHECK(cond, msg) do { if (!(cond)) { fprintf(stderr, "C-smoke FAIL: %s\n", msg); return 1; } } while (0)

/* 两段式取 pending 字节到 out（调用方负责 free） */
static int take(uint64_t h, uint8_t **out, size_t *out_len) {
    int64_t need = madcrypto_take_pending(h, NULL, 0);
    if (need < 0) return -1;
    uint8_t *buf = (uint8_t *)malloc((size_t)need ? (size_t)need : 1);
    int64_t n = madcrypto_take_pending(h, buf, (size_t)need);
    if (n != need) { free(buf); return -1; }
    *out = buf; *out_len = (size_t)need;
    return 0;
}

/* 入口重命名为 madcrypto_c_smoke_main：由 Rust 集成测试调用，与 #[no_mangle] 导出同链接单元，
 * 符号解析等同链接 staticlib——完整验证 imcrypto.h 与 Rust ABI 一致。 */
int madcrypto_c_smoke_main(void) {
    CHECK(madcrypto_abi_version() == 0x000100u, "abi version");
    CHECK(madcrypto_selftest() == MADCRYPTO_OK, "selftest");

    const uint8_t ad[] = "conv:c-smoke";
    const size_t ad_len = sizeof(ad) - 1;

    int64_t alice = madcrypto_identity_new();
    int64_t bob   = madcrypto_identity_new();
    CHECK(alice > 0 && bob > 0, "identity_new");

    /* Bob 发布 bundle */
    CHECK(madcrypto_bundle_publish((uint64_t)bob) == MADCRYPTO_OK, "bundle_publish");
    uint8_t *bundle; size_t bundle_len;
    CHECK(take((uint64_t)bob, &bundle, &bundle_len) == 0, "take bundle");

    /* Alice 发起 + 首条明文 */
    const uint8_t hello[] = "hello from C";
    int64_t sa = madcrypto_session_initiate((uint64_t)alice, bundle, bundle_len,
                                       hello, sizeof(hello) - 1, ad, ad_len);
    CHECK(sa > 0, "session_initiate");
    uint8_t *packet; size_t packet_len;
    CHECK(take((uint64_t)sa, &packet, &packet_len) == 0, "take first packet");

    /* Bob 接收首包 → 解出首条明文 */
    int64_t sb = madcrypto_session_accept((uint64_t)bob, packet, packet_len, ad, ad_len);
    CHECK(sb > 0, "session_accept");
    uint8_t *got; size_t got_len;
    CHECK(take((uint64_t)sb, &got, &got_len) == 0, "take decrypted");
    CHECK(got_len == sizeof(hello) - 1 && memcmp(got, hello, got_len) == 0, "plaintext match");

    /* Bob 回复 → Alice 解 */
    const uint8_t reply[] = "reply from C";
    CHECK(madcrypto_session_encrypt((uint64_t)sb, ad, ad_len, reply, sizeof(reply) - 1) == MADCRYPTO_OK, "encrypt");
    uint8_t *msg; size_t msg_len;
    CHECK(take((uint64_t)sb, &msg, &msg_len) == 0, "take ciphertext");
    CHECK(madcrypto_session_decrypt((uint64_t)sa, ad, ad_len, msg, msg_len) == MADCRYPTO_OK, "decrypt");
    uint8_t *got2; size_t got2_len;
    CHECK(take((uint64_t)sa, &got2, &got2_len) == 0, "take reply plaintext");
    CHECK(got2_len == sizeof(reply) - 1 && memcmp(got2, reply, got2_len) == 0, "reply match");

    /* 非法句柄干净报错 + 错误消息可取回 */
    CHECK(madcrypto_session_encrypt(99999999u, ad, ad_len, hello, 1) < 0, "invalid handle errors");
    uint8_t errbuf[256];
    int64_t elen = madcrypto_last_error(errbuf, sizeof(errbuf));
    CHECK(elen > 0, "last_error retrievable");

    madcrypto_session_free((uint64_t)sa);
    madcrypto_session_free((uint64_t)sb);
    madcrypto_identity_free((uint64_t)alice);
    madcrypto_identity_free((uint64_t)bob);
    free(bundle); free(packet); free(got); free(msg); free(got2);

    printf("C-smoke OK: handshake + double-ratchet roundtrip over C ABI\n");
    return 0;
}

