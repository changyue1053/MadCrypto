#define CHECK(x) do { if (!(x)) return __LINE__; } while (0)
#include <stdint.h>
#include "madcrypto.h"
int main(void) {
  CHECK(madcrypto_abi_version() == 0x000100);
  CHECK(madcrypto_selftest() == 0);
  int64_t id = madcrypto_identity_new();
  CHECK(id > 0);
  CHECK(madcrypto_bundle_publish((uint64_t)id) == 0);
  CHECK(madcrypto_bundle_publish((uint64_t)id) < 0);
  CHECK(madcrypto_take_pending((uint64_t)id, 0, 0) > 0);
  CHECK(madcrypto_identity_free((uint64_t)id) == 0);
  CHECK(madcrypto_take_pending((uint64_t)id, 0, 0) < 0);
  return 0;
}
