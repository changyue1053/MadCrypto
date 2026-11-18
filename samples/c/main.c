#include <assert.h>
#include <stdint.h>
#include "madcrypto.h"
int main(void) {
  assert(madcrypto_abi_version() == 0x000100);
  assert(madcrypto_selftest() == 0);
  int64_t id = madcrypto_identity_new();
  assert(id > 0);
  assert(madcrypto_bundle_publish((uint64_t)id) == 0);
  assert(madcrypto_bundle_publish((uint64_t)id) < 0);
  assert(madcrypto_take_pending((uint64_t)id, 0, 0) > 0);
  assert(madcrypto_identity_free((uint64_t)id) == 0);
  assert(madcrypto_take_pending((uint64_t)id, 0, 0) < 0);
  return 0;
}
