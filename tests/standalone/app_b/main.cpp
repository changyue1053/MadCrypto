#include "madcrypto.h"
#include "madcrypto_store.h"
#include <cstdint>
#include <vector>
// Explicit return checks survive Release/NDEBUG builds.
int main() {
    if (madcrypto_abi_version() != 0x000100 || madcrypto_selftest() != 0) return 1;
    const auto identity = madcrypto_identity_new();
    if (identity <= 0) return 2;
    const auto handle = static_cast<std::uint64_t>(identity);
    if (madcrypto_bundle_publish(handle) != 0) return 3;
    const auto size = madcrypto_take_pending(handle, nullptr, 0);
    if (size <= 0) return 4;
    std::vector<std::uint8_t> bundle(static_cast<std::size_t>(size));
    if (madcrypto_take_pending(handle, bundle.data(), bundle.size()) != size) return 5;
    if (madcrypto_identity_free(handle) != 0) return 6;
    return 0;
}
