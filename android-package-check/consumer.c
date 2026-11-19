/* Link-only consumer. Never executed in this Android packaging check. */
#include <madcrypto.h>
int main(void) {
    if (madcrypto_abi_version() == 0) return 2;
    return madcrypto_selftest() == MADCRYPTO_OK ? 0 : 1;
}
