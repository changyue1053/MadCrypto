"""Strict test-only preparation. No downloads or builds."""
import hashlib
from pathlib import Path
import sys
FIXTURE_SHA256 = '4e355fb95a055883596ddc36d43ea58dd5d261a8e540bf20275d72db07fe7c88'
def transform(data):
    if hashlib.sha256(data).hexdigest() != FIXTURE_SHA256:
        raise ValueError('fixture-checkpoint')
    source = data.decode('ascii')
    anchor = '  received++;'
    if source.count(anchor) != 1 or source.count('int main(void) {') != 1:
        raise ValueError('fixture-shape')
    prefix = '''#ifdef NDEBUG
#error "Qualification requires assertions"
#endif
#include "Bridge.h"
'''
    return prefix + source.replace('int main(void) {', 'int madcrypto_fixture_main(void) {', 1).replace(anchor, '  assert(madcrypto_test_forward(event) == 1);\n' + anchor, 1)
if __name__ == '__main__':
    try:
        result = transform(Path(sys.argv[1]).read_bytes())
        with Path(sys.argv[2]).open('x') as out:
            out.write(result)
    except Exception:
        print('FAIL: fixture-preparation')
        sys.exit(1)
