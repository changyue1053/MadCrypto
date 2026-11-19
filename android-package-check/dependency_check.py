"""Local-only Cargo output; console diagnostics are fixed allowlisted labels."""
import re
import subprocess
import sys
from pathlib import Path

FAMILIES = ('openssl', 'aws-lc', 'ring', 'cmake', 'libsqlite3', 'rusqlite', 'madcrypto-store')
ARGS = ['cargo', 'tree', '--locked', '--offline', '-p', 'madcrypto-ffi', '--target',
        'aarch64-linux-android', '--no-default-features', '-e', 'normal,build', '--prefix', 'none', '--color', 'never']


def generation_class(text):
    if re.search(r'unexpected argument|unrecognized option|invalid value .*--', text):
        return 'arguments'
    if re.search(r'lock file .*needs to be updated|cannot update the lock file|lock file .*does not exist', text):
        return 'locked'
    if re.search(r'offline was specified|offline mode|no matching package named|failed to download', text):
        return 'cache'
    return 'other'


def inspect(text):
    lines = text.splitlines()
    if not lines or len(text) > 4 * 1024 * 1024:
        raise ValueError('invalid-tree')
    names = []
    for line in lines:
        if line in ('[build-dependencies]', '[dev-dependencies]'):
            if line == '[dev-dependencies]': raise ValueError('invalid-tree')
            continue
        match = re.fullmatch(r'([A-Za-z0-9_-]+) v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?(?: \([^\r\n]*\))*(?: \(\*\))?', line)
        if not match: raise ValueError('invalid-tree')
        names.append(match[1])
    if not names or names[0] != 'madcrypto-ffi' or not {'madcrypto-core', 'madcrypto-prims'} <= set(names):
        raise ValueError('invalid-tree')
    return [family for family in FAMILIES if any(name == family if family == 'ring' else name.startswith(family) for name in names)]


def scope(path):
    try:
        with path.open('r', encoding='utf-8') as f: text = f.read(4 * 1024 * 1024 + 1)
        families = inspect(text)
    except (OSError, UnicodeError, ValueError):
        print('FAIL: android-dependency-tree-invalid')
        return 1
    for family in families:
        print('FAIL: android-dependency-forbidden-' + family)
    return 1 if families else 0


def generate(path):
    # Error diagnostics and package paths never escape the local log directory.
    try:
        with path.open('wb') as out, path.with_suffix('.stderr').open('wb+') as err:
            result = subprocess.run(ARGS, stdout=out, stderr=err, timeout=180)
            if result.returncode:
                err.seek(0, 2); err.seek(max(0, err.tell() - 131072))
                label = generation_class(err.read(131072).decode('utf-8', errors='replace'))
                print('FAIL: android-dependency-generate-' + label)
                return 1
    except (OSError, subprocess.SubprocessError):
        print('FAIL: android-dependency-generate-other')
        return 1
    print('PASS: android-dependency-generate')
    return 0


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ('generate', 'scope'):
        print('FAIL: android-dependency-check-arguments'); sys.exit(1)
    sys.exit((generate if sys.argv[1] == 'generate' else scope)(Path(sys.argv[2])))
