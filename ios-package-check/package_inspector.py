"""Static XCFramework inspection, not execution or cryptographic validation."""
from pathlib import Path
import plistlib
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'build/ios-package-check/MadCrypto.xcframework'

def verify_entries(entries):
    if not isinstance(entries, list) or len(entries) != 2:
        raise ValueError('requires two slices')
    seen = set()
    for entry in entries:
        variant = entry.get('SupportedPlatformVariant', '')
        if variant not in ('', 'simulator') or variant in seen:
            raise ValueError('invalid platform variants')
        seen.add(variant)
        if entry.get('SupportedPlatform') != 'ios' or entry.get('SupportedArchitectures') != ['arm64']:
            raise ValueError('requires iOS ARM64')
        if entry.get('LibraryPath') != 'libmadcrypto_ffi.a':
            raise ValueError('wrong archive')
        for key in ('LibraryIdentifier', 'HeadersPath'):
            value = entry.get(key)
            if not isinstance(value, str) or not value or Path(value).is_absolute() or '..' in Path(value).parts:
                raise ValueError('invalid package relative path')
    return entries

REASONS = frozenset(('metadata', 'header', 'module-map', 'architecture',
                     'required-symbols', 'test-symbols', 'license', 'third-party-notice',
                     'file-access', 'tool-command', 'unexpected-schema'))

class Rejected(Exception):
    pass

def require(condition, reason):
    if not condition:
        raise Rejected(reason)

def verify_symbols(symbols, header):
    required = set(re.findall(r'\b(madcrypto_\w+)\s*\(', header.decode()))
    require(bool(required) and all('_' + symbol in symbols.splitlines() for symbol in required), 'required-symbols')
    require(not any(s in symbols for s in ('madcrypto_debug_trigger_panic', 'madcrypto_c_smoke_main', 'madcrypto_store_fixture_')), 'test-symbols')

def main():
    try:
        entries = verify_entries(plistlib.loads((PACKAGE / 'Info.plist').read_bytes())['AvailableLibraries'])
    except (ValueError, KeyError, TypeError, AttributeError):
        raise Rejected('metadata') from None
    header = (ROOT / 'crates/madcrypto-ffi/include/madcrypto.h').read_bytes()
    for entry in entries:
        folder = PACKAGE / entry['LibraryIdentifier']
        archive = folder / entry['LibraryPath']
        headers = folder / entry['HeadersPath']
        require((headers / 'madcrypto.h').read_bytes() == header, 'header')
        require((headers / 'module.modulemap').read_text() == 'module MadCrypto { header "madcrypto.h" export * }\n', 'module-map')
        require(subprocess.check_output(['xcrun', 'lipo', '-archs', str(archive)], text=True, stderr=subprocess.DEVNULL).strip() == 'arm64', 'architecture')
        symbols = subprocess.check_output(['xcrun', 'nm', '-gjU', str(archive)], text=True, stderr=subprocess.DEVNULL)
        verify_symbols(symbols, header)
    require((PACKAGE / 'Notices/LICENSE').read_bytes() == (ROOT / 'LICENSE').read_bytes(), 'license')
    require((PACKAGE / 'Notices/THIRD_PARTY.md').read_bytes() == (ROOT / 'THIRD_PARTY.md').read_bytes(), 'third-party-notice')

def run():
    try:
        main()
    except Rejected as error:
        reason = str(error) if str(error) in REASONS else 'unexpected-schema'
    except subprocess.SubprocessError:
        reason = 'tool-command'
    except OSError:
        reason = 'file-access'
    except Exception:
        reason = 'unexpected-schema'
    else:
        print('PASS: package-inspector')
        return 0
    print('FAIL: package-inspector-' + reason, file=sys.stderr)
    return 1

if __name__ == '__main__': sys.exit(run())
