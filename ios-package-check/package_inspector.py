"""Static XCFramework inspection, not execution or cryptographic validation."""
from pathlib import Path
import plistlib
import re
import subprocess

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

def main():
    entries = verify_entries(plistlib.loads((PACKAGE / 'Info.plist').read_bytes())['AvailableLibraries'])
    header = (ROOT / 'crates/madcrypto-ffi/include/madcrypto.h').read_bytes()
    for entry in entries:
        folder = PACKAGE / entry['LibraryIdentifier']
        archive = folder / entry['LibraryPath']
        headers = folder / entry['HeadersPath']
        assert (headers / 'madcrypto.h').read_bytes() == header
        assert (headers / 'module.modulemap').read_text() == 'module MadCrypto { header "madcrypto.h" export * }\n'
        assert subprocess.check_output(['xcrun', 'lipo', '-archs', str(archive)], text=True).strip() == 'arm64'
        symbols = subprocess.check_output(['xcrun', 'nm', '-gjU', str(archive)], text=True)
        required = set(re.findall(r'\b(madcrypto_\w+)\s*\(', header.decode()))
        assert all('_' + symbol in symbols.splitlines() for symbol in required)
        assert not any(s in symbols for s in ('madcrypto_debug_trigger_panic', 'madcrypto_c_smoke_main', 'madcrypto_store_fixture_'))
    assert (PACKAGE / 'Notices/LICENSE').read_bytes() == (ROOT / 'LICENSE').read_bytes()
    assert (PACKAGE / 'Notices/THIRD_PARTY.md').read_bytes() == (ROOT / 'THIRD_PARTY.md').read_bytes()

if __name__ == '__main__': main()
