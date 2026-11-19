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
                     'file-access', 'tool-command', 'unexpected-schema', 'rust-llvm-inventory', 'rust-llvm-version'))

TOOLS = {'lipo': ('lipo', '-archs'), 'nm': ('llvm-nm', '--extern-only', '--defined-only', '--format=just-symbols')}
KINDS = ('command', 'unavailable', 'timeout', 'bitcode-format', 'option', 'object-format')
REASONS |= frozenset(tool + '-' + variant + '-' + kind
                     for tool in TOOLS for variant in ('device', 'simulator') for kind in KINDS)

def command_failure_kind(stderr):
    # Only categories leave this function. Tool text and paths are never returned.
    text = stderr.lower()
    if any(marker in text for marker in ('opaque pointers', 'unknown attribute kind',
                                         'invalid bitcode', 'invalid bitcode signature',
                                         'bitcode version', 'producer: \'llvm')):
        return 'bitcode-format'
    if any(marker in text for marker in ('unknown argument', 'unknown option', 'unrecognized option')):
        return 'option'
    if any(marker in text for marker in ('file format not recognized', 'not an object file', 'malformed archive')):
        return 'object-format'
    return 'command'

def verified_rust_nm():
    # Resolve only inside the exact official Rust toolchain, never PATH or Homebrew.
    def output(args):
        try:
            return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL, timeout=30)
        except (OSError, subprocess.SubprocessError):
            raise Rejected('rust-llvm-inventory') from None
    version = output(['rustup', 'run', '1.100.0', 'rustc', '-vV'])
    fields = dict(line.split(': ', 1) for line in version.splitlines() if ': ' in line)
    require(fields.get('release') == '1.100.0' and fields.get('host') == 'aarch64-apple-darwin', 'rust-llvm-version')
    sysroot = Path(output(['rustup', 'run', '1.100.0', 'rustc', '--print', 'sysroot']).strip())
    require(sysroot.is_absolute(), 'rust-llvm-inventory')
    nm = sysroot / 'lib/rustlib/aarch64-apple-darwin/bin/llvm-nm'
    require(nm.is_file(), 'rust-llvm-inventory')
    reader = output([str(nm), '--version'])
    match = re.search(r'LLVM version (\d+\.\d+\.\d+)', reader)
    require(match is not None and match.group(1) == fields.get('LLVM version'), 'rust-llvm-version')
    return nm

def query_tool(tool, variant, archive):
    # Exact source-controlled command/label allowlists; never accept caller commands.
    if tool not in TOOLS or variant not in ('device', 'simulator'):
        raise Rejected('unexpected-schema')
    prefix = tool + '-' + variant + '-'
    try:
        command = (['xcrun', *TOOLS[tool]] if tool == 'lipo' else
                   [str(verified_rust_nm()), *TOOLS[tool][1:]])
        result = subprocess.run([*command, str(archive)],
                                capture_output=True, text=True, timeout=90, check=False)
    except subprocess.TimeoutExpired:
        raise Rejected(prefix + 'timeout') from None
    except OSError:
        raise Rejected(prefix + 'unavailable') from None
    if result.returncode != 0:
        # Never accept partial symbol output after an archive/member error.
        raise Rejected(prefix + command_failure_kind(result.stderr))
    print('PASS: package-inspector-' + tool + '-' + variant)
    return result.stdout

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
        variant = 'simulator' if entry.get('SupportedPlatformVariant') == 'simulator' else 'device'
        require(query_tool('lipo', variant, archive).strip() == 'arm64', 'architecture')
        symbols = query_tool('nm', variant, archive)
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

if __name__ == '__main__':
    if sys.argv[1:] == ['--check-llvm-tools']:
        try:
            verified_rust_nm()
        except Exception:
            print('FAIL: rust-llvm-reader-preflight', file=sys.stderr)
            sys.exit(1)
        print('PASS: rust-llvm-reader-preflight')
    else:
        sys.exit(run())
