#!/usr/bin/env python3
"""Build a clean, relocatable Linux host development SDK, never a release."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TARGET = "x86_64-unknown-linux-gnu"

def output_path(value):
    # Resolve the parent only: resolving the final component follows dangling
    # symlinks and can publish into an unintended destination.
    path = Path(value)
    if not path.name or path.name in (".", ".."):
        raise ValueError("output must name a new directory")
    result = path.parent.resolve() / path.name
    if os.path.lexists(result):
        raise FileExistsError("destination already exists; refusing overwrite")
    return result


def publish_no_replace(source, destination):
    """Linux atomic no-replace publication; never fall back to ordinary rename."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        raise RuntimeError("renameat2 unavailable; cannot safely publish")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    # AT_FDCWD=-100, RENAME_NOREPLACE=1. Existing directory/file/symlink must fail,
    # even if it appeared after output_path's advisory early check.
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destination))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new destination directory (must not exist)")
    args = parser.parse_args()
    try:
        output = output_path(args.output)
    except (ValueError, FileExistsError) as error:
        parser.error(str(error))
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("only native Linux x86_64 host development packages are supported")
    # Do not accidentally package a previous all-features test artifact.
    with tempfile.TemporaryDirectory(prefix="madcrypto-build-") as scratch:
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = scratch
        subprocess.run(["cargo", "build", "--locked", "--release", "--target", TARGET,
                        "-p", "madcrypto-ffi", "--no-default-features"],
                       cwd=ROOT, env=env, check=True)
        archive = Path(scratch) / TARGET / "release/libmadcrypto_ffi.a"
        symbols = subprocess.run(["nm", "--defined-only", str(archive)],
                                 check=True, capture_output=True, text=True).stdout
        if "madcrypto_store_fixture_" in symbols or "madcrypto_c_smoke_main" in symbols:
            raise RuntimeError("test fixture found in distributable archive")
        output.parent.mkdir(parents=True, exist_ok=True)
        # Stage completely before exposing the destination directory.
        with tempfile.TemporaryDirectory(prefix=".madcrypto-package-", dir=output.parent) as stage:
            package = Path(stage) / "sdk"
            def copy(src, dest):
                target = package / dest
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, target)
            copy(archive, "lib/libmadcrypto_ffi.a")
            for name in ("madcrypto.h", "madcrypto_store.h"):
                copy(ROOT / "crates/madcrypto-ffi/include" / name, "include/" + name)
            copy(ROOT / "adapters/obs/madcrypto_obs.h", "include/madcrypto_obs.h")
            copy(ROOT / "packaging/cmake/MadCryptoConfig.cmake", "lib/cmake/MadCrypto/MadCryptoConfig.cmake")
            for name in ("LICENSE", "THIRD_PARTY.md", "PUBLIC_API.md", "SUPPORT_MATRIX.md"):
                copy(ROOT / name, name)
            manifest = {
                "format": 1, "kind": "host-development-only", "target": TARGET,
                "abi": "0.1.0", "profile": "release", "features": [],
                "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
                "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
                "files": {str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in sorted(package.rglob("*")) if p.is_file()},
            }
            (package / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
            publish_no_replace(package, output)
    print(output)

if __name__ == "__main__":
    main()
