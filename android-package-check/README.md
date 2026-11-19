# Android ARM64 packaging preview

Packaging-only addition on public MadCrypto commit `2739b6bd88f5e72495337ccde7ea143e4d1dc91a`. No core, algorithm, key, provider, C ABI or iOS packaging edits. Source remains Proprietary. This is local development verification, not redistribution or a license-compliance audit.

The exact preview branch is `checkpoint/madcrypto-android-package-check`; only its push event runs the isolated workflow. No workflow was triggered by preparing this candidate.

## Environment and refusal boundaries

Linux x86_64 runner, Rust 1.100.0, target aarch64-linux-android, NDK r28c/28.2.13676358, API23. Only an existing nonempty runner Android SDK license file permits an official sdkmanager attempt. Its stdin is closed; no `--licenses`, affirmative pipe, credential input or fallback acceptance. If the installed version cannot then be verified, the job fails. New terms are not accepted. r28c is a deliberately pinned older tool, not a claim of current supported NDK status.

Official Rust tooling/target and locked crates.io dependencies are prepared separately. The FFI production slice excludes c-test-fixtures and store; resolved normal/build dependencies must not include SQLCipher/OpenSSL/AWS-LC/ring/CMake. Production primitives remain the baseline RustCrypto/dalek provider choices. No target CMake or Perl step is needed for this slice. No NDK or compiler downloads were performed locally for this candidate.

## Checks

A fresh refused-if-existing output directory owns the isolated Cargo target. The actual ARM64 static archive and unchanged header are staged with original notices, then the stage is renamed. A separately copied C consumer links only the relocated SDK plus NDK system libraries, without project include directories. It references the existing ABI version and selftest exports; the resulting ELF must define both. The executable is **not run**, including its selftest. No fabricated runtime result is emitted.

NDK Clang explicitly requests 16KiB alignment. The final binary (not the `.a`) is parsed for ELF64 little-endian AArch64 PIE, Android linker64 interpreter, valid table/file bounds, and at least one PT_LOAD. Every load requires power-of-two alignment at least 16KiB, matching offset/virtual-address congruence and file size <= memory size. This is an ELF structural check, not APK zip alignment, Android runtime or real-device qualification.

Raw compiler/tool output stays in ignored local build logs. Public console output is fixed pass/fail labels; no archive or logs are uploaded. Hash manifest is local only. The package has no CMake/Gradle/AAR wrapper and is not an SDK binary release. Full transitive third-party notices need a separate distribution review if distribution is later authorized.

## Local results

`bash -n android-package-check/check.sh` passes. `python3 android-package-check/test_elf.py` passes two tests (valid synthetic ELF and ten rejection mutations). These do not establish an actual Android build or link pass; only the exact-SHA runner execution can do that.

## Follow-up fail-closed audit

Checkout explicitly uses github.sha and HEAD is compared to GITHUB_SHA before tests or tooling. The dependency gate accepts grep status 1 only; matching forbidden crates and inspection errors reject. Local regression covers seven forbidden crate names plus missing-file/directory errors. PT_INTERP was already required by the parser; added tests explicitly reject a wrong interpreter and missing interpreter segment. PIE structure means ELF type ET_DYN with the Android interpreter, not runtime execution.
