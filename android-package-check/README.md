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

## Hosted dependency-stage diagnosis follow-up

Run 44492293892 at public commit 3a67ebda7d7c48d92df78ebd06464b45fa308730 passed NDK preflight but failed at the combined dependency-scope label before an archive was attempted. That label alone does **not** prove a forbidden dependency or a Cargo argument/cache failure. No raw CI log or dependency tree is published by this change.

Generation now has a separate failure boundary. Cargo arguments preserve the exact selected package, Android target, no-default-features and normal/build edges, adding only color=never. Those options are documented cargo-tree semantics; local Rust 1.100.0 execution is unavailable, so no exact-version reproduction or root cause is claimed. Bounded local stderr is reduced to the fixed categories arguments/locked/cache/other. On generation failure, scope inspection never runs. On success, an empty, malformed, oversized or unexpected-root/incomplete tree is rejected. Valid matching trees report only the fixed forbidden family names; the original forbidden family scope is not relaxed. A real forbidden match remains a stop, not permission to bypass it.

Local tests cover generation classification including a mocked failing process with partial output, nonempty/valid tree checks, every forbidden family, file read errors and safe labels despite secret-shaped paths in inputs. No Android compilation or runtime success is claimed.


## Locked cache preparation correction

Run 44493019110 at exact public commit 457ea5121b15fe65a9054733e3221f164ecaad8f failed `android-dependency-generate-cache`, before scope inspection or archive generation. Synthetic forbidden-family failures from the test step are intentional, not actual build dependencies.

The narrow successor removes the Android-only filter from the preparation `cargo fetch --locked`. Cargo documents that an unfiltered fetch retrieves all locked target dependencies; this includes resolver data outside the final Android slice. Fetching is not building or permission to link those crates. Generation still uses locked, offline, normal/build edges for the exact Android FFI slice; every forbidden scope gate is unchanged, and archive compilation remains locked/offline. This addresses incomplete resolver cache as a plausible cause, not proof of the precise missing package. The original iOS preflight at 2739 also uses target-filtered fetch (two Apple targets), so it is not cited as evidence of a successful unfiltered command.

Official semantics: https://doc.rust-lang.org/cargo/commands/cargo-fetch.html . No lockfile, provider, core, fixture or build feature changes; no actual Android build pass is claimed before exact-SHA hosted execution.
