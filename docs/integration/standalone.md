# Standalone host integration (development only)

Each app may integrate MadCrypto without MadDB, MadLink, MadObs or IMSDK.
`python3 scripts/package_host.py /new/destination` builds a clean release-profile
Linux x86_64 **development** archive with default features disabled, then copies
its public headers and a relocatable CMake imported target. Requires Cargo/Rust,
C compiler/linker and GNU nm. Source checkout need not accompany the resulting
package. Existing output directories are never overwritten. Build output is
staged before exposing the destination with Linux `renameat2(RENAME_NOREPLACE)`.
Dangling output symlinks and targets created after the initial check are rejected.
There is no unsafe rename fallback when the OS/filesystem lacks support. The
parent directory is trusted and must not be concurrently redirected by another
actor; this is not a hostile-filesystem sandbox. Use `TMPDIR=/large/scratch` to
choose a filesystem with enough temporary build space. A fresh Cargo target directory prevents
an earlier all-features test build from contaminating the artifact.

The name `release` is a compiler profile, NOT a product release approval.
This tool does not upload artifacts. Complete third-party license texts/NOTICE,
security review and product release gates before redistributing binary packages.
Current Proprietary source terms remain unchanged.

```cmake
find_package(MadCrypto CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE MadCrypto::MadCrypto)
```

Pass `-DCMAKE_PREFIX_PATH=/new/destination` to CMake. The target supplies the
include path and host native link dependencies. The package can be moved after
building. Its SHA-256 manifest detects accidental content mismatch, not origin
or adversarial tampering: it is neither a signature nor reproducible-build proof.
The source commit, dirty flag, toolchain and target are recorded. Environment
and native compiler/libc details are not a fully hermetic build attestation.

`MADOBS_INCLUDE_DIR=/path/to/MadObs/include scripts/verify_package.sh` builds two
separate C/C++ consumer projects using **only** the relocated SDK, runs them as
independent processes, tests optional MadObs integration and rejects non-Linux
configuration. CMake, C++ and the normal native build tools are needed for this
verification. The two apps exercise their own memory-only identity lifecycles;
this does not prove tenant isolation inside a shared process or persistence.

MadObs remains opt-in: only include `madcrypto_obs.h` when independently adding
MadObs's `madobs/observer.h` to the consuming app's include path. No MadObs binary
is shipped or required for ordinary integration. `madcrypto_store.h` describes
storage callbacks only, not a callable durable C session lifecycle API.

## Actual platform boundaries

This package rejects non-Linux/non-x86_64 CMake targets. It is not an iOS
XCFramework, Android AAR/JNI or HarmonyOS HAR/N-API module. Header portability
and a Linux C++ compile do not establish Swift/Kotlin/ArkTS usability. Mobile
work needs actual SDK/NDK toolchains, minimum-version decisions and device
validation; Keychain/Keystore/HUKS adapters are still absent. Do not cross-compile
this host archive or relabel it for mobile distribution. Linux libc/runtime
compatibility outside the tested host is also unverified.

Across apps, use separate persistence scopes and key aliases per application,
account and session; never share a raw process handle, key material or store
namespace to simulate account switching. Host C handles are process-local and
not an access-control mechanism. Production apps must complete identity/OPK
persistence and replay/recovery lifecycle work before relying on this snapshot.
