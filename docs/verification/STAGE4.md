# Stage four: independent host SDK consumers

## Scope

New host-development packaging, relocatable CMake target, independent C/C++
consumers, and filesystem publication safety tests. No protocol/ABI changes.
Only Linux x86_64 host was exercised; this is not mobile support or production
release approval. No compiled binaries are committed or uploaded.

## Verification

- `scripts/verify_package.sh`: PASS with MadObs header integration enabled.
- Python publication suite: 4 passed, including late directory/file/symlink
  collision subcases and dangling output symlink rejection.
- C and C++ isolated CMake projects: 1 CTest each passed in Release mode.
  Consumer checks are not disabled by NDEBUG.
- Moved package path includes spaces; neither app receives source-tree include
  or archive paths. Separate processes also run concurrently.
- Same-package re-import accepted, conflicting imported target rejected.
- Wrong-platform configuration and pre-existing output rejected.
- Optional MadObs consumer compiles/runs against packaged headers and archive.
- Manifest covers every packaged file other than itself; SHA-256 verified.
- Full workspace: 117 passed, 0 failed, 2 inherited ignored tests. Full Clippy,
  native C consumer, optional Obs consumer and source hygiene scan passed.
  Results recorded in stage4-host.log; 112 dependency license metadata entries.

Initial `/tmp` build and CMake tool installation failed with insufficient space.
Both were retried using an owned isolated directory on `/workspace/shared`.
No unrelated files were removed. CMake 3.31.10 was installed from PyPI.
The successful package test log is stage4-package.log.

## Independent review corrections

Reviewer reproduced dangling-symlink redirection and an empty-target TOCTOU
replacement in the original draft. Fixed by resolving only the output parent,
checking lexists and atomically publishing with Linux renameat2 NOREPLACE.
Unsupported syscall/filesystem errors fail closed with no ordinary rename
fallback. Regression tests deliberately create a collision after preflight.
Parent directories remain trusted; this is not a hostile-filesystem sandbox.

The manifest is not signed and cannot authenticate origin. Linux libc/other
host compatibility, mobile toolchains/device testing, actual platform keystore,
durable C sessions, full third-party binary redistribution notices and external
security audit remain release gates. Release compiler profile is not a formal
SDK release. Existing source license remains Proprietary.
