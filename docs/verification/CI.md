# Continuous host verification

`.github/workflows/host.yml` runs on push, pull requests and manual dispatch.
It uses Ubuntu 24.04 x86_64 and Rust 1.100.0, with read-only contents permission,
no persisted checkout credentials and no deployment or artifact publication.
Checkout and the optional MadObs source revision are immutable SHA pins.
No secrets, signing material or platform account credentials are requested.

Three required-by-workflow jobs fail normally (no continue-on-error):

1. **Host Rust and standalone C** runs workspace tests (including the optional
   SQLCipher reference), Clippy, default static-artifact fixture exclusion,
   native C consumers, hygiene inventory and publication filesystem regressions.
   It intentionally does not check out MadObs, proving no mandatory SDK link.
2. **Host package (standalone)** builds a clean isolated release-profile archive
   and tests relocated C/C++ apps and publication/platform/import negative cases.
3. **Host package (madobs)** repeats packaging with separately pinned MadObs
   headers and exercises the optional adapter consumer. No MadObs runtime is
   built, and no network exporter is tested.

“Required-by-workflow” means a failing step fails that job, not branch-protection
configuration. No branch protection or merge settings are changed here. The two
inherited ignored SM2 stress tests remain ignored, visible in Cargo output.
Rust 1.85 MSRV is not established. Neither these jobs nor a green result prove
mobile platform support, real OS secure storage, durable C sessions, physical
power-loss behavior, independent cryptographic audit or production readiness.

Native build prerequisites come from the hosted Ubuntu image. Their versions
are logged, not pinned as a hermetic build environment. Jobs have bounded
execution time and concurrent superseded runs are canceled. Generated package
binaries are temporary and are not uploaded as releases/artifacts; proprietary
license and incomplete binary-redistribution notice gates remain unchanged.

To reproduce locally use `scripts/verify.sh` and `scripts/verify_package.sh`,
optionally setting MADOBS_INCLUDE_DIR. Set TMPDIR to an owned filesystem with
adequate space if the system temporary directory is small. The remote CI result
must be read for the exact pushed commit; local checks alone are not remote CI.
