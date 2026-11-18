# Verification scope

| Target | Current status |
|---|---|
| Linux x86_64 Rust 1.100.0 | Host core/FFI tests and C consumers evaluated; see TASK_RESULT |
| Rust encrypted persistence ports | Host AES-GCM test provider + fault-injected memory store only; no OS provider/disk CAS |
| SQLCipher reference store | Host tests only, optional; not a product DB bridge |
| MadObs adapter | Header-contract recording sink tested; runtime/network export not tested |
| Relocatable C/C++ static SDK | Linux x86_64 host development package; no mobile/binary release claim |
| iOS/Swift/XCFramework | Not implemented/verified in this stage |
| Android/Kotlin/AAR | Not implemented/verified in this stage |
| OHOS/ArkTS/HAR | Not implemented/verified in this stage |
| Minimum supported Rust version | Original 1.85 metadata retained; NOT tested as MSRV |
| Production E2EE audit / device / power-loss | Not performed |
