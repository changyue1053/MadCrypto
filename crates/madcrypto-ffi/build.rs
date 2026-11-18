//! 用真 C 编译器（clang/cc）编译 C 冒烟，链接进 crate——验证手写头与 Rust ABI 一致。

fn main() {
    println!("cargo:rerun-if-changed=tests/c_smoke.c");
    println!("cargo:rerun-if-changed=include/madcrypto.h");
    cc::Build::new()
        .file("tests/c_smoke.c")
        .include("include")
        .warnings(true)
        .compile("madcrypto_c_smoke");
}

