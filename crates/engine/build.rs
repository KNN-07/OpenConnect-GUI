use std::{env, path::PathBuf};

fn main() {
    let native = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../../native");
    let header = native.join("bridge/ocgui.h");
    println!("cargo:rerun-if-changed={}", header.display());
    println!(
        "cargo:rerun-if-changed={}",
        native.join("include/openconnect.h").display()
    );
    println!(
        "cargo:rustc-env=OCVPN_ENGINE_TARGET={}",
        env::var("TARGET").unwrap()
    );
    bindgen::Builder::default()
        .header(header.to_string_lossy())
        .clang_arg(format!("-I{}", native.join("include").display()))
        .allowlist_function("openconnect_.*")
        .allowlist_function("ocgui_.*")
        .allowlist_type("oc_.*")
        .allowlist_type("ocgui_.*")
        .allowlist_type("openconnect_info")
        .opaque_type("openconnect_info")
        .allowlist_var("OPENCONNECT_API_VERSION_.*|OC_.*|RECONNECT_INTERVAL_.*")
        .dynamic_library_name("OpenConnect")
        .dynamic_link_require_all(true)
        .wrap_unsafe_ops(true)
        .derive_debug(false)
        .layout_tests(false)
        .generate_comments(false)
        .generate()
        .expect("Pinned OpenConnect bindings require clang/libclang and the target C headers")
        .write_to_file(PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("openconnect.rs"))
        .expect("write generated OpenConnect bindings");
}
