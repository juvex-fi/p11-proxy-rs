use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed={}", p11_idl::API_IDL);
    println!("cargo:rerun-if-changed=build.rs");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out.join("backend.rs"), p11_idl::backend_trait_source()).unwrap();
    fs::write(out.join("dl.rs"), p11_idl::dl_source()).unwrap();
}
