use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed={}", p11_idl::API_IDL);
    println!("cargo:rerun-if-changed=build.rs");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out.join("xlate.rs"), p11_idl::xlate_source()).unwrap();
}
