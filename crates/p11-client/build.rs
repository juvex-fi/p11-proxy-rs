use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed={}", p11_idl::API_IDL);
    println!("cargo:rerun-if-changed=build.rs");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out.join("stubs.rs"), p11_idl::client_source()).unwrap();
    fs::write(out.join("tables.rs"), p11_idl::client_tables_source()).unwrap();
}
