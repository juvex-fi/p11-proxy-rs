use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed={}", p11_idl::API_IDL);
    println!("cargo:rerun-if-changed=build.rs");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("calls.rs");
    fs::write(&out, p11_idl::wire_source()).unwrap();
    fs::write(out.with_file_name("samples.rs"), p11_idl::samples_source()).unwrap();
    fs::write(out.with_file_name("table.md"), p11_idl::calls_markdown()).unwrap();
}
