//! `p11-scenario MODULE`: run the scripted scenario against a PKCS#11 module
//! and print the transcript. Configure a proxy through its usual environment.
//! `P11_SCENARIO_SLOT=N` uses the Nth slot of the list instead of the first.

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: p11-scenario MODULE");
        std::process::exit(2);
    });
    match p11_conformance::Module::load(std::path::Path::new(&path)) {
        Ok(m) => print!("{}", p11_conformance::scenario::run(&m).render()),
        Err(e) => {
            eprintln!("p11-scenario: {e}");
            std::process::exit(1);
        }
    }
}
