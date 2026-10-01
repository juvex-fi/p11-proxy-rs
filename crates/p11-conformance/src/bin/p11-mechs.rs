//! `p11-mechs MODULE [SLOT_INDEX] [--strict]`: the mechanisms a module offers, sorted into what the
//! proxy carries, refuses on purpose, cannot know (vendor-defined) and does not recognise.
//! Run it against the module itself, not the proxy: the proxy leaves out what it cannot carry.
//! Exits 1 if any mechanism is unrecognised; `--strict` also fails on vendor-defined ones.
//! `SLOT_INDEX` (default `P11_TEST_SLOT`, else 0) counts slots with a token.

use p11_conformance::mechs::{counts, list, Class};

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let strict = args.iter().position(|a| a == "--strict").map(|i| args.remove(i)).is_some();
    let Some(path) = args.first() else {
        eprintln!("usage: p11-mechs MODULE [SLOT_INDEX] [--strict]");
        std::process::exit(2);
    };
    let index =
        args.get(1).cloned().or_else(|| std::env::var("P11_TEST_SLOT").ok()).and_then(|v| v.parse().ok()).unwrap_or(0);
    let entries = p11_conformance::Module::load(std::path::Path::new(path)).and_then(|m| list(&m, index));
    let entries = entries.unwrap_or_else(|e| {
        eprintln!("p11-mechs: {e}");
        std::process::exit(2);
    });
    for e in &entries {
        let class = match e.class {
            Class::Carried => "carried",
            Class::Refused => "refused",
            Class::Vendor => "VENDOR",
            Class::Unknown => "UNKNOWN",
        };
        println!("0x{:08x}  {:<8} {}", e.mechanism, class, e.name.unwrap_or("-"));
    }
    let c = counts(&entries);
    println!(
        "{} mechanisms: {} carried, {} refused on purpose, {} vendor-defined, {} unknown",
        entries.len(),
        c[0],
        c[1],
        c[2],
        c[3]
    );
    if c[Class::Unknown as usize] > 0 || (strict && c[Class::Vendor as usize] > 0) {
        std::process::exit(1);
    }
}
