//! With `P11_TEST_MODULE` set: every mechanism the module offers must be one the proxy carries, refuses
//! on purpose, or that is vendor-defined. A standard-range value the proxy does not recognise is a gap
//! in the mechanism table (`p11-params`) and fails here. Skips without an external module.

use p11_conformance::mechs::{counts, list, Class};

#[test]
fn every_mechanism_the_module_offers_is_accounted_for() {
    if !p11_testkit::softhsm::external() {
        eprintln!("SKIP: no P11_TEST_MODULE");
        return;
    }
    let module = std::env::var("P11_TEST_MODULE").unwrap();
    let m = p11_conformance::Module::load(std::path::Path::new(&module)).unwrap();
    let entries = list(&m, p11_testkit::softhsm::slot_index()).unwrap();
    let c = counts(&entries);
    eprintln!(
        "{} mechanisms: {} carried, {} refused, {} vendor-defined, {} unknown",
        entries.len(),
        c[0],
        c[1],
        c[2],
        c[3]
    );
    for e in entries.iter().filter(|e| e.class != Class::Carried) {
        eprintln!("  {:?} 0x{:x} {}", e.class, e.mechanism, e.name.unwrap_or("-"));
    }
    let unknown: Vec<_> = entries.iter().filter(|e| e.class == Class::Unknown).map(|e| e.mechanism).collect();
    assert!(unknown.is_empty(), "mechanisms the proxy does not recognise: {unknown:x?}");
}
