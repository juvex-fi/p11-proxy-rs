//! docs/PROTOCOL.md contains the call table generated from api.idl; keep it in sync.
//! `UPDATE_DOCS=1 cargo test -p p11-wire --test docs` rewrites it.

const BEGIN: &str = "<!-- BEGIN calls -->";
const END: &str = "<!-- END calls -->";

#[test]
fn protocol_md_lists_every_call() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/PROTOCOL.md");
    let text = std::fs::read_to_string(&path).unwrap();
    let (head, rest) = text.split_once(BEGIN).unwrap();
    let (_, tail) = rest.split_once(END).unwrap();
    let want = format!("{head}{BEGIN}{}{END}{tail}", generated());
    if std::env::var_os("UPDATE_DOCS").is_some() {
        std::fs::write(&path, want).unwrap();
        return;
    }
    assert_eq!(text, want, "docs/PROTOCOL.md is out of date: run UPDATE_DOCS=1 cargo test -p p11-wire --test docs");
}

fn generated() -> String {
    format!("\n### The calls\n\n{}\n", p11_wire::calls::CALL_TABLE_MARKDOWN)
}
