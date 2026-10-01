//! A forked child inherits the library's state but not the right to use the
//! parent's connections: it must initialise again, and doing so must leave the
//! parent's connections alone. One test in its own binary, so that no other
//! test thread is running when the process forks.
#![allow(clippy::undocumented_unsafe_blocks, unsafe_op_in_unsafe_fn)]

use p11_proxy::*;
use p11_testkit::proc::DaemonProc;
use p11_testkit::softhsm::Token;
use p11_types::*;
use std::ptr::null_mut;

#[test]
fn a_forked_child_initialises_again_and_the_parent_is_unaffected() {
    let Some(token) = Token::create() else {
        eprintln!("SKIP: no SoftHSM");
        return;
    };
    let sock = token.path().join("fork.sock");
    let listen = format!("unix://{}", sock.display());
    let module = token.module.to_str().unwrap().to_string();
    let daemon = DaemonProc::spawn(
        std::path::Path::new(env!("CARGO_BIN_EXE_p11-daemon")),
        &["--listen", &listen, &module],
        &token.envs(),
        1,
    )
    .unwrap();
    std::env::set_var("PKCS11_PROXY_SOCKET", &listen);
    unsafe {
        assert_eq!(C_Initialize(null_mut()), CKR_OK);
        let mut info: CK_INFO = std::mem::zeroed();
        assert_eq!(C_GetInfo(&mut info), CKR_OK);

        let pid = libc::fork();
        assert!(pid >= 0);
        if pid == 0 {
            // child: the inherited connection isn't ours to use
            let mut i: CK_INFO = std::mem::zeroed();
            let ok = C_GetInfo(&mut i) == CKR_CRYPTOKI_NOT_INITIALIZED
                && C_Initialize(null_mut()) == CKR_OK
                && C_GetInfo(&mut i) == CKR_OK
                && C_Finalize(null_mut()) == CKR_OK;
            libc::_exit(if ok { 0 } else { 1 });
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0, "child status {status}");

        // the parent's connection still works and its context is intact
        assert_eq!(C_GetInfo(&mut info), CKR_OK);
        let mut s = 0;
        let mut n = 8;
        let mut slots = [0 as CK_SLOT_ID; 8];
        assert_eq!(C_GetSlotList(1, slots.as_mut_ptr(), &mut n), CKR_OK);
        assert_eq!(C_OpenSession(slots[0], CKF_SERIAL_SESSION, null_mut(), None, &mut s), CKR_OK);
        assert_eq!(C_Finalize(null_mut()), CKR_OK);
    }
    drop(daemon);
}
