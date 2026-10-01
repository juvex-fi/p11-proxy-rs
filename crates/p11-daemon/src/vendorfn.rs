//! A vendor-defined function: not one of the PKCS#11 calls, declared in the configuration. The daemon
//! checks the call against the declaration, translates the handles, rebuilds the arguments in its own
//! memory, runs the module's exported function of that name, and translates what came back.

use crate::ctx::ClientCtx;
use crate::dispatch::{Answer, Malformed};
use crate::xlate::Xlate;
use p11_module::Backend;
use p11_params::vendorfn::{self, VendorCall};
use p11_types::*;
use p11_wire::vendorfn::*;

/// Whether a reply body goes with this result (the length a too small buffer needs, for one).
fn wants_body(rv: u64) -> bool {
    rv == CKR_OK as u64 || rv == CKR_BUFFER_TOO_SMALL as u64
}

pub(crate) fn handle(ctx: &ClientCtx, backend: &dyn Backend, body: &[u8]) -> Result<Answer, Malformed> {
    let name = request_name(body).map_err(Malformed)?;
    let Some(desc) = vendorfn::get(&name) else { return Ok((CKR_FUNCTION_NOT_SUPPORTED as u64, None)) };
    if !ctx.is_initialized() {
        return Ok((CKR_CRYPTOKI_NOT_INITIALIZED as u64, None));
    }
    if !ctx.rules.call_allowed(desc.rw) {
        return Ok((CKR_ACTION_PROHIBITED as u64, None));
    }
    let mut ins = decode_request(body, &desc).map_err(Malformed)?;
    // what the client calls a handle is translated into the module's
    for (k, v) in desc.args.iter().zip(ins.iter_mut()) {
        let r = match (k, v) {
            (ArgKind::Slot, InVal::Int(x)) => ctx.slot(*x),
            (ArgKind::Session, InVal::Int(x)) => ctx.session(*x).map(|real| *x = real),
            (ArgKind::Object, InVal::Int(x)) => ctx.object(*x, false).map(|real| *x = real),
            (ArgKind::Attrs, InVal::Attrs(a)) => ctx.attrs_in(CALL_VENDOR, a),
            _ => Ok(()),
        };
        if let Err(rv) = r {
            return Ok((rv, None));
        }
    }
    let mut call = match VendorCall::build(&desc, &ins) {
        Ok(c) => c,
        Err(rv) => return Ok((rv as u64, None)),
    };
    // a PIN in the decoded arguments is gone once the call is built
    for v in ins.iter_mut() {
        if let InVal::Bytes(b) = v {
            p11_wire::wipe_vec(b);
        }
    }
    // SAFETY: `desc` is what the operator declared for the module's function of this name.
    let rv = match backend.with_vendor_symbol(&name, &mut |addr| unsafe { call.invoke(addr) }) {
        Ok(rv) => rv,
        Err(e) => return Ok((e, None)),
    };
    let mut reply = call.finish(rv);
    if rv == CKR_OK as u64 {
        // an object the function made is registered under a handle of the client's own
        let outs = desc.args.iter().filter(|k| k.is_output());
        for (k, o) in outs.zip(reply.0.iter_mut()) {
            if let (ArgKind::OObject, OutVal::Int(h)) = (k, o) {
                if *h != 0 {
                    *h = ctx.new_object(*h);
                }
            }
        }
    }
    Ok((rv, wants_body(rv).then(|| reply.encode())))
}
