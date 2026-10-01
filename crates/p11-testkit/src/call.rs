//! Thin helpers for driving a `Backend` in tests.

use p11_module::Backend;
use p11_types::*;
use p11_wire::calls::*;
use p11_wire::structs::OutSpec;

pub fn slot_list(b: &dyn Backend, token_present: bool) -> Option<Vec<u64>> {
    let r = b.c_get_slot_list(&GetSlotListReq { token_present, slots: OutSpec::Capacity(64) });
    (r.rv == CKR_OK as u64).then(|| r.resp.unwrap().slots.data.unwrap().0)
}
