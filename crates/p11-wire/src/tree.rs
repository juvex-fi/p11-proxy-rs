//! Parameter trees.
//!
//! Mechanism parameters are C structures with pointers, so they can't be sent
//! as memory. The client turns each one into a [`Node`] tree (integers, byte
//! strings, lists) and the daemon rebuilds an equivalent structure in its own
//! memory from the tree. The wire form is self-describing, so this crate can
//! decode and bound any tree without knowing which mechanism it belongs to;
//! the code that builds structures from trees checks the shape.

use crate::attr::Attr;
use crate::codec::{Decode, Encode, Reader, Seq, Writer};
use crate::error::{Result, WireError};
use crate::limits::{MAX_ARRAY, MAX_DEPTH, MAX_TREE_BYTES, MAX_TREE_NODES};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Node {
    /// A NULL pointer or an optional member that isn't there.
    #[default]
    Absent,
    /// Any integer member (`CK_ULONG`, `CK_BBOOL`, `CK_BYTE`, handles).
    U(u64),
    /// A byte buffer or a string.
    B(Vec<u8>),
    /// A structure's members, or an array of elements.
    L(Vec<Node>),
    /// An attribute template (`CK_ATTRIBUTE_PTR` and count).
    T(Vec<Attr>),
}

const TAG_ABSENT: u8 = 0;
const TAG_U: u8 = 1;
const TAG_B: u8 = 2;
const TAG_L: u8 = 3;
const TAG_T: u8 = 4;

impl Node {
    pub fn as_u(&self) -> Option<u64> {
        if let Node::U(v) = self {
            Some(*v)
        } else {
            None
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        if let Node::B(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_list(&self) -> Option<&[Node]> {
        if let Node::L(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn as_template(&self) -> Option<&[Attr]> {
        if let Node::T(v) = self {
            Some(v)
        } else {
            None
        }
    }
    pub fn is_absent(&self) -> bool {
        matches!(self, Node::Absent)
    }
}

impl Encode for Node {
    fn encode(&self, w: &mut Writer) {
        match self {
            Node::Absent => w.u8(TAG_ABSENT),
            Node::U(v) => {
                w.u8(TAG_U);
                w.u64(*v)
            }
            Node::B(b) => {
                w.u8(TAG_B);
                w.bytes(b)
            }
            Node::L(l) => {
                w.u8(TAG_L);
                w.count(l.len());
                for n in l {
                    n.encode(w);
                }
            }
            Node::T(t) => {
                w.u8(TAG_T);
                w.count(t.len());
                for a in t {
                    a.encode(w);
                }
            }
        }
    }
}

struct Budget {
    nodes: usize,
    bytes: usize,
}

fn decode_node(r: &mut Reader<'_>, depth: usize, b: &mut Budget) -> Result<Node> {
    if depth > MAX_DEPTH {
        return Err(WireError::TooDeep);
    }
    b.nodes = b.nodes.checked_sub(1).ok_or(WireError::TooLarge)?;
    Ok(match r.u8()? {
        TAG_ABSENT => Node::Absent,
        TAG_U => Node::U(r.u64()?),
        TAG_B => {
            let s = r.bytes_ref()?;
            b.bytes = b.bytes.checked_sub(s.len()).ok_or(WireError::TooLarge)?;
            Node::B(s.to_vec())
        }
        TAG_L => {
            // every element takes at least its tag byte
            let n = r.count(MAX_ARRAY, 1)?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(decode_node(r, depth + 1, b)?);
            }
            Node::L(v)
        }
        TAG_T => {
            let t = Seq::<Attr>::decode(r)?;
            b.nodes = b.nodes.checked_sub(t.0.len()).ok_or(WireError::TooLarge)?;
            Node::T(t.0)
        }
        _ => return Err(WireError::BadTag),
    })
}

impl Decode for Node {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        let mut b = Budget { nodes: MAX_TREE_NODES, bytes: MAX_TREE_BYTES };
        decode_node(r, 0, &mut b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{from_slice, to_vec};
    use proptest::prelude::*;

    fn arb_node() -> impl Strategy<Value = Node> {
        let leaf = prop_oneof![
            Just(Node::Absent),
            any::<u64>().prop_map(Node::U),
            proptest::collection::vec(any::<u8>(), 0..20).prop_map(Node::B),
        ];
        leaf.prop_recursive(4, 64, 6, |inner| proptest::collection::vec(inner, 0..6).prop_map(Node::L))
    }

    proptest! {
        #[test]
        fn roundtrip(n in arb_node()) {
            prop_assert_eq!(from_slice::<Node>(&to_vec(&n)).unwrap(), n);
        }
        #[test]
        fn garbage_never_panics(b in proptest::collection::vec(any::<u8>(), 0..128)) {
            let _ = from_slice::<Node>(&b);
        }
    }

    #[test]
    fn depth_is_limited() {
        let mut n = Node::U(1);
        for _ in 0..=MAX_DEPTH {
            n = Node::L(vec![n]);
        }
        assert_eq!(from_slice::<Node>(&to_vec(&n)).unwrap_err(), WireError::TooDeep);
        let mut n = Node::U(1);
        for _ in 0..MAX_DEPTH {
            n = Node::L(vec![n]);
        }
        assert!(from_slice::<Node>(&to_vec(&n)).is_ok());
    }

    #[test]
    fn node_budget_is_limited() {
        // one list of MAX_TREE_NODES+ empty nodes, all within MAX_ARRAY
        let n = Node::L(vec![Node::Absent; MAX_ARRAY]);
        let m = Node::L(vec![n.clone(), n.clone(), n.clone(), n.clone(), n]);
        assert_eq!(from_slice::<Node>(&to_vec(&m)).unwrap_err(), WireError::TooLarge);
    }
}
