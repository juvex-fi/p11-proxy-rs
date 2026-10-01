//! Memory for structures the daemon rebuilds from wire values. Everything
//! allocated here stays at a fixed address until the arena is dropped, so the
//! rebuilt structures can point into it.

use p11_types::*;

/// Most memory one call may make the daemon allocate for rebuilt structures.
pub const ARENA_MAX: usize = 32 << 20;

#[derive(Debug, Default)]
pub struct Arena {
    blocks: Vec<Box<[u64]>>,
    used: usize,
}

impl Arena {
    pub fn new() -> Self {
        Self::default()
    }

    /// Zeroed, 8-byte aligned memory of at least `n` bytes (never null).
    pub fn alloc(&mut self, n: usize) -> Result<*mut u8, Rv> {
        let words = n.div_ceil(8).max(1);
        self.used = self.used.checked_add(words * 8).ok_or(CKR_HOST_MEMORY)?;
        if self.used > ARENA_MAX {
            return Err(CKR_HOST_MEMORY);
        }
        let mut b = vec![0u64; words].into_boxed_slice();
        let p = b.as_mut_ptr() as *mut u8;
        self.blocks.push(b);
        Ok(p)
    }

    /// Zeroed array of `n` `T`s. `T` must not need more than 8-byte alignment.
    pub fn alloc_array<T>(&mut self, n: usize) -> Result<*mut T, Rv> {
        debug_assert!(core::mem::align_of::<T>() <= 8);
        let bytes = core::mem::size_of::<T>().checked_mul(n).ok_or(CKR_HOST_MEMORY)?;
        Ok(self.alloc(bytes)?.cast())
    }

    /// Copy `b` into the arena (a valid pointer even when `b` is empty).
    pub fn copy(&mut self, b: &[u8]) -> Result<*mut u8, Rv> {
        let p = self.alloc(b.len())?;
        // SAFETY: `p` points to at least `b.len()` writable bytes we just allocated.
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), p, b.len()) };
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_stable_and_zeroed() {
        let mut a = Arena::new();
        let p = a.alloc(10).unwrap();
        for _ in 0..1000 {
            a.alloc(100).unwrap();
        }
        // SAFETY: p points to 16 zeroed bytes owned by the arena.
        unsafe {
            assert_eq!(*p.add(9), 0);
            *p = 7;
            assert_eq!(*p, 7);
        }
    }

    #[test]
    fn budget_is_enforced() {
        let mut a = Arena::new();
        assert!(a.alloc(ARENA_MAX / 2).is_ok());
        assert!(a.alloc(ARENA_MAX / 2 + 1024).is_err());
    }
}
