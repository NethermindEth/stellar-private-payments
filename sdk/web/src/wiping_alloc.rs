//! Global allocator that wipes every heap block before freeing it.
//!
//! Secrets leave copies on the heap that their owners never see. Wiping on
//! free clears all of them, including SQLite's which allocates through Rust

use std::alloc::{GlobalAlloc, Layout, System};
use zeroize::Zeroize;

/// [`System`] with a zeroizing `dealloc`. The default `realloc` allocates,
/// copies and calls `dealloc`, so blocks a resize leaves behind are wiped too.
pub(crate) struct WipingAllocator;

#[allow(unsafe_code)]
// SAFETY: forwards every request to `System`, and only writes to a block the
// caller still owns.
unsafe impl GlobalAlloc for WipingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as `GlobalAlloc::alloc`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as `GlobalAlloc::alloc_zeroed`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller guarantees `ptr` is a live block of
        // `layout.size()` bytes allocated by this allocator. `zeroize` uses
        // volatile writes, so the wipe is not removed as a dead store.
        unsafe {
            std::slice::from_raw_parts_mut(ptr, layout.size()).zeroize();
            System.dealloc(ptr, layout);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(unsafe_code, clippy::unwrap_used)]

    use super::*;
    use wasm_bindgen_test::*;

    // Reads the block after `dealloc`. Wasm memory is never unmapped, so the
    // read is safe. dlmalloc may store free-list links in the first 24 bytes
    // and a size footer at the end, so only the interior is checked.
    #[wasm_bindgen_test]
    fn dealloc_wipes_the_block() {
        let layout = Layout::from_size_align(256, 8).unwrap();
        unsafe {
            let ptr = WipingAllocator.alloc(layout);
            assert!(!ptr.is_null());
            ptr.write_bytes(0xAA, layout.size());
            WipingAllocator.dealloc(ptr, layout);
            for i in 32..layout.size().wrapping_sub(16) {
                assert_eq!(ptr.add(i).read_volatile(), 0, "byte {i} survived dealloc");
            }
        }
    }
}
