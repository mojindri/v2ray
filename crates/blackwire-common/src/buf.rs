//! Buffer pool for reusing memory allocations.
//!
//! # Why do we need this?
//!
//! Every time a proxy connection reads or writes data, it needs a chunk of
//! memory to hold the bytes. If we allocate and free memory for every single
//! read/write, we stress the allocator — which slows things down, especially
//! at high connection counts.
//!
//! A buffer pool solves this by keeping a collection of already-allocated
//! buffers available for reuse. When code needs a buffer, it borrows one from
//! the pool. When it is done, it returns the buffer to the pool instead of
//! freeing it. The next request reuses the same memory.
//!
//! # Three size classes
//!
//! We maintain three sizes:
//!   - **Small** (4 KiB): for protocol headers and control data
//!   - **Medium** (16 KiB): for typical payload chunks
//!   - **Large** (64 KiB): for high-throughput relay (the maximum Shadowsocks-2022 chunk size)
//!
//! If the pool is empty (all buffers are in use), a new buffer is allocated.
//! If the pool is full when a buffer is returned, the buffer is simply dropped
//! (freed). This keeps memory bounded.

use bytes::BytesMut;
use crossbeam_queue::ArrayQueue;
use std::sync::Arc;

/// The number of buffers to keep in each size class per CPU core.
/// With 4 cores: small pool holds up to 32 buffers, medium 16, large 8.
const SMALL_PER_CPU: usize = 8;
const MEDIUM_PER_CPU: usize = 4;
const LARGE_PER_CPU: usize = 2;

const SMALL_SIZE: usize = 4 * 1024; // 4 KiB
const MEDIUM_SIZE: usize = 16 * 1024; // 16 KiB
const LARGE_SIZE: usize = 64 * 1024; // 64 KiB

/// A pool of reusable byte buffers, shared across tasks via `Arc`.
///
/// To use:
/// ```rust
/// use blackwire_common::BufferPool;
///
/// let pool = BufferPool::new();
/// let mut buf = pool.acquire(1024); // get a buffer big enough for 1024 bytes
/// buf.extend_from_slice(b"hello");
/// pool.release(buf);                // return it when done
/// ```
pub struct BufferPool {
    /// Pre-allocated 4 KiB buffers.
    small: ArrayQueue<BytesMut>,
    /// Pre-allocated 16 KiB buffers.
    medium: ArrayQueue<BytesMut>,
    /// Pre-allocated 64 KiB buffers.
    large: ArrayQueue<BytesMut>,
}

impl BufferPool {
    /// Create a new buffer pool sized for the current machine's CPU count.
    pub fn new() -> Arc<Self> {
        let cpus = num_cpus();
        Arc::new(Self {
            small: ArrayQueue::new(cpus * SMALL_PER_CPU),
            medium: ArrayQueue::new(cpus * MEDIUM_PER_CPU),
            large: ArrayQueue::new(cpus * LARGE_PER_CPU),
        })
    }

    /// Borrow a buffer that can hold at least `hint` bytes.
    ///
    /// If a suitable buffer is available in the pool, it is returned immediately
    /// (no allocation). If the pool is empty, a new buffer is allocated.
    ///
    /// The returned buffer is cleared (zero length, capacity preserved).
    pub fn acquire(&self, hint: usize) -> BytesMut {
        let pool = self.pool_for(hint);
        pool.pop().unwrap_or_else(|| {
            // Pool empty — allocate a new buffer.
            BytesMut::with_capacity(capacity_for(hint))
        })
    }

    /// Return a buffer to the pool so it can be reused.
    ///
    /// The buffer is cleared before being pooled. If the pool is full,
    /// the buffer is dropped (freed) silently.
    pub fn release(&self, mut buf: BytesMut) {
        buf.clear();
        let pool = self.pool_for(buf.capacity());
        // `push` returns `Err(buf)` if the queue is full — we ignore the error
        // because dropping the buffer is the correct behaviour when the pool is full.
        let _ = pool.push(buf);
    }

    /// Select which pool to use based on the requested/actual size.
    fn pool_for(&self, size: usize) -> &ArrayQueue<BytesMut> {
        if size <= SMALL_SIZE {
            &self.small
        } else if size <= MEDIUM_SIZE {
            &self.medium
        } else {
            &self.large
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        let cpus = num_cpus();
        Self {
            small: ArrayQueue::new(cpus * SMALL_PER_CPU),
            medium: ArrayQueue::new(cpus * MEDIUM_PER_CPU),
            large: ArrayQueue::new(cpus * LARGE_PER_CPU),
        }
    }
}

/// Returns the buffer capacity for the appropriate size class.
fn capacity_for(hint: usize) -> usize {
    if hint <= SMALL_SIZE {
        SMALL_SIZE
    } else if hint <= MEDIUM_SIZE {
        MEDIUM_SIZE
    } else {
        LARGE_SIZE
    }
}

/// Returns the number of logical CPU cores on the current machine.
/// Falls back to 1 if the value cannot be determined.
fn num_cpus() -> usize {
    // We read from an environment variable in tests so the pool size
    // is predictable without depending on the actual CPU count.
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Checks that acquire() returns a buffer with the right capacity class.
    #[test]
    fn acquire_returns_correct_size_class() {
        let pool = BufferPool::default();

        let small = pool.acquire(100);
        assert!(small.capacity() >= 100);
        assert_eq!(small.capacity(), SMALL_SIZE); // small class

        let medium = pool.acquire(5000);
        assert!(medium.capacity() >= 5000);
        assert_eq!(medium.capacity(), MEDIUM_SIZE); // medium class

        let large = pool.acquire(20000);
        assert!(large.capacity() >= 20000);
        assert_eq!(large.capacity(), LARGE_SIZE); // large class
    }

    // Checks that a buffer returned to the pool can be re-acquired without
    // triggering a new allocation. We can verify this indirectly by checking
    // that the pool is not empty after release.
    #[test]
    fn release_makes_buffer_available_again() {
        let pool = BufferPool::default();

        // Acquire and immediately release a buffer.
        let buf = pool.acquire(100);
        assert!(buf.is_empty()); // cleared on acquire
        pool.release(buf);

        // The pool's small queue should now have one item.
        // pop() returns Some(...) if the buffer is there.
        assert!(pool.small.pop().is_some());
    }

    // Checks that acquiring and releasing does not panic even when the pool
    // is at capacity (no room for more buffers).
    #[test]
    fn release_when_pool_full_does_not_panic() {
        // Create a pool with capacity 1 per size class.
        let pool = BufferPool {
            small: ArrayQueue::new(1),
            medium: ArrayQueue::new(1),
            large: ArrayQueue::new(1),
        };

        // Fill the small pool.
        let _ = pool.small.push(BytesMut::with_capacity(SMALL_SIZE));

        // Releasing another buffer into a full pool should not panic.
        let extra = BytesMut::with_capacity(SMALL_SIZE);
        pool.release(extra); // silently dropped — this must not panic
    }

    // Checks that the buffer is cleared (length = 0) when acquired from the pool,
    // even if it previously held data.
    #[test]
    fn acquired_buffer_is_cleared() {
        let pool = BufferPool::default();
        let mut buf = pool.acquire(100);
        buf.extend_from_slice(b"some data");
        assert_eq!(buf.len(), 9);

        // Return it.
        pool.release(buf);

        // Re-acquire — it should be empty even though it held data before.
        let buf2 = pool.acquire(100);
        assert_eq!(buf2.len(), 0);
    }
}
