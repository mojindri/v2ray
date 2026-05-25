//! Zero-copy bidirectional relay using Linux `splice(2)`.
//!
//! # What is splice?
//!
//! Normally, when we relay bytes between two TCP sockets, data travels like this:
//!
//!   NIC → kernel socket buffer → **user space** → kernel socket buffer → NIC
//!
//! The "user space" step means the CPU copies every byte twice (once out of
//! the kernel into our process memory, once back in from our process memory to
//! the kernel). For a proxy that just forwards bytes without inspecting them,
//! this is pure overhead.
//!
//! Linux `splice(2)` eliminates the user-space copy:
//!
//!   NIC → kernel socket buffer → **kernel pipe buffer** → kernel socket buffer → NIC
//!
//! The data never leaves the kernel. This halves CPU usage for high-throughput
//! connections (e.g. video streaming, large file downloads).
//!
//! # How it works
//!
//! `splice` can move data between a file descriptor and a pipe, but NOT
//! directly between two sockets. So the trick is:
//!
//!   1. Create an anonymous kernel pipe (just a fixed-size kernel buffer).
//!   2. `splice(src_socket → pipe_write_end)` — moves data into the pipe.
//!   3. `splice(pipe_read_end → dst_socket)` — moves data out of the pipe.
//!
//! We run two of these chains concurrently (A→B and B→A) for bidirectional relay.
//!
//! # When is this used?
//!
//! The dispatcher uses `splice_bidirectional` when:
//!   - We are on Linux (compile-time check via `#[cfg(target_os = "linux")]`)
//!   - Both streams are raw TCP sockets that expose a file descriptor
//!
//! If either condition is false, the dispatcher falls back to
//! `tokio::io::copy_bidirectional` (the userspace copy path).
//!
//! # Async integration
//!
//! `splice(2)` is a blocking syscall. We integrate it with Tokio using
//! `AsyncFd<T>`, which lets us wait for the fd to be readable/writable
//! without blocking the async runtime's thread pool.

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::io::{AsRawFd, RawFd};

    use tokio::net::TcpStream;

    // The pipe capacity we request from the kernel.
    // Linux defaults to 65536 bytes (16 × 4096 page size).
    // Using a larger pipe reduces the number of splice calls needed for
    // big transfers. 256 KiB is a good balance between memory and throughput.
    const PIPE_CAPACITY: usize = 256 * 1024;

    /// A pair of anonymous kernel pipe file descriptors.
    ///
    /// `read_fd`  — data flows OUT of the kernel buffer through this end.
    /// `write_fd` — data flows INTO the kernel buffer through this end.
    struct Pipe {
        read_fd: RawFd,
        write_fd: RawFd,
    }

    impl Pipe {
        /// Create a new anonymous kernel pipe and set the requested capacity.
        fn new() -> std::io::Result<Self> {
            let mut fds = [0i32; 2];
            // SAFETY: pipe2 is safe to call with a valid array; O_NONBLOCK makes
            // the fds non-blocking so they can be used with epoll/Tokio.
            let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let pipe = Pipe {
                read_fd: fds[0],
                write_fd: fds[1],
            };

            // Try to increase the pipe capacity. This is advisory — if the kernel
            // refuses (e.g. /proc/sys/fs/pipe-max-size is lower), we silently
            // continue with the default capacity.
            unsafe {
                libc::fcntl(
                    pipe.write_fd,
                    libc::F_SETPIPE_SZ,
                    PIPE_CAPACITY as libc::c_int,
                );
            }

            Ok(pipe)
        }
    }

    impl Drop for Pipe {
        fn drop(&mut self) {
            // SAFETY: we own these fds and must close them exactly once.
            unsafe {
                libc::close(self.read_fd);
                libc::close(self.write_fd);
            }
        }
    }

    /// Call `splice(src_fd → pipe_write_fd)` once, returning how many bytes moved.
    ///
    /// Returns 0 if the source has no more data (EOF / connection closed).
    ///
    /// SPLICE_F_MOVE hints to the kernel that it can move page references instead
    /// of copying — the kernel may or may not honour this hint.
    /// SPLICE_F_NONBLOCK makes the call return EAGAIN instead of blocking when
    /// the pipe is full or the source has no data.
    fn splice_in(src_fd: RawFd, pipe_write_fd: RawFd) -> std::io::Result<usize> {
        // SAFETY: splice is safe to call with valid fds. `offset` = NULL means
        // "use the current file position" which is correct for sockets.
        let n = unsafe {
            libc::splice(
                src_fd,
                std::ptr::null_mut(),
                pipe_write_fd,
                std::ptr::null_mut(),
                PIPE_CAPACITY,
                libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
            )
        };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Call `splice(pipe_read_fd → dst_fd)` once, draining the pipe into the socket.
    fn splice_out(pipe_read_fd: RawFd, dst_fd: RawFd, len: usize) -> std::io::Result<usize> {
        let n = unsafe {
            libc::splice(
                pipe_read_fd,
                std::ptr::null_mut(),
                dst_fd,
                std::ptr::null_mut(),
                len,
                libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
            )
        };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Relay bytes from `src` to `dst` using splice, until EOF or error.
    ///
    /// Uses the TcpStream's own Tokio readiness notifications to avoid
    /// double-registering the underlying fd with the epoll reactor.
    /// When `src` reaches EOF, sends a TCP half-close (SHUT_WR) on `dst`
    /// so the remote peer sees a clean FIN in that direction.
    async fn splice_one_direction(src: &TcpStream, dst: &TcpStream) -> std::io::Result<u64> {
        let src_fd = src.as_raw_fd();
        let dst_fd = dst.as_raw_fd();

        let pipe = Pipe::new()?;
        let mut total: u64 = 0;

        loop {
            // --- Phase A: wait for src to be readable, then splice into pipe ---
            let in_bytes = loop {
                src.readable().await?;
                match splice_in(src_fd, pipe.write_fd) {
                    Ok(0) => {
                        // Source EOF — half-close the write side of dst so the peer
                        // receives a FIN and knows no more data will arrive.
                        // SAFETY: dst_fd is valid for the lifetime of this call.
                        unsafe { libc::shutdown(dst_fd, libc::SHUT_WR) };
                        return Ok(total);
                    }
                    Ok(n) => break n,
                    Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => {}
                    Err(e) => return Err(e),
                }
            };

            // --- Phase B: drain the pipe into dst (may take multiple splice calls) ---
            let mut remaining = in_bytes;
            while remaining > 0 {
                dst.writable().await?;
                match splice_out(pipe.read_fd, dst_fd, remaining) {
                    Ok(0) => return Ok(total), // dst closed
                    Ok(n) => {
                        remaining -= n;
                        total += n as u64;
                    }
                    Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => {}
                    Err(e) => return Err(e),
                }
            }
        }
    }

    /// Bidirectional zero-copy relay between two TCP streams using `splice(2)`.
    ///
    /// Runs two concurrent one-directional relays:
    ///   - `a → b` (client data going to server)
    ///   - `b → a` (server data coming back to client)
    ///
    /// Returns `(a_to_b_bytes, b_to_a_bytes)` when both directions finish.
    /// Each direction sends a TCP half-close when its source reaches EOF.
    pub async fn splice_bidirectional(a: &TcpStream, b: &TcpStream) -> std::io::Result<(u64, u64)> {
        tokio::try_join!(splice_one_direction(a, b), splice_one_direction(b, a),)
    }
}

#[cfg(target_os = "linux")]
pub use linux::splice_bidirectional;

// On non-Linux we just re-export nothing. Callers use `#[cfg(target_os = "linux")]`
// to decide whether to call splice or fall back to copy_bidirectional.
