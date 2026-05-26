//! Zero-copy bidirectional relay using Linux `splice(2)`.
//!
//! # What is splice?
//!
//! Normally, when we relay bytes between two TCP sockets, data travels like this:
//!
//!   NIC → kernel socket buffer → **user space** → kernel socket buffer → NIC
//!
//! The user-space step means the CPU copies every byte twice (once out of
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
//! `splice(2)` bypasses Tokio's I/O driver. We integrate it with Tokio using
//! `tokio::net::TcpStream::try_io` so readiness notifications stay accurate.

#[cfg(target_os = "linux")]
mod linux {
    use std::future::Future;
    use std::io;
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::pin::Pin;
    use std::time::Duration;

    use tokio::io::Interest;
    use tokio::net::TcpStream;

    // The pipe capacity we request from the kernel.
    // Linux defaults to 65536 bytes (16 × 4096 page size).
    // Using a larger pipe reduces the number of splice calls needed for
    // big transfers. 256 KiB is a good balance between memory and throughput.
    const PIPE_CAPACITY: usize = 256 * 1024;
    const PEER_DRAIN: Duration = Duration::from_millis(250);

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
        fn new() -> io::Result<Self> {
            let mut fds = [0i32; 2];
            // SAFETY: pipe2 is safe to call with a valid array; O_NONBLOCK makes
            // the fds non-blocking so they can be used with epoll/Tokio.
            let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
            if ret != 0 {
                return Err(io::Error::last_os_error());
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

    fn is_would_block(err: &io::Error) -> bool {
        err.kind() == io::ErrorKind::WouldBlock || err.raw_os_error() == Some(libc::EAGAIN)
    }

    /// Call `splice(src_fd → pipe_write_fd)` once, returning how many bytes moved.
    ///
    /// Returns 0 if the source has no more data (EOF / connection closed).
    fn splice_in(src_fd: RawFd, pipe_write_fd: RawFd) -> io::Result<usize> {
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
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Call `splice(pipe_read_fd → dst_fd)` once, draining the pipe into the socket.
    fn splice_out(pipe_read_fd: RawFd, dst_fd: RawFd, len: usize) -> io::Result<usize> {
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
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    /// Relay bytes from `src` to `dst` using splice, until EOF or error.
    ///
    /// Uses `tokio::net::TcpStream::try_io` so splice syscalls stay in sync with Tokio
    /// readiness. Raw `readable()`/`writable()` waits can miss wakeups because
    /// splice moves data without touching the runtime's I/O driver.
    async fn splice_one_direction(src: &TcpStream, dst: &TcpStream) -> io::Result<u64> {
        let src_fd = src.as_raw_fd();
        let dst_fd = dst.as_raw_fd();

        let pipe = Pipe::new()?;
        let mut total: u64 = 0;

        loop {
            // --- Phase A: wait for src to be readable, then splice into pipe ---
            let in_bytes = loop {
                match src.try_io(Interest::READABLE, || splice_in(src_fd, pipe.write_fd)) {
                    Ok(0) => {
                        // Source EOF — half-close the write side of dst so the peer
                        // receives a FIN and knows no more data will arrive.
                        // SAFETY: dst_fd is valid for the lifetime of this call.
                        unsafe { libc::shutdown(dst_fd, libc::SHUT_WR) };
                        return Ok(total);
                    }
                    Ok(n) => break n,
                    Err(e) if is_would_block(&e) => {
                        tokio::task::yield_now().await;
                    }
                    Err(e) => return Err(e),
                }
            };

            // --- Phase B: drain the pipe into dst (may take multiple splice calls) ---
            let mut remaining = in_bytes;
            while remaining > 0 {
                match dst.try_io(Interest::WRITABLE, || {
                    splice_out(pipe.read_fd, dst_fd, remaining)
                }) {
                    Ok(0) => {
                        // Peer closed or pipe temporarily empty; retry briefly before giving up.
                        if remaining > 0 {
                            tokio::task::yield_now().await;
                            continue;
                        }
                        return Ok(total);
                    }
                    Ok(n) => {
                        remaining -= n;
                        total += n as u64;
                    }
                    Err(e) if is_would_block(&e) => {
                        tokio::task::yield_now().await;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    async fn drain_peer(peer: Pin<&mut impl Future<Output = io::Result<u64>>>) -> io::Result<u64> {
        match tokio::time::timeout(PEER_DRAIN, peer).await {
            Ok(res) => res,
            Err(_) => Ok(0),
        }
    }

    /// Bidirectional zero-copy relay between two TCP streams using `splice(2)`.
    ///
    /// Runs two concurrent one-directional relays:
    ///   - `a → b` (client data going to server)
    ///   - `b → a` (server data coming back to client)
    ///
    /// Returns `(a_to_b_bytes, b_to_a_bytes)` when relay ends.
    ///
    /// Each direction sends a TCP half-close when its source reaches EOF. If one
    /// direction finishes while the other is idle (common for download-only or
    /// upload-only flows), the idle direction is unblocked and given a short drain
    /// window so the relay does not hang waiting for data that will never arrive.
    pub async fn splice_bidirectional(a: &TcpStream, b: &TcpStream) -> io::Result<(u64, u64)> {
        let a_fd = a.as_raw_fd();

        let mut ab = std::pin::pin!(splice_one_direction(a, b));
        let mut ba = std::pin::pin!(splice_one_direction(b, a));

        tokio::select! {
            res = ab.as_mut() => {
                let up = res?;
                let down = drain_peer(ba.as_mut()).await?;
                Ok((up, down))
            }
            res = ba.as_mut() => {
                let down = res?;
                // Download-only flows leave a→b waiting for client payload forever.
                // Stop reading from the client side so the idle direction can exit.
                unsafe { libc::shutdown(a_fd, libc::SHUT_RD) };
                let up = drain_peer(ab.as_mut()).await?;
                Ok((up, down))
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        async fn relay_pair() -> (TcpStream, TcpStream, TcpStream, TcpStream) {
            let listener_a = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let listener_b = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let addr_a = listener_a.local_addr().unwrap();
            let addr_b = listener_b.local_addr().unwrap();

            let (client_a, client_b) =
                tokio::join!(TcpStream::connect(addr_a), TcpStream::connect(addr_b),);
            let (server_a, server_b) = tokio::join!(listener_a.accept(), listener_b.accept());
            (
                client_a.unwrap(),
                server_a.unwrap().0,
                client_b.unwrap(),
                server_b.unwrap().0,
            )
        }

        #[tokio::test]
        async fn splice_download_only_completes_without_client_upload() {
            let (mut client, inbound, mut upstream, outbound) = relay_pair().await;
            let relay = tokio::spawn(async move {
                splice_bidirectional(&inbound, &outbound)
                    .await
                    .expect("relay")
            });

            let payload = vec![0x5Au8; 16 * 1024];
            upstream.write_all(&payload).await.unwrap();
            upstream.shutdown().await.unwrap();

            let mut got = vec![0u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut got))
                .await
                .expect("client read timed out")
                .expect("client read");
            assert_eq!(got, payload);

            let (up, down) = tokio::time::timeout(Duration::from_secs(5), relay)
                .await
                .expect("relay timed out")
                .expect("relay join");
            assert_eq!(up, 0);
            assert_eq!(down, payload.len() as u64);
        }

        #[tokio::test]
        async fn splice_echo_roundtrip_without_deadlock() {
            let (mut client, inbound, mut upstream, outbound) = relay_pair().await;
            let relay = tokio::spawn(async move {
                splice_bidirectional(&inbound, &outbound)
                    .await
                    .expect("relay")
            });

            let upstream_task = tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = upstream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    upstream.write_all(&buf[..n]).await.unwrap();
                }
            });

            let chunk = vec![0xCDu8; 2048];
            client.write_all(&chunk).await.unwrap();
            client.flush().await.unwrap();
            let mut got = vec![0u8; chunk.len()];
            tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut got))
                .await
                .expect("echo read timed out")
                .expect("echo read");
            assert_eq!(got, chunk);

            client.shutdown().await.unwrap();
            upstream_task.await.unwrap();
            relay.await.unwrap();
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::splice_bidirectional;

// On non-Linux we just re-export nothing. Callers use `#[cfg(target_os = "linux")]`
// to decide whether to call splice or fall back to copy_bidirectional.
