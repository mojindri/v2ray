//! Bidirectional relay implementations.
//!
//! The default relay uses `tokio::io::copy_bidirectional`, which works for any
//! async stream. On Linux, raw TCP streams can use `splice(2)` to move bytes
//! through kernel pipes without copying them into userspace.

use std::io;

use proxy_common::BoxedStream;

/// Relay bytes between two streams until either side closes.
pub async fn relay_bidirectional(
    inbound: BoxedStream,
    outbound: BoxedStream,
) -> io::Result<(u64, u64)> {
    // Keep the public relay API platform-neutral. The `platform` module below
    // decides whether this build can use Linux splice or needs the fallback.
    platform::relay_bidirectional(inbound, outbound).await
}

async fn tokio_copy_bidirectional(
    mut inbound: BoxedStream,
    mut outbound: BoxedStream,
) -> io::Result<(u64, u64)> {
    // Portable path: works for TCP, TLS, WebSocket, in-memory test streams, and
    // every other async stream type. This is the correctness baseline.
    tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use std::io;

    use proxy_common::BoxedStream;

    pub async fn relay_bidirectional(
        inbound: BoxedStream,
        outbound: BoxedStream,
    ) -> io::Result<(u64, u64)> {
        // macOS, Windows, BSD, and other platforms do not have Linux splice.
        // Use the portable Tokio copy loop everywhere outside Linux.
        super::tokio_copy_bidirectional(inbound, outbound).await
    }
}

// Everything in this module is compiled only for Linux. That keeps macOS and
// Windows builds away from Linux-only APIs like `splice`, `pipe2`, and raw file
// descriptor routing.
#[cfg(target_os = "linux")]
mod platform {
    use std::io;
    use std::net::{Shutdown, TcpStream as StdTcpStream};
    use std::os::fd::{AsRawFd, RawFd};

    use proxy_common::{try_into_tcp_stream, BoxedStream};
    use tokio::net::TcpStream;

    const SPLICE_CHUNK_SIZE: usize = 128 * 1024;

    pub async fn relay_bidirectional(
        inbound: BoxedStream,
        outbound: BoxedStream,
    ) -> io::Result<(u64, u64)> {
        // Splice can only move bytes between real file descriptors. A boxed
        // TLS/WebSocket/etc. stream is not a raw socket anymore, so we must
        // recover `TcpStream` before taking the optimized path.
        let inbound = match try_into_tcp_stream(inbound) {
            Ok(stream) => stream,
            Err(inbound) => {
                // The inbound side is not raw TCP. Nothing special to do:
                // fall back to the normal async copy and preserve behavior.
                return super::tokio_copy_bidirectional(inbound, outbound).await;
            }
        };

        let outbound = match try_into_tcp_stream(outbound) {
            Ok(stream) => stream,
            Err(outbound) => {
                // The inbound was raw TCP, but the outbound was not. Put the
                // inbound socket back into a box and use the portable path.
                return super::tokio_copy_bidirectional(Box::new(inbound), outbound).await;
            }
        };

        splice_tcp_bidirectional(inbound, outbound).await
    }

    async fn splice_tcp_bidirectional(
        inbound: TcpStream,
        outbound: TcpStream,
    ) -> io::Result<(u64, u64)> {
        // `libc::splice` is a blocking syscall API. Convert Tokio sockets to
        // standard sockets and run the work on blocking threads so we do not
        // stall Tokio's async worker threads.
        let inbound = inbound.into_std()?;
        let outbound = outbound.into_std()?;

        // The blocking splice loops expect blocking sockets. Tokio sockets are
        // nonblocking by default, so switch the std sockets before using libc.
        inbound.set_nonblocking(false)?;
        outbound.set_nonblocking(false)?;

        // Each direction needs its own readable socket handle. `try_clone`
        // duplicates the file descriptor; both handles still refer to the same
        // underlying TCP connection.
        let inbound_reader = inbound.try_clone()?;
        let outbound_reader = outbound.try_clone()?;

        // Run both directions at the same time:
        //   upload   = client/inbound  -> server/outbound
        //   download = server/outbound -> client/inbound
        let upload = tokio::task::spawn_blocking(move || splice_one_way(inbound_reader, outbound));
        let download =
            tokio::task::spawn_blocking(move || splice_one_way(outbound_reader, inbound));

        let (upload, download) =
            tokio::try_join!(async { upload.await.map_err(io::Error::other)? }, async {
                download.await.map_err(io::Error::other)?
            },)?;

        Ok((upload, download))
    }

    fn splice_one_way(reader: StdTcpStream, writer: StdTcpStream) -> io::Result<u64> {
        // Linux splice needs a pipe as the middle step:
        //   socket -> pipe -> socket
        // The bytes stay inside the kernel; Rust never allocates a userspace
        // buffer for the payload.
        let pipe = Pipe::new()?;
        let mut transferred = 0u64;

        loop {
            // Move bytes from the source socket into the pipe. `read == 0`
            // means EOF: the peer closed its write side.
            let read = splice(reader.as_raw_fd(), pipe.write_fd, SPLICE_CHUNK_SIZE)?;
            if read == 0 {
                // Tell the destination there will be no more bytes in this
                // direction, but do not close the whole connection. The other
                // direction may still be sending data.
                let _ = writer.shutdown(Shutdown::Write);
                return Ok(transferred);
            }

            // Drain exactly the bytes we just moved into the pipe. A splice
            // call may write only part of the pipe, so loop until empty.
            let mut remaining = read;
            while remaining > 0 {
                let written = splice(pipe.read_fd, writer.as_raw_fd(), remaining)?;
                if written == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "splice wrote zero bytes",
                    ));
                }
                remaining -= written;
                transferred += written as u64;
            }
        }
    }

    fn splice(read_fd: RawFd, write_fd: RawFd, len: usize) -> io::Result<usize> {
        loop {
            // SAFETY: `read_fd` and `write_fd` are live file descriptors owned
            // by `StdTcpStream` or `Pipe`. We pass null offsets because sockets
            // and pipes do not use seek offsets.
            let n = unsafe {
                libc::splice(
                    read_fd,
                    std::ptr::null_mut(),
                    write_fd,
                    std::ptr::null_mut(),
                    len,
                    0,
                )
            };

            if n >= 0 {
                return Ok(n as usize);
            }

            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
    }

    struct Pipe {
        read_fd: RawFd,
        write_fd: RawFd,
    }

    impl Pipe {
        fn new() -> io::Result<Self> {
            let mut fds = [0; 2];
            // O_CLOEXEC prevents these internal pipe descriptors from leaking
            // into child processes if the proxy ever spawns one.
            // SAFETY: `fds` is a valid two-element array; pipe2 writes both ends on success.
            let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                read_fd: fds[0],
                write_fd: fds[1],
            })
        }
    }

    impl Drop for Pipe {
        fn drop(&mut self) {
            // Close both pipe ends when the relay direction exits. Ignoring
            // close errors is normal in Drop; there is no useful recovery path.
            // SAFETY: we own these fds and must close them exactly once.
            unsafe {
                libc::close(self.read_fd);
                libc::close(self.write_fd);
            }
        }
    }
}
