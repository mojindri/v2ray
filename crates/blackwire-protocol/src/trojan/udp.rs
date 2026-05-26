//! Trojan UDP ASSOCIATE relay over the TLS/TCP connection.
//!
//! Wire format matches Xray-core `proxy/trojan` (`PacketReader` / `PacketWriter`):
//! `CMD 0x03` on the TCP/TLS stream, then per-packet SOCKS5 address + BE length +
//! `\r\n` + payload (max 8192 bytes per packet). See
//! <https://github.com/XTLS/Xray-core/tree/main/proxy/trojan>.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use blackwire_common::{Address, BoxedStream, ProxyError};

use super::codec::{encode_udp_datagram, parse_udp_datagram};

/// Relay Trojan UDP datagrams until the control stream closes.
pub async fn relay_trojan_udp(stream: BoxedStream) -> Result<(), ProxyError> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (reply_tx, mut reply_rx) = mpsc::channel::<Vec<u8>>(16);

    let write_task = tokio::spawn(async move {
        while let Some(reply) = reply_rx.recv().await {
            writer
                .write_all(&reply)
                .await
                .map_err(|e| ProxyError::Transport(e.to_string()))?;
            writer
                .flush()
                .await
                .map_err(|e| ProxyError::Transport(e.to_string()))?;
        }
        Ok::<(), ProxyError>(())
    });

    let mut buf = vec![0u8; 65535];
    let mut acc = Vec::new();
    let read_result = async {
        loop {
            acc.reserve(4096);
            let n = reader
                .read(&mut buf)
                .await
                .map_err(|e| ProxyError::Transport(e.to_string()))?;
            if n == 0 {
                break;
            }
            acc.extend_from_slice(&buf[..n]);

            while !acc.is_empty() {
                match parse_udp_datagram(&acc) {
                    Ok((dest, payload, consumed)) => {
                        let data = payload.to_vec();
                        acc.drain(..consumed);
                        if data.is_empty() {
                            continue;
                        }
                        let upstream = resolve_udp_dest(&dest).await?;
                        if let Some(reply_payload) =
                            exchange_udp_datagram(upstream, &data).await?
                        {
                            let reply = encode_udp_datagram(&dest, &reply_payload)?;
                            reply_tx
                                .send(reply)
                                .await
                                .map_err(|_| {
                                    ProxyError::Transport("Trojan UDP reply channel closed".into())
                                })?;
                        }
                    }
                    Err(ProxyError::Protocol(_)) if acc.len() > 65507 => {
                        return Err(ProxyError::Protocol(
                            "Trojan UDP datagram buffer overflow".into(),
                        ));
                    }
                    Err(ProxyError::Protocol(_)) => {
                        if acc.len() > 65507 {
                            return Err(ProxyError::Protocol(
                                "Trojan UDP datagram buffer overflow".into(),
                            ));
                        }
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok::<(), ProxyError>(())
    }
    .await;

    drop(reply_tx);
    let write_result = write_task
        .await
        .map_err(|e| ProxyError::Transport(format!("Trojan UDP writer task: {e}")))?;
    read_result?;
    write_result
}

/// Send one datagram to `upstream` and wait for a single reply.
async fn exchange_udp_datagram(
    upstream: std::net::SocketAddr,
    data: &[u8],
) -> Result<Option<Vec<u8>>, ProxyError> {
    let bind_addr = if upstream.ip().is_loopback() {
        "127.0.0.1:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| ProxyError::Transport(format!("Trojan UDP bind failed: {e}")))?;
    sock.send_to(data, upstream)
        .await
        .map_err(|e| ProxyError::Transport(format!("Trojan UDP send: {e}")))?;

    let mut buf = vec![0u8; 65535];
    match tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) if n > 0 => Ok(Some(buf[..n].to_vec())),
        Ok(Ok(_)) => Ok(None),
        Ok(Err(e)) => Err(ProxyError::Transport(format!("Trojan UDP recv: {e}"))),
        Err(_) => Ok(None),
    }
}

async fn resolve_udp_dest(dest: &Address) -> Result<std::net::SocketAddr, ProxyError> {
    match dest {
        Address::Ipv4(ip, port) => Ok(std::net::SocketAddr::new((*ip).into(), *port)),
        Address::Ipv6(ip, port) => Ok(std::net::SocketAddr::new((*ip).into(), *port)),
        Address::Domain(name, port) => {
            let mut addrs = tokio::net::lookup_host((name.as_str(), *port))
                .await
                .map_err(|e| ProxyError::DnsResolutionFailed(format!("{name}: {e}")))?;
            addrs
                .next()
                .ok_or_else(|| ProxyError::DnsResolutionFailed(name.clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trojan::codec::encode_udp_datagram;
    use blackwire_common::Address;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn relay_returns_udp_reply_on_duplex() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            sock.send_to(&buf[..n], peer).await.unwrap();
        });

        let (mut client, server) = tokio::io::duplex(8192);
        let dest = Address::Ipv4(std::net::Ipv4Addr::LOCALHOST, port);
        let dg = encode_udp_datagram(&dest, b"ping").unwrap();
        let relay = tokio::spawn(async move {
            relay_trojan_udp(Box::new(server) as BoxedStream)
                .await
                .unwrap();
        });

        client.write_all(&dg).await.unwrap();
        client.flush().await.unwrap();
        let mut acc = [0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut acc))
            .await
            .expect("timeout")
            .expect("read");
        assert!(n > 0, "expected reply bytes");
        drop(client);
        echo.await.unwrap();
        let _ = relay.await;
    }
}
