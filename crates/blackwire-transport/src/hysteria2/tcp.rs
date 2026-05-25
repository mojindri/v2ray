//! TCP proxy over Hysteria2 QUIC streams.

use proxy_common::{Address, ProxyError};
use tokio::io::{AsyncRead, AsyncWrite};

use super::proto::{
    decode_tcp_request, decode_tcp_response, encode_tcp_request, encode_tcp_response, TcpResponse,
};

/// Format an [`Address`] as a Hysteria2 `host:port` string.
pub fn address_to_hysteria(addr: &Address) -> String {
    match addr {
        Address::Ipv4(ip, port) => format!("{ip}:{port}"),
        Address::Ipv6(ip, port) => format!("[{ip}]:{port}"),
        Address::Domain(host, port) => format!("{host}:{port}"),
    }
}

/// Parse a Hysteria2 `host:port` address string.
pub fn hysteria_to_address(addr: &str) -> Result<Address, ProxyError> {
    if let Some(inner) = addr.strip_prefix('[') {
        let (host, rest) = inner
            .split_once(']')
            .ok_or_else(|| ProxyError::Protocol(format!("bad IPv6 address: {addr}")))?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| ProxyError::Protocol(format!("bad IPv6 address: {addr}")))?
            .parse()
            .map_err(|_| ProxyError::Protocol(format!("bad port in address: {addr}")))?;
        let ip: std::net::Ipv6Addr = host
            .parse()
            .map_err(|_| ProxyError::Protocol(format!("bad IPv6 host: {host}")))?;
        return Ok(Address::Ipv6(ip, port));
    }

    let (host, port_str) = addr
        .rsplit_once(':')
        .ok_or_else(|| ProxyError::Protocol(format!("bad address: {addr}")))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| ProxyError::Protocol(format!("bad port in address: {addr}")))?;

    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        Ok(Address::Ipv4(ip, port))
    } else {
        Ok(Address::Domain(host.to_string(), port))
    }
}

/// Read and parse one TCP connect request on the server side.
pub async fn server_read_request<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<Address, ProxyError> {
    let req = decode_tcp_request(stream)
        .await
        .map_err(|e| ProxyError::Protocol(format!("bad TCP request: {e}")))?;
    hysteria_to_address(&req.addr)
}

/// Write a TCP connect response (`ok` + optional message) on the server side.
pub async fn server_write_response<W: AsyncWrite + Unpin>(
    stream: &mut W,
    ok: bool,
    msg: &str,
) -> Result<(), ProxyError> {
    let resp = TcpResponse {
        ok,
        message: msg.to_string(),
    };
    encode_tcp_response(stream, &resp)
        .await
        .map_err(ProxyError::Io)
}

/// Encode and send the client connect request for `dest`.
pub async fn client_write_request<W: AsyncWrite + Unpin>(
    stream: &mut W,
    dest: &Address,
) -> Result<(), ProxyError> {
    let addr = address_to_hysteria(dest);
    encode_tcp_request(stream, &addr)
        .await
        .map_err(ProxyError::Io)
}

/// Read the server response and return an error if connect was rejected.
pub async fn client_read_response<R: AsyncRead + Unpin>(stream: &mut R) -> Result<(), ProxyError> {
    let resp = decode_tcp_response(stream)
        .await
        .map_err(|e| ProxyError::Protocol(format!("bad TCP response: {e}")))?;
    if !resp.ok {
        return Err(ProxyError::Protocol(format!(
            "server refused connection: {}",
            resp.message
        )));
    }
    Ok(())
}
