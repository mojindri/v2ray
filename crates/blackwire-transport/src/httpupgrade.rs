//! HTTPUpgrade transport — Xray `transport/internet/httpupgrade`.
//!
//! After the HTTP/1.1 `101 Switching Protocols` handshake the connection is a
//! raw byte tunnel (not a WebSocket frame codec).

use blackwire_common::{BoxedStream, PrependedStream, ProxyError};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use blackwire_config::schema::StreamSettingsConfig;

const MAX_HEADER_BYTES: usize = 8192;

/// Dial TCP, send HTTP/1.1 Upgrade request, return stream after `101 Switching Protocols`.
pub async fn dial_httpupgrade(
    server: std::net::SocketAddr,
    dest_domain: &str,
    stream_settings: &StreamSettingsConfig,
) -> Result<BoxedStream, ProxyError> {
    let (path, host) = httpupgrade_path_host(stream_settings, dest_domain);

    let mut stream = TcpStream::connect(server).await?;
    stream.set_nodelay(true)?;

    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         \r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;
    let response = std::str::from_utf8(&buf[..n])
        .map_err(|_| ProxyError::Protocol("HTTPUpgrade response not UTF-8".into()))?;
    if !response.starts_with("HTTP/1.1 101") && !response.starts_with("HTTP/1.0 101") {
        return Err(ProxyError::Protocol(format!(
            "HTTPUpgrade expected 101, got: {}",
            response.lines().next().unwrap_or("")
        )));
    }

    Ok(Box::new(stream))
}

/// Accept an inbound HTTPUpgrade request and return the upgraded byte stream.
pub async fn accept_httpupgrade(
    stream: BoxedStream,
    expected_path: Option<&str>,
) -> Result<BoxedStream, ProxyError> {
    let mut reader = BufReader::new(stream);
    let mut total_bytes = 0usize;
    let mut first_line = String::new();

    let n = reader.read_line(&mut first_line).await?;
    if n == 0 {
        return Err(ProxyError::Protocol("HTTPUpgrade: unexpected EOF".into()));
    }
    total_bytes += n;

    let (method, path) = parse_get_line(first_line.trim())?;
    if let Some(want) = expected_path {
        let got = path.split('?').next().unwrap_or(&path);
        let want_base = want.split('?').next().unwrap_or(want);
        if got != want_base {
            return Err(ProxyError::Protocol(format!(
                "HTTPUpgrade: path mismatch (got '{got}', want '{want_base}')"
            )));
        }
    }

    let mut has_upgrade = false;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(ProxyError::Protocol(
                "HTTPUpgrade: unexpected EOF in headers".into(),
            ));
        }
        total_bytes += n;
        if total_bytes > MAX_HEADER_BYTES {
            return Err(ProxyError::Protocol(
                "HTTPUpgrade: headers too large".into(),
            ));
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if line.to_ascii_lowercase().starts_with("upgrade:") {
            has_upgrade = true;
        }
    }

    if !method.eq_ignore_ascii_case("GET") {
        return Err(ProxyError::Protocol(format!(
            "HTTPUpgrade: expected GET, got '{method}'"
        )));
    }
    if !has_upgrade {
        return Err(ProxyError::Protocol(
            "HTTPUpgrade: missing Upgrade header".into(),
        ));
    }

    let remainder = reader.buffer().to_vec();
    let mut inner = reader.into_inner();
    inner
        .write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        )
        .await?;
    inner.flush().await?;

    let stream = if remainder.is_empty() {
        inner
    } else {
        Box::new(PrependedStream::new(inner, remainder)) as BoxedStream
    };

    Ok(stream)
}

fn parse_get_line(line: &str) -> Result<(String, String), ProxyError> {
    let mut parts = line.splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let path = parts
        .next()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| ProxyError::Protocol("HTTPUpgrade: missing path".into()))?
        .to_string();
    let _version = parts
        .next()
        .ok_or_else(|| ProxyError::Protocol("HTTPUpgrade: missing HTTP version".into()))?;
    Ok((method, path))
}

fn httpupgrade_path_host(
    stream_settings: &StreamSettingsConfig,
    dest_domain: &str,
) -> (String, String) {
    let cfg = stream_settings
        .httpupgrade_settings
        .as_ref()
        .or(stream_settings.ws_settings.as_ref());
    let path = cfg
        .map(|c| c.path.clone())
        .unwrap_or_else(|| "/".to_string());
    let host = cfg
        .and_then(|c| {
            c.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.clone())
        })
        .or_else(|| {
            stream_settings
                .tls_settings
                .as_ref()
                .map(|t| t.server_name.clone())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| dest_domain.to_string());
    (path, host)
}

/// Resolve the configured HTTPUpgrade path for inbound acceptance.
pub fn httpupgrade_listen_path(stream_settings: &StreamSettingsConfig) -> Option<String> {
    stream_settings
        .httpupgrade_settings
        .as_ref()
        .or(stream_settings.ws_settings.as_ref())
        .map(|c| c.path.clone())
}
