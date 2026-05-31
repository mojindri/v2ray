//! VLESS Mux.Cool framing and inbound demux (Xray `common/mux`, `common/xudp`).
//!
//! Wire format: <https://xtls.github.io/en/development/protocols/muxcool.html>
//!
//! **XUDP** (sing-box `packet_encoding: xudp`, Xray mux + GlobalID): session id
//! `0`, 8-byte GlobalID on the first UDP `New` frame with `Opt(D)`, and per-packet
//! destination on UDP `Keep` replies (Xray `common/xudp/xudp.go`).
//!
//!   \[u16 metadata length\]\[metadata\]\[optional u16 data length + payload\]

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{BufMut, BytesMut};
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use blackwire_app::context::Context;
use blackwire_app::dispatcher::Dispatcher;
use blackwire_common::{Address, BoxedStream, ProxyError};

use super::codec::{decode_address_port_with_len, encode_address_port, Command};

/// Mux session id used by XUDP (Xray always sends `0` for XUDP frames).
pub const XUDP_SESSION_ID: u16 = 0;

/// Xray `MuxCoolAddress` — VLESS/VMess mux marker destination.
pub use super::codec::MUX_COOL_DOMAIN as MUX_DOMAIN;

/// Metadata option: frame carries extra payload (`Opt(D)`).
pub const OPT_DATA: u8 = 0x01;

const MAX_META_LEN: usize = 512;
const MAX_DATA_LEN: usize = 512 * 1024;

/// Mux session status byte (metadata byte 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionStatus {
    /// Open a new mux sub-connection.
    New = 0x01,
    /// Continue an existing sub-connection (may carry payload).
    Keep = 0x02,
    /// Close a sub-connection.
    End = 0x03,
    /// Session keep-alive with no payload.
    KeepAlive = 0x04,
}

impl SessionStatus {
    fn from_byte(b: u8) -> Result<Self, ProxyError> {
        match b {
            0x01 => Ok(Self::New),
            0x02 => Ok(Self::Keep),
            0x03 => Ok(Self::End),
            0x04 => Ok(Self::KeepAlive),
            other => Err(ProxyError::Protocol(format!(
                "mux: unknown session status {other:#x}"
            ))),
        }
    }
}

/// Target network in a New (or UDP Keep) metadata block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TargetNetwork {
    /// TCP sub-connection target.
    Tcp = 0x01,
    /// UDP sub-connection target (XUDP).
    Udp = 0x02,
}

impl TargetNetwork {
    fn from_byte(b: u8) -> Result<Self, ProxyError> {
        match b {
            0x01 => Ok(Self::Tcp),
            0x02 => Ok(Self::Udp),
            other => Err(ProxyError::Protocol(format!(
                "mux: unknown target network {other:#x}"
            ))),
        }
    }
}

/// Parsed Mux.Cool metadata (without the outer length prefix or payload).
#[derive(Debug, Clone)]
pub struct FrameMetadata {
    /// Mux session identifier (0 for XUDP).
    pub session_id: u16,
    /// Frame lifecycle status (`New`, `Keep`, `End`, `KeepAlive`).
    pub status: SessionStatus,
    /// Metadata option flags (e.g. [`OPT_DATA`]).
    pub option: u8,
    /// Present on `New` and on UDP `Keep` when address fields follow.
    pub target: Option<(TargetNetwork, Address)>,
    /// XUDP: present on first UDP `New` with `Opt(D)` after the target address.
    pub global_id: Option<[u8; 8]>,
}

/// Returns true when the VLESS request should enter Mux.Cool demux.
pub fn is_mux_request(command: Command, dest: &Address) -> bool {
    command == Command::Mux || is_mux_cool_dest(dest)
}

/// True when the destination is the internal mux marker (`v1.mux.cool`).
pub fn is_mux_cool_dest(dest: &Address) -> bool {
    matches!(dest, Address::Domain(host, _) if host == MUX_DOMAIN)
}

/// Build metadata bytes for a New sub-connection (TCP target only).
pub fn encode_new_metadata(
    session_id: u16,
    dest: &Address,
    opt: u8,
) -> Result<Vec<u8>, ProxyError> {
    let mut meta = BytesMut::with_capacity(64);
    meta.put_u16(session_id);
    meta.put_u8(SessionStatus::New as u8);
    meta.put_u8(opt);
    meta.put_u8(TargetNetwork::Tcp as u8);
    meta.extend_from_slice(&encode_address_port(dest)?);
    Ok(meta.to_vec())
}

/// Build metadata bytes for an End frame.
pub fn encode_end_metadata(session_id: u16, opt: u8) -> Vec<u8> {
    let mut meta = Vec::with_capacity(4);
    meta.extend_from_slice(&session_id.to_be_bytes());
    meta.push(SessionStatus::End as u8);
    meta.push(opt);
    meta
}

/// Build metadata for an XUDP first UDP packet (`New` + GlobalID).
pub fn encode_new_metadata_xudp(
    dest: &Address,
    global_id: &[u8; 8],
    opt: u8,
) -> Result<Vec<u8>, ProxyError> {
    let mut meta = BytesMut::with_capacity(64);
    meta.put_u16(XUDP_SESSION_ID);
    meta.put_u8(SessionStatus::New as u8);
    meta.put_u8(opt);
    meta.put_u8(TargetNetwork::Udp as u8);
    meta.extend_from_slice(&encode_address_port(dest)?);
    meta.extend_from_slice(global_id);
    Ok(meta.to_vec())
}

/// Build metadata for an XUDP / mux UDP `Keep` with per-packet destination.
pub fn encode_keep_metadata_udp(
    session_id: u16,
    dest: &Address,
    opt: u8,
) -> Result<Vec<u8>, ProxyError> {
    let mut meta = BytesMut::with_capacity(48);
    meta.put_u16(session_id);
    meta.put_u8(SessionStatus::Keep as u8);
    meta.put_u8(opt);
    meta.put_u8(TargetNetwork::Udp as u8);
    meta.extend_from_slice(&encode_address_port(dest)?);
    Ok(meta.to_vec())
}

/// Build metadata bytes for a Keep frame (no address extension).
pub fn encode_keep_metadata(session_id: u16, opt: u8) -> Vec<u8> {
    let mut meta = Vec::with_capacity(4);
    meta.extend_from_slice(&session_id.to_be_bytes());
    meta.push(SessionStatus::Keep as u8);
    meta.push(opt);
    meta
}

/// Encode a full mux frame (metadata length + metadata + optional payload).
pub fn encode_frame(metadata: &[u8], payload: Option<&[u8]>) -> Result<Vec<u8>, ProxyError> {
    if metadata.len() > MAX_META_LEN {
        return Err(ProxyError::Protocol("mux: metadata too long".into()));
    }
    let mut out =
        BytesMut::with_capacity(4 + metadata.len() + payload.map(|p| p.len() + 2).unwrap_or(0));
    out.put_u16(metadata.len() as u16);
    out.extend_from_slice(metadata);
    if let Some(data) = payload {
        if data.len() > MAX_DATA_LEN {
            return Err(ProxyError::Protocol("mux: payload too long".into()));
        }
        out.put_u16(data.len() as u16);
        out.extend_from_slice(data);
    }
    Ok(out.to_vec())
}

/// Skip optional inbound source/local blocks after a `New` target (Xray `FrameMetadata::WriteTo`).
fn skip_mux_inbound_extensions(mut rest: &[u8]) -> Result<&[u8], ProxyError> {
    for _ in 0..2 {
        if rest.is_empty() {
            break;
        }
        if rest[0] == 0 {
            rest = &rest[1..];
            continue;
        }
        let _network = TargetNetwork::from_byte(rest[0])?;
        rest = &rest[1..];
        let consumed = decode_address_port_with_len(rest)?.1;
        rest = &rest[consumed..];
    }
    Ok(rest)
}

/// Parse metadata from `meta` (the L-byte block after the outer length prefix).
pub fn parse_metadata(meta: &[u8]) -> Result<FrameMetadata, ProxyError> {
    if meta.len() < 4 {
        return Err(ProxyError::Protocol("mux: metadata too short".into()));
    }
    let session_id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = SessionStatus::from_byte(meta[2])?;
    let option = meta[3];
    let mut rest = &meta[4..];
    let mut target = None;
    let mut global_id = None;

    if status == SessionStatus::New {
        if rest.is_empty() {
            return Err(ProxyError::Protocol("mux: New missing target".into()));
        }
        let network = TargetNetwork::from_byte(rest[0])?;
        rest = &rest[1..];
        let (addr, consumed) = decode_address_port_with_len(rest)?;
        rest = &rest[consumed..];
        target = Some((network, addr));
        if network == TargetNetwork::Tcp {
            rest = skip_mux_inbound_extensions(rest)?;
        }
        if network == TargetNetwork::Udp && option & OPT_DATA != 0 && rest.len() >= 8 {
            let mut gid = [0u8; 8];
            gid.copy_from_slice(&rest[..8]);
            global_id = Some(gid);
        }
    } else if status == SessionStatus::Keep
        && !rest.is_empty()
        && matches!(TargetNetwork::from_byte(rest[0]), Ok(TargetNetwork::Udp))
    {
        let network = TargetNetwork::from_byte(rest[0])?;
        rest = &rest[1..];
        let (addr, _) = decode_address_port_with_len(rest)?;
        target = Some((network, addr));
    }

    Ok(FrameMetadata {
        session_id,
        status,
        option,
        target,
        global_id,
    })
}

/// True when metadata matches XUDP framing (session `0` + UDP target).
pub fn is_xudp_metadata(meta: &FrameMetadata) -> bool {
    meta.session_id == XUDP_SESSION_ID
        && matches!(meta.target, Some((TargetNetwork::Udp, _)))
        && (meta.status == SessionStatus::Keep
            || (meta.status == SessionStatus::New && meta.global_id.is_some()))
}

/// Parse one mux frame from a byte buffer; returns bytes consumed.
pub fn parse_frame(buf: &[u8]) -> Result<(FrameMetadata, Option<Vec<u8>>, usize), ProxyError> {
    if buf.len() < 2 {
        return Err(ProxyError::Protocol("mux: frame too short".into()));
    }
    let meta_len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
    if meta_len > MAX_META_LEN {
        return Err(ProxyError::Protocol(format!(
            "mux: invalid metadata length {meta_len}"
        )));
    }
    let need = 2 + meta_len;
    if buf.len() < need {
        return Err(ProxyError::Protocol("mux: truncated metadata".into()));
    }
    let meta = parse_metadata(&buf[2..need])?;
    let mut consumed = need;
    let payload = if meta.option & OPT_DATA != 0 {
        if buf.len() < need + 2 {
            return Err(ProxyError::Protocol("mux: truncated payload length".into()));
        }
        let data_len = usize::from(u16::from_be_bytes([buf[need], buf[need + 1]]));
        if data_len > MAX_DATA_LEN {
            return Err(ProxyError::Protocol(format!(
                "mux: invalid payload length {data_len}"
            )));
        }
        consumed += 2 + data_len;
        if buf.len() < consumed {
            return Err(ProxyError::Protocol("mux: truncated payload".into()));
        }
        Some(buf[need + 2..consumed].to_vec())
    } else {
        None
    };
    Ok((meta, payload, consumed))
}

async fn read_mux_frame<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<(FrameMetadata, Option<Vec<u8>>), ProxyError> {
    let meta_len = reader.read_u16().await? as usize;
    if meta_len > MAX_META_LEN {
        return Err(ProxyError::Protocol(format!(
            "mux: invalid metadata length {meta_len}"
        )));
    }
    let mut meta_buf = vec![0u8; meta_len];
    reader.read_exact(&mut meta_buf).await?;
    let meta = parse_metadata(&meta_buf)?;
    let payload = if meta.option & OPT_DATA != 0 {
        let data_len = reader.read_u16().await? as usize;
        if data_len > MAX_DATA_LEN {
            return Err(ProxyError::Protocol(format!(
                "mux: invalid payload length {data_len}"
            )));
        }
        let mut data = vec![0u8; data_len];
        if data_len > 0 {
            reader.read_exact(&mut data).await?;
        }
        Some(data)
    } else {
        None
    };
    Ok((meta, payload))
}

async fn write_mux_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    metadata: &[u8],
    payload: Option<&[u8]>,
) -> Result<(), ProxyError> {
    let frame = encode_frame(metadata, payload)?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

struct MuxSession {
    upstream: Arc<tokio::sync::Mutex<BoxedStream>>,
    reader_task: tokio::task::JoinHandle<()>,
}

struct MuxUdpSession {
    socket: Arc<UdpSocket>,
    dest: Address,
    reader_task: tokio::task::JoinHandle<()>,
}

struct XudpUdpSession {
    socket: Arc<UdpSocket>,
    reader_task: tokio::task::JoinHandle<()>,
}

fn socket_addr_to_address(peer: SocketAddr) -> Address {
    match peer {
        SocketAddr::V4(v4) => Address::Ipv4(*v4.ip(), v4.port()),
        SocketAddr::V6(v6) => Address::Ipv6(*v6.ip(), v6.port()),
    }
}

async fn resolve_udp_dest(dest: &Address) -> Result<SocketAddr, ProxyError> {
    match dest {
        Address::Ipv4(ip, port) => Ok(SocketAddr::from((*ip, *port))),
        Address::Ipv6(ip, port) => Ok(SocketAddr::from((*ip, *port))),
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

/// Demux Mux.Cool sub-streams on an authenticated VLESS connection.
pub async fn relay_mux_cool(
    stream: BoxedStream,
    ctx: Context,
    dispatcher: Arc<dyn Dispatcher>,
) -> Result<(), ProxyError> {
    let (mut reader, writer) = tokio::io::split(stream);
    let mux_writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<BoxedStream>>> =
        Arc::new(tokio::sync::Mutex::new(writer));
    let sessions: Arc<DashMap<u16, Arc<MuxSession>>> = Arc::new(DashMap::new());
    let udp_sessions: Arc<DashMap<u16, Arc<MuxUdpSession>>> = Arc::new(DashMap::new());
    let xudp_sessions: Arc<DashMap<[u8; 8], Arc<XudpUdpSession>>> = Arc::new(DashMap::new());
    let active_xudp: Arc<tokio::sync::Mutex<Option<[u8; 8]>>> =
        Arc::new(tokio::sync::Mutex::new(None));

    loop {
        let (meta, payload) = match read_mux_frame(&mut reader).await {
            Ok(v) => v,
            Err(ProxyError::Transport(_)) => break,
            Err(e) if matches!(&e, ProxyError::Protocol(_)) => return Err(e),
            Err(_) => break,
        };

        match meta.status {
            SessionStatus::New => {
                if is_xudp_metadata(&meta) {
                    let Some((_, dest)) = meta.target.clone() else {
                        return Err(ProxyError::Protocol("mux: New without target".into()));
                    };
                    let global_id = meta.global_id.expect("checked by is_xudp_metadata");
                    debug!(
                        session_id = meta.session_id,
                        %dest,
                        global_id = %hex::encode(global_id),
                        "mux: new XUDP flow"
                    );
                    if let Some((_, old)) = xudp_sessions.remove(&global_id) {
                        old.reader_task.abort();
                    }
                    let socket = Arc::new(
                        UdpSocket::bind("0.0.0.0:0")
                            .await
                            .map_err(|e| ProxyError::Transport(format!("xudp bind: {e}")))?,
                    );
                    if let Some(ref data) = payload {
                        if !data.is_empty() {
                            let upstream = resolve_udp_dest(&dest).await?;
                            socket.send_to(data, upstream).await.map_err(|e| {
                                ProxyError::Transport(format!("xudp UDP send: {e}"))
                            })?;
                        }
                    }
                    let writer = Arc::clone(&mux_writer);
                    let sid = meta.session_id;
                    let sock_reader = Arc::clone(&socket);
                    let reader_task = tokio::spawn(async move {
                        mux_xudp_to_client(writer, sid, sock_reader).await;
                    });
                    xudp_sessions.insert(
                        global_id,
                        Arc::new(XudpUdpSession {
                            socket,
                            reader_task,
                        }),
                    );
                    *active_xudp.lock().await = Some(global_id);
                    continue;
                }
                let Some((network, dest)) = meta.target else {
                    return Err(ProxyError::Protocol("mux: New without target".into()));
                };
                match network {
                    TargetNetwork::Tcp => {
                        debug!(
                            session_id = meta.session_id,
                            %dest,
                            "mux: new TCP sub-connection"
                        );
                        let mut upstream =
                            dispatcher
                                .connect_outbound(&ctx, &dest)
                                .await
                                .map_err(|e| {
                                    warn!(
                                        session_id = meta.session_id,
                                        %dest,
                                        error = %e,
                                        "mux: outbound connect failed"
                                    );
                                    e
                                })?;
                        if let Some(ref data) = payload {
                            if !data.is_empty() {
                                upstream.write_all(data).await?;
                            }
                        }
                        let upstream = Arc::new(tokio::sync::Mutex::new(upstream));
                        let writer = Arc::clone(&mux_writer);
                        let sid = meta.session_id;
                        let upstream_reader = Arc::clone(&upstream);
                        let reader_task = tokio::spawn(async move {
                            mux_upstream_to_client(writer, sid, upstream_reader).await;
                        });
                        sessions.insert(
                            meta.session_id,
                            Arc::new(MuxSession {
                                upstream,
                                reader_task,
                            }),
                        );
                    }
                    TargetNetwork::Udp => {
                        debug!(
                            session_id = meta.session_id,
                            %dest,
                            "mux: new UDP sub-connection"
                        );
                        let socket =
                            Arc::new(UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
                                ProxyError::Transport(format!("mux UDP bind: {e}"))
                            })?);
                        let upstream = resolve_udp_dest(&dest).await?;
                        socket.connect(upstream).await.map_err(|e| {
                            ProxyError::Transport(format!("mux UDP connect: {e}"))
                        })?;
                        if let Some(ref data) = payload {
                            if !data.is_empty() {
                                socket.send(data).await.map_err(|e| {
                                    ProxyError::Transport(format!("mux UDP send: {e}"))
                                })?;
                            }
                        }
                        let writer = Arc::clone(&mux_writer);
                        let sid = meta.session_id;
                        let sock_reader = Arc::clone(&socket);
                        let dest_copy = dest.clone();
                        let reader_task = tokio::spawn(async move {
                            mux_udp_to_client(writer, sid, sock_reader, dest_copy).await;
                        });
                        udp_sessions.insert(
                            meta.session_id,
                            Arc::new(MuxUdpSession {
                                socket,
                                dest,
                                reader_task,
                            }),
                        );
                    }
                }
            }
            SessionStatus::Keep => {
                if let Some((network, dest)) = meta.target {
                    if network == TargetNetwork::Udp {
                        if meta.session_id == XUDP_SESSION_ID {
                            let gid = *active_xudp.lock().await;
                            if let Some(gid) = gid {
                                if let Some(session) = xudp_sessions.get(&gid) {
                                    if let Some(ref data) = payload {
                                        if !data.is_empty() {
                                            let upstream = resolve_udp_dest(&dest).await?;
                                            session.socket.send_to(data, upstream).await.map_err(
                                                |e| {
                                                    ProxyError::Transport(format!(
                                                        "xudp UDP send: {e}"
                                                    ))
                                                },
                                            )?;
                                        }
                                    }
                                }
                            }
                            continue;
                        }
                        if let Some(session) = udp_sessions.get(&meta.session_id) {
                            if let Some(ref data) = payload {
                                if !data.is_empty() {
                                    if dest == session.dest {
                                        session.socket.send(data).await.map_err(|e| {
                                            ProxyError::Transport(format!("mux UDP send: {e}"))
                                        })?;
                                    } else {
                                        let upstream = resolve_udp_dest(&dest).await?;
                                        session.socket.send_to(data, upstream).await.map_err(
                                            |e| ProxyError::Transport(format!("mux UDP send: {e}")),
                                        )?;
                                    }
                                }
                            }
                        }
                        continue;
                    }
                }
                if let Some(session) = sessions.get(&meta.session_id) {
                    if let Some(ref data) = payload {
                        if !data.is_empty() {
                            let mut up = session.upstream.lock().await;
                            up.write_all(data).await?;
                        }
                    }
                } else if let Some(session) = udp_sessions.get(&meta.session_id) {
                    if let Some(ref data) = payload {
                        if !data.is_empty() {
                            session
                                .socket
                                .send(data)
                                .await
                                .map_err(|e| ProxyError::Transport(format!("mux UDP send: {e}")))?;
                        }
                    }
                } else {
                    debug!(
                        session_id = meta.session_id,
                        "mux: Keep for unknown session"
                    );
                }
            }
            SessionStatus::End => {
                if let Some(ref data) = payload {
                    if !data.is_empty() {
                        if let Some(session) = sessions.get(&meta.session_id) {
                            let mut up = session.upstream.lock().await;
                            let _ = up.write_all(data).await;
                        } else if let Some(session) = udp_sessions.get(&meta.session_id) {
                            let _ = session.socket.send(data).await;
                        }
                    }
                }
                if let Some((_, session)) = sessions.remove(&meta.session_id) {
                    session.reader_task.abort();
                    let mut up = session.upstream.lock().await;
                    let _ = up.shutdown().await;
                }
                if let Some((_, session)) = udp_sessions.remove(&meta.session_id) {
                    session.reader_task.abort();
                }
                if meta.session_id == XUDP_SESSION_ID {
                    let gid = active_xudp.lock().await.take();
                    if let Some(gid) = gid {
                        if let Some((_, session)) = xudp_sessions.remove(&gid) {
                            session.reader_task.abort();
                        }
                    }
                }
            }
            SessionStatus::KeepAlive => {
                // Payload must be discarded per spec.
            }
        }
    }

    for entry in sessions.iter() {
        entry.value().reader_task.abort();
    }
    for entry in udp_sessions.iter() {
        entry.value().reader_task.abort();
    }
    for entry in xudp_sessions.iter() {
        entry.value().reader_task.abort();
    }
    Ok(())
}

async fn mux_xudp_to_client(
    mux_writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<BoxedStream>>>,
    session_id: u16,
    socket: Arc<UdpSocket>,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, peer)) if n > 0 => {
                let reply_dest = socket_addr_to_address(peer);
                let meta = match encode_keep_metadata_udp(session_id, &reply_dest, OPT_DATA) {
                    Ok(m) => m,
                    Err(_) => break,
                };
                let mut guard = mux_writer.lock().await;
                if write_mux_frame(&mut *guard, &meta, Some(&buf[..n]))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            _ => break,
        }
    }
    let end_meta = encode_end_metadata(session_id, 0);
    let mut guard = mux_writer.lock().await;
    let _ = write_mux_frame(&mut *guard, &end_meta, None).await;
}

async fn mux_udp_to_client(
    mux_writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<BoxedStream>>>,
    session_id: u16,
    socket: Arc<UdpSocket>,
    _reply_dest: Address,
) {
    let mut buf = vec![0u8; 65535];
    loop {
        match socket.recv(&mut buf).await {
            Ok(n) if n > 0 => {
                let meta = encode_keep_metadata(session_id, OPT_DATA);
                let mut guard = mux_writer.lock().await;
                if write_mux_frame(&mut *guard, &meta, Some(&buf[..n]))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            _ => break,
        }
    }
    let end_meta = encode_end_metadata(session_id, 0);
    let mut guard = mux_writer.lock().await;
    let _ = write_mux_frame(&mut *guard, &end_meta, None).await;
}

async fn mux_upstream_to_client(
    mux_writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<BoxedStream>>>,
    session_id: u16,
    upstream: Arc<tokio::sync::Mutex<BoxedStream>>,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = {
            let mut up = upstream.lock().await;
            match up.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            }
        };
        let meta = encode_keep_metadata(session_id, OPT_DATA);
        let mut guard = mux_writer.lock().await;
        if write_mux_frame(&mut *guard, &meta, Some(&buf[..n]))
            .await
            .is_err()
        {
            break;
        }
    }
    let end_meta = encode_end_metadata(session_id, 0);
    let mut guard = mux_writer.lock().await;
    let _ = write_mux_frame(&mut *guard, &end_meta, None).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use blackwire_app::context::Context;
    use blackwire_app::dispatcher::Dispatcher;
    use blackwire_common::{tcp_connect, Address, BoxedStream};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct EchoDispatcher;

    #[async_trait]
    impl Dispatcher for EchoDispatcher {
        async fn dispatch(
            &self,
            _ctx: Context,
            _dest: Address,
            _inbound_stream: BoxedStream,
        ) -> Result<(), ProxyError> {
            Ok(())
        }

        async fn connect_outbound(
            &self,
            _ctx: &Context,
            dest: &Address,
        ) -> Result<BoxedStream, ProxyError> {
            let socket_addr = match dest {
                Address::Ipv4(ip, port) => SocketAddr::from((*ip, *port)),
                _ => return Err(ProxyError::Protocol("mux test: ipv4 only".into())),
            };
            Ok(Box::new(tcp_connect(socket_addr).await?))
        }
    }

    async fn spawn_echo() -> u16 {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut b = [0u8; 4096];
                    while let Ok(n) = s.read(&mut b).await {
                        if n == 0 {
                            break;
                        }
                        let _ = s.write_all(&b[..n]).await;
                    }
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn relay_mux_echoes_over_freedom_path() {
        let echo_port = spawn_echo().await;
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server = Box::new(server_io) as BoxedStream;
        let mut client = client_io;

        let ctx = Context::new("mux-test", "127.0.0.1:1".parse().unwrap());
        let dispatcher = Arc::new(EchoDispatcher);
        tokio::spawn(async move {
            relay_mux_cool(server, ctx, dispatcher).await.unwrap();
        });

        let dest = Address::Ipv4(Ipv4Addr::LOCALHOST, echo_port);
        let payload = b"MUX-ECHO\n";
        let meta = encode_new_metadata(42, &dest, OPT_DATA).unwrap();
        let frame = encode_frame(&meta, Some(payload)).unwrap();
        client.write_all(&frame).await.unwrap();

        let mut raw = vec![0u8; 4096];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut raw))
            .await
            .expect("timed out")
            .expect("read failed");
        let (parsed, data, _) = parse_frame(&raw[..n]).expect("parse mux reply");
        assert_eq!(parsed.status, SessionStatus::Keep);
        assert_eq!(data.as_deref(), Some(payload.as_ref()));
    }

    #[test]
    fn roundtrip_new_frame_with_payload() {
        let dest = Address::Ipv4(Ipv4Addr::new(203, 0, 113, 9), 443);
        let meta = encode_new_metadata(7, &dest, OPT_DATA).unwrap();
        let frame = encode_frame(&meta, Some(b"hello")).unwrap();
        let (parsed, payload, n) = parse_frame(&frame).unwrap();
        assert_eq!(n, frame.len());
        assert_eq!(parsed.session_id, 7);
        assert_eq!(parsed.status, SessionStatus::New);
        assert_eq!(payload.as_deref(), Some(b"hello".as_ref()));
        let (net, addr) = parsed.target.unwrap();
        assert_eq!(net, TargetNetwork::Tcp);
        assert_eq!(addr, dest);
    }

    #[test]
    fn new_metadata_skips_xray_inbound_source_local() {
        let dest = Address::Ipv4(Ipv4Addr::new(203, 0, 113, 9), 443);
        let mut meta = encode_new_metadata(3, &dest, OPT_DATA).unwrap();
        // Xray appends SOCKS inbound source (TCP) + local (TCP) after target on client-originated New.
        let source = Address::Ipv4(Ipv4Addr::new(10, 0, 0, 1), 1080);
        let local = Address::Ipv4(Ipv4Addr::new(10, 0, 0, 2), 1080);
        meta.push(TargetNetwork::Tcp as u8);
        meta.extend_from_slice(&encode_address_port(&source).unwrap());
        meta.push(TargetNetwork::Tcp as u8);
        meta.extend_from_slice(&encode_address_port(&local).unwrap());
        let parsed = parse_metadata(&meta).unwrap();
        assert_eq!(parsed.session_id, 3);
        assert_eq!(parsed.target, Some((TargetNetwork::Tcp, dest)));
    }

    #[test]
    fn xudp_new_metadata_roundtrip() {
        let dest = Address::Ipv4(Ipv4Addr::new(1, 1, 1, 1), 53);
        let gid = [0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1];
        let meta = encode_new_metadata_xudp(&dest, &gid, OPT_DATA).unwrap();
        let parsed = parse_metadata(&meta).unwrap();
        assert_eq!(parsed.session_id, XUDP_SESSION_ID);
        assert_eq!(parsed.status, SessionStatus::New);
        assert_eq!(parsed.global_id, Some(gid));
        assert!(is_xudp_metadata(&parsed));
        let (net, addr) = parsed.target.unwrap();
        assert_eq!(net, TargetNetwork::Udp);
        assert_eq!(addr, dest);
    }

    #[test]
    fn xudp_keep_metadata_includes_dest() {
        let dest = Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8), 53);
        let meta = encode_keep_metadata_udp(XUDP_SESSION_ID, &dest, OPT_DATA).unwrap();
        let parsed = parse_metadata(&meta).unwrap();
        assert_eq!(parsed.status, SessionStatus::Keep);
        assert_eq!(parsed.target, Some((TargetNetwork::Udp, dest)));
    }

    #[test]
    fn is_mux_request_detects_cmd_and_domain() {
        assert!(is_mux_request(
            Command::Mux,
            &Address::Domain("example.com".into(), 443)
        ));
        assert!(is_mux_request(
            Command::Tcp,
            &Address::Domain(MUX_DOMAIN.into(), 0)
        ));
        assert!(!is_mux_request(
            Command::Tcp,
            &Address::Domain("example.com".into(), 443)
        ));
    }
}
