use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Number of bytes in the fixed KCP segment header.
pub const OVERHEAD: usize = 24;
/// KCP command: push data segment.
pub const CMD_PUSH: u8 = 81;
/// KCP command: acknowledge received segment.
pub const CMD_ACK: u8 = 82;
/// KCP command: ask peer to report its window size.
pub const CMD_WASK: u8 = 83;
/// KCP command: report current receive window size.
pub const CMD_WINS: u8 = 84;

#[derive(Debug, Clone)]
/// One KCP segment (header + payload + local resend metadata).
pub struct Segment {
    /// Conversation ID for this session.
    pub conv: u32,
    /// KCP command code (`CMD_PUSH`, `CMD_ACK`, ...).
    pub cmd: u8,
    /// Fragment index (0 means last fragment).
    pub frg: u8,
    /// Receiver window size advertised by sender.
    pub wnd: u16,
    /// Sender timestamp used for RTT and ordering logic.
    pub ts: u32,
    /// Segment sequence number.
    pub sn: u32,
    /// Lowest unacknowledged sequence number on sender side.
    pub una: u32,
    /// Application payload bytes.
    pub data: Bytes,
    // retransmission bookkeeping (not serialised)
    /// Next resend timestamp (local state, not serialized).
    pub resendts: u32,
    /// Retransmission timeout in milliseconds (local state).
    pub rto: u32,
    /// Fast-ack counter used by fast retransmit (local state).
    pub fastack: u32,
    /// Number of times this segment has been sent (local state).
    pub xmit: u32,
}

impl Segment {
    /// Build a new empty segment with default retransmit state.
    pub fn new(conv: u32, cmd: u8) -> Self {
        Self {
            conv,
            cmd,
            frg: 0,
            wnd: 0,
            ts: 0,
            sn: 0,
            una: 0,
            data: Bytes::new(),
            resendts: 0,
            rto: 200,
            fastack: 0,
            xmit: 0,
        }
    }

    /// Encode this segment to wire format and append to `dst`.
    pub fn encode(&self, dst: &mut BytesMut) {
        dst.put_u32_le(self.conv);
        dst.put_u8(self.cmd);
        dst.put_u8(self.frg);
        dst.put_u16_le(self.wnd);
        dst.put_u32_le(self.ts);
        dst.put_u32_le(self.sn);
        dst.put_u32_le(self.una);
        dst.put_u32_le(self.data.len() as u32);
        dst.extend_from_slice(&self.data);
    }

    /// Decode one segment from `src`, advancing the slice on success.
    ///
    /// Returns `None` if there are not enough bytes.
    pub fn decode(src: &mut &[u8]) -> Option<Self> {
        if src.len() < OVERHEAD {
            return None;
        }
        let conv = src.get_u32_le();
        let cmd = src.get_u8();
        let frg = src.get_u8();
        let wnd = src.get_u16_le();
        let ts = src.get_u32_le();
        let sn = src.get_u32_le();
        let una = src.get_u32_le();
        let len = src.get_u32_le() as usize;
        if src.len() < len {
            return None;
        }
        let data = Bytes::copy_from_slice(&src[..len]);
        src.advance(len);
        Some(Self {
            conv,
            cmd,
            frg,
            wnd,
            ts,
            sn,
            una,
            data,
            resendts: 0,
            rto: 200,
            fastack: 0,
            xmit: 0,
        })
    }
}
