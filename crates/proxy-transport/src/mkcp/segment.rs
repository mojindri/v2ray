use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const OVERHEAD: usize = 24;
pub const CMD_PUSH: u8 = 81;
pub const CMD_ACK: u8 = 82;
pub const CMD_WASK: u8 = 83;
pub const CMD_WINS: u8 = 84;

#[derive(Debug, Clone)]
pub struct Segment {
    pub conv: u32,
    pub cmd: u8,
    pub frg: u8,
    pub wnd: u16,
    pub ts: u32,
    pub sn: u32,
    pub una: u32,
    pub data: Bytes,
    // retransmission bookkeeping (not serialised)
    pub resendts: u32,
    pub rto: u32,
    pub fastack: u32,
    pub xmit: u32,
}

impl Segment {
    pub fn new(conv: u32, cmd: u8) -> Self {
        Self {
            conv, cmd, frg: 0, wnd: 0, ts: 0, sn: 0, una: 0,
            data: Bytes::new(),
            resendts: 0, rto: 200, fastack: 0, xmit: 0,
        }
    }

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

    pub fn decode(src: &mut &[u8]) -> Option<Self> {
        if src.len() < OVERHEAD { return None; }
        let conv = src.get_u32_le();
        let cmd = src.get_u8();
        let frg = src.get_u8();
        let wnd = src.get_u16_le();
        let ts = src.get_u32_le();
        let sn = src.get_u32_le();
        let una = src.get_u32_le();
        let len = src.get_u32_le() as usize;
        if src.len() < len { return None; }
        let data = Bytes::copy_from_slice(&src[..len]);
        src.advance(len);
        Some(Self { conv, cmd, frg, wnd, ts, sn, una, data, resendts: 0, rto: 200, fastack: 0, xmit: 0 })
    }
}
