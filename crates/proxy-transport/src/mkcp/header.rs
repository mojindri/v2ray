use std::sync::atomic::{AtomicU32, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/// Packet disguise header used by mKCP UDP frames.
pub enum HeaderType {
    /// No extra header bytes.
    #[default]
    None,
    /// 4-byte SRTP-like header.
    Srtp,
    /// 4-byte uTP-like header.
    Utp,
    /// 4-byte WeChat-video-like header.
    WechatVideo,
    /// 13-byte DTLS-like record header.
    Dtls,
    /// 4-byte WireGuard-like header.
    Wireguard,
}

impl HeaderType {
    /// Return the number of disguise-header bytes for this type.
    pub fn size(self) -> usize {
        match self {
            HeaderType::None => 0,
            HeaderType::Srtp
            | HeaderType::Utp
            | HeaderType::WechatVideo
            | HeaderType::Wireguard => 4,
            HeaderType::Dtls => 13,
        }
    }

    /// Prefix a payload with the configured disguise header.
    pub fn encode(self, payload: &[u8]) -> Vec<u8> {
        let hdr = self.size();
        let mut out = vec![0u8; hdr + payload.len()];
        self.write_header(&mut out[..hdr]);
        out[hdr..].copy_from_slice(payload);
        out
    }

    /// Remove the configured disguise header from a packet.
    ///
    /// Returns `None` when the packet is shorter than the header.
    pub fn strip(self, packet: &[u8]) -> Option<&[u8]> {
        let hdr = self.size();
        if packet.len() < hdr {
            return None;
        }
        Some(&packet[hdr..])
    }

    fn write_header(self, buf: &mut [u8]) {
        match self {
            HeaderType::None => {}
            HeaderType::Srtp => {
                buf[0] = 0x80;
                buf[1] = 0x61;
                let r = (buf.as_ptr() as u32).wrapping_mul(0x9e3779b9);
                buf[2] = (r >> 8) as u8;
                buf[3] = r as u8;
            }
            HeaderType::Utp => {
                buf[0] = 0x01;
                buf[1] = 0x00;
                let r = (buf.as_ptr() as u32).wrapping_mul(0x9e3779b9);
                buf[2] = (r >> 8) as u8;
                buf[3] = r as u8;
            }
            HeaderType::WechatVideo => {
                static C: AtomicU32 = AtomicU32::new(0);
                let c = C.fetch_add(1, Ordering::Relaxed);
                buf[0] = 0xa1;
                buf[1] = 0x08;
                buf[2] = (c >> 8) as u8;
                buf[3] = c as u8;
            }
            HeaderType::Dtls => {
                static C: AtomicU32 = AtomicU32::new(0);
                let c = C.fetch_add(1, Ordering::Relaxed);
                buf[0] = 0x16;
                buf[1] = 0xfe;
                buf[2] = 0xff;
                buf[3] = 0;
                buf[4] = 0;
                buf[5] = 0;
                buf[6] = 0;
                buf[7] = (c >> 24) as u8;
                buf[8] = (c >> 16) as u8;
                buf[9] = (c >> 8) as u8;
                buf[10] = c as u8;
                buf[11] = 0;
                buf[12] = 0;
            }
            HeaderType::Wireguard => {
                buf[0] = 0x04;
                buf[1] = 0;
                buf[2] = 0;
                buf[3] = 0;
            }
        }
    }
}

impl std::str::FromStr for HeaderType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Ok(match s {
            "none" => HeaderType::None,
            "srtp" => HeaderType::Srtp,
            "utp" => HeaderType::Utp,
            "wechat-video" => HeaderType::WechatVideo,
            "dtls" => HeaderType::Dtls,
            "wireguard" => HeaderType::Wireguard,
            o => return Err(format!("unknown header type: {o}")),
        })
    }
}
