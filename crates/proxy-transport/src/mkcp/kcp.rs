use super::segment::{Segment, CMD_ACK, CMD_PUSH, CMD_WASK, CMD_WINS, OVERHEAD};
use bytes::{Bytes, BytesMut};
use std::collections::VecDeque;

const RTO_NDL: u32 = 30;
const RTO_MIN: u32 = 100;
const RTO_DEF: u32 = 200;
const RTO_MAX: u32 = 60_000;
const WND_SND: u16 = 32;
const WND_RCV: u16 = 128;
const THRESH_MIN: u16 = 2;
const THRESH_INIT: u16 = 2;
const PROBE_INIT: u32 = 7_000;
const PROBE_LIMIT: u32 = 120_000;
const DEAD_LINK: u32 = 20;

/// Minimal KCP protocol engine used by mKCP drivers.
pub struct Kcp {
    conv: u32,
    _mtu: usize,
    mss: u32,
    state: i32,
    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    ssthresh: u16,
    rx_rttval: u32,
    rx_srtt: u32,
    rx_rto: u32,
    rx_minrto: u32,
    snd_wnd: u16,
    rcv_wnd: u16,
    rmt_wnd: u16,
    cwnd: u16,
    probe: u32,
    current: u32,
    _interval: u32,
    ts_flush: u32,
    xmit: u32,
    nodelay: bool,
    updated: bool,
    ts_probe: u32,
    probe_wait: u32,
    dead_link: u32,
    incr: u32,
    snd_queue: VecDeque<Segment>,
    rcv_queue: VecDeque<Segment>,
    snd_buf: VecDeque<Segment>,
    rcv_buf: VecDeque<Segment>,
    acklist: Vec<(u32, u32)>,
    fastresend: u32,
    nocwnd: bool,
}

impl Kcp {
    /// Create a new KCP engine for one conversation ID.
    pub fn new(conv: u32) -> Self {
        let mtu = 1400usize;
        Self {
            conv,
            _mtu: mtu,
            mss: (mtu - OVERHEAD) as u32,
            state: 0,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            ssthresh: THRESH_INIT,
            rx_rttval: 0,
            rx_srtt: 0,
            rx_rto: RTO_DEF,
            rx_minrto: RTO_MIN,
            snd_wnd: WND_SND,
            rcv_wnd: WND_RCV,
            rmt_wnd: WND_RCV,
            cwnd: 0,
            probe: 0,
            current: 0,
            _interval: 100,
            ts_flush: 100,
            xmit: 0,
            nodelay: false,
            updated: false,
            ts_probe: 0,
            probe_wait: 0,
            dead_link: DEAD_LINK,
            incr: 0,
            snd_queue: VecDeque::new(),
            rcv_queue: VecDeque::new(),
            snd_buf: VecDeque::new(),
            rcv_buf: VecDeque::new(),
            acklist: Vec::new(),
            fastresend: 0,
            nocwnd: false,
        }
    }

    /// Enable or disable low-latency mode.
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nodelay = nodelay;
        self.rx_minrto = if nodelay { RTO_NDL } else { RTO_MIN };
    }

    /// Set send/receive window sizes in segments.
    ///
    /// Values of `0` are ignored.
    pub fn set_wndsize(&mut self, snd: u16, rcv: u16) {
        if snd > 0 {
            self.snd_wnd = snd;
        }
        if rcv > 0 {
            self.rcv_wnd = rcv;
        }
    }

    /// Return `true` when the session is considered dead.
    pub fn is_dead(&self) -> bool {
        self.state == -1
    }

    /// Read one fully reassembled message into `buf`.
    ///
    /// Returns:
    /// - `> 0`: number of bytes written
    /// - `-1`: no complete message ready
    /// - `-2`: `buf` is too small
    pub fn recv(&mut self, buf: &mut [u8]) -> i32 {
        if self.rcv_queue.is_empty() {
            return -1;
        }
        let peeksz = self.peeksize();
        if peeksz < 0 {
            return -1;
        }
        if peeksz > buf.len() as i32 {
            return -2;
        }
        let recover = self.rcv_queue.len() >= self.rcv_wnd as usize;
        let mut pos = 0usize;
        loop {
            let seg = match self.rcv_queue.pop_front() {
                None => break,
                Some(s) => s,
            };
            let n = seg.data.len();
            buf[pos..pos + n].copy_from_slice(&seg.data);
            pos += n;
            if seg.frg == 0 {
                break;
            }
        }
        self.move_rcv_buf();
        if recover && self.rcv_queue.len() < self.rcv_wnd as usize {
            self.probe |= 2;
        }
        pos as i32
    }

    /// Queue one application message for sending.
    ///
    /// Returns:
    /// - `0`: queued
    /// - `-1`: empty input
    /// - `-2`: message would need too many fragments
    pub fn send(&mut self, buf: &[u8]) -> i32 {
        if buf.is_empty() {
            return -1;
        }
        let mss = self.mss as usize;
        let count = buf.len().div_ceil(mss);
        if count >= 256 {
            return -2;
        }
        let mut offset = 0;
        for i in 0..count {
            let size = (buf.len() - offset).min(mss);
            let mut seg = Segment::new(self.conv, CMD_PUSH);
            seg.frg = (count - i - 1) as u8;
            seg.data = Bytes::copy_from_slice(&buf[offset..offset + size]);
            self.snd_queue.push_back(seg);
            offset += size;
        }
        0
    }

    /// Feed one or more received KCP segments into the engine.
    ///
    /// Returns `0` on success or a negative value on parse/validation failure.
    pub fn input(&mut self, data: &[u8]) -> i32 {
        let prev_una = self.snd_una;
        let mut maxack = 0u32;
        let mut latest_ts = 0u32;
        let mut flag = false;
        let mut cursor = data;
        while !cursor.is_empty() {
            let seg = match Segment::decode(&mut cursor) {
                None => return -1,
                Some(s) => s,
            };
            if seg.conv != self.conv {
                return -1;
            }
            self.rmt_wnd = seg.wnd;
            self.parse_una(seg.una);
            self.shrink_buf();
            match seg.cmd {
                CMD_ACK => {
                    let rtt = self.current.wrapping_sub(seg.ts);
                    self.update_ack(rtt);
                    self.parse_ack(seg.sn);
                    self.shrink_buf();
                    if !flag || seg.sn > maxack {
                        flag = true;
                        maxack = seg.sn;
                        latest_ts = seg.ts;
                    }
                }
                CMD_PUSH => {
                    if seg.sn < self.rcv_nxt + self.rcv_wnd as u32 {
                        self.acklist.push((seg.sn, seg.ts));
                        if seg.sn >= self.rcv_nxt {
                            self.parse_data(seg);
                        }
                    }
                }
                CMD_WASK => {
                    self.probe |= 2;
                }
                CMD_WINS => {}
                _ => return -3,
            }
        }
        if flag {
            self.parse_fastack(maxack);
        }
        if self.snd_una > prev_una && self.cwnd < self.rmt_wnd {
            let mss = self.mss;
            if (self.cwnd as u32) < self.ssthresh as u32 {
                self.cwnd += 1;
                self.incr += mss;
            } else {
                if self.incr < mss {
                    self.incr = mss;
                }
                self.incr += (mss * mss) / self.incr + mss / 16;
                if (self.cwnd as u32 + 1) * mss <= self.incr {
                    self.cwnd += 1;
                }
            }
            if self.cwnd > self.rmt_wnd {
                self.cwnd = self.rmt_wnd;
                self.incr = self.cwnd as u32 * mss;
            }
        }
        // suppress unused variable warning
        let _ = latest_ts;
        0
    }

    /// Update internal clocks before calling `flush`.
    pub fn update(&mut self, current: u32) {
        self.current = current;
        if !self.updated {
            self.updated = true;
            self.ts_flush = current;
        }
    }

    /// Flush outbound packets into `out`.
    ///
    /// Each entry in `out` is one encoded UDP payload to send.
    pub fn flush(&mut self, out: &mut Vec<Vec<u8>>) {
        if !self.updated {
            return;
        }
        let current = self.current;
        let mut change = false;
        let mut lost = false;

        for (sn, ts) in std::mem::take(&mut self.acklist) {
            let mut seg = Segment::new(self.conv, CMD_ACK);
            seg.wnd = self.wnd_unused();
            seg.ts = ts;
            seg.sn = sn;
            seg.una = self.rcv_nxt;
            out.push(self.encode_seg(&seg));
        }

        // Window probing
        if self.rmt_wnd == 0 {
            if self.probe_wait == 0 {
                self.probe_wait = PROBE_INIT;
                self.ts_probe = current + self.probe_wait;
            } else if current >= self.ts_probe {
                if self.probe_wait < PROBE_INIT {
                    self.probe_wait = PROBE_INIT;
                }
                self.probe_wait += self.probe_wait / 2;
                if self.probe_wait > PROBE_LIMIT {
                    self.probe_wait = PROBE_LIMIT;
                }
                self.ts_probe = current + self.probe_wait;
                self.probe |= 1;
            }
        } else {
            self.ts_probe = 0;
            self.probe_wait = 0;
        }

        if self.probe & 1 != 0 {
            let seg = self.make_ctrl(CMD_WASK);
            out.push(self.encode_seg(&seg));
        }
        if self.probe & 2 != 0 {
            let seg = self.make_ctrl(CMD_WINS);
            out.push(self.encode_seg(&seg));
        }
        self.probe = 0;

        let cwnd = {
            let c = self.snd_wnd.min(self.rmt_wnd);
            if self.nocwnd {
                c
            } else {
                c.min(self.cwnd)
            }
        };

        while self.snd_nxt < self.snd_una + cwnd as u32 {
            let mut seg = match self.snd_queue.pop_front() {
                None => break,
                Some(s) => s,
            };
            seg.conv = self.conv;
            seg.cmd = CMD_PUSH;
            seg.wnd = self.wnd_unused();
            seg.ts = current;
            seg.sn = self.snd_nxt;
            self.snd_nxt += 1;
            seg.una = self.rcv_nxt;
            seg.resendts = current;
            seg.rto = self.rx_rto;
            seg.xmit = 0;
            self.snd_buf.push_back(seg);
        }

        let resent = if self.fastresend > 0 {
            self.fastresend
        } else {
            u32::MAX
        };
        let rtomin = if !self.nodelay { self.rx_rto >> 3 } else { 0 };
        // pre-compute values that would require re-borrowing self inside the loop
        let wnd_unused = self.wnd_unused();
        let rcv_nxt = self.rcv_nxt;
        let dead_link = self.dead_link;
        let nodelay = self.nodelay;
        let rx_rto = self.rx_rto;
        let fastresend = self.fastresend;

        for seg in self.snd_buf.iter_mut() {
            let send = if seg.xmit == 0 {
                seg.xmit += 1;
                seg.rto = rx_rto;
                seg.resendts = current + seg.rto + rtomin;
                true
            } else if current >= seg.resendts {
                seg.xmit += 1;
                self.xmit += 1;
                seg.rto += if !nodelay {
                    rx_rto.max(seg.rto)
                } else {
                    rx_rto / 2
                };
                seg.resendts = current + seg.rto;
                lost = true;
                true
            } else if seg.fastack >= resent && seg.xmit <= fastresend {
                seg.xmit += 1;
                seg.fastack = 0;
                seg.resendts = current + seg.rto;
                change = true;
                true
            } else {
                false
            };

            if send {
                seg.ts = current;
                seg.wnd = wnd_unused;
                seg.una = rcv_nxt;
                let mut buf = BytesMut::with_capacity(OVERHEAD + seg.data.len());
                seg.encode(&mut buf);
                out.push(buf.to_vec());
                if seg.xmit >= dead_link {
                    self.state = -1;
                }
            }
        }

        if change {
            let inflight = self.snd_nxt.wrapping_sub(self.snd_una);
            self.ssthresh = ((inflight / 2) as u16).max(THRESH_MIN);
            self.cwnd = self.ssthresh + resent as u16;
            self.incr = self.cwnd as u32 * self.mss;
        }
        if lost {
            self.ssthresh = (cwnd / 2).max(THRESH_MIN);
            self.cwnd = 1;
            self.incr = self.mss;
        }
        if self.cwnd < 1 {
            self.cwnd = 1;
            self.incr = self.mss;
        }
    }

    fn peeksize(&self) -> i32 {
        let seg = match self.rcv_queue.front() {
            None => return -1,
            Some(s) => s,
        };
        if seg.frg == 0 {
            return seg.data.len() as i32;
        }
        if self.rcv_queue.len() < (seg.frg + 1) as usize {
            return -1;
        }
        self.rcv_queue.iter().map(|s| s.data.len() as i32).sum()
    }

    fn wnd_unused(&self) -> u16 {
        self.rcv_wnd.saturating_sub(self.rcv_queue.len() as u16)
    }

    fn make_ctrl(&self, cmd: u8) -> Segment {
        let mut seg = Segment::new(self.conv, cmd);
        seg.wnd = self.wnd_unused();
        seg.una = self.rcv_nxt;
        seg
    }

    fn encode_seg(&self, seg: &Segment) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(OVERHEAD + seg.data.len());
        seg.encode(&mut buf);
        buf.to_vec()
    }

    fn parse_una(&mut self, una: u32) {
        self.snd_buf.retain(|s| s.sn >= una);
    }
    fn shrink_buf(&mut self) {
        self.snd_una = self.snd_buf.front().map(|s| s.sn).unwrap_or(self.snd_nxt);
    }

    fn update_ack(&mut self, rtt: u32) {
        if self.rx_srtt == 0 {
            self.rx_srtt = rtt;
            self.rx_rttval = rtt / 2;
        } else {
            let delta = rtt.abs_diff(self.rx_srtt);
            self.rx_rttval = (3 * self.rx_rttval + delta) / 4;
            self.rx_srtt = (7 * self.rx_srtt + rtt) / 8;
            if self.rx_srtt < 1 {
                self.rx_srtt = 1;
            }
        }
        self.rx_rto = (self.rx_srtt + 4 * self.rx_rttval)
            .max(self.rx_minrto)
            .min(RTO_MAX);
    }

    fn parse_ack(&mut self, sn: u32) {
        if sn < self.snd_una || sn >= self.snd_nxt {
            return;
        }
        self.snd_buf.retain(|s| s.sn != sn);
    }

    fn parse_fastack(&mut self, sn: u32) {
        if sn < self.snd_una || sn >= self.snd_nxt {
            return;
        }
        for seg in self.snd_buf.iter_mut() {
            if seg.sn < sn {
                seg.fastack += 1;
            } else {
                break;
            }
        }
    }

    fn parse_data(&mut self, seg: Segment) {
        let sn = seg.sn;
        if sn >= self.rcv_nxt + self.rcv_wnd as u32 || sn < self.rcv_nxt {
            return;
        }
        if self.rcv_buf.iter().any(|s| s.sn == sn) {
            return;
        }
        let pos = self
            .rcv_buf
            .iter()
            .rposition(|s| s.sn < sn)
            .map(|i| i + 1)
            .unwrap_or(0);
        self.rcv_buf.insert(pos, seg);
        self.move_rcv_buf();
    }

    fn move_rcv_buf(&mut self) {
        while let Some(seg) = self.rcv_buf.front() {
            if seg.sn == self.rcv_nxt && self.rcv_queue.len() < self.rcv_wnd as usize {
                let Some(s) = self.rcv_buf.pop_front() else {
                    break;
                };
                self.rcv_nxt += 1;
                self.rcv_queue.push_back(s);
            } else {
                break;
            }
        }
    }
}
