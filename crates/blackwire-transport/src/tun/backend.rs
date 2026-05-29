use anyhow::Result;

/// Current platform's TUN runtime support level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunPlatformSupport {
    /// Human-readable platform backend name.
    pub backend: &'static str,
    /// Raw packet parsing/NAT/session helpers are available on this target.
    pub packet_api: bool,
    /// This crate can create a native OS TUN device on this target.
    pub device_backend: bool,
    /// This crate can run full-device routing on this target.
    pub full_device_runtime: bool,
    /// TCP flows can be redirected into the proxy TCP listener on this target.
    pub tcp_redirection: bool,
    /// UDP packets can be forwarded through the runtime NAT table on this target.
    pub udp_nat: bool,
    /// The runtime needs elevated OS privileges.
    pub requires_privileges: bool,
    /// Short operator-facing status note.
    pub note: &'static str,
}

/// Return the compile-time TUN support contract for the current target.
pub fn current_tun_support() -> TunPlatformSupport {
    #[cfg(target_os = "linux")]
    {
        TunPlatformSupport {
            backend: "linux",
            packet_api: true,
            device_backend: true,
            full_device_runtime: true,
            tcp_redirection: true,
            udp_nat: true,
            requires_privileges: true,
            note: "Linux /dev/net/tun runtime with iptables/ip-rule TCP redirection and UDP NAT",
        }
    }

    #[cfg(target_os = "macos")]
    {
        TunPlatformSupport {
            backend: "macos-utun",
            packet_api: true,
            device_backend: true,
            full_device_runtime: false,
            tcp_redirection: false,
            udp_nat: true,
            requires_privileges: true,
            note: "macOS utun device creation is wired, but full runtime requires native routing and TCP redirection before it can be supported",
        }
    }

    #[cfg(target_os = "windows")]
    {
        TunPlatformSupport {
            backend: "windows-wintun",
            packet_api: true,
            device_backend: true,
            full_device_runtime: false,
            tcp_redirection: false,
            udp_nat: true,
            requires_privileges: true,
            note: "Windows Wintun device creation is wired, but full runtime requires wintun.dll packaging plus native routing and TCP redirection before it can be supported",
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        TunPlatformSupport {
            backend: "unsupported",
            packet_api: true,
            device_backend: false,
            full_device_runtime: false,
            tcp_redirection: false,
            udp_nat: true,
            requires_privileges: true,
            note: "no native TUN backend is implemented for this target",
        }
    }
}

/// Fail early unless the current target has the complete TUN runtime contract.
pub fn ensure_tun_runtime_supported() -> Result<()> {
    let support = current_tun_support();
    if support.full_device_runtime {
        return Ok(());
    }

    anyhow::bail!(
        "TUN full-device runtime is not supported on {} yet: {}",
        support.backend,
        support.note
    );
}
