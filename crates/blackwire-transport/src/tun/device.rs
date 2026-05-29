use anyhow::Result;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use tracing::info;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use super::backend::current_tun_support;

/// Platform TUN device type used by [`TunRuntime`].
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub type TunDevice = tun::AsyncDevice;

/// Placeholder device type for platforms whose TUN backend is not implemented yet.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[derive(Debug)]
pub struct TunDevice;

/// Settings used when creating the OS TUN interface.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Interface name (for example `blackwire-tun`).
    pub name: String,
    /// IPv4 address assigned to the TUN interface.
    pub address: std::net::Ipv4Addr,
    /// IPv4 netmask assigned to the TUN interface.
    pub netmask: std::net::Ipv4Addr,
    /// MTU for the interface.
    pub mtu: u16,
    /// Packet mark used to bypass TUN redirection rules.
    pub bypass_mark: u32,
    /// Local TCP port where redirected TCP flows are sent.
    pub redirect_port: u16,
    /// Local UDP port where redirected DNS packets are sent.
    pub dns_port: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        let address: std::net::Ipv4Addr = "198.18.0.1"
            .parse()
            .expect("valid default TUN address literal");
        let netmask: std::net::Ipv4Addr = "255.255.0.0"
            .parse()
            .expect("valid default TUN netmask literal");
        Self {
            name: "blackwire-tun".into(),
            address,
            netmask,
            mtu: 1500,
            bypass_mark: 0x1234,
            redirect_port: 7890,
            dns_port: 5300,
        }
    }
}

/// Create and bring up an async TUN device using `config`.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn create_tun(config: &TunConfig) -> Result<TunDevice> {
    let mut cfg = tun::Configuration::default();

    configure_tun_name(&mut cfg, &config.name);

    cfg.address(config.address)
        .netmask(config.netmask)
        .mtu(config.mtu)
        .up();

    #[cfg(target_os = "linux")]
    cfg.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    #[cfg(target_os = "macos")]
    cfg.platform_config(|p| {
        p.packet_information(true);
        p.enable_routing(false);
    });

    let dev = tun::create_as_async(&cfg)?;
    info!(name = %config.name, address = %config.address, mtu = config.mtu, "TUN interface created");
    Ok(dev)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn configure_tun_name(cfg: &mut tun::Configuration, name: &str) {
    cfg.tun_name(name);
}

#[cfg(target_os = "macos")]
fn configure_tun_name(cfg: &mut tun::Configuration, name: &str) {
    if is_macos_utun_name(name) {
        cfg.tun_name(name);
    }
}

#[cfg(target_os = "macos")]
fn is_macos_utun_name(name: &str) -> bool {
    name.strip_prefix("utun")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
}

/// Return a clear unsupported error until a native backend exists.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn create_tun(_config: &TunConfig) -> Result<TunDevice> {
    let support = current_tun_support();
    anyhow::bail!(
        "TUN device backend is not supported on {} yet: {}",
        support.backend,
        support.note
    );
}
