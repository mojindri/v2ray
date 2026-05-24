use anyhow::Result;
use tracing::info;

#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub address: std::net::Ipv4Addr,
    pub netmask: std::net::Ipv4Addr,
    pub mtu: u16,
    pub bypass_mark: u32,
    pub redirect_port: u16,
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
            name: "proxy-tun".into(),
            address,
            netmask,
            mtu: 1500,
            bypass_mark: 0x1234,
            redirect_port: 7890,
            dns_port: 5300,
        }
    }
}

pub fn create_tun(config: &TunConfig) -> Result<tun::AsyncDevice> {
    let mut cfg = tun::Configuration::default();
    cfg.tun_name(&config.name)
        .address(config.address)
        .netmask(config.netmask)
        .mtu(config.mtu)
        .up();

    #[cfg(target_os = "linux")]
    cfg.platform_config(|p| {
        p.ensure_root_privileges(true);
    });

    let dev = tun::create_as_async(&cfg)?;
    info!(name = %config.name, address = %config.address, mtu = config.mtu, "TUN interface created");
    Ok(dev)
}
