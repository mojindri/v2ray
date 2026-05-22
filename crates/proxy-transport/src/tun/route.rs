use anyhow::{Context as _, Result};
use tokio::process::Command;
use tracing::{info, warn};

pub async fn setup_routes(
    tun_name: &str,
    bypass_mark: u32,
    dns_port: u16,
    redirect_port: u16,
) -> Result<()> {
    let mark_hex = format!("0x{bypass_mark:x}");
    run(&["ip", "route", "add", "default", "dev", tun_name, "table", "100"]).await
        .context("add default route")?;
    run(&["ip", "rule", "add", "not", "fwmark", &mark_hex, "lookup", "100"]).await
        .context("add policy rule")?;
    run(&["iptables", "-t", "nat", "-A", "OUTPUT",
          "-p", "udp", "--dport", "53",
          "-j", "REDIRECT", "--to-port", &dns_port.to_string()]).await
        .context("iptables DNS redirect")?;
    run(&["iptables", "-t", "nat", "-A", "OUTPUT",
          "-p", "tcp", "-m", "mark", "!", "--mark", &mark_hex,
          "-j", "REDIRECT", "--to-port", &redirect_port.to_string()]).await
        .context("iptables TCP redirect")?;
    info!(%tun_name, "TUN routes installed");
    Ok(())
}

pub async fn cleanup_routes(
    tun_name: &str,
    bypass_mark: u32,
    dns_port: u16,
    redirect_port: u16,
) {
    let mark_hex = format!("0x{bypass_mark:x}");
    for cmd in &[
        vec!["ip", "route", "del", "default", "dev", tun_name, "table", "100"],
        vec!["ip", "rule", "del", "not", "fwmark", &mark_hex, "lookup", "100"],
        vec!["iptables", "-t", "nat", "-D", "OUTPUT",
             "-p", "udp", "--dport", "53",
             "-j", "REDIRECT", "--to-port", &dns_port.to_string()],
        vec!["iptables", "-t", "nat", "-D", "OUTPUT",
             "-p", "tcp", "-m", "mark", "!", "--mark", &mark_hex,
             "-j", "REDIRECT", "--to-port", &redirect_port.to_string()],
    ] {
        if let Err(e) = run(cmd).await {
            warn!(cmd = %cmd.join(" "), error = %e, "cleanup failed");
        }
    }
    info!(%tun_name, "TUN routes removed");
}

async fn run(args: &[&str]) -> Result<()> {
    let (prog, rest) = args.split_first().unwrap();
    let status = Command::new(prog).args(rest).status().await
        .with_context(|| format!("spawn {prog}"))?;
    if status.success() { Ok(()) }
    else { Err(anyhow::anyhow!("{} failed: {status}", args.join(" "))) }
}
