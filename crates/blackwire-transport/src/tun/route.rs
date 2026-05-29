#[cfg(any(test, target_os = "macos", target_os = "windows"))]
use anyhow::bail;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use anyhow::Context as _;
use anyhow::Result;

#[cfg(target_os = "macos")]
use std::{fs, path::PathBuf};

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use tokio::process::Command;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use tracing::{info, warn};

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use super::backend::ensure_tun_runtime_supported;
use super::device::TunConfig;

/// Installed platform route/redirection state for one TUN runtime.
///
/// The guard stores enough config to clean up platform rules after the packet
/// loop exits. Cleanup is explicit because it must run async process/OS calls.
pub struct TunRouteGuard {
    config: TunConfig,
}

impl TunRouteGuard {
    /// Remove route/redirection state installed by [`setup_runtime_routes`].
    pub async fn cleanup(self) {
        cleanup_runtime_routes(&self.config).await;
    }
}

/// Install route/redirection state for the active platform.
pub async fn setup_runtime_routes(config: &TunConfig) -> Result<TunRouteGuard> {
    setup_platform_routes(config).await?;
    Ok(TunRouteGuard {
        config: config.clone(),
    })
}

/// Remove route/redirection state for the active platform.
pub async fn cleanup_runtime_routes(config: &TunConfig) {
    cleanup_platform_routes(config).await;
}

#[cfg(target_os = "linux")]
async fn setup_platform_routes(config: &TunConfig) -> Result<()> {
    setup_routes(
        &config.name,
        config.bypass_mark,
        config.dns_port,
        config.redirect_port,
    )
    .await
}

#[cfg(target_os = "linux")]
async fn cleanup_platform_routes(config: &TunConfig) {
    cleanup_routes(
        &config.name,
        config.bypass_mark,
        config.dns_port,
        config.redirect_port,
    )
    .await;
}

#[cfg(target_os = "macos")]
async fn setup_platform_routes(config: &TunConfig) -> Result<()> {
    setup_macos_routes(config).await
}

#[cfg(target_os = "macos")]
async fn cleanup_platform_routes(config: &TunConfig) {
    cleanup_macos_routes(config).await;
}

#[cfg(target_os = "windows")]
async fn setup_platform_routes(config: &TunConfig) -> Result<()> {
    setup_windows_routes(config).await
}

#[cfg(target_os = "windows")]
async fn cleanup_platform_routes(config: &TunConfig) {
    cleanup_windows_routes(config).await;
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
async fn setup_platform_routes(_config: &TunConfig) -> Result<()> {
    ensure_tun_runtime_supported()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
async fn cleanup_platform_routes(_config: &TunConfig) {}

/// Applies Linux policy routing and iptables rules that redirect all
/// non-bypass-marked traffic through the TUN interface.
///
/// IPv4 rules are mandatory and cause the function to return an error (with
/// rollback) if any step fails. IPv6 rules are best-effort: failure is logged
/// as a warning so the proxy still works for IPv4-only environments.
///
/// Call [`cleanup_routes`] to undo every rule this function installed.
#[cfg(target_os = "linux")]
pub async fn setup_routes(
    tun_name: &str,
    bypass_mark: u32,
    dns_port: u16,
    redirect_port: u16,
) -> Result<()> {
    let mark = format!("0x{bypass_mark:x}");
    let dns = dns_port.to_string();
    let redir = redirect_port.to_string();

    let mut rb = RollbackList::default();

    // ── IPv4: policy routing ────────────────────────────────────────────────
    must(
        &[
            "ip", "route", "add", "default", "dev", tun_name, "table", "100",
        ],
        &[
            "ip", "route", "del", "default", "dev", tun_name, "table", "100",
        ],
        &mut rb,
        "add IPv4 default route via TUN",
    )
    .await?;

    must(
        &["ip", "rule", "add", "not", "fwmark", &mark, "lookup", "100"],
        &["ip", "rule", "del", "not", "fwmark", &mark, "lookup", "100"],
        &mut rb,
        "add IPv4 policy rule",
    )
    .await?;

    // ── IPv4: iptables ──────────────────────────────────────────────────────
    must(
        &[
            "iptables",
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-port",
            &dns,
        ],
        &[
            "iptables",
            "-t",
            "nat",
            "-D",
            "OUTPUT",
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-port",
            &dns,
        ],
        &mut rb,
        "iptables: redirect DNS UDP to proxy",
    )
    .await?;

    must(
        &[
            "iptables",
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "-m",
            "mark",
            "!",
            "--mark",
            &mark,
            "-j",
            "REDIRECT",
            "--to-port",
            &redir,
        ],
        &[
            "iptables",
            "-t",
            "nat",
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "-m",
            "mark",
            "!",
            "--mark",
            &mark,
            "-j",
            "REDIRECT",
            "--to-port",
            &redir,
        ],
        &mut rb,
        "iptables: redirect TCP to proxy",
    )
    .await?;

    // ── IPv6: policy routing (best-effort) ──────────────────────────────────
    try_best_effort(
        &[
            "ip", "-6", "route", "add", "default", "dev", tun_name, "table", "100",
        ],
        "ip -6 route add",
    )
    .await;

    try_best_effort(
        &[
            "ip", "-6", "rule", "add", "not", "fwmark", &mark, "lookup", "100",
        ],
        "ip -6 rule add",
    )
    .await;

    // ── IPv6: ip6tables (best-effort) ───────────────────────────────────────
    try_best_effort(
        &[
            "ip6tables",
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-port",
            &dns,
        ],
        "ip6tables: redirect DNS UDP",
    )
    .await;

    try_best_effort(
        &[
            "ip6tables",
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "-m",
            "mark",
            "!",
            "--mark",
            &mark,
            "-j",
            "REDIRECT",
            "--to-port",
            &redir,
        ],
        "ip6tables: redirect TCP",
    )
    .await;

    info!(%tun_name, "TUN routes installed");
    Ok(())
}

/// Removes all rules that [`setup_routes`] installed.
///
/// Errors are logged as warnings and do not short-circuit; every undo command
/// is attempted regardless of whether earlier ones fail.
#[cfg(target_os = "linux")]
pub async fn cleanup_routes(tun_name: &str, bypass_mark: u32, dns_port: u16, redirect_port: u16) {
    let mark = format!("0x{bypass_mark:x}");
    let dns = dns_port.to_string();
    let redir = redirect_port.to_string();

    let cmds: &[&[&str]] = &[
        // IPv4
        &[
            "ip", "route", "del", "default", "dev", tun_name, "table", "100",
        ],
        &["ip", "rule", "del", "not", "fwmark", &mark, "lookup", "100"],
        &[
            "iptables",
            "-t",
            "nat",
            "-D",
            "OUTPUT",
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-port",
            &dns,
        ],
        &[
            "iptables",
            "-t",
            "nat",
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "-m",
            "mark",
            "!",
            "--mark",
            &mark,
            "-j",
            "REDIRECT",
            "--to-port",
            &redir,
        ],
        // IPv6 (best-effort)
        &[
            "ip", "-6", "route", "del", "default", "dev", tun_name, "table", "100",
        ],
        &[
            "ip", "-6", "rule", "del", "not", "fwmark", &mark, "lookup", "100",
        ],
        &[
            "ip6tables",
            "-t",
            "nat",
            "-D",
            "OUTPUT",
            "-p",
            "udp",
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-port",
            &dns,
        ],
        &[
            "ip6tables",
            "-t",
            "nat",
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "-m",
            "mark",
            "!",
            "--mark",
            &mark,
            "-j",
            "REDIRECT",
            "--to-port",
            &redir,
        ],
    ];

    for cmd in cmds {
        if let Err(e) = run(cmd).await {
            warn!(cmd = %cmd.join(" "), error = %e, "route cleanup step failed (ignored)");
        }
    }

    info!(%tun_name, "TUN routes removed");
}

/// Applies macOS utun route and PF redirection state.
///
/// The runtime routes IPv4 traffic through the utun interface using split
/// default routes. PF then redirects TCP and DNS packets that arrive on that
/// utun interface to the local proxy listeners. Outbound proxy sockets must be
/// bound to the physical egress interface so they do not re-enter the utun path.
#[cfg(target_os = "macos")]
pub async fn setup_macos_routes(config: &TunConfig) -> Result<()> {
    validate_macos_runtime_config(config)?;

    let pf_rules = macos_pf_rules(config)?;
    let pf_rules_path = macos_pf_rules_path(&config.name);
    fs::write(&pf_rules_path, pf_rules).with_context(|| {
        format!(
            "write macOS PF rules to {}",
            pf_rules_path.to_string_lossy()
        )
    })?;

    let mut rb = RollbackList::default();

    must(
        &[
            "route",
            "-n",
            "add",
            "-net",
            "0.0.0.0/1",
            "-interface",
            &config.name,
        ],
        &[
            "route",
            "-n",
            "delete",
            "-net",
            "0.0.0.0/1",
            "-interface",
            &config.name,
        ],
        &mut rb,
        "add macOS lower split default route via utun",
    )
    .await?;

    must(
        &[
            "route",
            "-n",
            "add",
            "-net",
            "128.0.0.0/1",
            "-interface",
            &config.name,
        ],
        &[
            "route",
            "-n",
            "delete",
            "-net",
            "128.0.0.0/1",
            "-interface",
            &config.name,
        ],
        &mut rb,
        "add macOS upper split default route via utun",
    )
    .await?;

    must(
        &[
            "pfctl",
            "-a",
            MACOS_PF_ANCHOR,
            "-f",
            pf_rules_path
                .to_str()
                .context("macOS PF rules path is not valid UTF-8")?,
        ],
        &["pfctl", "-a", MACOS_PF_ANCHOR, "-F", "all"],
        &mut rb,
        "load macOS PF TUN redirection anchor",
    )
    .await?;

    enable_macos_pf(&config.name).await?;

    let _ = fs::remove_file(&pf_rules_path);
    info!(tun_name = %config.name, anchor = MACOS_PF_ANCHOR, "macOS TUN routes installed");
    Ok(())
}

/// Removes macOS route/PF state installed by [`setup_macos_routes`].
#[cfg(target_os = "macos")]
pub async fn cleanup_macos_routes(config: &TunConfig) {
    let cmds: &[&[&str]] = &[
        &["pfctl", "-a", MACOS_PF_ANCHOR, "-F", "all"],
        &[
            "route",
            "-n",
            "delete",
            "-net",
            "0.0.0.0/1",
            "-interface",
            &config.name,
        ],
        &[
            "route",
            "-n",
            "delete",
            "-net",
            "128.0.0.0/1",
            "-interface",
            &config.name,
        ],
    ];

    for cmd in cmds {
        if let Err(e) = run(cmd).await {
            warn!(cmd = %cmd.join(" "), error = %e, "macOS TUN cleanup step failed (ignored)");
        }
    }

    disable_macos_pf(&config.name).await;
    let _ = fs::remove_file(macos_pf_rules_path(&config.name));
    info!(tun_name = %config.name, "macOS TUN routes removed");
}

#[cfg(target_os = "macos")]
const MACOS_PF_ANCHOR: &str = "blackwire/tun";

#[cfg(target_os = "macos")]
fn validate_macos_runtime_config(config: &TunConfig) -> Result<()> {
    if !is_safe_interface_name(&config.name) {
        bail!("invalid macOS TUN interface name: {}", config.name);
    }
    if !config.name.starts_with("utun") {
        bail!("macOS TUN runtime requires a utun interface name");
    }

    let Some(outbound_interface) = &config.outbound_interface else {
        bail!(
            "macOS TUN runtime requires tun.outboundInterface/tun.outbound_interface so proxy egress can bypass utun capture"
        );
    };
    if !is_safe_interface_name(outbound_interface) {
        bail!("invalid macOS outbound interface name: {outbound_interface}");
    }

    Ok(())
}

#[cfg(any(test, target_os = "macos"))]
fn build_macos_pf_rules(tun_name: &str, dns_port: u16, redirect_port: u16) -> Result<String> {
    if !is_safe_interface_name(tun_name) {
        bail!("invalid macOS TUN interface name: {tun_name}");
    }

    Ok(format!(
        "\
set skip on lo0
rdr pass on {tun_name} inet proto tcp from any to any -> 127.0.0.1 port {redirect_port}
rdr pass on {tun_name} inet proto udp from any to any port 53 -> 127.0.0.1 port {dns_port}
"
    ))
}

#[cfg(target_os = "macos")]
fn macos_pf_rules(config: &TunConfig) -> Result<String> {
    build_macos_pf_rules(&config.name, config.dns_port, config.redirect_port)
}

#[cfg(any(test, target_os = "macos"))]
fn is_safe_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

#[cfg(target_os = "macos")]
fn macos_pf_rules_path(tun_name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("blackwire-pf-{tun_name}.conf"))
}

#[cfg(target_os = "macos")]
fn macos_pf_token_path(tun_name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("blackwire-pf-{tun_name}.token"))
}

#[cfg(target_os = "macos")]
async fn enable_macos_pf(tun_name: &str) -> Result<()> {
    let output = run_output(&["pfctl", "-E"])
        .await
        .context("enable macOS PF")?;
    if let Some(token) = parse_macos_pf_token(&output) {
        let token_path = macos_pf_token_path(tun_name);
        fs::write(&token_path, token)
            .with_context(|| format!("write macOS PF token to {}", token_path.to_string_lossy()))?;
    } else {
        warn!(
            "macOS PF enabled without a parsed reference token; cleanup will only flush the anchor"
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
async fn disable_macos_pf(tun_name: &str) {
    let token_path = macos_pf_token_path(tun_name);
    let Ok(token) = fs::read_to_string(&token_path) else {
        return;
    };
    let token = token.trim();
    if token.is_empty() {
        return;
    }

    if let Err(e) = run(&["pfctl", "-X", token]).await {
        warn!(%token, error = %e, "failed to release macOS PF enable token (ignored)");
    }
    let _ = fs::remove_file(token_path);
}

#[cfg(any(test, target_os = "macos"))]
fn parse_macos_pf_token(output: &str) -> Option<String> {
    output
        .split_whitespace()
        .find(|part| part.bytes().all(|b| b.is_ascii_digit()))
        .map(ToOwned::to_owned)
}

/// Applies Windows Wintun split-default route state.
///
/// This sends IPv4 traffic into the Wintun adapter. TCP is handled by the
/// runtime's packet-level bridge because Windows does not expose an iptables/PF
/// equivalent for arbitrary original-destination redirects.
#[cfg(target_os = "windows")]
pub async fn setup_windows_routes(config: &TunConfig) -> Result<()> {
    validate_windows_runtime_config(config)?;

    let mut rb = RollbackList::default();
    let route_pairs = windows_route_command_pairs(&config.name);
    for pair in &route_pairs {
        let setup = pair.setup_refs();
        let undo = pair.undo_refs();
        must(&setup, &undo, &mut rb, pair.label.as_str()).await?;
    }

    info!(tun_name = %config.name, "Windows Wintun routes installed");
    Ok(())
}

/// Removes Windows Wintun route state installed by [`setup_windows_routes`].
#[cfg(target_os = "windows")]
pub async fn cleanup_windows_routes(config: &TunConfig) {
    for cmd in windows_route_delete_commands(&config.name) {
        let args = cmd.as_refs();
        if let Err(e) = run(&args).await {
            warn!(cmd = %cmd.args.join(" "), error = %e, "Windows TUN cleanup step failed (ignored)");
        }
    }
    info!(tun_name = %config.name, "Windows Wintun routes removed");
}

#[cfg(target_os = "windows")]
fn validate_windows_runtime_config(config: &TunConfig) -> Result<()> {
    if !is_safe_windows_interface_name(&config.name) {
        bail!("invalid Windows TUN interface name: {}", config.name);
    }
    Ok(())
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsRouteCommand {
    args: Vec<String>,
}

#[cfg(any(test, target_os = "windows"))]
#[cfg_attr(test, allow(dead_code))]
impl WindowsRouteCommand {
    fn as_refs(&self) -> Vec<&str> {
        self.args.iter().map(String::as_str).collect()
    }
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone)]
struct WindowsRouteCommandPair {
    #[cfg_attr(test, allow(dead_code))]
    label: String,
    setup: WindowsRouteCommand,
    undo: WindowsRouteCommand,
}

#[cfg(any(test, target_os = "windows"))]
#[cfg_attr(test, allow(dead_code))]
impl WindowsRouteCommandPair {
    fn setup_refs(&self) -> Vec<&str> {
        self.setup.as_refs()
    }

    fn undo_refs(&self) -> Vec<&str> {
        self.undo.as_refs()
    }
}

#[cfg(any(test, target_os = "windows"))]
fn windows_route_command_pairs(interface_name: &str) -> Vec<WindowsRouteCommandPair> {
    ["0.0.0.0/1", "128.0.0.0/1"]
        .into_iter()
        .map(|prefix| WindowsRouteCommandPair {
            label: format!("add Windows split default route {prefix} via Wintun"),
            setup: windows_route_add_command(interface_name, prefix),
            undo: windows_route_delete_command(interface_name, prefix),
        })
        .collect()
}

#[cfg(any(test, target_os = "windows"))]
#[cfg_attr(test, allow(dead_code))]
fn windows_route_delete_commands(interface_name: &str) -> Vec<WindowsRouteCommand> {
    ["0.0.0.0/1", "128.0.0.0/1"]
        .into_iter()
        .map(|prefix| windows_route_delete_command(interface_name, prefix))
        .collect()
}

#[cfg(any(test, target_os = "windows"))]
fn windows_route_add_command(interface_name: &str, prefix: &str) -> WindowsRouteCommand {
    WindowsRouteCommand {
        args: vec![
            "netsh".into(),
            "interface".into(),
            "ipv4".into(),
            "add".into(),
            "route".into(),
            format!("prefix={prefix}"),
            format!("interface={interface_name}"),
            "nexthop=0.0.0.0".into(),
            "metric=1".into(),
            "store=active".into(),
        ],
    }
}

#[cfg(any(test, target_os = "windows"))]
fn windows_route_delete_command(interface_name: &str, prefix: &str) -> WindowsRouteCommand {
    WindowsRouteCommand {
        args: vec![
            "netsh".into(),
            "interface".into(),
            "ipv4".into(),
            "delete".into(),
            "route".into(),
            format!("prefix={prefix}"),
            format!("interface={interface_name}"),
            "nexthop=0.0.0.0".into(),
            "store=active".into(),
        ],
    }
}

#[cfg(any(test, target_os = "windows"))]
fn is_safe_windows_interface_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(['\0', '\r', '\n']) && name.len() <= 256
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Accumulated undo commands for partial-failure rollback.
#[derive(Default)]
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
struct RollbackList {
    undos: Vec<Vec<String>>,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl RollbackList {
    async fn rollback(self) {
        for undo in self.undos.into_iter().rev() {
            let args: Vec<&str> = undo.iter().map(String::as_str).collect();
            if let Err(e) = run(&args).await {
                warn!(cmd = %undo.join(" "), error = %e, "rollback step failed (ignored)");
            }
        }
    }
}

/// Run a mandatory setup command. On failure, roll back all previous steps.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn must(setup: &[&str], undo: &[&str], rb: &mut RollbackList, ctx: &str) -> Result<()> {
    if let Err(e) = run(setup).await.with_context(|| ctx.to_string()) {
        // Take the list so we can call rollback (consumes self).
        let taken = std::mem::take(rb);
        taken.rollback().await;
        return Err(e);
    }
    rb.undos.push(undo.iter().map(|s| s.to_string()).collect());
    Ok(())
}

/// Run a best-effort command, logging a warning on failure.
#[cfg(target_os = "linux")]
async fn try_best_effort(cmd: &[&str], label: &str) {
    if let Err(e) = run(cmd).await {
        warn!(label, error = %e, "best-effort route step failed (IPv6 may not be proxied)");
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn run(args: &[&str]) -> Result<()> {
    let (prog, rest) = args.split_first().expect("non-empty command");
    let status = Command::new(prog)
        .args(rest)
        .status()
        .await
        .with_context(|| format!("spawn {prog}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("{} failed: {status}", args.join(" ")))
    }
}

#[cfg(target_os = "macos")]
async fn run_output(args: &[&str]) -> Result<String> {
    let (prog, rest) = args.split_first().expect("non-empty command");
    let output = Command::new(prog)
        .args(rest)
        .output()
        .await
        .with_context(|| format!("spawn {prog}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(anyhow::anyhow!(
            "{} failed: {}",
            args.join(" "),
            output.status
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_pf_rules_capture_tcp_and_dns_on_utun() {
        let rules = build_macos_pf_rules("utun8", 5300, 7890).unwrap();

        assert!(rules.contains("set skip on lo0"));
        assert!(rules
            .contains("rdr pass on utun8 inet proto tcp from any to any -> 127.0.0.1 port 7890"));
        assert!(rules.contains(
            "rdr pass on utun8 inet proto udp from any to any port 53 -> 127.0.0.1 port 5300"
        ));
    }

    #[test]
    fn macos_pf_rules_reject_unsafe_interface_names() {
        let err = build_macos_pf_rules("utun0\npass all", 5300, 7890).unwrap_err();
        assert!(err.to_string().contains("invalid macOS TUN interface"));
    }

    #[test]
    fn macos_pf_token_parser_extracts_reference_token() {
        let output = "Token : 1234567890\n";
        assert_eq!(parse_macos_pf_token(output).as_deref(), Some("1234567890"));
    }

    #[test]
    fn windows_route_commands_install_split_default_routes() {
        let pairs = windows_route_command_pairs("Blackwire Wintun");

        assert_eq!(pairs.len(), 2);
        assert_eq!(
            pairs[0].setup.args,
            vec![
                "netsh",
                "interface",
                "ipv4",
                "add",
                "route",
                "prefix=0.0.0.0/1",
                "interface=Blackwire Wintun",
                "nexthop=0.0.0.0",
                "metric=1",
                "store=active"
            ]
        );
        assert_eq!(
            pairs[1].undo.args,
            vec![
                "netsh",
                "interface",
                "ipv4",
                "delete",
                "route",
                "prefix=128.0.0.0/1",
                "interface=Blackwire Wintun",
                "nexthop=0.0.0.0",
                "store=active"
            ]
        );
    }

    #[test]
    fn windows_interface_name_rejects_newline_injection() {
        assert!(!is_safe_windows_interface_name("tun\r\nnetsh bad"));
        assert!(is_safe_windows_interface_name("Blackwire Wintun"));
    }
}
