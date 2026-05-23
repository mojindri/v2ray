use anyhow::{Context as _, Result};
use tokio::process::Command;
use tracing::{info, warn};

/// Applies Linux policy routing and iptables rules that redirect all
/// non-bypass-marked traffic through the TUN interface.
///
/// IPv4 rules are mandatory and cause the function to return an error (with
/// rollback) if any step fails. IPv6 rules are best-effort: failure is logged
/// as a warning so the proxy still works for IPv4-only environments.
///
/// Call [`cleanup_routes`] to undo every rule this function installed.
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

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Accumulated undo commands for partial-failure rollback.
#[derive(Default)]
struct RollbackList {
    undos: Vec<Vec<String>>,
}

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
async fn try_best_effort(cmd: &[&str], label: &str) {
    if let Err(e) = run(cmd).await {
        warn!(label, error = %e, "best-effort route step failed (IPv6 may not be proxied)");
    }
}

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
