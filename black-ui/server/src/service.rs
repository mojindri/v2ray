use std::process::Command;

use crate::models::ServiceStatus;

pub fn blackwire_status() -> ServiceStatus {
    let systemd_available = Command::new("systemctl").arg("--version").output().is_ok();
    let (active_state, sub_state) = if systemd_available {
        let active = command_text("systemctl", &["is-active", "blackwire"])
            .unwrap_or_else(|| "unknown".into());
        let sub = command_text(
            "systemctl",
            &["show", "blackwire", "--property=SubState", "--value"],
        )
        .unwrap_or_else(|| "unknown".into());
        (active.trim().to_string(), sub.trim().to_string())
    } else {
        ("unavailable".into(), "systemd unavailable".into())
    };
    ServiceStatus {
        systemd_available,
        active_state,
        sub_state,
        logs: recent_logs(),
    }
}

pub fn restart_blackwire() -> anyhow::Result<ServiceStatus> {
    let status = Command::new("systemctl")
        .args(["restart", "blackwire"])
        .status()?;
    if !status.success() {
        anyhow::bail!("systemctl restart blackwire failed with {status}");
    }
    Ok(blackwire_status())
}

pub fn recent_logs() -> Vec<String> {
    command_text(
        "journalctl",
        &[
            "-u",
            "blackwire",
            "-n",
            "120",
            "--no-pager",
            "--output=short-iso",
        ],
    )
    .map(|text| text.lines().map(str::to_string).collect())
    .unwrap_or_default()
}

fn command_text(cmd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(cmd).args(args).output().ok()?;
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}
