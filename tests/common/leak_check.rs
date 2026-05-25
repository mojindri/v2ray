//! Process leak snapshots for integration tests. RSS checks remain for heavy
//! suites; most adversarial binaries use [`assert_fd_tasks_close_to_baseline`] only.
#![allow(dead_code)]

use std::time::Duration;

/// Process-level snapshot used by adversarial tests to catch obvious leaks.
#[derive(Debug, Clone, Copy)]
pub struct LeakSnapshot {
    pub fd_count: usize,
    pub task_count: usize,
    pub rss_kb: usize,
}

impl LeakSnapshot {
    pub fn capture() -> Self {
        Self {
            fd_count: proc_fd_count().unwrap_or(0),
            task_count: proc_task_count().unwrap_or(0),
            rss_kb: proc_rss_kb().unwrap_or(0),
        }
    }
}

/// Sleep briefly to let background cleanup/cancellation run before measuring.
pub async fn settle_for_cleanup() {
    // CI runners need a bit longer for relay tasks and sockets to tear down.
    tokio::time::sleep(Duration::from_millis(400)).await;
}

/// Capture a leak baseline after listeners/tasks are already running.
///
/// RSS taken before `Instance::from_config` is misleading (the proxy allocates
/// several MB at startup). Call this only once the instance and peers have warmed up.
pub async fn steady_state_baseline() -> LeakSnapshot {
    settle_for_cleanup().await;
    LeakSnapshot::capture()
}

/// Assert that process resources remain close to baseline.
pub fn assert_close_to_baseline(
    before: &LeakSnapshot,
    after: &LeakSnapshot,
    fd_slack: usize,
    task_slack: usize,
    rss_kb_slack: usize,
) {
    assert!(
        after.fd_count <= before.fd_count + fd_slack,
        "fd count grew too much: before={} after={} slack={}",
        before.fd_count,
        after.fd_count,
        fd_slack
    );
    assert!(
        after.task_count <= before.task_count + task_slack,
        "task count grew too much: before={} after={} slack={}",
        before.task_count,
        after.task_count,
        task_slack
    );
    assert!(
        after.rss_kb <= before.rss_kb + rss_kb_slack,
        "rss grew too much: before={}KB after={}KB slack={}KB",
        before.rss_kb,
        after.rss_kb,
        rss_kb_slack
    );
}

/// Like [`assert_close_to_baseline`] but skips RSS.
///
/// VmRSS is too noisy in CI (allocator arenas, large transient I/O buffers, MADV_DONTNEED
/// timing). Adversarial backpressure tests use this and rely on fd/task growth instead.
pub fn assert_fd_tasks_close_to_baseline(
    before: &LeakSnapshot,
    after: &LeakSnapshot,
    fd_slack: usize,
    task_slack: usize,
) {
    assert!(
        after.fd_count <= before.fd_count + fd_slack,
        "fd count grew too much: before={} after={} slack={}",
        before.fd_count,
        after.fd_count,
        fd_slack
    );
    assert!(
        after.task_count <= before.task_count + task_slack,
        "task count grew too much: before={} after={} slack={}",
        before.task_count,
        after.task_count,
        task_slack
    );
}

fn proc_fd_count() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        return std::fs::read_dir("/proc/self/fd").ok().map(|it| it.count());
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg("lsof -p $$ | wc -l")
            .output()
            .ok()?;
        let s = String::from_utf8(out.stdout).ok()?;
        return s.trim().parse::<usize>().ok();
    }
    #[allow(unreachable_code)]
    None
}

fn proc_task_count() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        return std::fs::read_dir("/proc/self/task")
            .ok()
            .map(|it| it.count());
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Best effort fallback where /proc/self/task is unavailable.
        Some(std::thread::available_parallelism().ok()?.get())
    }
}

fn proc_rss_kb() -> Option<usize> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb = rest.split_whitespace().next()?.parse::<usize>().ok()?;
                return Some(kb);
            }
        }
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg("ps -o rss= -p $$")
            .output()
            .ok()?;
        let s = String::from_utf8(out.stdout).ok()?;
        return s.trim().parse::<usize>().ok();
    }
    #[allow(unreachable_code)]
    None
}
