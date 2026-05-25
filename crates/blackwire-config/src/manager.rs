//! Config hot-reload manager.
//!
//! The `ConfigManager` watches the config file on disk and automatically
//! reloads it when it changes. This lets operators update the proxy
//! (add users, change routing rules, rotate certificates) without restarting
//! the process or dropping any existing connections.
//!
//! # How hot-reload works
//!
//! 1. The manager registers a file-system watcher on the config file.
//! 2. When the OS reports that the file has changed, the manager reads
//!    and validates the new config.
//! 3. If validation passes, the running config is atomically swapped out
//!    using `ArcSwap::store()`. Tasks that already loaded the old config
//!    (e.g. a connection currently being processed) continue using the old
//!    version until they finish. New connections immediately see the new config.
//! 4. If validation fails, the error is logged and the old config stays active.
//! 5. Subscribers from `subscribe()` receive the new config; `blackwire run` calls
//!    `ReloadState::apply()` to hot-swap routing rules and VLESS user lists.
//!
//! # Thread safety
//!
//! `ConfigManager` is wrapped in `Arc` and can be shared across threads.
//! `ArcSwap` provides wait-free reads on the hot path — reading the current
//! config does not block even if a reload is happening simultaneously.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::{mpsc, watch};
use tracing::{error, info};

use crate::env::substitute;
use crate::schema::Config;
use validator::Validate;

/// Manages the live configuration and its hot-reload lifecycle.
pub struct ConfigManager {
    /// The currently active configuration.
    /// Wrapped in `ArcSwap` so readers never block on a config swap.
    current: ArcSwap<Config>,

    /// Path to the config file on disk.
    path: PathBuf,

    /// Notifies subscribers when a validated config has been loaded or reloaded.
    reload_tx: watch::Sender<Arc<Config>>,
}

impl ConfigManager {
    /// Load a config file from `path`, validate it, and return a manager
    /// ready to watch for changes.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read, the JSON is invalid,
    /// or validation fails (e.g. no inbounds defined).
    pub async fn load(path: impl AsRef<Path>) -> anyhow::Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        let config = Self::read_and_validate(&path).await?;
        let config = Arc::new(config);
        let (reload_tx, _) = watch::channel(Arc::clone(&config));

        Ok(Arc::new(Self {
            current: ArcSwap::from(config),
            path,
            reload_tx,
        }))
    }

    /// Return a clone of the currently active configuration.
    ///
    /// This is a wait-free operation — it never blocks. The returned `Arc`
    /// keeps the config alive even if a reload happens immediately after.
    pub fn get(&self) -> Arc<Config> {
        self.current.load_full()
    }

    /// Subscribe to validated config reload notifications.
    ///
    /// The receiver's current value is the config active at subscription time.
    /// Call `changed().await` and then `borrow_and_update()` after each reload.
    pub fn subscribe(&self) -> watch::Receiver<Arc<Config>> {
        self.reload_tx.subscribe()
    }

    /// Start watching the config file for changes.
    ///
    /// This method runs indefinitely. Spawn it as a background task:
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use proxy_config::ConfigManager;
    ///
    /// async fn spawn_watch(manager: Arc<ConfigManager>) {
    ///     let mgr = Arc::clone(&manager);
    ///     tokio::spawn(async move {
    ///         let _ = mgr.watch().await;
    ///     });
    /// }
    /// ```
    ///
    /// When the file changes:
    /// - If the new config is valid, it replaces the current config immediately.
    /// - If the new config is invalid, an error is logged and the old config
    ///   remains active.
    pub async fn watch(self: Arc<Self>) -> anyhow::Result<()> {
        // mpsc channel: the file watcher (sync) sends events to this async task.
        let (tx, mut rx) = mpsc::channel::<notify::Result<notify::Event>>(16);

        // Create the OS file watcher. `RecommendedWatcher` uses inotify on Linux,
        // FSEvents on macOS, ReadDirectoryChangesW on Windows.
        let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
            // `blocking_send` is safe here because the channel buffer is 16,
            // and file-change events are infrequent. If the buffer is full,
            // we drop the event — the next change will trigger another reload.
            let _ = tx.blocking_send(res);
        })?;

        watcher.watch(&self.path, RecursiveMode::NonRecursive)?;

        info!(path = %self.path.display(), "watching config file for changes");

        while let Some(event) = rx.recv().await {
            match event {
                Ok(e) if e.kind.is_modify() || e.kind.is_create() => {
                    // Wait briefly for the file write to complete.
                    // Many editors write configs by creating a new file and
                    // renaming it, which can cause a brief moment where the
                    // file is empty or partially written.
                    tokio::time::sleep(Duration::from_millis(100)).await;

                    match Self::read_and_validate(&self.path).await {
                        Ok(new_cfg) => {
                            let new_cfg = Arc::new(new_cfg);
                            self.current.store(Arc::clone(&new_cfg));
                            // Wake `subscribe()` receivers so ReloadState::apply() runs.
                            let _ = self.reload_tx.send(new_cfg);
                            info!(path = %self.path.display(), "config reloaded successfully");
                        }
                        Err(e) => {
                            error!(
                                error = %e,
                                path = %self.path.display(),
                                "config reload failed — keeping current config"
                            );
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, "file watcher error");
                }
                _ => {} // access events, etc. — ignore
            }
        }

        Ok(())
    }

    /// Read the config file at `path`, substitute environment variables,
    /// parse the JSON, and validate the result.
    async fn read_and_validate(path: &Path) -> anyhow::Result<Config> {
        // Read the raw bytes from disk.
        let raw = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| anyhow::anyhow!("failed to read config file {}: {}", path.display(), e))?;

        // Substitute ${ENV_VAR} placeholders before parsing.
        let substituted = substitute(&raw);

        // Parse JSON into the Config struct.
        let config: Config = serde_json::from_str(&substituted)
            .map_err(|e| anyhow::anyhow!("config JSON parse error: {}", e))?;

        // Validate the parsed config (check port ranges, required fields, etc.).
        config
            .validate()
            .map_err(|e| anyhow::anyhow!("config validation error: {}", e))?;

        Ok(config)
    }
}
