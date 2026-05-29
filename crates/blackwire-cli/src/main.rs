//! blackwire — command-line entry point.
//!
//! This binary is the "front door" to the entire proxy platform. Everything
//! you do — start the proxy, test a config file, generate crypto keys — goes
//! through one of the subcommands defined here.
//!
//! # Subcommands
//!
//! | Command            | What it does                                              |
//! |--------------------|-----------------------------------------------------------|
//! | `run  -c PATH`     | Load the config file and start the proxy.                 |
//! | `test -c PATH`     | Parse and validate the config; print OK or errors. Exit.  |
//! | `x25519`           | Generate a new X25519 key pair (for REALITY).             |
//! | `uuid`             | Generate a random UUID v4 (for VLESS user IDs).           |
//! | `version`          | Print the binary version and quit.                        |
//!
//! # How startup works
//!
//! `run`:
//!   1. Initialise the tracing/logging subsystem.
//!   2. Load the config file via `ConfigManager::load()`.
//!   3. Start the config file watcher (so SIGHUP / file changes hot-reload).
//!   4. Build the proxy `Instance` from the config.
//!   5. Install signal handlers for SIGTERM / SIGINT.
//!   6. Wait for either the instance to exit or a shutdown signal.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use async_trait::async_trait;
use clap::{Parser, Subcommand};
use tracing::{error, info};
use validator::Validate;

use blackwire_api::management::{InboundManagement, NativeEndpointConfig};
use blackwire_config::schema::{
    validate_fast_profile, Config, InboundConfig, OutboundConfig, ProfileMode, ProfileViolation,
};
use blackwire_config::ConfigManager;
use blackwire_core::{requires_instance_restart, Instance};

struct RunningInstance {
    config: Arc<Config>,
    instance: Instance,
}

#[derive(Clone)]
struct RuntimeControl {
    instance: Arc<tokio::sync::Mutex<Option<RunningInstance>>>,
    profile_override: Option<ProfileMode>,
}

// ── Top-level CLI struct ──────────────────────────────────────────────────────

/// A production-grade, v2ray-compatible proxy platform.
///
/// Run `blackwire help <COMMAND>` for detailed usage of any subcommand.
#[derive(Parser)]
#[command(
    name    = "blackwire",
    version = env!("CARGO_PKG_VERSION"),
    about   = "A v2ray-compatible proxy platform written in pure Rust.",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the proxy with the given config file.
    ///
    /// The proxy runs until you press Ctrl-C or send SIGTERM/SIGINT.
    /// If the config file changes on disk while running, the proxy
    /// automatically reloads it without dropping any live connections.
    Run(RunArgs),

    /// Parse and validate a config file, then exit.
    ///
    /// Prints "Config OK" and exits 0 if the config is valid.
    /// Prints a detailed error and exits 1 if anything is wrong.
    Test(TestArgs),

    /// Generate a new X25519 key pair for use with REALITY transport.
    ///
    /// Prints the private key and public key as hex strings.
    /// Copy them into your config.json under `realitySettings`.
    X25519,

    /// Generate a new random UUID v4 for use as a VLESS user ID.
    ///
    /// Prints the UUID in the standard `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
    /// format. Copy it into your config.json under `clients[n].id`.
    Uuid,

    /// Print the build version and quit.
    Version,
}

/// Arguments for the `run` subcommand.
#[derive(clap::Args)]
struct RunArgs {
    /// Path to the JSON config file.
    ///
    /// Example: `blackwire run -c /etc/blackwire/config.json`
    #[arg(short = 'c', long = "config", value_name = "PATH")]
    config: PathBuf,

    /// Override the operating profile (`compat` or `fast`).
    ///
    /// Overrides the `profile` field in the config file. `fast` enforces a
    /// latency-first subset: VLESS+TCP only, no sniffing, no FakeIP.
    ///
    /// Example: `blackwire run -c config.json --profile fast`
    #[arg(long = "profile", value_name = "PROFILE")]
    profile: Option<ProfileMode>,
}

/// Arguments for the `test` subcommand.
#[derive(clap::Args)]
struct TestArgs {
    /// Path to the JSON config file to validate.
    ///
    /// Example: `blackwire test -c /etc/blackwire/config.json`
    #[arg(short = 'c', long = "config", value_name = "PATH")]
    config: PathBuf,

    /// Override the operating profile (`compat` or `fast`).
    ///
    /// Validates the config against the given profile's constraints.
    #[arg(long = "profile", value_name = "PROFILE")]
    profile: Option<ProfileMode>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => {
            // Build the async runtime first, then hand control to `run_proxy`.
            // We use 2× CPU cores: relay tasks are I/O-bound and yield frequently,
            // but at high PPS spare threads let new-connection tasks run without
            // waiting behind an active relay task's local queue.
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(num_cpus::get() * 2)
                .enable_all()
                .build()
            {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: failed to build Tokio runtime: {e}");
                    std::process::exit(1);
                }
            };

            // `block_on` runs the async function to completion on this thread.
            // It returns only when the proxy exits (Ctrl-C or error).
            if let Err(e) = rt.block_on(run_proxy(args)) {
                // Print a human-readable error chain, e.g.:
                //   Error: failed to start proxy
                //     caused by: building VLESS outbound 'out-vless'
                //     caused by: invalid VLESS server address '999.0.0.1:443'
                eprintln!("Error: {e:#}");
                std::process::exit(1);
            }
        }

        Command::Test(args) => {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: failed to build Tokio runtime: {e}");
                    std::process::exit(1);
                }
            };

            if let Err(e) = rt.block_on(test_config(args)) {
                eprintln!("Config error: {e:#}");
                std::process::exit(1);
            }
            println!("Config OK");
        }

        Command::X25519 => cmd_x25519(),
        Command::Uuid => cmd_uuid(),

        Command::Version => {
            println!("blackwire {}", env!("CARGO_PKG_VERSION"));
        }
    }
}

// ── `run` subcommand ──────────────────────────────────────────────────────────

/// Load config, build the Instance, run until a shutdown signal arrives.
///
/// This is an `async fn` so it can use `.await` for Tokio-based I/O.
async fn run_proxy(args: RunArgs) -> Result<()> {
    // Step 1: Initialise logging.
    // We do this before anything else so all startup messages are captured.
    init_tracing();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config  = %args.config.display(),
        "blackwire starting"
    );

    // Step 2: Load and validate the config.
    // `ConfigManager::load()` reads the file, substitutes ${ENV} vars,
    // parses JSON, and runs the validator rules.
    let manager: Arc<ConfigManager> = ConfigManager::load(&args.config)
        .await
        .with_context(|| format!("loading config from {}", args.config.display()))?;

    // Apply CLI profile override and run Fast Profile validation.
    let profile_override = args.profile;
    apply_profile_override_and_validate(&manager.get(), profile_override)?;

    // Step 3: Start the file watcher for hot-reload.
    // The watcher runs in a background Tokio task. When the config file
    // changes on disk, `ConfigManager::watch()` parses the new version and
    // atomically swaps it in. This does NOT restart any listeners — only
    // config values that are consulted per-connection (like routing rules)
    // change immediately.
    {
        let manager_clone = Arc::clone(&manager);
        tokio::spawn(async move {
            if let Err(e) = manager_clone.watch().await {
                error!(error = %e, "config watcher failed");
            }
        });
    }

    // Step 4: Build the proxy Instance.
    // `Instance::from_config()` reads the current config snapshot, builds
    // all inbound/outbound handlers, and starts all TCP listener tasks.
    let config = effective_config(manager.get(), profile_override);
    let api_addr = config
        .api
        .as_ref()
        .and_then(blackwire_api::server::api_listen_addr);
    let runtime_config = instance_runtime_config(&config);
    let instance = Arc::new(tokio::sync::Mutex::new(Some(RunningInstance {
        config: Arc::clone(&runtime_config),
        instance: Instance::from_config(runtime_config)
            .await
            .context("building proxy instance from config")?,
    })));

    if let Some(api_addr) = api_addr {
        let management: blackwire_api::management::ManagementHandle = Arc::new(RuntimeControl {
            instance: Arc::clone(&instance),
            profile_override,
        });
        blackwire_api::server::start_api_server(&api_addr, management)
            .with_context(|| format!("starting blackwire-api gRPC server on '{api_addr}'"))?;
        info!(addr = %api_addr, "blackwire-api gRPC server started");
    }

    // Step 4b: Apply hot-reload when config file changes (routing + VLESS users).
    // Listeners keep running; only per-connection lookup tables are refreshed.
    {
        let live_instance = Arc::clone(&instance);
        let mut reload_rx = manager.subscribe();
        tokio::spawn(async move {
            loop {
                if reload_rx.changed().await.is_err() {
                    break;
                }
                let effective =
                    effective_config(reload_rx.borrow_and_update().clone(), profile_override);
                let new_config = instance_runtime_config(&effective);

                let should_restart = {
                    let guard = live_instance.lock().await;
                    let Some(running) = guard.as_ref() else {
                        break;
                    };
                    requires_instance_restart(&running.config, &new_config)
                };

                if should_restart {
                    info!("structural config change detected — rebuilding running instance");
                    let (old_config, old_instance) = {
                        let mut guard = live_instance.lock().await;
                        let Some(running) = guard.take() else {
                            break;
                        };
                        (running.config, running.instance)
                    };
                    drop(old_instance);

                    let rebuilt = match Instance::from_config(Arc::clone(&new_config)).await {
                        Ok(instance) => {
                            info!("instance rebuilt successfully after config change");
                            Some(RunningInstance {
                                config: Arc::clone(&new_config),
                                instance,
                            })
                        }
                        Err(e) => {
                            error!(error = %e, "instance rebuild failed — attempting rollback to previous config");
                            match Instance::from_config(Arc::clone(&old_config)).await {
                                Ok(instance) => Some(RunningInstance {
                                    config: old_config,
                                    instance,
                                }),
                                Err(rollback_err) => {
                                    error!(error = %rollback_err, "rollback failed — no running instance remains");
                                    None
                                }
                            }
                        }
                    };

                    let mut guard = live_instance.lock().await;
                    *guard = rebuilt;
                    continue;
                }

                let reload = {
                    let guard = live_instance.lock().await;
                    let Some(running) = guard.as_ref() else {
                        break;
                    };
                    running.instance.reload.clone()
                };
                if let Err(e) = reload.apply(&new_config) {
                    error!(error = %e, "config reload apply failed — keeping prior routing/users");
                }
            }
        });
    }

    info!("blackwire started — waiting for connections");

    // Step 5: Wait for a shutdown signal or for all listeners to exit.
    // We listen for Ctrl-C (SIGINT) plus SIGTERM on Unix (what systemd sends).
    shutdown_signal(instance).await;

    Ok(())
}

/// Wait for a shutdown signal or for all listeners to exit.
///
/// On Unix, listens for both SIGINT (Ctrl-C) and SIGTERM (systemd stop).
/// On other platforms, only SIGINT.
async fn shutdown_signal(instance: Arc<tokio::sync::Mutex<Option<RunningInstance>>>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(v) => Some(v),
            Err(e) => {
                info!("SIGTERM handler unavailable ({e}); waiting for SIGINT/listener exit");
                None
            }
        };

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("received SIGINT — shutting down");
            }
            _ = async {
                if let Some(sigterm) = sigterm.as_mut() {
                    sigterm.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                info!("received SIGTERM — shutting down");
            }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("received SIGINT — shutting down");
            }
        }
    }

    let mut guard = instance.lock().await;
    if let Some(running) = guard.take() {
        running.instance.shutdown();
    }
}

impl RuntimeControl {
    async fn with_reload<T>(
        &self,
        f: impl FnOnce(&blackwire_core::ReloadState) -> T,
    ) -> Result<T, String> {
        let guard = self.instance.lock().await;
        let running = guard
            .as_ref()
            .ok_or_else(|| "no running instance is available".to_string())?;
        Ok(f(&running.instance.reload))
    }

    async fn rebuild_with_config(&self, new_config: Config) -> Result<(), String> {
        let runtime_config = Arc::new(new_config);
        runtime_config
            .validate()
            .map_err(|e| format!("config validation failed: {e}"))?;
        apply_profile_override_and_validate(&runtime_config, self.profile_override)
            .map_err(|e| format!("{e:#}"))?;

        let (old_config, old_instance) = {
            let mut guard = self.instance.lock().await;
            let running = guard
                .take()
                .ok_or_else(|| "no running instance is available".to_string())?;
            (running.config, running.instance)
        };
        drop(old_instance);

        match Instance::from_config(Arc::clone(&runtime_config)).await {
            Ok(instance) => {
                let mut guard = self.instance.lock().await;
                *guard = Some(RunningInstance {
                    config: runtime_config,
                    instance,
                });
                Ok(())
            }
            Err(e) => {
                let rollback = Instance::from_config(Arc::clone(&old_config)).await;
                let mut guard = self.instance.lock().await;
                match rollback {
                    Ok(instance) => {
                        *guard = Some(RunningInstance {
                            config: old_config,
                            instance,
                        });
                        Err(format!("instance rebuild failed; rolled back: {e:#}"))
                    }
                    Err(rollback_err) => {
                        *guard = None;
                        Err(format!(
                            "instance rebuild failed and rollback failed; no instance is running: rebuild={e:#}; rollback={rollback_err:#}"
                        ))
                    }
                }
            }
        }
    }

    async fn mutate_config(
        &self,
        f: impl FnOnce(&mut Config) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut new_config = {
            let guard = self.instance.lock().await;
            guard
                .as_ref()
                .ok_or_else(|| "no running instance is available".to_string())?
                .config
                .as_ref()
                .clone()
        };
        f(&mut new_config)?;
        self.rebuild_with_config(new_config).await
    }
}

fn parse_inbound_endpoint(config: NativeEndpointConfig) -> Result<InboundConfig, String> {
    let endpoint: InboundConfig = serde_json::from_value(config.config)
        .map_err(|e| format!("invalid inbound config JSON: {e}"))?;
    if endpoint.tag != config.tag {
        return Err(format!(
            "inbound tag mismatch: request tag '{}' != config tag '{}'",
            config.tag, endpoint.tag
        ));
    }
    endpoint
        .validate()
        .map_err(|e| format!("inbound validation failed: {e}"))?;
    Ok(endpoint)
}

fn parse_outbound_endpoint(config: NativeEndpointConfig) -> Result<OutboundConfig, String> {
    let endpoint: OutboundConfig = serde_json::from_value(config.config)
        .map_err(|e| format!("invalid outbound config JSON: {e}"))?;
    if endpoint.tag != config.tag {
        return Err(format!(
            "outbound tag mismatch: request tag '{}' != config tag '{}'",
            config.tag, endpoint.tag
        ));
    }
    endpoint
        .validate()
        .map_err(|e| format!("outbound validation failed: {e}"))?;
    Ok(endpoint)
}

#[async_trait]
impl InboundManagement for RuntimeControl {
    async fn list_inbound_tags(&self) -> Vec<String> {
        self.with_reload(|r| r.inbound_tags.read().map(|t| t.clone()).unwrap_or_default())
            .await
            .unwrap_or_default()
    }

    async fn list_outbound_tags(&self) -> Vec<String> {
        self.with_reload(|r| {
            r.outbound_tags
                .read()
                .map(|t| t.clone())
                .unwrap_or_default()
        })
        .await
        .unwrap_or_default()
    }

    async fn vless_user_count(&self, inbound_tag: &str) -> Option<i64> {
        self.with_reload(|r| {
            r.vless_registries
                .get(inbound_tag)
                .map(|registry| registry.len() as i64)
        })
        .await
        .ok()
        .flatten()
    }

    async fn list_vless_users(
        &self,
        inbound_tag: &str,
        email: &str,
    ) -> Result<Vec<blackwire_api::management::VlessUserRecord>, String> {
        self.with_reload(|r| {
            r.vless_registries
                .get(inbound_tag)
                .map(|registry| {
                    registry
                        .list_users(email)
                        .into_iter()
                        .map(|u| blackwire_api::management::VlessUserRecord {
                            email: u.email.to_string(),
                            uuid: uuid::Uuid::from_bytes(u.uuid).to_string(),
                            flow: u.flow.clone(),
                            level: 0,
                        })
                        .collect()
                })
                .ok_or_else(|| format!("inbound '{inbound_tag}' has no VLESS user registry"))
        })
        .await?
    }

    async fn add_vless_user(
        &self,
        inbound_tag: &str,
        email: &str,
        uuid: &str,
        flow: &str,
    ) -> Result<(), String> {
        self.with_reload(|r| {
            r.vless_registries
                .get(inbound_tag)
                .ok_or_else(|| format!("inbound '{inbound_tag}' has no VLESS user registry"))
                .and_then(|registry| {
                    let uuid = uuid::Uuid::parse_str(uuid)
                        .map_err(|e| format!("invalid UUID '{uuid}': {e}"))?
                        .into_bytes();
                    registry.add_user(blackwire_protocol::vless::VlessUser {
                        email: email.into(),
                        uuid,
                        flow: flow.to_string(),
                    });
                    Ok(())
                })
        })
        .await?
    }

    async fn remove_vless_user(&self, inbound_tag: &str, email: &str) -> Result<(), String> {
        self.with_reload(|r| {
            r.vless_registries
                .get(inbound_tag)
                .ok_or_else(|| format!("inbound '{inbound_tag}' has no VLESS user registry"))
                .and_then(|registry| {
                    if registry.remove_user_by_email(email) {
                        Ok(())
                    } else {
                        Err(format!(
                            "no VLESS user with email '{email}' on inbound '{inbound_tag}'"
                        ))
                    }
                })
        })
        .await?
    }

    async fn add_inbound(&self, config: NativeEndpointConfig) -> Result<(), String> {
        let endpoint = parse_inbound_endpoint(config)?;
        self.mutate_config(|cfg| {
            if cfg.inbounds.iter().any(|i| i.tag == endpoint.tag) {
                return Err(format!("inbound '{}' already exists", endpoint.tag));
            }
            cfg.inbounds.push(endpoint);
            Ok(())
        })
        .await
    }

    async fn remove_inbound(&self, tag: &str) -> Result<(), String> {
        self.mutate_config(|cfg| {
            let before = cfg.inbounds.len();
            cfg.inbounds.retain(|i| i.tag != tag);
            if cfg.inbounds.len() == before {
                return Err(format!("inbound '{tag}' not found"));
            }
            Ok(())
        })
        .await
    }

    async fn add_outbound(&self, config: NativeEndpointConfig) -> Result<(), String> {
        let endpoint = parse_outbound_endpoint(config)?;
        self.mutate_config(|cfg| {
            if cfg.outbounds.iter().any(|o| o.tag == endpoint.tag) {
                return Err(format!("outbound '{}' already exists", endpoint.tag));
            }
            cfg.outbounds.push(endpoint);
            Ok(())
        })
        .await
    }

    async fn remove_outbound(&self, tag: &str) -> Result<(), String> {
        self.mutate_config(|cfg| {
            let before = cfg.outbounds.len();
            cfg.outbounds.retain(|o| o.tag != tag);
            if cfg.outbounds.len() == before {
                return Err(format!("outbound '{tag}' not found"));
            }
            Ok(())
        })
        .await
    }

    async fn alter_outbound(&self, config: NativeEndpointConfig) -> Result<(), String> {
        let endpoint = parse_outbound_endpoint(config)?;
        self.mutate_config(|cfg| {
            let existing = cfg
                .outbounds
                .iter_mut()
                .find(|o| o.tag == endpoint.tag)
                .ok_or_else(|| format!("outbound '{}' not found", endpoint.tag))?;
            *existing = endpoint;
            Ok(())
        })
        .await
    }
}

// ── `test` subcommand ─────────────────────────────────────────────────────────

/// Parse and validate the config file; return Ok or an error.
async fn test_config(args: TestArgs) -> Result<()> {
    let manager = ConfigManager::load(&args.config)
        .await
        .with_context(|| format!("loading config from {}", args.config.display()))?;
    apply_profile_override_and_validate(&manager.get(), args.profile)?;
    Ok(())
}

// ── Profile helpers ───────────────────────────────────────────────────────────

/// Return an `Arc<Config>` with the CLI profile override applied (if any).
fn effective_config(
    base: Arc<blackwire_config::schema::Config>,
    override_: Option<ProfileMode>,
) -> Arc<Config> {
    let Some(profile) = override_ else {
        return base;
    };
    if base.profile == profile {
        return base;
    }
    let mut cfg = (*base).clone();
    cfg.profile = profile;
    Arc::new(cfg)
}

/// The CLI owns the gRPC API server so HandlerService can rebuild the live
/// `Instance`. Strip `api` before handing config to core to avoid a second API
/// server being started by direct `Instance::from_config` compatibility code.
fn instance_runtime_config(base: &Arc<Config>) -> Arc<Config> {
    if base.api.is_none() {
        return Arc::clone(base);
    }
    let mut cfg = base.as_ref().clone();
    cfg.api = None;
    Arc::new(cfg)
}

/// Run Fast Profile validation on `config`, printing warnings and returning an
/// error if any hard violations are present.
fn apply_profile_override_and_validate(
    config: &blackwire_config::schema::Config,
    override_: Option<ProfileMode>,
) -> Result<()> {
    // Build effective config for validation (clone only if override is set).
    let effective_profile = override_.unwrap_or(config.profile);
    if effective_profile != ProfileMode::Fast {
        return Ok(());
    }

    // Temporarily override profile in a clone for validation.
    let validated = if override_.is_some() && config.profile != effective_profile {
        let mut c = config.clone();
        c.profile = effective_profile;
        std::borrow::Cow::Owned(c)
    } else {
        std::borrow::Cow::Borrowed(config)
    };

    let violations = validate_fast_profile(&validated);

    for v in &violations {
        match v {
            ProfileViolation::Warning(msg) => {
                eprintln!("Fast Profile warning: {msg}");
            }
            ProfileViolation::Error(_) => {}
        }
    }

    let errors: Vec<&str> = violations
        .iter()
        .filter(|v| v.is_error())
        .map(|v| v.message())
        .collect();

    if !errors.is_empty() {
        let mut msg = format!(
            "config rejected by Fast Profile ({} error(s)):\n",
            errors.len()
        );
        for e in errors {
            msg.push_str(&format!("  • {e}\n"));
        }
        anyhow::bail!("{}", msg.trim_end());
    }

    Ok(())
}

// ── `x25519` subcommand ───────────────────────────────────────────────────────

/// Generate a fresh X25519 key pair and print it.
///
/// X25519 is the elliptic-curve Diffie-Hellman algorithm used in REALITY.
/// The server holds the private key; the public key goes in client configs.
fn cmd_x25519() {
    use x25519_dalek::{PublicKey, StaticSecret};

    // `StaticSecret` is a long-term key suitable for REALITY configuration.
    // It is generated from the OS CSPRNG and can be serialised to bytes.
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);

    // Print as hex so the user can paste them into a JSON config file.
    // The private key stays on the server; the public key goes in client configs.
    println!(
        "Private key (server config): {}",
        hex::encode(secret.to_bytes())
    );
    println!(
        "Public key  (client config): {}",
        hex::encode(public.as_bytes())
    );
}

// ── `uuid` subcommand ─────────────────────────────────────────────────────────

/// Generate a random UUID v4 and print it in the standard dashed format.
///
/// UUID v4 is entirely random (122 random bits). It is used as a VLESS
/// user identifier — each user gets a unique UUID that acts as an
/// authentication token.
fn cmd_uuid() {
    // `uuid::Uuid::new_v4()` generates cryptographically random bytes using
    // the OS CSPRNG and formats them with the version (4) and variant bits set.
    let id = uuid::Uuid::new_v4();
    println!("{id}");
}

// ── Logging setup ─────────────────────────────────────────────────────────────

/// Initialise the tracing subscriber for structured logging.
///
/// Log level is controlled by the `RUST_LOG` environment variable.
/// Default level is `info` if `RUST_LOG` is not set.
///
/// Examples:
///   `RUST_LOG=debug blackwire run -c config.json`   — very verbose
///   `RUST_LOG=warn  blackwire run -c config.json`   — warnings only
fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};

    // `EnvFilter::try_from_default_env()` reads `RUST_LOG`.
    // If that env var isn't set, fall back to "info".
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt()
        .with_env_filter(filter)
        // Print timestamps, log level, target module, and the message.
        .with_target(true)
        .with_line_number(false)
        .init();
}
