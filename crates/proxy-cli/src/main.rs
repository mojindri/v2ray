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
use clap::{Parser, Subcommand};
use tracing::{error, info};

use proxy_config::ConfigManager;
use proxy_core::Instance;

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
}

/// Arguments for the `test` subcommand.
#[derive(clap::Args)]
struct TestArgs {
    /// Path to the JSON config file to validate.
    ///
    /// Example: `blackwire test -c /etc/blackwire/config.json`
    #[arg(short = 'c', long = "config", value_name = "PATH")]
    config: PathBuf,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => {
            // Build the async runtime first, then hand control to `run_proxy`.
            // We use `new_multi_thread` so we get one OS thread per CPU core.
            // All proxy I/O is async, so more threads = more parallelism.
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(num_cpus::get())
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
            if let Err(e) = rt.block_on(run_proxy(args.config)) {
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

            if let Err(e) = rt.block_on(test_config(args.config)) {
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
async fn run_proxy(config_path: PathBuf) -> Result<()> {
    // Step 1: Initialise logging.
    // We do this before anything else so all startup messages are captured.
    init_tracing();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        config  = %config_path.display(),
        "blackwire starting"
    );

    // Step 2: Load and validate the config.
    // `ConfigManager::load()` reads the file, substitutes ${ENV} vars,
    // parses JSON, and runs the validator rules.
    let manager: Arc<ConfigManager> = ConfigManager::load(&config_path)
        .await
        .with_context(|| format!("loading config from {}", config_path.display()))?;

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
    let config = manager.get();
    let instance = Instance::from_config(config)
        .await
        .context("building proxy instance from config")?;

    // Step 4b: Apply hot-reload when config file changes (routing + VLESS users).
    // Listeners keep running; only per-connection lookup tables are refreshed.
    {
        let reload = instance.reload.clone();
        let mut reload_rx = manager.subscribe();
        tokio::spawn(async move {
            loop {
                if reload_rx.changed().await.is_err() {
                    break;
                }
                let config = reload_rx.borrow_and_update().clone();
                if let Err(e) = reload.apply(&config) {
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
async fn shutdown_signal(instance: Instance) {
    // Pin the futures so they can be polled in select.
    tokio::pin!(
        let listeners_done = instance.wait();
    );

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
            _ = &mut listeners_done => {
                info!("all listeners have exited — shutting down");
            }
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
            _ = &mut listeners_done => {
                info!("all listeners have exited — shutting down");
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received SIGINT — shutting down");
            }
        }
    }
}

// ── `test` subcommand ─────────────────────────────────────────────────────────

/// Parse and validate the config file; return Ok or an error.
async fn test_config(config_path: PathBuf) -> Result<()> {
    ConfigManager::load(&config_path)
        .await
        .with_context(|| format!("loading config from {}", config_path.display()))?;
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
