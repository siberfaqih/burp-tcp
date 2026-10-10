//! Phase 1A relay binary.
//!
//! Usage:
//! ```text
//! rawtcp-engine [--bind ADDR] [--port PORT] [--connect-timeout-ms MS]
//!               [--negotiation-timeout-ms MS] [--max-connections N]
//!               [--buffer-bytes N]
//! ```
//!
//! Defaults bind `127.0.0.1:1080`. Ctrl-C stops the listener gracefully.

use std::net::IpAddr;
use std::process::ExitCode;
use std::time::Duration;

use rawtcp_engine::{spawn_relay, RelayConfig};

#[tokio::main]
async fn main() -> ExitCode {
    let config = match parse_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("error: {message}");
            eprintln!("usage: rawtcp-engine [--bind ADDR] [--port PORT] [--connect-timeout-ms MS] [--negotiation-timeout-ms MS] [--max-connections N] [--buffer-bytes N]");
            return ExitCode::FAILURE;
        }
    };

    let relay = match spawn_relay(config).await {
        Ok(relay) => relay,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };

    // `RelayConfig::validate` rejects non-loopback binds, so reaching here means
    // the engine is loopback-only.
    eprintln!("SOCKS5 relay listening on {}", relay.local_addr());

    match tokio::signal::ctrl_c().await {
        Ok(()) => eprintln!("shutdown requested; stopping listener"),
        Err(error) => eprintln!("warning: cannot listen for ctrl-c: {error}"),
    }

    relay.shutdown().await;
    ExitCode::SUCCESS
}

fn parse_args<I>(args: I) -> Result<RelayConfig, String>
where
    I: IntoIterator<Item = String>,
{
    let mut config = RelayConfig::loopback_default();
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        let mut take_value = |name: &str| -> Result<String, String> {
            args.next()
                .ok_or_else(|| format!("{name} requires a value"))
        };
        match arg.as_str() {
            "--bind" => {
                let raw = take_value("--bind")?;
                let parsed: IpAddr = raw
                    .parse()
                    .map_err(|_| format!("invalid --bind address: {raw}"))?;
                config.bind_addr = parsed;
            }
            "--port" => {
                let raw = take_value("--port")?;
                let parsed: u16 = raw.parse().map_err(|_| format!("invalid --port: {raw}"))?;
                config.port = parsed;
            }
            "--connect-timeout-ms" => {
                let raw = take_value("--connect-timeout-ms")?;
                let parsed: u64 = raw
                    .parse()
                    .map_err(|_| format!("invalid --connect-timeout-ms: {raw}"))?;
                if parsed == 0 {
                    return Err("--connect-timeout-ms must be greater than 0".into());
                }
                config.connect_timeout = Duration::from_millis(parsed);
            }
            "--negotiation-timeout-ms" => {
                let raw = take_value("--negotiation-timeout-ms")?;
                let parsed: u64 = raw
                    .parse()
                    .map_err(|_| format!("invalid --negotiation-timeout-ms: {raw}"))?;
                if parsed == 0 {
                    return Err("--negotiation-timeout-ms must be greater than 0".into());
                }
                config.negotiation_timeout = Duration::from_millis(parsed);
            }
            "--max-connections" => {
                let raw = take_value("--max-connections")?;
                let parsed: usize = raw
                    .parse()
                    .map_err(|_| format!("invalid --max-connections: {raw}"))?;
                if parsed == 0 {
                    return Err("--max-connections must be greater than 0".into());
                }
                config.max_connections = parsed;
            }
            "--buffer-bytes" => {
                let raw = take_value("--buffer-bytes")?;
                let parsed: usize = raw
                    .parse()
                    .map_err(|_| format!("invalid --buffer-bytes: {raw}"))?;
                if parsed == 0 {
                    return Err("--buffer-bytes must be greater than 0".into());
                }
                config.buffer_bytes = parsed;
            }
            "--help" | "-h" => return Err("help requested".into()),
            other => return Err(format!("unrecognised argument: {other}")),
        }
    }

    config.validate().map_err(|error| error.to_string())?;
    Ok(config)
}
