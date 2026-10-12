//! Phase 1A relay binary.
//!
//! Usage:
//! ```text
//! rawtcp-engine [--bind ADDR] [--port PORT] [--connect-timeout-ms MS]
//!               [--negotiation-timeout-ms MS] [--max-connections N]
//!               [--buffer-bytes N] [--ipc-port PORT]
//!               [--ipc-event-capacity N]
//! ```
//!
//! Defaults bind `127.0.0.1:1080`. Ctrl-C stops the listener gracefully.
//!
//! `--ipc-port` enables the Phase 4A control-plane IPC server on
//! `127.0.0.1:PORT` (0 = ephemeral). When enabled, the startup banner
//! prints the endpoint, the per-launch capability token, and the daemon
//! epoch the operator pastes into the Burp Raw TCP extension.

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
            eprintln!("{USAGE}");
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

    // Phase 4B: the control-plane endpoint and per-launch token the operator
    // pastes into the Burp Raw TCP extension. Printed only when IPC is enabled.
    if let Some(ipc) = relay.ipc() {
        eprintln!("IPC control plane listening on {}", ipc.local_addr());
        eprintln!("IPC capability token: {}", ipc.capability_token());
        eprintln!("IPC daemon epoch: {}", ipc.daemon_epoch());
    }

    match tokio::signal::ctrl_c().await {
        Ok(()) => eprintln!("shutdown requested; stopping listener"),
        Err(error) => eprintln!("warning: cannot listen for ctrl-c: {error}"),
    }

    relay.shutdown().await;
    ExitCode::SUCCESS
}

/// Usage string shared by the argument-error path.
const USAGE: &str = "usage: rawtcp-engine [--bind ADDR] [--port PORT] \
[--connect-timeout-ms MS] [--negotiation-timeout-ms MS] [--max-connections N] \
[--buffer-bytes N] [--ipc-port PORT] [--ipc-event-capacity N]";

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
            "--ipc-port" => {
                let raw = take_value("--ipc-port")?;
                let parsed: u16 = raw
                    .parse()
                    .map_err(|_| format!("invalid --ipc-port: {raw}"))?;
                // 0 requests an ephemeral port; both 0 and a fixed port are
                // valid, so no non-zero check here.
                config.ipc_port = Some(parsed);
            }
            "--ipc-event-capacity" => {
                let raw = take_value("--ipc-event-capacity")?;
                let parsed: usize = raw
                    .parse()
                    .map_err(|_| format!("invalid --ipc-event-capacity: {raw}"))?;
                if parsed == 0 {
                    return Err("--ipc-event-capacity must be greater than 0".into());
                }
                config.ipc_event_capacity = parsed;
            }
            "--help" | "-h" => return Err("help requested".into()),
            other => return Err(format!("unrecognised argument: {other}")),
        }
    }

    config.validate().map_err(|error| error.to_string())?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<RelayConfig, String> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn defaults_bind_loopback_1080_without_ipc() {
        let config = parse(&[]).expect("defaults parse");
        assert_eq!(config.port, 1080);
        assert_eq!(config.ipc_port, None);
        assert_eq!(config.ipc_event_capacity, 64);
    }

    #[test]
    fn ipc_port_flag_enables_control_plane() {
        let config = parse(&["--ipc-port", "8080"]).expect("parse ipc port");
        assert_eq!(config.ipc_port, Some(8080));
    }

    #[test]
    fn ipc_port_zero_requests_ephemeral() {
        let config = parse(&["--ipc-port", "0"]).expect("parse ephemeral ipc port");
        assert_eq!(config.ipc_port, Some(0));
    }

    #[test]
    fn ipc_event_capacity_flag_is_parsed() {
        let config =
            parse(&["--ipc-port", "0", "--ipc-event-capacity", "4"]).expect("parse ipc capacity");
        assert_eq!(config.ipc_event_capacity, 4);
    }

    #[test]
    fn ipc_event_capacity_zero_is_rejected() {
        let err = parse(&["--ipc-event-capacity", "0"]).expect_err("zero capacity rejected");
        assert!(err.contains("greater than 0"), "unexpected error: {err}");
    }

    #[test]
    fn invalid_ipc_port_is_rejected() {
        let err = parse(&["--ipc-port", "not-a-port"]).expect_err("bad port rejected");
        assert!(
            err.contains("invalid --ipc-port"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn missing_ipc_port_value_is_rejected() {
        let err = parse(&["--ipc-port"]).expect_err("missing value rejected");
        assert!(err.contains("requires a value"), "unexpected error: {err}");
    }

    #[test]
    fn non_loopback_bind_is_rejected() {
        let err = parse(&["--bind", "0.0.0.0"]).expect_err("non-loopback rejected");
        assert!(err.contains("loopback"), "unexpected error: {err}");
    }
}
