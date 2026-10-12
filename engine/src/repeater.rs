//! Phase 5 — manual one-shot TCP repeater.
//!
//! A repeater operation is a distinct session type: it opens a fresh TCP
//! connection, writes one operator-supplied payload exactly once, captures a
//! bounded response, then closes. It never reuses a relayed SOCKS session,
//! never retries a failed dial or write, and never interprets response bytes
//! as protocol messages.
//!
//! The request itself is the manual approval. Resolution pins exactly one
//! IPv4 address and the dialer makes exactly one connect attempt, so there
//! is no fallback or retry that could create an ambiguous duplicate send.
//! After the full payload has been accepted, the write half is shut down to
//! delimit the one-shot request while preserving the read half for the
//! bounded response capture.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::{sleep_until, Instant as TokioInstant};

use crate::ipc::proto;

/// Maximum destination-host bytes, matching the SOCKS domain wire bound.
pub const MAX_DESTINATION_HOST_BYTES: usize = 255;
/// Maximum repeater payload accepted in one manual send.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
/// Maximum response bytes retained for one manual send.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// Maximum overall dial + send + receive deadline for one manual send.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum idle-response deadline for `READ_UNTIL_IDLE`.
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Fixed read buffer: response bytes are never accumulated beyond the
/// caller-supplied response limit.
const READ_BUFFER_BYTES: usize = 8 * 1024;

/// Explicit response-completion policy selected by the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    /// Read until the target closes its write half, the response cap is
    /// reached, or the overall deadline expires.
    ReadUntilClose,
    /// Read exactly `response_byte_limit` bytes. An early close completes
    /// with the partial response rather than failing ambiguously.
    ReadExactBytes,
    /// Read until no response byte arrives for `idle_timeout_ms`.
    ReadUntilIdle,
}

/// Terminal outcome of one repeater operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    CompletedClosed,
    CompletedByteCount,
    CompletedIdleTimeout,
    Stopped,
    TimedOut,
    Truncated,
    Failed,
}

/// A validated repeater request. All bounds are checked before any socket
/// is opened.
#[derive(Debug, Clone)]
pub struct ValidatedSend {
    destination_host: String,
    destination_port: u16,
    payload: Vec<u8>,
    response_limit: usize,
    timeout: Duration,
    completion: Completion,
    idle_timeout: Duration,
}

impl ValidatedSend {
    /// Overall dial + send + receive deadline for the operation.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// Result of one repeater operation.
#[derive(Debug, Clone)]
pub struct Report {
    pub sent: bool,
    pub bytes_sent: u64,
    pub response: Vec<u8>,
    pub truncated: bool,
    pub outcome: Outcome,
    pub elapsed: Duration,
    pub error_kind: &'static str,
}

/// Convert an operation report into the IPC response body.
pub fn result_to_proto(send_id: &str, report: &Report) -> proto::RepeaterResult {
    proto::RepeaterResult {
        send_id: send_id.to_owned(),
        sent: report.sent,
        bytes_sent: report.bytes_sent,
        response: report.response.clone(),
        response_truncated: report.truncated,
        outcome: to_proto_outcome(report.outcome),
        elapsed_ms: report.elapsed.as_millis() as u64,
        error_kind: report.error_kind.to_owned(),
    }
}

fn to_proto_outcome(outcome: Outcome) -> i32 {
    match outcome {
        Outcome::CompletedClosed => proto::RepeaterOutcome::CompletedClosed as i32,
        Outcome::CompletedByteCount => proto::RepeaterOutcome::CompletedByteCount as i32,
        Outcome::CompletedIdleTimeout => proto::RepeaterOutcome::CompletedIdleTimeout as i32,
        Outcome::Stopped => proto::RepeaterOutcome::Stopped as i32,
        Outcome::TimedOut => proto::RepeaterOutcome::TimedOut as i32,
        Outcome::Truncated => proto::RepeaterOutcome::Truncated as i32,
        Outcome::Failed => proto::RepeaterOutcome::Failed as i32,
    }
}

/// Validate a repeater request without performing any network I/O.
pub fn validate_send(request: &proto::RepeaterSend) -> Result<ValidatedSend, &'static str> {
    let destination_host = validate_host(&request.destination_host)?;
    if request.destination_port == 0 || request.destination_port > u32::from(u16::MAX) {
        return Err("destination port must be 1..65535");
    }
    if request.payload.len() > MAX_PAYLOAD_BYTES {
        return Err("payload exceeds the repeater payload bound");
    }
    if request.response_byte_limit == 0 || request.response_byte_limit > MAX_RESPONSE_BYTES as u32 {
        return Err("response limit must be 1..=262144");
    }
    if request.timeout_ms == 0 || Duration::from_millis(request.timeout_ms) > MAX_TIMEOUT {
        return Err("timeout must be 1..30000 milliseconds");
    }
    let completion = match request.completion {
        1 => Completion::ReadUntilClose,
        2 => Completion::ReadExactBytes,
        3 => Completion::ReadUntilIdle,
        _ => return Err("response completion policy must be explicit"),
    };
    let idle_timeout = Duration::from_millis(request.idle_timeout_ms);
    match completion {
        Completion::ReadUntilIdle => {
            if request.idle_timeout_ms == 0 || idle_timeout > MAX_IDLE_TIMEOUT {
                return Err("idle timeout must be 1..10000 milliseconds");
            }
        }
        Completion::ReadUntilClose | Completion::ReadExactBytes => {
            if request.idle_timeout_ms != 0 {
                return Err("idle timeout applies only to READ_UNTIL_IDLE");
            }
        }
    }

    Ok(ValidatedSend {
        destination_host,
        destination_port: request.destination_port as u16,
        payload: request.payload.clone(),
        response_limit: request.response_byte_limit as usize,
        timeout: Duration::from_millis(request.timeout_ms),
        completion,
        idle_timeout,
    })
}

/// Run one validated repeater operation.
///
/// `deadline` is absolute from Send acceptance (not from first poll), so the
/// timeout cannot be postponed by delaying the future's first poll.
/// `cancel` is checked before every network await, so a stop request from
/// the control plane ends the operation promptly. Dropping the returned
/// future also drops the socket, so cancellation and connection teardown
/// can never leave a detached send or receive in flight.
pub async fn run_send(
    request: ValidatedSend,
    mut cancel: watch::Receiver<bool>,
    deadline: TokioInstant,
) -> Report {
    let started = Instant::now();

    let addr = match resolve_target(&request, deadline, &mut cancel).await {
        Ok(addr) => addr,
        Err(report) => return report_with(report, started),
    };
    let mut stream = match connect_pinned(addr, deadline, &mut cancel).await {
        Ok(stream) => stream,
        Err(report) => return report_with(report, started),
    };
    let bytes_sent = match write_payload(&request, &mut stream, deadline, &mut cancel).await {
        Ok(bytes_sent) => bytes_sent,
        Err(report) => return report_with(report, started),
    };

    // Delimit the one-shot request while preserving the read half for the
    // bounded response capture. Expiration-first on every poll: after the
    // deadline the session ends instead of signalling EOF.
    let expiry = sleep_until(deadline);
    tokio::pin!(expiry);
    tokio::select! {
        biased;
        _ = cancel.changed() => {
            return stopped_report(
                &request,
                !request.payload.is_empty(),
                bytes_sent,
                Vec::new(),
                false,
                started,
            );
        }
        _ = &mut expiry => {
            return timed_out_report(&request, bytes_sent, Vec::new(), started);
        }
        result = stream.shutdown() => match result {
            Ok(()) => {}
            Err(_) => {
                return failed_report(&request, bytes_sent, Vec::new(), "shutdown_failed", started);
            }
        },
    }

    read_response(
        &request,
        &mut stream,
        deadline,
        &mut cancel,
        bytes_sent,
        started,
    )
    .await
}

/// Validate an operator-supplied host as an IPv4 literal or DNS name.
/// IPv6 is rejected to match the relay's IPv4-only dial policy.
fn validate_host(raw: &str) -> Result<String, &'static str> {
    let host = raw.trim();
    if host.is_empty() {
        return Err("destination host is required");
    }
    if host.len() > MAX_DESTINATION_HOST_BYTES {
        return Err("destination host exceeds 255 bytes");
    }
    if !host.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("destination host must be printable ASCII without whitespace");
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(host.to_owned());
    }
    if host.parse::<Ipv6Addr>().is_ok() {
        return Err("IPv6 destinations are not supported");
    }

    let name = host.strip_suffix('.').unwrap_or(host);
    if name.len() > 253 {
        return Err("domain name exceeds 253 bytes");
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("domain name has an empty or oversized label");
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("domain name contains an invalid character");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("domain label must not start or end with '-'");
        }
    }
    Ok(host.to_owned())
}

/// Resolve the destination and pin exactly one IPv4 address.
async fn resolve_target(
    request: &ValidatedSend,
    deadline: TokioInstant,
    cancel: &mut watch::Receiver<bool>,
) -> Result<SocketAddr, PartialReport> {
    if let Ok(address) = request.destination_host.parse::<Ipv4Addr>() {
        return Ok(SocketAddr::from((address, request.destination_port)));
    }
    let lookup = format!("{}:{}", request.destination_host, request.destination_port);
    // Expiration-first on every poll: the expiry branch precedes the lookup,
    // so a lookup that became ready while polling was suspended still loses
    // to an elapsed deadline on resumption.
    let expiry = sleep_until(deadline);
    tokio::pin!(expiry);
    let resolved = tokio::select! {
        biased;
        _ = cancel.changed() => {
            return Err(PartialReport::stopped(false, 0));
        }
        _ = &mut expiry => {
            return Err(PartialReport::timed_out(false, 0));
        }
        resolved = tokio::net::lookup_host(lookup.as_str()) => resolved,
    };
    match resolved {
        Ok(addrs) => {
            // Pin the first IPv4 candidate. Trying further addresses would
            // be an automatic retry with ambiguous send semantics.
            match addrs.into_iter().find(|addr| addr.is_ipv4()) {
                Some(addr) => Ok(addr),
                None => Err(PartialReport::failed(false, 0, "address_type")),
            }
        }
        Err(_) => Err(PartialReport::failed(false, 0, "resolve_failed")),
    }
}

/// Make exactly one connect attempt to the pinned address.
async fn connect_pinned(
    addr: SocketAddr,
    deadline: TokioInstant,
    cancel: &mut watch::Receiver<bool>,
) -> Result<TcpStream, PartialReport> {
    // Expiration-first on every poll: a connect that became ready while
    // polling was suspended must not be used after the deadline.
    let expiry = sleep_until(deadline);
    tokio::pin!(expiry);
    let connected = tokio::select! {
        biased;
        _ = cancel.changed() => {
            return Err(PartialReport::stopped(false, 0));
        }
        _ = &mut expiry => {
            return Err(PartialReport::timed_out(false, 0));
        }
        connected = TcpStream::connect(addr) => connected,
    };
    match connected {
        Ok(stream) => Ok(stream),
        Err(_) => Err(PartialReport::failed(false, 0, "connect_failed")),
    }
}

/// Write the payload exactly once, counting partial progress on failure.
async fn write_payload(
    request: &ValidatedSend,
    stream: &mut TcpStream,
    deadline: TokioInstant,
    cancel: &mut watch::Receiver<bool>,
) -> Result<u64, PartialReport> {
    let mut written = 0usize;
    while written < request.payload.len() {
        // Expiration-first on every poll: a write that became possible while
        // polling was suspended must not transmit after the deadline.
        let expiry = sleep_until(deadline);
        tokio::pin!(expiry);
        let attempt = tokio::select! {
            biased;
            _ = cancel.changed() => {
                return Err(PartialReport::stopped(false, written as u64));
            }
            _ = &mut expiry => {
                return Err(PartialReport::timed_out(false, written as u64));
            }
            result = stream.write(&request.payload[written..]) => result,
        };
        match attempt {
            Ok(0) => return Err(PartialReport::failed(false, written as u64, "write_failed")),
            Ok(count) => written += count,
            Err(_) => {
                return Err(PartialReport::failed(false, written as u64, "write_failed"));
            }
        }
    }
    Ok(written as u64)
}

/// Capture a bounded response under the selected completion policy.
async fn read_response(
    request: &ValidatedSend,
    stream: &mut TcpStream,
    deadline: TokioInstant,
    cancel: &mut watch::Receiver<bool>,
    bytes_sent: u64,
    started: Instant,
) -> Report {
    let mut response = Vec::new();
    let mut buffer = vec![0u8; READ_BUFFER_BYTES];

    loop {
        if response.len() >= request.response_limit {
            if request.completion == Completion::ReadExactBytes {
                return completed_report(
                    request,
                    bytes_sent,
                    response,
                    false,
                    Outcome::CompletedByteCount,
                    started,
                );
            }
            return completed_report(
                request,
                bytes_sent,
                response,
                true,
                Outcome::Truncated,
                started,
            );
        }
        // A fully arrived response above already won. The expiry branch
        // below precedes every read on every poll, so bytes that became
        // ready while polling was suspended still lose to an elapsed
        // deadline and are never appended after expiration.
        let max_read = (request.response_limit - response.len()).min(buffer.len());
        let expiry = sleep_until(deadline);
        tokio::pin!(expiry);
        let read = match request.completion {
            Completion::ReadUntilIdle => {
                let idle = tokio::time::sleep(request.idle_timeout);
                tokio::pin!(idle);
                tokio::select! {
                    biased;
                    _ = cancel.changed() => {
                        return stopped_report(request, true, bytes_sent, response, false, started);
                    }
                    _ = &mut expiry => {
                        return timed_out_report(request, bytes_sent, response, started);
                    }
                    _ = &mut idle => {
                        return completed_report(
                            request,
                            bytes_sent,
                            response,
                            false,
                            Outcome::CompletedIdleTimeout,
                            started,
                        );
                    }
                    result = stream.read(&mut buffer[..max_read]) => result,
                }
            }
            Completion::ReadUntilClose | Completion::ReadExactBytes => {
                tokio::select! {
                    biased;
                    _ = cancel.changed() => {
                        return stopped_report(request, true, bytes_sent, response, false, started);
                    }
                    _ = &mut expiry => {
                        return timed_out_report(request, bytes_sent, response, started);
                    }
                    result = stream.read(&mut buffer[..max_read]) => result,
                }
            }
        };

        match read {
            Ok(0) => {
                return completed_report(
                    request,
                    bytes_sent,
                    response,
                    false,
                    Outcome::CompletedClosed,
                    started,
                );
            }
            Ok(count) => response.extend_from_slice(&buffer[..count]),
            Err(_) => {
                return failed_report(request, bytes_sent, response, "read_failed", started);
            }
        }
    }
}

/// An unfinished report: outcome metadata without the final elapsed time.
struct PartialReport {
    sent: bool,
    bytes_sent: u64,
    response: Vec<u8>,
    truncated: bool,
    outcome: Outcome,
    error_kind: &'static str,
}

impl PartialReport {
    fn stopped(sent: bool, bytes_sent: u64) -> Self {
        Self {
            sent,
            bytes_sent,
            response: Vec::new(),
            truncated: false,
            outcome: Outcome::Stopped,
            error_kind: "stopped",
        }
    }

    fn timed_out(sent: bool, bytes_sent: u64) -> Self {
        Self {
            sent,
            bytes_sent,
            response: Vec::new(),
            truncated: false,
            outcome: Outcome::TimedOut,
            error_kind: "",
        }
    }

    fn failed(sent: bool, bytes_sent: u64, error_kind: &'static str) -> Self {
        Self {
            sent,
            bytes_sent,
            response: Vec::new(),
            truncated: false,
            outcome: Outcome::Failed,
            error_kind,
        }
    }
}

fn report_with(partial: PartialReport, started: Instant) -> Report {
    Report {
        sent: partial.sent,
        bytes_sent: partial.bytes_sent,
        response: partial.response,
        truncated: partial.truncated,
        outcome: partial.outcome,
        elapsed: started.elapsed(),
        error_kind: partial.error_kind,
    }
}

fn completed_report(
    request: &ValidatedSend,
    bytes_sent: u64,
    response: Vec<u8>,
    truncated: bool,
    outcome: Outcome,
    started: Instant,
) -> Report {
    let _ = request;
    Report {
        sent: true,
        bytes_sent,
        response,
        truncated,
        outcome,
        elapsed: started.elapsed(),
        error_kind: "",
    }
}

fn stopped_report(
    request: &ValidatedSend,
    sent: bool,
    bytes_sent: u64,
    response: Vec<u8>,
    truncated: bool,
    started: Instant,
) -> Report {
    let _ = request;
    Report {
        sent,
        bytes_sent,
        response,
        truncated,
        outcome: Outcome::Stopped,
        elapsed: started.elapsed(),
        error_kind: "stopped",
    }
}

fn timed_out_report(
    request: &ValidatedSend,
    bytes_sent: u64,
    response: Vec<u8>,
    started: Instant,
) -> Report {
    let _ = request;
    Report {
        sent: true,
        bytes_sent,
        response,
        truncated: false,
        outcome: Outcome::TimedOut,
        elapsed: started.elapsed(),
        error_kind: "",
    }
}

fn failed_report(
    request: &ValidatedSend,
    bytes_sent: u64,
    response: Vec<u8>,
    error_kind: &'static str,
    started: Instant,
) -> Report {
    let _ = request;
    Report {
        sent: true,
        bytes_sent,
        response,
        truncated: false,
        outcome: Outcome::Failed,
        elapsed: started.elapsed(),
        error_kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> proto::RepeaterSend {
        proto::RepeaterSend {
            destination_host: "127.0.0.1".to_owned(),
            destination_port: 9,
            payload: vec![0x00, 0xff],
            response_byte_limit: 8,
            timeout_ms: 1_000,
            completion: 2,
            idle_timeout_ms: 0,
        }
    }

    #[test]
    fn valid_repeater_send_is_accepted() {
        let validated = validate_send(&valid_request()).expect("valid request");
        assert_eq!(validated.destination_port, 9);
        assert_eq!(validated.response_limit, 8);
        assert_eq!(validated.timeout, Duration::from_millis(1_000));
    }

    #[test]
    fn destination_host_rules_are_explicit() {
        let mut request = valid_request();
        request.destination_host.clear();
        assert_eq!(
            validate_send(&request).expect_err("empty host"),
            "destination host is required"
        );

        request = valid_request();
        request.destination_host = "2001:db8::1".to_owned();
        assert_eq!(
            validate_send(&request).expect_err("IPv6 rejected"),
            "IPv6 destinations are not supported"
        );

        request = valid_request();
        request.destination_host = "bad_host!".to_owned();
        assert!(validate_send(&request).is_err());
    }

    #[test]
    fn exact_bounds_are_accepted() {
        let mut request = valid_request();
        request.payload = vec![0u8; MAX_PAYLOAD_BYTES];
        request.response_byte_limit = MAX_RESPONSE_BYTES as u32;
        request.timeout_ms = MAX_TIMEOUT.as_millis() as u64;
        assert!(validate_send(&request).is_ok());

        request = valid_request();
        request.completion = 3;
        request.idle_timeout_ms = MAX_IDLE_TIMEOUT.as_millis() as u64;
        assert!(validate_send(&request).is_ok());
    }

    #[test]
    fn bound_plus_one_is_rejected() {
        let mut request = valid_request();
        request.timeout_ms = MAX_TIMEOUT.as_millis() as u64 + 1;
        assert!(validate_send(&request).is_err());

        request = valid_request();
        request.response_byte_limit = MAX_RESPONSE_BYTES as u32 + 1;
        assert!(validate_send(&request).is_err());

        request = valid_request();
        request.completion = 3;
        request.idle_timeout_ms = MAX_IDLE_TIMEOUT.as_millis() as u64 + 1;
        assert!(validate_send(&request).is_err());
    }

    #[test]
    fn bounds_are_checked_before_any_socket_opens() {
        let mut request = valid_request();
        request.destination_port = 0;
        assert!(validate_send(&request).is_err());

        request = valid_request();
        request.payload = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        assert!(validate_send(&request).is_err());

        request = valid_request();
        request.response_byte_limit = 0;
        assert!(validate_send(&request).is_err());

        request = valid_request();
        request.timeout_ms = 0;
        assert!(validate_send(&request).is_err());

        request = valid_request();
        request.completion = 0;
        assert!(validate_send(&request).is_err());

        request = valid_request();
        request.completion = 3;
        request.idle_timeout_ms = 0;
        assert!(validate_send(&request).is_err());

        request = valid_request();
        request.idle_timeout_ms = 10;
        assert!(validate_send(&request).is_err());
    }
}
