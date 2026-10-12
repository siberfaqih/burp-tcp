//! Protobuf message types mirroring `proto/burp_tcp.proto` (v1).
//!
//! These are hand-written `prost::Message` structs so the Rust build
//! needs no `protoc` binary. The `.proto` file is the canonical schema
//! for the Java extension (Phase 4B); these structs MUST stay in sync
//! with it: field names, tag numbers, and oneof layout identical.

// --- Enums ---

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum Direction {
    Unspecified = 0,
    ClientToServer = 1,
    ServerToClient = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum InterceptActionKind {
    Unspecified = 0,
    Forward = 1,
    Replace = 2,
    Suppress = 3,
    Close = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum RepeaterCompletion {
    Unspecified = 0,
    ReadUntilClose = 1,
    ReadExactBytes = 2,
    ReadUntilIdle = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum RepeaterOutcome {
    Unspecified = 0,
    CompletedClosed = 1,
    CompletedByteCount = 2,
    CompletedIdleTimeout = 3,
    Stopped = 4,
    TimedOut = 5,
    Truncated = 6,
    Failed = 7,
}

// --- Handshake ---

#[derive(Clone, PartialEq, prost::Message)]
pub struct Hello {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(string, tag = "2")]
    pub client_name: String,
    #[prost(string, tag = "3")]
    pub client_version: String,
    #[prost(string, tag = "4")]
    pub capability_token: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HelloAck {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(string, tag = "2")]
    pub daemon_epoch: String,
    #[prost(string, tag = "3")]
    pub server_version: String,
    /// Engine SOCKS listener address (e.g. "127.0.0.1:1080") so the
    /// control plane can show which proxy endpoint the app must use.
    #[prost(string, tag = "4")]
    pub socks_addr: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Error {
    #[prost(uint32, tag = "1")]
    pub code: u32,
    #[prost(string, tag = "2")]
    pub message: String,
}

// --- RPC request bodies ---

#[derive(Clone, PartialEq, prost::Message)]
pub struct ListConnections {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HistorySnapshot {
    #[prost(string, tag = "1")]
    pub conn_id: String,
    #[prost(enumeration = "Direction", tag = "2")]
    pub direction: i32,
    /// Per-direction newest chunk count; 0 = server default. The server
    /// enforces 300 chunks / 1 MiB per direction even for legacy clients.
    /// [`HistoryData::total_chunks`] reports the retained count before limits.
    #[prost(uint32, tag = "3")]
    pub max_chunks: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PendingUnits {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Decide {
    #[prost(string, tag = "1")]
    pub unit_id: String,
    #[prost(uint64, tag = "2")]
    pub revision: u64,
    #[prost(enumeration = "InterceptActionKind", tag = "3")]
    pub action: i32,
    #[prost(bytes, tag = "4")]
    pub replace_bytes: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SetEnabled {
    #[prost(enumeration = "Direction", tag = "1")]
    pub direction: i32,
    #[prost(bool, tag = "2")]
    pub enabled: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct GetStats {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Subscribe {
    #[prost(bool, tag = "1")]
    pub state_changes: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RepeaterSend {
    #[prost(string, tag = "1")]
    pub destination_host: String,
    #[prost(uint32, tag = "2")]
    pub destination_port: u32,
    #[prost(bytes, tag = "3")]
    pub payload: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub response_byte_limit: u32,
    #[prost(uint64, tag = "5")]
    pub timeout_ms: u64,
    #[prost(enumeration = "RepeaterCompletion", tag = "6")]
    pub completion: i32,
    #[prost(uint64, tag = "7")]
    pub idle_timeout_ms: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RepeaterStartResult {
    #[prost(string, tag = "1")]
    pub send_id: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RepeaterStop {
    #[prost(string, tag = "1")]
    pub send_id: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RepeaterStopResult {
    #[prost(string, tag = "1")]
    pub send_id: String,
    #[prost(bool, tag = "2")]
    pub accepted: bool,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RepeaterStatus {
    #[prost(string, tag = "1")]
    pub send_id: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RepeaterStatusResult {
    #[prost(string, tag = "1")]
    pub send_id: String,
    #[prost(bool, tag = "2")]
    pub finished: bool,
    #[prost(message, tag = "3")]
    pub result: Option<RepeaterResult>,
}

// --- RPC responses ---

#[derive(Clone, PartialEq, prost::Message)]
pub struct ConnectionInfo {
    #[prost(string, tag = "1")]
    pub conn_id: String,
    #[prost(string, tag = "2")]
    pub requested_host: String,
    #[prost(uint32, tag = "3")]
    pub requested_port: u32,
    #[prost(bool, tag = "4")]
    pub established: bool,
    #[prost(bool, tag = "5")]
    pub closed: bool,
    #[prost(uint64, tag = "6")]
    pub bytes_client_to_server: u64,
    #[prost(uint64, tag = "7")]
    pub bytes_server_to_client: u64,
    /// Terminal reason once closed (e.g. "eof"); "" while live.
    #[prost(string, tag = "8")]
    pub close_reason: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ConnectionList {
    #[prost(message, repeated, tag = "1")]
    pub connections: Vec<ConnectionInfo>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct TrafficChunkInfo {
    #[prost(string, tag = "1")]
    pub chunk_id: String,
    #[prost(uint64, tag = "2")]
    pub seq: u64,
    #[prost(uint64, tag = "3")]
    pub offset: u64,
    #[prost(uint64, tag = "4")]
    pub len: u64,
    #[prost(bytes, tag = "5")]
    pub bytes: Vec<u8>,
    #[prost(uint64, tag = "6")]
    pub recorded_unix_ms: u64,
    #[prost(enumeration = "Direction", tag = "7")]
    pub direction: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct HistoryData {
    #[prost(message, repeated, tag = "1")]
    pub chunks: Vec<TrafficChunkInfo>,
    /// Chunks retained for this query before `max_chunks` truncation.
    #[prost(uint64, tag = "2")]
    pub total_chunks: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PendingUnitInfo {
    #[prost(string, tag = "1")]
    pub unit_id: String,
    #[prost(string, tag = "2")]
    pub conn_id: String,
    #[prost(enumeration = "Direction", tag = "3")]
    pub direction: i32,
    #[prost(uint64, tag = "4")]
    pub seq: u64,
    #[prost(uint64, tag = "5")]
    pub offset: u64,
    #[prost(uint64, tag = "6")]
    pub len: u64,
    #[prost(bytes, tag = "7")]
    pub bytes: Vec<u8>,
    #[prost(uint64, tag = "8")]
    pub revision: u64,
    #[prost(uint64, tag = "9")]
    pub expires_unix_ms: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PendingList {
    #[prost(message, repeated, tag = "1")]
    pub units: Vec<PendingUnitInfo>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct DecideResult {
    #[prost(bool, tag = "1")]
    pub committed: bool,
    #[prost(string, tag = "2")]
    pub error_kind: String,
    #[prost(uint64, tag = "3")]
    pub expected_revision: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct SetEnabledResult {
    #[prost(uint64, tag = "1")]
    pub released: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct RepeaterResult {
    #[prost(string, tag = "1")]
    pub send_id: String,
    #[prost(bool, tag = "2")]
    pub sent: bool,
    #[prost(uint64, tag = "3")]
    pub bytes_sent: u64,
    #[prost(bytes, tag = "4")]
    pub response: Vec<u8>,
    #[prost(bool, tag = "5")]
    pub response_truncated: bool,
    #[prost(enumeration = "RepeaterOutcome", tag = "6")]
    pub outcome: i32,
    #[prost(uint64, tag = "7")]
    pub elapsed_ms: u64,
    #[prost(string, tag = "8")]
    pub error_kind: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Stats {
    #[prost(uint64, tag = "1")]
    pub offers: u64,
    #[prost(uint64, tag = "2")]
    pub overflow_forwards: u64,
    #[prost(uint64, tag = "3")]
    pub lease_releases: u64,
    #[prost(uint64, tag = "4")]
    pub disable_releases: u64,
    #[prost(uint64, tag = "5")]
    pub abandoned: u64,
    #[prost(uint64, tag = "6")]
    pub commits: u64,
    #[prost(bool, tag = "7")]
    pub c2s_enabled: bool,
    #[prost(bool, tag = "8")]
    pub s2c_enabled: bool,
    #[prost(uint64, tag = "9")]
    pub ipc_dropped_events: u64,
    #[prost(uint64, tag = "10")]
    pub history_dropped_chunks: u64,
    #[prost(uint64, tag = "11")]
    pub history_dropped_bytes: u64,
    #[prost(uint64, tag = "12")]
    pub accepted_connections: u64,
    #[prost(uint64, tag = "13")]
    pub active_connections: u64,
}

// --- Events ---

#[derive(Clone, PartialEq, prost::Message)]
pub struct StateChanged {
    #[prost(uint64, tag = "1")]
    pub connection_count: u64,
    #[prost(uint64, tag = "2")]
    pub pending_count: u64,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Event {
    #[prost(uint64, tag = "1")]
    pub seq: u64,
    #[prost(uint64, tag = "2")]
    pub timestamp_unix_ms: u64,
    #[prost(message, tag = "3")]
    pub state_changed: Option<StateChanged>,
}

// --- Envelopes ---

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum RequestBody {
    #[prost(message, tag = "2")]
    Hello(Hello),
    #[prost(message, tag = "3")]
    ListConnections(ListConnections),
    #[prost(message, tag = "4")]
    HistorySnapshot(HistorySnapshot),
    #[prost(message, tag = "5")]
    PendingUnits(PendingUnits),
    #[prost(message, tag = "6")]
    Decide(Decide),
    #[prost(message, tag = "7")]
    SetEnabled(SetEnabled),
    #[prost(message, tag = "8")]
    GetStats(GetStats),
    #[prost(message, tag = "9")]
    Subscribe(Subscribe),
    #[prost(message, tag = "10")]
    RepeaterSend(RepeaterSend),
    #[prost(message, tag = "11")]
    RepeaterStop(RepeaterStop),
    #[prost(message, tag = "12")]
    RepeaterStatus(RepeaterStatus),
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Request {
    #[prost(uint32, tag = "1")]
    pub request_id: u32,
    #[prost(oneof = "RequestBody", tags = "2,3,4,5,6,7,8,9,10,11,12")]
    pub body: Option<RequestBody>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum ResponseBody {
    #[prost(message, tag = "2")]
    HelloAck(HelloAck),
    #[prost(message, tag = "3")]
    ConnectionList(ConnectionList),
    #[prost(message, tag = "4")]
    HistoryData(HistoryData),
    #[prost(message, tag = "5")]
    PendingList(PendingList),
    #[prost(message, tag = "6")]
    DecideResult(DecideResult),
    #[prost(message, tag = "7")]
    SetEnabledResult(SetEnabledResult),
    #[prost(message, tag = "8")]
    Stats(Stats),
    #[prost(message, tag = "9")]
    Error(Error),
    #[prost(message, tag = "10")]
    RepeaterStartResult(RepeaterStartResult),
    #[prost(message, tag = "11")]
    RepeaterStopResult(RepeaterStopResult),
    #[prost(message, tag = "12")]
    RepeaterStatusResult(RepeaterStatusResult),
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Response {
    #[prost(uint32, tag = "1")]
    pub request_id: u32,
    #[prost(oneof = "ResponseBody", tags = "2,3,4,5,6,7,8,9,10,11,12")]
    pub body: Option<ResponseBody>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum ServerMessageBody {
    #[prost(message, tag = "1")]
    Response(Response),
    #[prost(message, tag = "2")]
    Event(Event),
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ServerMessage {
    #[prost(oneof = "ServerMessageBody", tags = "1,2")]
    pub body: Option<ServerMessageBody>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ClientMessage {
    #[prost(message, tag = "1")]
    pub request: Option<Request>,
}

#[cfg(test)]
mod tests {
    //! Golden wire-format tests. These pin the exact protobuf encoding so a
    //! schema change that breaks compatibility with the Java extension (which
    //! compiles `proto/burp_tcp.proto` with protoc) fails here. The Java side
    //! asserts the same byte sequences in
    //! `extension/src/test/java/.../WireFormatTest.java`.

    use super::*;
    use prost::Message;

    fn hello_abc() -> Hello {
        Hello {
            protocol_version: 1,
            client_name: String::new(),
            client_version: String::new(),
            capability_token: "abc".to_string(),
        }
    }

    #[test]
    fn hello_wire_format_is_stable() {
        // field 1 varint = 1; field 4 string = "abc".
        let expected = [0x08, 0x01, 0x22, 0x03, b'a', b'b', b'c'];
        assert_eq!(hello_abc().encode_to_vec(), expected);
    }

    #[test]
    fn request_wire_format_is_stable() {
        // request_id = 7 (field 1), hello (field 2) as above.
        let request = Request {
            request_id: 7,
            body: Some(RequestBody::Hello(hello_abc())),
        };
        let expected = [
            0x08, 0x07, // request_id = 7
            0x12, 0x07, // field 2, len 7
            0x08, 0x01, 0x22, 0x03, b'a', b'b', b'c',
        ];
        assert_eq!(request.encode_to_vec(), expected);
    }

    #[test]
    fn client_message_wire_format_is_stable() {
        let message = ClientMessage {
            request: Some(Request {
                request_id: 7,
                body: Some(RequestBody::Hello(hello_abc())),
            }),
        };
        let expected = [
            0x0A, 0x0B, // field 1, len 11
            0x08, 0x07, // request_id = 7
            0x12, 0x07, // hello, len 7
            0x08, 0x01, 0x22, 0x03, b'a', b'b', b'c',
        ];
        assert_eq!(message.encode_to_vec(), expected);
    }

    #[test]
    fn server_message_wire_format_is_stable() {
        let message = ServerMessage {
            body: Some(ServerMessageBody::Response(Response {
                request_id: 7,
                body: Some(ResponseBody::HelloAck(HelloAck {
                    protocol_version: 1,
                    daemon_epoch: String::new(),
                    server_version: String::new(),
                    socks_addr: String::new(),
                })),
            })),
        };
        let expected = [
            0x0A, 0x06, // server_message.response, len 6
            0x08, 0x07, // request_id = 7
            0x12, 0x02, // response.hello_ack, len 2
            0x08, 0x01, // protocol_version = 1
        ];
        assert_eq!(message.encode_to_vec(), expected);
    }

    #[test]
    fn repeater_send_wire_format_is_stable() {
        let send = RepeaterSend {
            destination_host: "h".to_owned(),
            destination_port: 7,
            payload: vec![0x01],
            response_byte_limit: 2,
            timeout_ms: 3,
            completion: RepeaterCompletion::ReadExactBytes as i32,
            idle_timeout_ms: 4,
        };
        let expected = [
            0x0A, 0x01, b'h', // destination_host = "h"
            0x10, 0x07, // destination_port = 7
            0x1A, 0x01, 0x01, // payload
            0x20, 0x02, // response_byte_limit = 2
            0x28, 0x03, // timeout_ms = 3
            0x30, 0x02, // completion = READ_EXACT_BYTES
            0x38, 0x04, // idle_timeout_ms = 4
        ];
        assert_eq!(send.encode_to_vec(), expected);
    }

    #[test]
    fn connection_info_close_reason_wire_format_is_stable() {
        // New additive fields must encode exactly as protoc does: field 8
        // (close_reason) is tag 0x42. Empty fields are omitted entirely, so
        // old binaries see identical bytes for live connections.
        let live = ConnectionInfo {
            conn_id: "c".to_string(),
            requested_host: String::new(),
            requested_port: 0,
            established: true,
            closed: false,
            bytes_client_to_server: 0,
            bytes_server_to_client: 0,
            close_reason: String::new(),
        };
        let live_bytes = live.encode_to_vec();
        assert!(
            !live_bytes.contains(&0x42),
            "empty close_reason must be omitted: {live_bytes:?}"
        );
        let dead = ConnectionInfo {
            close_reason: "eof".to_string(),
            ..live.clone()
        };
        let dead_bytes = dead.encode_to_vec();
        assert_eq!(
            &dead_bytes[live_bytes.len()..],
            &[0x42, 0x03, b'e', b'o', b'f'],
            "close_reason must append as field 8"
        );
    }

    #[test]
    fn decode_round_trips_request() {
        let original = ClientMessage {
            request: Some(Request {
                request_id: 42,
                body: Some(RequestBody::Decide(Decide {
                    unit_id: "unit-1".to_string(),
                    revision: 0,
                    action: InterceptActionKind::Replace as i32,
                    replace_bytes: vec![0x00, 0xFF, 0x10],
                })),
            }),
        };
        let bytes = original.encode_to_vec();
        let decoded = ClientMessage::decode(&bytes[..]).expect("decode");
        assert_eq!(decoded, original);
    }
}
