//! Upstream dialing and bidirectional transport.

pub mod dialer;
pub mod relay;

pub use dialer::{dial_burp, dial_upstream, UpstreamConnection};
pub use relay::{relay, relay_with_counters, wait_for_shutdown, RelayOutcome};
