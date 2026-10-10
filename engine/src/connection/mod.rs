//! Connection lifecycle tracking.

pub mod registry;

pub use registry::{Admission, Connection, ConnectionRegistry, ConnectionState};
