//! Deterministic test payloads.
//!
//! Reproducibility matters: the same length always yields the same bytes, and
//! payloads always include `0x00` and `0xff` so binary-safety regressions cannot
//! pass by accident on ASCII-only data.

/// Client request used by the functional login flow.
pub const LOGIN_REQUEST: &[u8] = b"LOGIN faqih password\n";
/// Server response for [`LOGIN_REQUEST`].
pub const AUTH_OK_RESPONSE: &[u8] = b"AUTH_OK\n";

/// Small binary payload with NUL and high bytes: `00 01 FF 10 00 41 42`.
pub const BINARY_SAMPLE: &[u8] = &[0x00, 0x01, 0xff, 0x10, 0x00, 0x41, 0x42];

/// Deterministic pseudo-random payload of exactly `len` bytes.
///
/// Uses xorshift64* so results are identical across platforms and runs.
pub fn deterministic_payload(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let value = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        let byte = (value >> 32) as u8;
        // Guarantee NUL and high-byte coverage regardless of length.
        out.push(match out.len() % 5 {
            0 => 0x00,
            1 => 0xff,
            _ => byte,
        });
    }
    out
}

/// Count of zero bytes, used by tests that assert NUL preservation.
pub fn count_nuls(data: &[u8]) -> usize {
    data.iter().filter(|byte| **byte == 0).count()
}
