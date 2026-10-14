//! Destination-based routing of SOCKS sessions through a Burp Proxy listener.
//!
//! When a SOCKS CONNECT target matches a route, the engine dials the
//! configured Burp listener instead of the original destination and relays
//! bytes unchanged. Burp (typically in invisible-proxy mode with a redirect
//! to the real target) then parses HTTP, so the operator can use the native
//! Proxy history, Intercept, Repeater, Intruder, and Scanner.
//!
//! Routed sessions bypass engine interception: holding the same bytes in two
//! queues would force two Forward clicks per chunk. Passive history still
//! records routed sessions with the original requested destination.

use std::net::SocketAddr;

/// One destination rule: SOCKS targets matching `host_pattern`/`port` are
/// relayed to `burp_addr` (a Burp Proxy listener) instead of dialled directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BurpRoute {
    /// Exact hostname/IPv4 (case-insensitive) or `"*"` for any host.
    pub host_pattern: String,
    /// Destination port, or `0` for any port.
    pub port: u16,
    /// Burp Proxy listener to relay through (loopback only).
    pub burp_addr: SocketAddr,
}

impl BurpRoute {
    /// True when this route handles a SOCKS target.
    pub fn matches(&self, host: &str, port: u16) -> bool {
        let host_ok = self.host_pattern == "*" || self.host_pattern.eq_ignore_ascii_case(host);
        let port_ok = self.port == 0 || self.port == port;
        host_ok && port_ok
    }

    /// Parse `HOST[:PORT]=>BURP_ADDR`, e.g. `10.0.0.5:7007=>127.0.0.1:8081`
    /// or `*=>127.0.0.1:8080`. A missing destination port means any port.
    pub fn parse(rule: &str) -> Result<Self, String> {
        let (left, right) = rule.split_once("=>").ok_or_else(|| {
            format!("invalid --burp-route (expected HOST[:PORT]=>BURP_ADDR): {rule}")
        })?;
        let left = left.trim();
        let right = right.trim();
        if left.is_empty() {
            return Err(format!(
                "invalid --burp-route: empty destination pattern: {rule}"
            ));
        }
        let burp_addr: SocketAddr = right
            .parse()
            .map_err(|_| format!("invalid --burp-route Burp address: {right}"))?;
        if !burp_addr.ip().is_loopback() {
            return Err(format!(
                "invalid --burp-route: Burp listener must be loopback: {right}"
            ));
        }
        let (host_pattern, port) = match left.split_once(':') {
            Some((host, port_raw)) => {
                if host.trim().is_empty() {
                    return Err(format!("invalid --burp-route: empty host: {rule}"));
                }
                let port: u16 = port_raw
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid --burp-route port: {port_raw}"))?;
                if port == 0 {
                    return Err(format!(
                        "invalid --burp-route: port must be 1..65535: {rule}"
                    ));
                }
                (host.trim().to_owned(), port)
            }
            None => (left.to_owned(), 0),
        };
        if host_pattern.is_empty() {
            return Err(format!("invalid --burp-route: empty host: {rule}"));
        }
        Ok(Self {
            host_pattern,
            port,
            burp_addr,
        })
    }
}

/// Thread-safe route table shared by the SOCKS supervisor and the IPC server.
#[derive(Debug, Default)]
pub struct BurpRouter {
    routes: std::sync::RwLock<Vec<BurpRoute>>,
}

/// Maximum routes retained; bounds memory for IPC-driven updates.
pub const MAX_BURP_ROUTES: usize = 64;

impl BurpRouter {
    /// Build a table from static configuration.
    pub fn new(routes: Vec<BurpRoute>) -> Self {
        Self {
            routes: std::sync::RwLock::new(routes),
        }
    }

    /// Replace the whole table (IPC `SetBurpRoutes`).
    pub fn set_routes(&self, routes: Vec<BurpRoute>) {
        let mut guard = self.routes.write().unwrap_or_else(|p| p.into_inner());
        *guard = routes;
    }

    /// Snapshot the table (IPC `ListBurpRoutes`).
    pub fn list(&self) -> Vec<BurpRoute> {
        self.routes
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// First matching Burp listener for a SOCKS target, if any.
    pub fn route_for(&self, host: &str, port: u16) -> Option<SocketAddr> {
        let guard = self.routes.read().unwrap_or_else(|p| p.into_inner());
        guard
            .iter()
            .find(|route| route.matches(host, port))
            .map(|route| route.burp_addr)
    }
}

/// Shared router handle.
pub type SharedBurpRouter = std::sync::Arc<BurpRouter>;

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("addr")
    }

    #[test]
    fn exact_host_and_port_match() {
        let route = BurpRoute {
            host_pattern: "10.0.0.5".into(),
            port: 7007,
            burp_addr: addr("127.0.0.1:8081"),
        };
        assert!(route.matches("10.0.0.5", 7007));
        assert!(!route.matches("10.0.0.5", 7008));
        assert!(!route.matches("10.0.0.6", 7007));
    }

    #[test]
    fn host_match_is_case_insensitive_and_port_zero_is_any() {
        let route = BurpRoute {
            host_pattern: "Example.COM".into(),
            port: 0,
            burp_addr: addr("127.0.0.1:8080"),
        };
        assert!(route.matches("example.com", 80));
        assert!(route.matches("EXAMPLE.COM", 443));
        assert!(!route.matches("other.com", 80));
    }

    #[test]
    fn wildcard_matches_any_host_but_respects_port() {
        let route = BurpRoute {
            host_pattern: "*".into(),
            port: 7007,
            burp_addr: addr("127.0.0.1:8080"),
        };
        assert!(route.matches("anything.example", 7007));
        assert!(!route.matches("anything.example", 80));
    }

    #[test]
    fn first_match_wins() {
        let router = BurpRouter::new(vec![
            BurpRoute {
                host_pattern: "10.0.0.5".into(),
                port: 7007,
                burp_addr: addr("127.0.0.1:8081"),
            },
            BurpRoute {
                host_pattern: "*".into(),
                port: 0,
                burp_addr: addr("127.0.0.1:8082"),
            },
        ]);
        assert_eq!(
            router.route_for("10.0.0.5", 7007),
            Some(addr("127.0.0.1:8081"))
        );
        assert_eq!(router.route_for("other", 1), Some(addr("127.0.0.1:8082")));
        assert_eq!(
            BurpRouter::new(vec![]).route_for("other", 1),
            None,
            "empty table routes nothing"
        );
    }

    #[test]
    fn parse_full_rule() {
        let route = BurpRoute::parse("10.0.0.5:7007=>127.0.0.1:8081").expect("parse");
        assert_eq!(route.host_pattern, "10.0.0.5");
        assert_eq!(route.port, 7007);
        assert_eq!(route.burp_addr, addr("127.0.0.1:8081"));
    }

    #[test]
    fn parse_without_port_means_any_port() {
        let route = BurpRoute::parse("example.com=>127.0.0.1:8080").expect("parse");
        assert_eq!(route.port, 0);
        assert!(route.matches("example.com", 1234));
    }

    #[test]
    fn parse_rejects_non_loopback_burp_addr() {
        let err = BurpRoute::parse("*=>192.168.1.1:8080").expect_err("must reject");
        assert!(err.contains("loopback"), "unexpected: {err}");
    }

    #[test]
    fn parse_rejects_malformed_rules() {
        for bad in [
            "",
            "=>127.0.0.1:8080",
            "*127.0.0.1:8080",
            "*=>not-an-addr",
            ":80=>127.0.0.1:8080",
        ] {
            assert!(BurpRoute::parse(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn set_and_list_round_trip() {
        let router = BurpRouter::new(vec![]);
        router.set_routes(vec![BurpRoute {
            host_pattern: "*".into(),
            port: 0,
            burp_addr: addr("127.0.0.1:8080"),
        }]);
        assert_eq!(router.list().len(), 1);
        router.set_routes(vec![]);
        assert!(router.list().is_empty());
    }
}
