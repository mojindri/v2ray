//! Routing engine: decides which outbound to use for each connection.
//!
//! # How routing works
//!
//! The router has a list of rules. For each new connection, it evaluates
//! the rules in order until it finds one that matches. It then uses the
//! outbound tag from that rule.
//!
//! A rule can match based on:
//!   - The destination domain name (exact, suffix, keyword, regex)
//!   - The destination IP address (CIDR range)
//!   - The destination port
//!   - The inbound tag the connection arrived on
//!
//! If no rule matches, the `default_tag` is used (usually "direct" or the
//! first configured outbound).
//!
//! # Hot-swap without dropping connections
//!
//! The router is stored behind `ArcSwap`. When the config is reloaded,
//! a new `RouterInner` is built and swapped in atomically. Connections that
//! are already being processed keep a reference to the old router until they
//! finish. New connections see the new router immediately.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use arc_swap::ArcSwap;
use ipnet::IpNet;
use regex::RegexSet;

use proxy_common::{Address, Network, ProxyError};

use crate::geo::{GeoIpMatcher, GeoSiteMatcher};

/// The result of a routing decision: which outbound to use.
#[derive(Debug, Clone)]
pub struct Route {
    /// The tag of the outbound to use for this connection.
    pub outbound_tag: Arc<str>,
}

/// Context passed to the router for each connection.
///
/// The router evaluates its rules against this context to pick an outbound.
#[derive(Debug)]
pub struct RoutingContext<'a> {
    /// The destination address (domain or IP + port).
    pub dest: &'a Address,

    /// The network type (TCP or UDP).
    pub network: Network,

    /// The inbound tag this connection arrived on.
    pub inbound_tag: &'a str,

    /// The authenticated user, if any.
    pub user: Option<&'a str>,
}

/// The routing trait. Can be swapped out at runtime via `ArcSwap`.
pub trait Router: Send + Sync + 'static {
    /// Pick an outbound for the given connection context.
    ///
    /// Returns `Route` on success, or `ProxyError::RoutingFailed` if no rule
    /// matched and there is no default outbound configured.
    fn pick_route(&self, ctx: &RoutingContext<'_>) -> Result<Route, ProxyError>;
}

/// The live router, stored behind `ArcSwap` for hot-reload support.
pub struct LiveRouter {
    inner: ArcSwap<RouterInner>,
}

impl LiveRouter {
    /// Build a router from a list of rules and a default outbound tag.
    ///
    /// `geoip` and `geosite` are optional geo databases. Pass empty `HashMap`s
    /// if geo data is not available.
    pub fn new(
        rules: Vec<CompiledRule>,
        default_tag: impl Into<Arc<str>>,
        geoip: HashMap<String, GeoIpMatcher>,
        geosite: HashMap<String, GeoSiteMatcher>,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: ArcSwap::from_pointee(RouterInner {
                rules,
                default_tag: default_tag.into(),
                geoip,
                geosite,
            }),
        })
    }

    /// Hot-swap the routing rules, default tag, and geo data.
    ///
    /// The swap is atomic: any concurrent routing decisions in progress will
    /// use either the old rules or the new rules, never a mix.
    pub fn swap(
        &self,
        rules: Vec<CompiledRule>,
        default_tag: impl Into<Arc<str>>,
        geoip: HashMap<String, GeoIpMatcher>,
        geosite: HashMap<String, GeoSiteMatcher>,
    ) {
        self.inner.store(Arc::new(RouterInner {
            rules,
            default_tag: default_tag.into(),
            geoip,
            geosite,
        }));
    }
}

impl Router for LiveRouter {
    fn pick_route(&self, ctx: &RoutingContext<'_>) -> Result<Route, ProxyError> {
        // Load the current router snapshot (wait-free read).
        let inner = self.inner.load();

        // Evaluate rules in order; first match wins.
        for rule in &inner.rules {
            if rule.matches_with_geo(ctx, &inner.geoip, &inner.geosite) {
                return Ok(Route {
                    outbound_tag: Arc::clone(&rule.outbound_tag),
                });
            }
        }

        // No rule matched — use the default outbound.
        Ok(Route {
            outbound_tag: Arc::clone(&inner.default_tag),
        })
    }
}

/// The immutable inner state of the router, swapped atomically on reload.
struct RouterInner {
    /// Rules evaluated in order. First match wins.
    rules: Vec<CompiledRule>,
    /// Fallback outbound tag when no rule matches.
    default_tag: Arc<str>,
    /// GeoIP data indexed by uppercase country code.
    geoip: HashMap<String, GeoIpMatcher>,
    /// GeoSite data indexed by uppercase group name.
    geosite: HashMap<String, GeoSiteMatcher>,
}

/// A single compiled routing rule, ready for fast matching.
///
/// "Compiled" means the domain patterns and IP ranges have been pre-processed
/// into efficient data structures (Aho-Corasick automaton for keywords,
/// RegexSet for regexes, sorted CIDR list for IPs). This way the matching
/// is fast even with many rules.
pub struct CompiledRule {
    /// The outbound tag to use when this rule matches.
    pub outbound_tag: Arc<str>,

    /// Domain matcher, if this rule matches by domain.
    pub domain_matcher: Option<DomainMatcher>,

    /// GeoSite codes to match against (e.g. `["CN", "GOOGLE"]`).
    pub geosite_codes: Vec<String>,

    /// IP matcher, if this rule matches by IP address.
    pub ip_matcher: Option<IpMatcher>,

    /// GeoIP codes to match against (e.g. `["CN", "private"]`).
    pub geoip_codes: Vec<String>,

    /// Port ranges this rule applies to. Empty means "any port".
    pub port_ranges: Vec<(u16, u16)>,

    /// Inbound tags this rule applies to. Empty means "any inbound".
    pub inbound_tags: Vec<String>,
}

impl CompiledRule {
    /// Returns `true` if all conditions in this rule match the given context.
    ///
    /// This version does not use geo data. Use `matches_with_geo` when geo
    /// databases are available.
    pub fn matches(&self, ctx: &RoutingContext<'_>) -> bool {
        self.matches_with_geo(ctx, &HashMap::new(), &HashMap::new())
    }

    /// Returns `true` if all conditions in this rule match the given context,
    /// using the provided GeoIP and GeoSite databases for `geoip:` / `geosite:`
    /// rule patterns.
    pub fn matches_with_geo(
        &self,
        ctx: &RoutingContext<'_>,
        geoip: &HashMap<String, GeoIpMatcher>,
        geosite: &HashMap<String, GeoSiteMatcher>,
    ) -> bool {
        // Check inbound tag restriction first (cheapest check).
        if !self.inbound_tags.is_empty() && !self.inbound_tags.iter().any(|t| t == ctx.inbound_tag)
        {
            return false;
        }

        // Check port restriction.
        if !self.port_ranges.is_empty() {
            let port = ctx.dest.port();
            if !self
                .port_ranges
                .iter()
                .any(|(lo, hi)| port >= *lo && port <= *hi)
            {
                return false;
            }
        }

        // Check domain restriction (literal patterns + geosite codes).
        let has_domain_restriction =
            self.domain_matcher.is_some() || !self.geosite_codes.is_empty();
        if has_domain_restriction {
            match ctx.dest {
                Address::Domain(name, _) => {
                    let literal_ok = self
                        .domain_matcher
                        .as_ref()
                        .is_some_and(|dm| dm.matches(name));
                    let geosite_ok = self.geosite_codes.iter().any(|code| {
                        geosite
                            .get(code.as_str())
                            .is_some_and(|m| m.match_domain(name))
                    });
                    if !(literal_ok || geosite_ok) {
                        return false;
                    }
                }
                _ => return false, // rule requires a domain, but dest is an IP
            }
        }

        // Check IP restriction (literal CIDR ranges + geoip codes).
        let has_ip_restriction = self.ip_matcher.is_some() || !self.geoip_codes.is_empty();
        if has_ip_restriction {
            match ctx.dest.ip() {
                Some(ip) => {
                    let literal_ok = self.ip_matcher.as_ref().is_some_and(|im| im.matches(ip));
                    let geoip_ok = self
                        .geoip_codes
                        .iter()
                        .any(|code| geoip.get(code.as_str()).is_some_and(|m| m.match_ip(ip)));
                    if !(literal_ok || geoip_ok) {
                        return false;
                    }
                }
                None => return false, // rule requires an IP, but dest is a domain
            }
        }

        true
    }
}

/// Matches domain names using four strategies in priority order:
///   1. Full match (e.g. "example.com" matches only "example.com")
///   2. Suffix match (e.g. "example.com" matches "sub.example.com" and "example.com")
///   3. Keyword match (e.g. "vpn" matches any domain containing "vpn")
///   4. Regex match (e.g. ".*\\.google\\..*")
pub struct DomainMatcher {
    /// Exact full-domain matches. Fastest check — O(1) hash lookup.
    full: HashMap<String, ()>,

    /// Suffix matches. We check each suffix level of the input domain.
    /// For "sub.example.com" we check "sub.example.com", "example.com", "com".
    suffix: HashMap<String, ()>,

    /// Keyword automaton — matches if the domain contains any keyword.
    /// Aho-Corasick scans the domain string in O(n) time for all keywords at once.
    keyword: AhoCorasick,

    /// Regex set — matches if the domain matches any regex.
    /// `RegexSet` checks all regexes in one pass.
    regex: RegexSet,
}

impl DomainMatcher {
    /// Build a `DomainMatcher` from lists of patterns in each category.
    pub fn new(
        full: Vec<String>,
        suffix: Vec<String>,
        keywords: Vec<String>,
        regexes: Vec<String>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            full: full.into_iter().map(|s| (s, ())).collect(),
            suffix: suffix.into_iter().map(|s| (s, ())).collect(),
            keyword: AhoCorasick::new(&keywords)?,
            regex: RegexSet::new(&regexes)?,
        })
    }

    /// Returns `true` if `domain` matches any pattern in this matcher.
    pub fn matches(&self, domain: &str) -> bool {
        // 1. Full exact match.
        if self.full.contains_key(domain) {
            return true;
        }

        // 2. Suffix match: walk domain labels without allocating.
        {
            let mut start = 0;
            while start < domain.len() {
                if self.suffix.contains_key(&domain[start..]) {
                    return true;
                }
                match domain[start..].find('.') {
                    Some(dot) => start += dot + 1,
                    None => break,
                }
            }
        }

        // 3. Keyword match — does the domain contain any keyword?
        if self.keyword.is_match(domain) {
            return true;
        }

        // 4. Regex match.
        if self.regex.is_match(domain) {
            return true;
        }

        false
    }
}

/// Matches IP addresses against a list of CIDR ranges.
///
/// For example, "192.168.0.0/16" matches 192.168.0.1, 192.168.1.1, etc.
pub struct IpMatcher {
    /// The CIDR ranges to match against.
    ranges: Vec<IpNet>,
}

impl IpMatcher {
    /// Build an `IpMatcher` from a list of CIDR range strings.
    pub fn new(ranges: Vec<String>) -> anyhow::Result<Self> {
        let parsed = ranges
            .iter()
            .map(|r| {
                r.parse::<IpNet>()
                    .map_err(|e| anyhow::anyhow!("invalid CIDR '{}': {}", r, e))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self { ranges: parsed })
    }

    /// Returns `true` if `ip` falls within any of the configured CIDR ranges.
    pub fn matches(&self, ip: IpAddr) -> bool {
        self.ranges.iter().any(|net| net.contains(&ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // Checks that a domain full-match rule correctly accepts and rejects domains.
    #[test]
    fn domain_full_match() {
        let matcher =
            DomainMatcher::new(vec!["example.com".into()], vec![], vec![], vec![]).unwrap();

        assert!(matcher.matches("example.com"));
        assert!(!matcher.matches("sub.example.com")); // full match, not suffix
        assert!(!matcher.matches("other.com"));
    }

    // Checks that a suffix rule matches both the domain itself and its subdomains.
    #[test]
    fn domain_suffix_match() {
        let matcher =
            DomainMatcher::new(vec![], vec!["example.com".into()], vec![], vec![]).unwrap();

        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("sub.example.com"));
        assert!(matcher.matches("deep.sub.example.com"));
        assert!(!matcher.matches("notexample.com"));
    }

    // Checks that a keyword rule matches any domain containing the keyword.
    #[test]
    fn domain_keyword_match() {
        let matcher = DomainMatcher::new(vec![], vec![], vec!["vpn".into()], vec![]).unwrap();

        assert!(matcher.matches("myvpn.com"));
        assert!(matcher.matches("vpn-service.net"));
        assert!(!matcher.matches("example.com"));
    }

    // Checks that a regex rule works correctly.
    #[test]
    fn domain_regex_match() {
        let matcher =
            DomainMatcher::new(vec![], vec![], vec![], vec![r".*\.google\..*".into()]).unwrap();

        assert!(matcher.matches("www.google.com"));
        assert!(matcher.matches("mail.google.co.uk"));
        assert!(!matcher.matches("notgoogle.com"));
    }

    // Checks that IP CIDR matching works for addresses inside and outside the range.
    #[test]
    fn ip_cidr_match() {
        let matcher = IpMatcher::new(vec!["192.168.0.0/16".into()]).unwrap();

        assert!(matcher.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(matcher.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255))));
        assert!(!matcher.matches(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    // Checks that domain and geosite restrictions in one rule are OR'd (v2ray semantics).
    #[test]
    fn domain_and_geosite_are_or_alternatives() {
        use crate::geo::proto::{Domain, DomainType, GeoSite};
        use crate::geo::GeoSiteMatcher;
        use std::collections::HashMap;

        let rule = CompiledRule {
            outbound_tag: "proxy".into(),
            domain_matcher: Some(
                DomainMatcher::new(vec!["never-match.example".into()], vec![], vec![], vec![])
                    .unwrap(),
            ),
            geosite_codes: vec!["TEST".into()],
            ip_matcher: None,
            geoip_codes: vec![],
            port_ranges: vec![],
            inbound_tags: vec![],
        };

        let geosite_entry = GeoSite {
            country_code: "TEST".into(),
            domain: vec![Domain {
                r#type: DomainType::Full as i32,
                value: "google.com".into(),
            }],
        };
        let mut geosite = HashMap::new();
        geosite.insert("TEST".into(), GeoSiteMatcher::from_proto(&geosite_entry));

        let ctx = RoutingContext {
            dest: &Address::Domain("google.com".into(), 443),
            network: Network::Tcp,
            inbound_tag: "in",
            user: None,
        };

        assert!(rule.matches_with_geo(&ctx, &HashMap::new(), &geosite));
    }

    // Checks that an invalid CIDR string returns an error rather than panicking.
    #[test]
    fn invalid_cidr_returns_error() {
        let result = IpMatcher::new(vec!["not-a-cidr".into()]);
        assert!(result.is_err());
    }
}
