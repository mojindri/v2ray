//! GeoSite matcher: match domain names against country-code domain lists.
//!
//! `GeoSiteMatcher` supports four matching strategies:
//!
//! - **Full** (`DomainType::Full`): exact domain match only.
//! - **Suffix** (`DomainType::Domain`): matches the domain and all subdomains.
//! - **Keyword** (`DomainType::Plain`): substring match (domain contains keyword).
//! - **Regex** (`DomainType::Regex`): regular expression match.
//!
//! The matcher uses the same four-bucket approach as `router.rs`'s
//! `DomainMatcher`, but is built from GeoSite protobuf data.
//!
//! # Hot-path optimizations
//!
//! - `to_lowercase()` is deferred: we first check with the original casing
//!   (fast path for already-lowercase domains) and only allocate if needed.
//! - Suffix match walks label boundaries with `find('.')` — zero allocations.
//! - Keywords use an `AhoCorasick` automaton (O(n) single pass) instead of a
//!   `Vec<String>` linear scan (O(n·k)).

use std::collections::HashSet;

use aho_corasick::AhoCorasick;
use regex::RegexSet;
use tracing::warn;

use super::proto::{DomainType, GeoSite};

/// Matches domain names against a GeoSite entry.
#[derive(Clone)]
pub struct GeoSiteMatcher {
    /// Full (exact) matches.
    full: HashSet<String>,

    /// Suffix matches. We check each suffix level of the input domain.
    suffix: HashSet<String>,

    /// Keyword automaton — matches if the domain contains any keyword (O(n) scan).
    keyword: AhoCorasick,

    /// Compiled regex set.
    regex: RegexSet,
}

impl GeoSiteMatcher {
    /// Build a `GeoSiteMatcher` from a `GeoSite` protobuf message.
    ///
    /// Invalid regex patterns are skipped with a warning rather than panicking.
    pub fn from_proto(entry: &GeoSite) -> Self {
        let mut full = HashSet::new();
        let mut suffix = HashSet::new();
        let mut keywords = Vec::new();
        let mut regex_patterns = Vec::new();

        for domain in &entry.domain {
            match DomainType::try_from(domain.r#type).unwrap_or(DomainType::Plain) {
                DomainType::Full => {
                    full.insert(domain.value.to_lowercase());
                }
                DomainType::Domain => {
                    suffix.insert(domain.value.to_lowercase());
                }
                DomainType::Plain => {
                    keywords.push(domain.value.to_lowercase());
                }
                DomainType::Regex => {
                    regex_patterns.push(domain.value.clone());
                }
            }
        }

        let keyword = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&keywords)
            .unwrap_or_else(|_| AhoCorasick::new(&[] as &[&str]).unwrap());

        let regex = match RegexSet::new(&regex_patterns) {
            Ok(rs) => rs,
            Err(e) => {
                warn!("GeoSite regex compile error: {e}; some patterns skipped");
                let valid: Vec<_> = regex_patterns
                    .iter()
                    .filter(|p| regex::Regex::new(p).is_ok())
                    .cloned()
                    .collect();
                RegexSet::new(&valid).unwrap_or_else(|_| RegexSet::empty())
            }
        };

        Self {
            full,
            suffix,
            keyword,
            regex,
        }
    }

    /// Build from explicit lists — useful for tests.
    pub fn from_parts(
        full: Vec<String>,
        suffix: Vec<String>,
        keywords: Vec<String>,
        regexes: Vec<String>,
    ) -> anyhow::Result<Self> {
        let keyword = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&keywords)
            .map_err(|e| anyhow::anyhow!("AhoCorasick build failed: {e}"))?;
        Ok(Self {
            full: full.into_iter().map(|s| s.to_lowercase()).collect(),
            suffix: suffix.into_iter().map(|s| s.to_lowercase()).collect(),
            keyword,
            regex: RegexSet::new(&regexes)?,
        })
    }

    /// Returns `true` if `domain` matches any pattern in this matcher.
    pub fn match_domain(&self, domain: &str) -> bool {
        // Avoid allocation for already-lowercase domains (the common case).
        // Only call to_lowercase() lazily when an uppercase char is detected.
        let lower_buf;
        let lower: &str = if domain.bytes().any(|b| b.is_ascii_uppercase()) {
            lower_buf = domain.to_lowercase();
            &lower_buf
        } else {
            domain
        };

        // 1. Full exact match.
        if self.full.contains(lower) {
            return true;
        }

        // 2. Suffix match: walk label boundaries without allocating.
        {
            let mut start = 0;
            while start < lower.len() {
                if self.suffix.contains(&lower[start..]) {
                    return true;
                }
                match lower[start..].find('.') {
                    Some(dot) => start += dot + 1,
                    None => break,
                }
            }
        }

        // 3. Keyword match — AhoCorasick O(n) single-pass scan.
        if self.keyword.is_match(lower) {
            return true;
        }

        // 4. Regex match.
        if self.regex.is_match(lower) {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::super::proto::Domain;
    use super::*;

    fn make_matcher(
        full: &[&str],
        suffix: &[&str],
        keywords: &[&str],
        regexes: &[&str],
    ) -> GeoSiteMatcher {
        GeoSiteMatcher::from_parts(
            full.iter().map(|s| s.to_string()).collect(),
            suffix.iter().map(|s| s.to_string()).collect(),
            keywords.iter().map(|s| s.to_string()).collect(),
            regexes.iter().map(|s| s.to_string()).collect(),
        )
        .unwrap()
    }

    #[test]
    fn full_match() {
        let m = make_matcher(&["example.com"], &[], &[], &[]);
        assert!(m.match_domain("example.com"));
        assert!(!m.match_domain("sub.example.com")); // full only, not suffix
    }

    #[test]
    fn suffix_match() {
        let m = make_matcher(&[], &["example.com"], &[], &[]);
        assert!(m.match_domain("example.com"));
        assert!(m.match_domain("sub.example.com"));
        assert!(m.match_domain("deep.sub.example.com"));
        assert!(!m.match_domain("notexample.com"));
    }

    #[test]
    fn keyword_match() {
        let m = make_matcher(&[], &[], &["vpn"], &[]);
        assert!(m.match_domain("myvpn.com"));
        assert!(m.match_domain("vpn-service.net"));
        assert!(!m.match_domain("example.com"));
    }

    #[test]
    fn regex_match() {
        let m = make_matcher(&[], &[], &[], &[r".*\.google\..*"]);
        assert!(m.match_domain("www.google.com"));
        assert!(m.match_domain("mail.google.co.uk"));
        assert!(!m.match_domain("notgoogle.com"));
    }

    #[test]
    fn from_proto_all_types() {
        let entry = GeoSite {
            country_code: "TEST".into(),
            domain: vec![
                Domain {
                    r#type: DomainType::Full as i32,
                    value: "exact.com".into(),
                },
                Domain {
                    r#type: DomainType::Domain as i32,
                    value: "suffix.com".into(),
                },
                Domain {
                    r#type: DomainType::Plain as i32,
                    value: "keyword".into(),
                },
                Domain {
                    r#type: DomainType::Regex as i32,
                    value: r".*\.regex\..*".into(),
                },
            ],
        };
        let m = GeoSiteMatcher::from_proto(&entry);
        assert!(m.match_domain("exact.com"));
        assert!(!m.match_domain("sub.exact.com"));
        assert!(m.match_domain("sub.suffix.com"));
        assert!(m.match_domain("has-keyword-inside.net"));
        assert!(m.match_domain("www.regex.com"));
    }

    #[test]
    fn from_proto_invalid_regex_skipped() {
        let entry = GeoSite {
            country_code: "TEST".into(),
            domain: vec![Domain {
                r#type: DomainType::Regex as i32,
                value: "[invalid regex".into(),
            }],
        };
        // Must not panic.
        let m = GeoSiteMatcher::from_proto(&entry);
        assert!(!m.match_domain("anything.com"));
    }

    #[test]
    fn case_insensitive() {
        let m = make_matcher(&["Example.COM"], &[], &[], &[]);
        assert!(m.match_domain("example.com"));
        assert!(m.match_domain("EXAMPLE.COM"));
    }
}
