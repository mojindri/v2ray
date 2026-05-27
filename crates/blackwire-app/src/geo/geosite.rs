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

use std::collections::HashSet;

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

    /// Keywords to search for in the domain string.
    keywords: Vec<String>,

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

        let regex = match RegexSet::new(&regex_patterns) {
            Ok(rs) => rs,
            Err(e) => {
                warn!("GeoSite regex compile error: {e}; some patterns skipped");
                // Try building regex patterns one by one, skipping bad ones.
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
            keywords,
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
        Ok(Self {
            full: full.into_iter().map(|s| s.to_lowercase()).collect(),
            suffix: suffix.into_iter().map(|s| s.to_lowercase()).collect(),
            keywords: keywords.into_iter().map(|s| s.to_lowercase()).collect(),
            regex: RegexSet::new(&regexes)?,
        })
    }

    /// Returns `true` if `domain` matches any pattern in this matcher.
    pub fn match_domain(&self, domain: &str) -> bool {
        let lower = domain.to_lowercase();

        // 1. Full exact match.
        if self.full.contains(&lower) {
            return true;
        }

        // 2. Suffix match: check each level of the domain hierarchy.
        {
            let parts: Vec<&str> = lower.split('.').collect();
            for i in 0..parts.len() {
                let suffix = parts[i..].join(".");
                if self.suffix.contains(&suffix) {
                    return true;
                }
            }
        }

        // 3. Keyword match.
        if self.keywords.iter().any(|kw| lower.contains(kw.as_str())) {
            return true;
        }

        // 4. Regex match.
        if self.regex.is_match(&lower) {
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
