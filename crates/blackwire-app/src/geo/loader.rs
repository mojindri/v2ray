//! Load and decode `geoip.dat` and `geosite.dat` files.
//!
//! # Error handling
//!
//! - If the file does not exist or cannot be read, an empty `HashMap` is
//!   returned and a warning is logged. The proxy continues to function;
//!   routing rules that reference missing geo data simply do not match.
//! - If the file exists but cannot be decoded (corrupt data), the same
//!   "empty map + warning" behavior applies.
//! - Panics are never allowed from this module.
//!
//! # Hot-reload caching
//!
//! `load_geoip` and `load_geosite` cache the last loaded result keyed by the
//! file's BLAKE3 content hash. On a hot-reload where the database file has not
//! changed, the cached `Arc<HashMap<...>>` is cloned instead of re-parsing the
//! binary protobuf — avoiding the 5–10 MB re-parse + 100 k+ entry rebuild.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use prost::Message;
use tracing::{debug, warn};

use super::geoip::GeoIpMatcher;
use super::geosite::GeoSiteMatcher;
use super::proto::{GeoIpList, GeoSiteList};

// ---- GeoIP cache ----

struct GeoCache<T> {
    hash: [u8; 32],
    data: Arc<HashMap<String, T>>,
}

static GEOIP_CACHE: OnceLock<Mutex<Option<GeoCache<GeoIpMatcher>>>> = OnceLock::new();
static GEOSITE_CACHE: OnceLock<Mutex<Option<GeoCache<GeoSiteMatcher>>>> = OnceLock::new();

fn geoip_cache() -> &'static Mutex<Option<GeoCache<GeoIpMatcher>>> {
    GEOIP_CACHE.get_or_init(|| Mutex::new(None))
}

fn geosite_cache() -> &'static Mutex<Option<GeoCache<GeoSiteMatcher>>> {
    GEOSITE_CACHE.get_or_init(|| Mutex::new(None))
}

/// Load a `geoip.dat` file and return a map of country code → `GeoIpMatcher`.
///
/// Country codes are normalised to uppercase (e.g. `"cn"` → `"CN"`).
///
/// The result is cached by BLAKE3 content hash: if the file has not changed
/// since the last call (same hash), the cached `Arc<HashMap>` is cloned
/// instead of re-parsing the protobuf — making hot-reloads with unchanged
/// geo databases essentially free.
///
/// Returns an empty `HashMap` if the file is missing, unreadable, or corrupt.
pub fn load_geoip(path: impl AsRef<Path>) -> HashMap<String, GeoIpMatcher> {
    let path = path.as_ref();
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "cannot read geoip.dat; GeoIP matching disabled");
            return HashMap::new();
        }
    };

    let hash = *blake3::hash(&bytes).as_bytes();

    // Return cached data if the file content is unchanged.
    {
        let guard = geoip_cache().lock().unwrap();
        if let Some(cached) = guard.as_ref() {
            if cached.hash == hash {
                debug!(path = %path.display(), "GeoIP cache hit — skipping re-parse");
                return Arc::try_unwrap(Arc::clone(&cached.data))
                    .unwrap_or_else(|arc| (*arc).clone());
            }
        }
    }

    let list = match GeoIpList::decode(bytes.as_slice()) {
        Ok(l) => l,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "cannot decode geoip.dat; GeoIP matching disabled");
            return HashMap::new();
        }
    };

    let map: HashMap<String, GeoIpMatcher> = list
        .entry
        .iter()
        .map(|entry| {
            let code = entry.country_code.to_uppercase();
            let matcher = GeoIpMatcher::from_proto(entry);
            (code, matcher)
        })
        .collect();

    let shared = Arc::new(map);
    *geoip_cache().lock().unwrap() = Some(GeoCache {
        hash,
        data: Arc::clone(&shared),
    });

    Arc::try_unwrap(shared).unwrap_or_else(|arc| (*arc).clone())
}

/// Load a `geosite.dat` file and return a map of group name → `GeoSiteMatcher`.
///
/// Group names are normalised to uppercase.
///
/// The result is cached by BLAKE3 content hash — identical to `load_geoip`.
/// Returns an empty `HashMap` if the file is missing, unreadable, or corrupt.
pub fn load_geosite(path: impl AsRef<Path>) -> HashMap<String, GeoSiteMatcher> {
    let path = path.as_ref();
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "cannot read geosite.dat; GeoSite matching disabled");
            return HashMap::new();
        }
    };

    let hash = *blake3::hash(&bytes).as_bytes();

    {
        let guard = geosite_cache().lock().unwrap();
        if let Some(cached) = guard.as_ref() {
            if cached.hash == hash {
                debug!(path = %path.display(), "GeoSite cache hit — skipping re-parse");
                return Arc::try_unwrap(Arc::clone(&cached.data))
                    .unwrap_or_else(|arc| (*arc).clone());
            }
        }
    }

    let list = match GeoSiteList::decode(bytes.as_slice()) {
        Ok(l) => l,
        Err(e) => {
            warn!(path = %path.display(), error = %e, "cannot decode geosite.dat; GeoSite matching disabled");
            return HashMap::new();
        }
    };

    let map: HashMap<String, GeoSiteMatcher> = list
        .entry
        .iter()
        .map(|entry| {
            let code = entry.country_code.to_uppercase();
            let matcher = GeoSiteMatcher::from_proto(entry);
            (code, matcher)
        })
        .collect();

    let shared = Arc::new(map);
    *geosite_cache().lock().unwrap() = Some(GeoCache {
        hash,
        data: Arc::clone(&shared),
    });

    Arc::try_unwrap(shared).unwrap_or_else(|arc| (*arc).clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use prost::Message;

    use crate::geo::proto::{Cidr, Domain, DomainType, GeoIp, GeoIpList, GeoSite, GeoSiteList};

    /// Encode a GeoIPList to bytes.
    fn encode_geoip(list: &GeoIpList) -> Vec<u8> {
        let mut buf = Vec::new();
        list.encode(&mut buf).unwrap();
        buf
    }

    /// Encode a GeoSiteList to bytes.
    fn encode_geosite(list: &GeoSiteList) -> Vec<u8> {
        let mut buf = Vec::new();
        list.encode(&mut buf).unwrap();
        buf
    }

    /// Load from raw bytes via a temporary file.
    fn load_geoip_from_bytes(bytes: &[u8]) -> HashMap<String, GeoIpMatcher> {
        let dir = tempfile_dir();
        let path = dir.join("geoip.dat");
        std::fs::write(&path, bytes).unwrap();
        load_geoip(&path)
    }

    fn load_geosite_from_bytes(bytes: &[u8]) -> HashMap<String, GeoSiteMatcher> {
        let dir = tempfile_dir();
        let path = dir.join("geosite.dat");
        std::fs::write(&path, bytes).unwrap();
        load_geosite(&path)
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "blackwire-geo-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_file_returns_empty() {
        let result = load_geoip("/nonexistent/path/geoip.dat");
        assert!(result.is_empty());
    }

    #[test]
    fn corrupt_file_returns_empty() {
        let dir = tempfile_dir();
        let path = dir.join("corrupt.dat");
        std::fs::write(&path, b"this is not valid protobuf").unwrap();
        let result = load_geoip(&path);
        assert!(result.is_empty());
    }

    #[test]
    fn geoip_match_no_match() {
        let list = GeoIpList {
            entry: vec![GeoIp {
                country_code: "CN".into(),
                cidr: vec![Cidr {
                    ip: vec![1, 0, 1, 0], // 1.0.1.0
                    prefix: 24,
                }],
                inverse_match: false,
            }],
        };
        let map = load_geoip_from_bytes(&encode_geoip(&list));
        let matcher = map.get("CN").unwrap();
        assert!(matcher.match_ip(IpAddr::V4(Ipv4Addr::new(1, 0, 1, 1))));
        assert!(!matcher.match_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn geoip_country_code_normalized() {
        let list = GeoIpList {
            entry: vec![GeoIp {
                country_code: "us".into(),
                cidr: vec![],
                inverse_match: false,
            }],
        };
        let map = load_geoip_from_bytes(&encode_geoip(&list));
        // Should be stored as uppercase.
        assert!(map.contains_key("US"));
        assert!(!map.contains_key("us"));
    }

    #[test]
    fn geosite_suffix_match() {
        let list = GeoSiteList {
            entry: vec![GeoSite {
                country_code: "CN".into(),
                domain: vec![Domain {
                    r#type: DomainType::Domain as i32,
                    value: "baidu.com".into(),
                }],
            }],
        };
        let map = load_geosite_from_bytes(&encode_geosite(&list));
        let matcher = map.get("CN").unwrap();
        assert!(matcher.match_domain("www.baidu.com"));
        assert!(!matcher.match_domain("www.google.com"));
    }

    #[test]
    fn geosite_missing_file_returns_empty() {
        let result = load_geosite("/nonexistent/path/geosite.dat");
        assert!(result.is_empty());
    }
}
