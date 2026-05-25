//! GeoIP and GeoSite matchers using v2fly binary format.
//!
//! This module loads `geoip.dat` and `geosite.dat` files in the v2fly
//! protobuf format and exposes them as matchers that can be used by the
//! routing engine.
//!
//! # File format
//!
//! Both files use protobuf encoding. The structures match the v2fly schema:
//!
//! - `geoip.dat`: a `GeoIPList` message containing repeated `GeoIP` entries.
//!   Each `GeoIP` has a `country_code` and a list of `CIDR` ranges.
//!
//! - `geosite.dat`: a `GeoSiteList` message containing repeated `GeoSite`
//!   entries. Each `GeoSite` has a `country_code` and a list of `Domain` entries.
//!
//! # Usage
//!
//! ```no_run
//! use blackwire_app::geo::{load_geoip, load_geosite};
//!
//! let geoip = load_geoip("/usr/share/v2ray/geoip.dat");
//! let geosite = load_geosite("/usr/share/v2ray/geosite.dat");
//!
//! if let Some(matcher) = geoip.get("CN") {
//!     assert!(matcher.match_ip("1.0.1.0".parse().unwrap()));
//! }
//!
//! // Missing or unreadable files degrade to empty maps instead of panicking.
//! assert!(geosite.get("CN").is_none() || geosite.contains_key("CN"));
//! ```

pub mod geoip;
pub mod geosite;
pub mod loader;
pub mod proto;

pub use geoip::GeoIpMatcher;
pub use geosite::GeoSiteMatcher;
pub use loader::{load_geoip, load_geosite};
