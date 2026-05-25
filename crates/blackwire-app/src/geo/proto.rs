//! Hand-written prost structs for v2fly geoip.dat and geosite.dat formats.
//!
//! These structs mirror the v2fly protobuf schema without requiring .proto
//! files or a build step. All decoding uses the `prost` crate directly.
//!
//! # Wire format reference
//!
//! **geoip.dat** (`GeoIPList`):
//! ```text
//! message GeoIPList {
//!   repeated GeoIP entry = 1;
//! }
//! message GeoIP {
//!   string country_code = 1;
//!   repeated CIDR cidr   = 2;
//!   bool inverse_match   = 3;
//! }
//! message CIDR {
//!   bytes  ip     = 1;  // 4 bytes for IPv4, 16 for IPv6
//!   uint32 prefix = 2;
//! }
//! ```
//!
//! **geosite.dat** (`GeoSiteList`):
//! ```text
//! message GeoSiteList {
//!   repeated GeoSite entry = 1;
//! }
//! message GeoSite {
//!   string country_code = 1;
//!   repeated Domain domain = 2;
//! }
//! message Domain {
//!   DomainType type  = 1;
//!   string     value = 2;
//! }
//! enum DomainType {
//!   Plain  = 0;   // keyword match
//!   Regex  = 1;
//!   Domain = 2;   // suffix match
//!   Full   = 3;
//! }
//! ```

/// Top-level GeoIP list (the entire geoip.dat).
#[derive(Clone, prost::Message)]
pub struct GeoIpList {
    /// All GeoIP entries in the file.
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoIp>,
}

/// A single country's IP ranges.
#[derive(Clone, prost::Message)]
pub struct GeoIp {
    /// ISO 3166-1 alpha-2 country code, e.g. "CN", "US".
    #[prost(string, tag = "1")]
    pub country_code: String,

    /// The CIDR ranges belonging to this country.
    #[prost(message, repeated, tag = "2")]
    pub cidr: Vec<Cidr>,

    /// When true, the list represents addresses NOT in this country.
    #[prost(bool, tag = "3")]
    pub inverse_match: bool,
}

/// A single CIDR range in binary (network address + prefix length).
#[derive(Clone, prost::Message)]
pub struct Cidr {
    /// Network address in network byte order. 4 bytes for IPv4, 16 for IPv6.
    #[prost(bytes = "vec", tag = "1")]
    pub ip: Vec<u8>,

    /// Prefix length, e.g. 24 for /24.
    #[prost(uint32, tag = "2")]
    pub prefix: u32,
}

/// Top-level GeoSite list (the entire geosite.dat).
#[derive(Clone, prost::Message)]
pub struct GeoSiteList {
    /// All GeoSite entries in the file.
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<GeoSite>,
}

/// A single country/group's domain list.
#[derive(Clone, prost::Message)]
pub struct GeoSite {
    /// Country code or group name, e.g. "CN", "GOOGLE", "CATEGORY-ADS".
    #[prost(string, tag = "1")]
    pub country_code: String,

    /// Domain patterns for this group.
    #[prost(message, repeated, tag = "2")]
    pub domain: Vec<Domain>,
}

/// A single domain entry with its matching type.
#[derive(Clone, prost::Message)]
pub struct Domain {
    /// How to interpret `value`.
    #[prost(enumeration = "DomainType", tag = "1")]
    pub r#type: i32,

    /// The pattern string.
    #[prost(string, tag = "2")]
    pub value: String,
}

/// Domain matching strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum DomainType {
    /// Keyword: matches if the domain contains this string.
    Plain = 0,
    /// Regular expression.
    Regex = 1,
    /// Suffix: matches the domain itself and all subdomains.
    Domain = 2,
    /// Full: exact domain match only.
    Full = 3,
}
