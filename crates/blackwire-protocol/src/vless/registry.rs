//! VLESS user registry — fast UUID-to-user lookup.
//!
//! When a VLESS connection arrives, the server reads a 16-byte UUID from the
//! header and looks it up in this registry to find the associated user.
//!
//! # Why DashMap?
//!
//! The registry is read by many Tokio tasks concurrently (one per connection).
//! `DashMap` is a concurrent hash map that uses sharding to allow multiple
//! readers and writers to operate simultaneously without blocking each other.
//! It is much faster than wrapping a `HashMap` in a `Mutex`.
//!
//! # UUID normalisation
//!
//! UUIDs have version and variant bits in specific positions (bytes 6 and 8).
//! A string UUID like "a3482e88-686a-4a58-8126-99c9df64b7bf" encodes:
//!   - byte 6 high nibble = version (4 = UUIDv4)
//!   - byte 8 high 2 bits = variant (10 = RFC 4122)
//!
//! When we store UUIDs in the registry, we normalise these bits so that a UUID
//! generated with version=5 but the same other bytes matches a version=4 UUID.
//! Xray-core does the same normalisation.

use dashmap::DashMap;
use std::sync::Arc;

/// Information about a VLESS user.
#[derive(Debug, Clone)]
pub struct VlessUser {
    /// A human-readable name for this user, used in logs and statistics.
    /// Typically an email address like "user@example.com".
    pub email: Arc<str>,

    /// The raw 16-byte UUID for this user.
    pub uuid: [u8; 16],

    /// The optional XTLS flow for this user.
    /// "xtls-rprx-vision" = XTLS Vision splice mode.
    /// Empty = no special flow.
    pub flow: String,
}

/// A concurrent registry of VLESS users, keyed by their UUID bytes.
///
/// Wrapped in `Arc` so it can be shared across Tokio tasks.
pub struct VlessUserRegistry {
    /// Map from normalised UUID bytes to user info.
    users: DashMap<[u8; 16], Arc<VlessUser>>,
}

impl VlessUserRegistry {
    /// Create an empty registry.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            users: DashMap::new(),
        })
    }

    /// Add a user to the registry.
    ///
    /// If a user with the same UUID already exists, it is replaced.
    pub fn add_user(&self, user: VlessUser) {
        let key = normalise_uuid(user.uuid);
        self.users.insert(key, Arc::new(user));
    }

    /// Look up a user by UUID.
    ///
    /// Returns `Some(user)` if found, `None` if the UUID is not registered.
    ///
    /// The lookup normalises the UUID before comparing, so users registered
    /// with a UUIDv5 can be matched by a client sending a UUIDv4 with the
    /// same content bytes (Xray-compatible behaviour).
    pub fn validate(&self, uuid: &[u8; 16]) -> Option<Arc<VlessUser>> {
        let key = normalise_uuid(*uuid);
        self.users.get(&key).map(|r| Arc::clone(r.value()))
    }

    /// Remove all users from the registry.
    ///
    /// Used during config hot-reload to replace the user list atomically.
    pub fn clear(&self) {
        self.users.clear();
    }

    /// Returns the number of registered users.
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Returns `true` if no users are registered.
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    /// List registered users, optionally filtered by email (empty = all).
    pub fn list_users(&self, email: &str) -> Vec<Arc<VlessUser>> {
        self.users
            .iter()
            .filter(|entry| email.is_empty() || &*entry.value().email == email)
            .map(|entry| Arc::clone(entry.value()))
            .collect()
    }

    /// Remove the user with the given email. Returns true if one was removed.
    pub fn remove_user_by_email(&self, email: &str) -> bool {
        let keys: Vec<[u8; 16]> = self
            .users
            .iter()
            .filter(|entry| &*entry.value().email == email)
            .map(|entry| *entry.key())
            .collect();
        let removed = !keys.is_empty();
        for key in keys {
            self.users.remove(&key);
        }
        removed
    }
}

impl Default for VlessUserRegistry {
    fn default() -> Self {
        Self {
            users: DashMap::new(),
        }
    }
}

/// Normalise a UUID by forcing the standard version (4) and variant bits.
///
/// Byte 6, high nibble: the UUID version. We set it to 4 (0x4_).
/// Byte 8, high 2 bits: the UUID variant. We set it to RFC 4122 (0b10______).
///
/// This allows UUIDs generated with different version numbers to match,
/// which is the same behaviour as Xray-core's UUID matching.
fn normalise_uuid(mut uuid: [u8; 16]) -> [u8; 16] {
    // Set the version to 4:  byte 6 becomes 0x4X (keep lower nibble, set upper to 0x4)
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    // Set the variant to RFC 4122: byte 8 becomes 0b10XXXXXX (set top 2 bits to 10)
    uuid[8] = (uuid[8] & 0x3F) | 0x80;
    uuid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_user(uuid: [u8; 16]) -> VlessUser {
        VlessUser {
            email: Arc::from("test@example.com"),
            uuid,
            flow: String::new(),
        }
    }

    // Checks that a user can be added and looked up by their exact UUID.
    #[test]
    fn add_and_validate_user() {
        let registry = VlessUserRegistry::new();
        let uuid = [
            0xa3, 0x48, 0x2e, 0x88, 0x68, 0x6a, 0x4a, 0x58, 0x81, 0x26, 0x99, 0xc9, 0xdf, 0x64,
            0xb7, 0xbf,
        ];
        registry.add_user(make_user(uuid));
        let found = registry.validate(&uuid);
        assert!(found.is_some());
        assert_eq!(&*found.unwrap().email, "test@example.com");
    }

    // Checks that an unknown UUID returns None, not a panic.
    #[test]
    fn unknown_uuid_returns_none() {
        let registry = VlessUserRegistry::new();
        let unknown = [0x00u8; 16];
        assert!(registry.validate(&unknown).is_none());
    }

    // Checks that UUID normalisation allows version-4 and version-5 UUIDs
    // with the same content bytes to match each other.
    #[test]
    fn uuid_normalisation_matches_across_versions() {
        let registry = VlessUserRegistry::new();

        // Register a UUIDv5 (version bits = 0x5_)
        let mut uuid_v5 = [0xAAu8; 16];
        uuid_v5[6] = 0x50; // version 5
        uuid_v5[8] = 0x80; // variant
        registry.add_user(make_user(uuid_v5));

        // Look up with a UUIDv4 that has the same content bytes (different version bits)
        let mut uuid_v4 = [0xAAu8; 16];
        uuid_v4[6] = 0x40; // version 4
        uuid_v4[8] = 0x80; // variant

        // Both normalise to the same key, so this must succeed.
        assert!(registry.validate(&uuid_v4).is_some());
    }

    #[test]
    fn list_and_remove_by_email() {
        let registry = VlessUserRegistry::new();
        registry.add_user(VlessUser {
            email: Arc::from("a@x"),
            uuid: [0x01; 16],
            flow: String::new(),
        });
        registry.add_user(VlessUser {
            email: Arc::from("b@x"),
            uuid: [0x02; 16],
            flow: String::new(),
        });
        assert_eq!(registry.list_users("").len(), 2);
        assert_eq!(registry.list_users("a@x").len(), 1);
        assert!(registry.remove_user_by_email("a@x"));
        assert_eq!(registry.len(), 1);
        assert!(!registry.remove_user_by_email("missing"));
    }

    // Checks that clear() removes all users.
    #[test]
    fn clear_removes_all_users() {
        let registry = VlessUserRegistry::new();
        registry.add_user(make_user([0x01u8; 16]));
        registry.add_user(make_user([0x02u8; 16]));
        assert_eq!(registry.len(), 2);
        registry.clear();
        assert!(registry.is_empty());
    }
}
