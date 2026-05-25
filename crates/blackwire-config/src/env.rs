//! Environment variable substitution in config files.
//!
//! This allows config files to reference environment variables using the
//! `${VAR_NAME}` syntax. For example:
//!
//! ```json
//! {
//!   "outbounds": [{
//!     "settings": {
//!       "address": "${SERVER_HOST}",
//!       "port": "${SERVER_PORT}"
//!     }
//!   }]
//! }
//! ```
//!
//! This is useful when deploying via Docker or systemd, where you want to pass
//! configuration values as environment variables rather than baking them into
//! the config file (which might be stored in git).
//!
//! # How it works
//!
//! The substitution happens on the raw JSON *string*, before parsing.
//! We scan for `${UPPER_CASE_NAME}` patterns and replace them with the
//! value of that environment variable. If the variable is not set, we
//! replace it with an empty string (not an error).

use once_cell::sync::Lazy;
use regex::Regex;

/// The regex that matches `${VARIABLE_NAME}` patterns.
///
/// The variable name must start with a letter or underscore and contain
/// only uppercase letters, digits, and underscores — standard Unix convention.
///
/// Panicking on invalid regex is intentional: the pattern is fixed at compile time.
static ENV_VAR_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\$\{([A-Z_][A-Z0-9_]*)\}")
        .expect("env var substitution regex is a compile-time invariant")
});

/// Replace all `${VAR_NAME}` placeholders in `raw` with their environment
/// variable values.
///
/// Returns the modified string. If no placeholders are found, returns the
/// original string unchanged (zero allocations).
///
/// # Arguments
/// * `raw` — the raw JSON config text, possibly containing `${VAR}` placeholders
///
/// # Example
/// ```
/// std::env::set_var("MY_PORT", "8443");
/// let result = blackwire_config::env::substitute("port: ${MY_PORT}");
/// assert_eq!(result, "port: 8443");
/// ```
pub fn substitute(raw: &str) -> String {
    ENV_VAR_RE
        .replace_all(raw, |caps: &regex::Captures<'_>| {
            let val = std::env::var(&caps[1]).unwrap_or_default();
            // Escape characters that would break JSON structure when inserted
            // into a string value context (e.g. quotes, backslashes, newlines).
            json_escape(&val)
        })
        .into_owned()
}

/// Escape a string for safe insertion into a JSON string value context.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = std::fmt::write(&mut out, format_args!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Checks that a set environment variable is substituted correctly.
    #[test]
    fn substitutes_set_variable() {
        // We use a unique name to avoid interference from other tests.
        std::env::set_var("PROXY_TEST_HOST_ABC", "example.com");
        let result = substitute("connect to ${PROXY_TEST_HOST_ABC}");
        assert_eq!(result, "connect to example.com");
    }

    // Checks that an unset environment variable becomes an empty string
    // (not an error, not a panic).
    #[test]
    fn unset_variable_becomes_empty_string() {
        // Ensure this variable is definitely not set.
        std::env::remove_var("PROXY_TEST_DEFINITELY_NOT_SET");
        let result = substitute("value=${PROXY_TEST_DEFINITELY_NOT_SET}");
        assert_eq!(result, "value=");
    }

    // Checks that text without any ${...} patterns is returned unchanged.
    #[test]
    fn no_placeholders_returns_unchanged() {
        let input = r#"{"port": 443, "host": "example.com"}"#;
        let result = substitute(input);
        assert_eq!(result, input);
    }

    // Checks that multiple placeholders in the same string are all substituted.
    #[test]
    fn multiple_placeholders_all_substituted() {
        std::env::set_var("PROXY_TEST_A", "hello");
        std::env::set_var("PROXY_TEST_B", "world");
        let result = substitute("${PROXY_TEST_A} ${PROXY_TEST_B}");
        assert_eq!(result, "hello world");
    }

    // Checks that lowercase variable names are NOT matched (standard convention
    // is uppercase-only for environment variables in our config).
    #[test]
    fn lowercase_variable_not_matched() {
        let input = "${lowercase_var}";
        let result = substitute(input);
        // The pattern did not match, so the string is returned as-is.
        assert_eq!(result, input);
    }
}
