//! Basic Authentication module for Blackgate
//!
//! This module provides HTTP Basic Authentication functionality
//! for the Blackgate API gateway.
//!
//! # Features
//!
//! - **Username/Password Authentication**: Standard HTTP Basic Auth using base64 encoding
//! - **Configurable Credentials**: Store username and password in route configuration
//! - **Header Generation**: Automatic Authorization header creation
//! - **Validation**: Validates incoming Basic Auth headers against configured credentials
//!
//! # Basic Auth Format
//!
//! Basic Authentication uses the following format:
//! ```
//! Authorization: Basic <base64(username:password)>
//! ```
//!
//! # Example Usage
//!
//! ```rust
//! use blackgate::auth::basic::{encode_basic_auth, validate_basic_auth};
//!
//! // Encode username and password for outgoing requests
//! let auth_header = encode_basic_auth("username", "password");
//!
//! // Validate incoming Basic Auth header
//! let is_valid = validate_basic_auth(&auth_header, "username", "password");
//! ```

use base64::{Engine as _, engine::general_purpose};

///////////////////////////////////////////////////////////////////////////////
//****                       Public Functions                            ****//
///////////////////////////////////////////////////////////////////////////////

/// Encode username and password into a Basic Auth header value
///
/// Takes a username and password and returns the properly formatted
/// Basic Authentication header value with base64 encoding.
///
/// # Arguments
///
/// * `username` - The username for authentication
/// * `password` - The password for authentication
///
/// # Returns
///
/// A string in the format "Basic <base64(username:password)>"
///
/// # Example
///
/// ```rust
/// let auth_header = encode_basic_auth("admin", "secret123");
/// // Returns: "Basic YWRtaW46c2VjcmV0MTIz"
/// ```
pub fn encode_basic_auth(username: &str, password: &str) -> String {
    let credentials = format!("{}:{}", username, password);
    let encoded = general_purpose::STANDARD.encode(credentials.as_bytes());
    format!("Basic {}", encoded)
}

/// Validate an incoming Basic Auth header against expected credentials
///
/// Decodes a Basic Authentication header and compares the extracted
/// username and password against the expected values.
///
/// # Arguments
///
/// * `auth_header` - The Authorization header value (e.g., "Basic YWRtaW46c2VjcmV0MTIz")
/// * `expected_username` - The expected username
/// * `expected_password` - The expected password
///
/// # Returns
///
/// `true` if the credentials match, `false` otherwise
///
/// # Example
///
/// ```rust
/// let is_valid = validate_basic_auth("Basic YWRtaW46c2VjcmV0MTIz", "admin", "secret123");
/// // Returns: true
/// ```
#[allow(dead_code)]
pub fn validate_basic_auth(auth_header: &str, expected_username: &str, expected_password: &str) -> bool {
    // Check if header starts with "Basic "
    if !auth_header.starts_with("Basic ") {
        return false;
    }

    // Extract the base64 encoded part
    let encoded_credentials = &auth_header[6..]; // Skip "Basic "

    // Decode the base64
    let decoded_bytes = match general_purpose::STANDARD.decode(encoded_credentials) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    // Convert to string
    let decoded_string = match String::from_utf8(decoded_bytes) {
        Ok(string) => string,
        Err(_) => return false,
    };

    // Split on the first colon to separate username and password
    if let Some(colon_pos) = decoded_string.find(':') {
        let (username, password) = decoded_string.split_at(colon_pos);
        let password = &password[1..]; // Skip the colon

        // Compare credentials
        username == expected_username && password == expected_password
    } else {
        false // No colon found, invalid format
    }
}

///////////////////////////////////////////////////////////////////////////////
//****                              Tests                                ****//
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_basic_auth() {
        let auth_header = encode_basic_auth("admin", "secret123");
        assert_eq!(auth_header, "Basic YWRtaW46c2VjcmV0MTIz");
    }

    #[test]
    fn test_encode_basic_auth_special_chars() {
        let auth_header = encode_basic_auth("user@example.com", "p@ssw0rd!");
        // The expected value is base64("user@example.com:p@ssw0rd!")
        let expected = general_purpose::STANDARD.encode("user@example.com:p@ssw0rd!");
        assert_eq!(auth_header, format!("Basic {}", expected));
    }

    #[test]
    fn test_validate_basic_auth_success() {
        let auth_header = "Basic YWRtaW46c2VjcmV0MTIz"; // admin:secret123
        assert!(validate_basic_auth(auth_header, "admin", "secret123"));
    }

    #[test]
    fn test_validate_basic_auth_wrong_username() {
        let auth_header = "Basic YWRtaW46c2VjcmV0MTIz"; // admin:secret123
        assert!(!validate_basic_auth(auth_header, "user", "secret123"));
    }

    #[test]
    fn test_validate_basic_auth_wrong_password() {
        let auth_header = "Basic YWRtaW46c2VjcmV0MTIz"; // admin:secret123
        assert!(!validate_basic_auth(auth_header, "admin", "wrongpass"));
    }

    #[test]
    fn test_validate_basic_auth_invalid_format() {
        assert!(!validate_basic_auth("Bearer token123", "admin", "secret123"));
        assert!(!validate_basic_auth("Basic", "admin", "secret123"));
        assert!(!validate_basic_auth("Basic invalid-base64!", "admin", "secret123"));
    }

    #[test]
    fn test_validate_basic_auth_no_colon() {
        // Create a base64 string without colon
        let invalid_creds = general_purpose::STANDARD.encode("adminpassword");
        let auth_header = format!("Basic {}", invalid_creds);
        assert!(!validate_basic_auth(&auth_header, "admin", "password"));
    }

    #[test]
    fn test_roundtrip() {
        let username = "testuser";
        let password = "testpass123";
        let auth_header = encode_basic_auth(username, password);
        assert!(validate_basic_auth(&auth_header, username, password));
    }
}
