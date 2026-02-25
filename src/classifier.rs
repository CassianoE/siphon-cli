//! Module 5b: Token Classifier
//!
//! Responsibilities:
//! - Classify token type (CSRF, JWT, session cookie, OAuth, API key, nonce)
//! - Use heuristics: name patterns, value structure, entropy
//! - Assign confidence scores

use crate::types::{TokenClassification, TokenType};
use shannon_entropy::shannon_entropy;

/// Classify a token based on its name and value
pub fn classify(name: &str, value: &str) -> TokenClassification {
    let lower_name = name.to_lowercase();
    let entropy = shannon_entropy(value) as f64;

    // Try each classifier in priority order
    let (token_type, confidence) = if is_jwt(value) {
        (TokenType::Jwt, 0.95)
    } else if is_oauth(&lower_name) {
        (TokenType::OAuthToken, 0.9)
    } else if is_csrf(&lower_name) {
        (TokenType::CsrfToken, 0.85)
    } else if is_session_cookie(&lower_name) {
        (TokenType::SessionCookie, 0.8)
    } else if is_api_key(&lower_name) {
        (TokenType::ApiKey, 0.7)
    } else if is_nonce(&lower_name, entropy) {
        (TokenType::Nonce, 0.6)
    } else if entropy > 3.5 && value.len() > 16 {
        // High entropy long string — likely some kind of token
        (TokenType::Unknown, 0.4)
    } else {
        (TokenType::Unknown, 0.1)
    };

    TokenClassification {
        token_type,
        confidence,
        name: name.to_string(),
        value: value.to_string(),
        entropy,
    }
}

/// Check if value looks like a JWT (header.payload.signature)
fn is_jwt(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    // Each part should be base64url encoded
    parts
        .iter()
        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '='))
}

/// Check if name suggests a CSRF token
fn is_csrf(name: &str) -> bool {
    (name.contains("csrf") || name.contains("xsrf") || name.contains("_token"))
        && !name.contains("access")
}

/// Check if name suggests a session cookie
fn is_session_cookie(name: &str) -> bool {
    name.contains("session")
        || name.contains("sid")
        || name == "phpsessid"
        || name == "jsessionid"
        || name == "asp.net_sessionid"
        || name == "connect.sid"
}

/// Check if name suggests an OAuth token
fn is_oauth(name: &str) -> bool {
    name.contains("access_token")
        || name.contains("refresh_token")
        || name.contains("id_token")
        || name.contains("oauth")
        || name.contains("bearer")
}

/// Check if name suggests an API key
fn is_api_key(name: &str) -> bool {
    name.contains("api_key") || name.contains("apikey") || name.contains("api-key")
}

/// Check if it looks like a nonce (high entropy, nonce-like name)
fn is_nonce(name: &str, entropy: f64) -> bool {
    (name.contains("nonce") || name.contains("random") || name.contains("salt")) && entropy > 3.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_jwt() {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let result = classify("authorization", token);
        assert_eq!(result.token_type, TokenType::Jwt);
        assert!(result.confidence > 0.9);
    }

    #[test]
    fn test_classify_csrf() {
        let result = classify("csrf_token", "abc123def456ghi789jkl012");
        assert_eq!(result.token_type, TokenType::CsrfToken);
    }

    #[test]
    fn test_classify_session() {
        let result = classify("session_id", "s%3Aabc123.longhashedvalue");
        assert_eq!(result.token_type, TokenType::SessionCookie);
    }

    #[test]
    fn test_classify_unknown_short() {
        let result = classify("status", "ok");
        assert_eq!(result.token_type, TokenType::Unknown);
        assert!(result.confidence < 0.5);
    }

    #[test]
    fn test_access_token_not_csrf() {
        // access_token should be OAuth, not CSRF (precedence fix)
        let result = classify("access_token", "abc123def456ghi789jkl012");
        assert_eq!(result.token_type, TokenType::OAuthToken);
    }

    #[test]
    fn test_refresh_token_not_csrf() {
        let result = classify("refresh_token", "rf_abc123def456ghi789");
        assert_eq!(result.token_type, TokenType::OAuthToken);
    }

    #[test]
    fn test_high_entropy_unknown() {
        // Random long string with high entropy
        let result = classify("some_field", "aZ9xQ2mK7pLw4rTj8sUv3nYb6");
        assert_eq!(result.token_type, TokenType::Unknown);
        assert!(result.confidence >= 0.4);
    }

    #[test]
    fn test_nonce_classification() {
        let result = classify("nonce", "aZ9xQ2mK7pLw4rTj8sUv3nYb6");
        assert_eq!(result.token_type, TokenType::Nonce);
    }

    #[test]
    fn test_api_key_classification() {
        let result = classify("api_key", "sk_live_abc123def456ghi789");
        assert_eq!(result.token_type, TokenType::ApiKey);
    }

    #[test]
    fn test_xsrf_classification() {
        let result = classify("xsrf_token", "abc123def456ghi789jkl012");
        assert_eq!(result.token_type, TokenType::CsrfToken);
    }

    #[test]
    fn test_session_cookie_variants() {
        assert_eq!(
            classify("phpsessid", "abc123def456ghi789").token_type,
            TokenType::SessionCookie
        );
        assert_eq!(
            classify("jsessionid", "abc123def456ghi789").token_type,
            TokenType::SessionCookie
        );
        assert_eq!(
            classify("connect.sid", "s%3Aabc123.longhash").token_type,
            TokenType::SessionCookie
        );
    }

    #[test]
    fn test_bearer_as_oauth() {
        let result = classify("bearer", "abc123def456ghi789jkl012");
        assert_eq!(result.token_type, TokenType::OAuthToken);
    }

    #[test]
    fn test_api_key_variants() {
        assert_eq!(
            classify("apikey", "sk_live_abc123def456ghi789").token_type,
            TokenType::ApiKey
        );
        assert_eq!(
            classify("api-key", "sk_live_abc123def456ghi789").token_type,
            TokenType::ApiKey
        );
    }

    #[test]
    fn test_id_token_as_oauth() {
        let result = classify("id_token", "abc123def456ghi789jkl012");
        assert_eq!(result.token_type, TokenType::OAuthToken);
    }

    #[test]
    fn test_entropy_stored() {
        let result = classify("some_field", "aZ9xQ2mK7pLw4rTj8sUv3nYb6");
        assert!(result.entropy > 0.0);
    }

    #[test]
    fn test_jwt_takes_priority_over_name() {
        // Even if the name says "csrf", JWT structure wins
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let result = classify("csrf_token", jwt);
        assert_eq!(result.token_type, TokenType::Jwt);
    }
}
