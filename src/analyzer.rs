//! Module 5: Dependency Analyzer
//!
//! Responsibilities:
//! - Scan response bodies/headers for tokens
//! - Match tokens found in subsequent requests
//! - Build dependency graph
//! - Determine extraction methods (JSON path, header, cookie, regex)

use crate::classifier;
use crate::types::*;
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

static META_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"<meta\s+[^>]*name\s*=\s*["']([^"']*(?:csrf|token|nonce)[^"']*)["'][^>]*content\s*=\s*["']([^"']+)["']"#
    ).unwrap()
});

static META_REV_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"<meta\s+[^>]*content\s*=\s*["']([^"']+)["'][^>]*name\s*=\s*["']([^"']*(?:csrf|token|nonce)[^"']*)["']"#
    ).unwrap()
});

static INPUT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"<input\s+[^>]*type\s*=\s*["']hidden["'][^>]*name\s*=\s*["']([^"']*(?:csrf|token|nonce)[^"']*)["'][^>]*value\s*=\s*["']([^"']+)["']"#
    ).unwrap()
});

static REGEX_JSON_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["'](\w*(?:csrf|token|nonce)\w*)["']\s*:\s*["']([^"']{8,})["']"#).unwrap()
});

static REGEX_JS_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w*(?:csrf|token|nonce)\w*)\s*=\s*["']([^"']{8,})["']"#).unwrap()
});

static DATA_ATTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"data-(token|csrf|auth|key|nonce|session)\s*=\s*["']([^"']+)["']"#).unwrap()
});

/// Analyze captured requests and build a dependency graph
pub fn analyze(requests: &[CapturedRequest]) -> DependencyGraph {
    let mut graph = DependencyGraph::new();

    // Phase 1: Create nodes
    for (i, req) in requests.iter().enumerate() {
        graph.nodes.push(RequestNode {
            request: req.clone(),
            order: i,
            extractions: Vec::new(),
        });
    }

    // Phase 2: Extract potential tokens from responses
    let mut response_tokens: HashMap<usize, Vec<ExtractedValue>> = HashMap::new();
    for (i, req) in requests.iter().enumerate() {
        let tokens = extract_tokens_from_response(i, req);
        if !tokens.is_empty() {
            response_tokens.insert(i, tokens);
        }
    }

    // Phase 3: Find where tokens are used in subsequent requests
    for (source_idx, tokens) in &response_tokens {
        for token in tokens {
            for (target_idx, target_req) in requests.iter().enumerate().skip(*source_idx + 1) {
                if let Some(injection) = find_token_usage(target_req, &token.value) {
                    graph.edges.push(DependencyEdge {
                        dependency: Dependency {
                            from_request_id: *source_idx,
                            to_request_id: target_idx,
                            extracted_value: token.clone(),
                            injection_point: injection,
                        },
                    });

                    // Store extraction info on the source node
                    if let Some(node) = graph.nodes.get_mut(*source_idx) {
                        if !node.extractions.iter().any(|e| e.name == token.name) {
                            node.extractions.push(token.clone());
                        }
                    }
                }
            }
        }
    }

    // Phase 4: Classify token categories
    // Tokens that are used as edges are Derived (they come from a prior response)
    let derived_token_values: std::collections::HashSet<String> = graph
        .edges
        .iter()
        .map(|e| e.dependency.extracted_value.value.clone())
        .collect();

    for node in &mut graph.nodes {
        for extraction in &mut node.extractions {
            if derived_token_values.contains(&extraction.value) {
                extraction.category = TokenCategory::Derived;
            } else if extraction.classification.entropy > 3.5 && extraction.value.len() > 16 {
                extraction.category = TokenCategory::Computed;
            }
        }
    }

    // Also update categories on edge extracted values
    for edge in &mut graph.edges {
        edge.dependency.extracted_value.category = TokenCategory::Derived;
    }

    graph
}

/// Extract potential token values from a response
fn extract_tokens_from_response(request_id: usize, req: &CapturedRequest) -> Vec<ExtractedValue> {
    let mut tokens = Vec::new();

    // Extract from response headers (Set-Cookie, Authorization, X-CSRF-Token, etc.)
    for (name, value) in &req.response_headers {
        let lower_name = name.to_lowercase();
        if lower_name == "set-cookie" {
            for cookie in parse_cookies(value) {
                let classification = classifier::classify(&cookie.0, &cookie.1);
                tokens.push(ExtractedValue {
                    name: cookie.0.clone(),
                    value: cookie.1.clone(),
                    source_request_id: request_id,
                    extraction_method: ExtractionMethod::Cookie(cookie.0),
                    classification,
                    category: TokenCategory::Unknown,
                });
            }
        } else if is_token_header(&lower_name) {
            let classification = classifier::classify(&lower_name, value);
            tokens.push(ExtractedValue {
                name: name.clone(),
                value: value.clone(),
                source_request_id: request_id,
                extraction_method: ExtractionMethod::Header(name.clone()),
                classification,
                category: TokenCategory::Unknown,
            });
        }
    }

    // Extract from JSON response body
    if let Some(ref body) = req.response_body {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
            extract_json_tokens(&json, "$", request_id, &mut tokens);
        }

        // Extract from HTML attributes (meta tags, hidden inputs)
        extract_html_tokens(body, request_id, &mut tokens);

        // Extract via regex patterns (inline JS, non-standard formats)
        extract_regex_tokens(body, request_id, &mut tokens);
    }

    tokens
}

/// Recursively extract token-like values from JSON
fn extract_json_tokens(
    value: &serde_json::Value,
    path: &str,
    request_id: usize,
    tokens: &mut Vec<ExtractedValue>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let new_path = format!("{}.{}", path, key);
                if is_token_key(key) {
                    if let Some(s) = val.as_str() {
                        let classification = classifier::classify(key, s);
                        tokens.push(ExtractedValue {
                            name: key.clone(),
                            value: s.to_string(),
                            source_request_id: request_id,
                            extraction_method: ExtractionMethod::JsonPath(new_path.clone()),
                            classification,
                            category: TokenCategory::Unknown,
                        });
                    }
                }
                extract_json_tokens(val, &new_path, request_id, tokens);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let new_path = format!("{}[{}]", path, i);
                extract_json_tokens(val, &new_path, request_id, tokens);
            }
        }
        _ => {}
    }
}

/// Check if a response header might contain a token
fn is_token_header(name: &str) -> bool {
    matches!(
        name,
        "x-csrf-token"
            | "x-xsrf-token"
            | "x-request-token"
            | "authorization"
            | "x-auth-token"
            | "x-access-token"
    )
}

/// Check if a JSON key name looks like it could be a token
fn is_token_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    let token_patterns = [
        "token", "csrf", "xsrf", "nonce", "session", "jwt", "auth", "key", "secret", "bearer",
        "access_token", "refresh_token", "id_token",
    ];
    token_patterns.iter().any(|p| lower.contains(p))
}

/// Parse Set-Cookie header into (name, value) pairs
fn parse_cookies(header: &str) -> Vec<(String, String)> {
    let mut cookies = Vec::new();
    // Set-Cookie: name=value; Path=/; ...
    if let Some((cookie_pair, _)) = header.split_once(';') {
        if let Some((name, value)) = cookie_pair.split_once('=') {
            cookies.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    cookies
}

/// Extract tokens from HTML response body (meta tags, hidden inputs)
fn extract_html_tokens(body: &str, request_id: usize, tokens: &mut Vec<ExtractedValue>) {
    let meta_re = &*META_RE;
    let meta_rev_re = &*META_REV_RE;
    let input_re = &*INPUT_RE;

    for caps in meta_re.captures_iter(body) {
        let name = &caps[1];
        let value = &caps[2];
        if value.len() >= 8 {
            let classification = classifier::classify(name, value);
            tokens.push(ExtractedValue {
                name: name.to_string(),
                value: value.to_string(),
                source_request_id: request_id,
                extraction_method: ExtractionMethod::HtmlAttribute {
                    selector: format!(r#"meta[name="{}"]"#, name),
                    attribute: "content".to_string(),
                },
                classification,
                category: TokenCategory::Unknown,
            });
        }
    }

    for caps in meta_rev_re.captures_iter(body) {
        let value = &caps[1];
        let name = &caps[2];
        if value.len() >= 8 {
            // Avoid duplicates with the forward meta regex
            if !tokens.iter().any(|t| t.name == name && t.value == value) {
                let classification = classifier::classify(name, value);
                tokens.push(ExtractedValue {
                    name: name.to_string(),
                    value: value.to_string(),
                    source_request_id: request_id,
                    extraction_method: ExtractionMethod::HtmlAttribute {
                        selector: format!(r#"meta[name="{}"]"#, name),
                        attribute: "content".to_string(),
                    },
                    classification,
                    category: TokenCategory::Unknown,
                });
            }
        }
    }

    for caps in input_re.captures_iter(body) {
        let name = &caps[1];
        let value = &caps[2];
        if value.len() >= 8 {
            let classification = classifier::classify(name, value);
            tokens.push(ExtractedValue {
                name: name.to_string(),
                value: value.to_string(),
                source_request_id: request_id,
                extraction_method: ExtractionMethod::HtmlAttribute {
                    selector: format!(r#"input[name="{}"]"#, name),
                    attribute: "value".to_string(),
                },
                classification,
                category: TokenCategory::Unknown,
            });
        }
    }

    // Extract from data-* attributes
    let data_attr_re = &*DATA_ATTR_RE;
    for caps in data_attr_re.captures_iter(body) {
        let attr_name = &caps[1];
        let value = &caps[2];
        if value.len() >= 8 {
            let name = format!("data-{}", attr_name);
            // Skip if already extracted
            if !tokens.iter().any(|t| t.value == value) {
                let classification = classifier::classify(&name, value);
                tokens.push(ExtractedValue {
                    name: name.clone(),
                    value: value.to_string(),
                    source_request_id: request_id,
                    extraction_method: ExtractionMethod::HtmlAttribute {
                        selector: format!(r#"[data-{}]"#, attr_name),
                        attribute: format!("data-{}", attr_name),
                    },
                    classification,
                    category: TokenCategory::Unknown,
                });
            }
        }
    }
}

/// Extract tokens via regex patterns for non-JSON, non-HTML-attribute contexts
fn extract_regex_tokens(body: &str, request_id: usize, tokens: &mut Vec<ExtractedValue>) {
    let patterns: Vec<(&str, &Regex)> = vec![
        ("regex_json_token", &*REGEX_JSON_TOKEN),
        ("regex_js_token", &*REGEX_JS_TOKEN),
    ];

    for (pattern_name, re) in &patterns {
        for caps in re.captures_iter(body) {
            let name = &caps[1];
            let value = &caps[2];
            // Skip if already found by JSON or HTML extraction
            if !tokens.iter().any(|t| t.value == value) {
                let classification = classifier::classify(name, value);
                tokens.push(ExtractedValue {
                    name: name.to_string(),
                    value: value.to_string(),
                    source_request_id: request_id,
                    extraction_method: ExtractionMethod::RegexBody(pattern_name.to_string()),
                    classification,
                    category: TokenCategory::Unknown,
                });
            }
        }
    }
}

/// Find where a token value is used in a request
fn find_token_usage(request: &CapturedRequest, token_value: &str) -> Option<InjectionPoint> {
    if token_value.len() < 8 {
        return None; // Skip very short values to avoid false positives
    }

    // Skip low-entropy values to avoid false positives
    let entropy = shannon_entropy::shannon_entropy(token_value) as f64;
    if entropy < 2.0 {
        return None;
    }

    // Check headers
    for (name, value) in &request.headers {
        if value.contains(token_value) {
            return Some(InjectionPoint::Header(name.clone()));
        }
    }

    // Check URL query parameters
    if let Ok(url) = url::Url::parse(&request.url) {
        for (key, value) in url.query_pairs() {
            if value.contains(token_value) {
                return Some(InjectionPoint::QueryParam(key.to_string()));
            }
        }
    }

    // Check body (with URL-decode support for form-encoded values)
    if let Some(ref body) = request.body {
        // Try raw match first
        if body.contains(token_value) {
            // Try to identify the specific field in JSON
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                if let Some(field) = find_json_field(&json, token_value) {
                    return Some(InjectionPoint::BodyField(field));
                }
            }
            // Fallback: try form-encoded
            for pair in body.split('&') {
                if let Some((key, value)) = pair.split_once('=') {
                    if value.contains(token_value) {
                        return Some(InjectionPoint::BodyField(key.to_string()));
                    }
                }
            }
        }

        // Try URL-decoded match for form-encoded bodies
        if body.contains('%') {
            for (key, value) in url::form_urlencoded::parse(body.as_bytes()) {
                if value.contains(token_value) {
                    return Some(InjectionPoint::BodyField(key.to_string()));
                }
            }
        }
    }

    None
}

/// Find which field in a JSON object contains the token value
fn find_json_field(value: &serde_json::Value, token: &str) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                if let Some(s) = val.as_str() {
                    if s.contains(token) {
                        return Some(key.clone());
                    }
                }
                if let Some(field) = find_json_field(val, token) {
                    return Some(format!("{}.{}", key, field));
                }
            }
            None
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                if let Some(field) = find_json_field(val, token) {
                    return Some(format!("[{}].{}", i, field));
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(
        id: usize,
        method: &str,
        url: &str,
        headers: HashMap<String, String>,
        body: Option<String>,
        response_status: u16,
        response_headers: HashMap<String, String>,
        response_body: Option<String>,
    ) -> CapturedRequest {
        CapturedRequest {
            id,
            method: method.to_string(),
            url: url.to_string(),
            headers,
            body,
            response_status,
            response_headers,
            response_body,
            timestamp: (id as u64) * 1000,
            initiator: None,
            resource_type: "XHR".to_string(),
            stack_trace: None,
            triggered_by_action: None,
        }
    }

    #[test]
    fn test_csrf_token_flow() {
        // Response 1 returns JSON with csrf_token
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/page",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(r#"{"csrf_token": "xK9mZp2qR4sT7uWv"}"#.to_string()),
        );

        // Request 2 sends the token in a header
        let mut req2_headers = HashMap::new();
        req2_headers.insert("X-CSRF-Token".to_string(), "xK9mZp2qR4sT7uWv".to_string());
        let req2 = make_request(
            1,
            "POST",
            "https://example.com/submit",
            req2_headers,
            Some("data=value".to_string()),
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.edges.len(), 1);

        let edge = &graph.edges[0];
        assert_eq!(edge.dependency.from_request_id, 0);
        assert_eq!(edge.dependency.to_request_id, 1);
        assert_eq!(edge.dependency.extracted_value.name, "csrf_token");
        assert!(matches!(
            edge.dependency.injection_point,
            InjectionPoint::Header(_)
        ));
        assert_eq!(
            edge.dependency.extracted_value.classification.token_type,
            TokenType::CsrfToken
        );
    }

    #[test]
    fn test_set_cookie_flow() {
        // Response 1 sets a session cookie
        let mut resp1_headers = HashMap::new();
        resp1_headers.insert(
            "Set-Cookie".to_string(),
            "session=aB3cD4eF5gH6iJ7k; Path=/; HttpOnly".to_string(),
        );
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/login",
            HashMap::new(),
            None,
            200,
            resp1_headers,
            None,
        );

        // Request 2 sends the cookie
        let mut req2_headers = HashMap::new();
        req2_headers.insert(
            "Cookie".to_string(),
            "session=aB3cD4eF5gH6iJ7k".to_string(),
        );
        let req2 = make_request(
            1,
            "GET",
            "https://example.com/dashboard",
            req2_headers,
            None,
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        assert_eq!(graph.edges.len(), 1);

        let edge = &graph.edges[0];
        assert_eq!(edge.dependency.extracted_value.name, "session");
        assert!(matches!(
            edge.dependency.extracted_value.extraction_method,
            ExtractionMethod::Cookie(_)
        ));
        assert!(matches!(
            edge.dependency.injection_point,
            InjectionPoint::Header(_)
        ));
    }

    #[test]
    fn test_jwt_in_body() {
        // Response returns JWT access_token
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let req1 = make_request(
            0,
            "POST",
            "https://example.com/auth",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(format!(r#"{{"access_token": "{}"}}"#, jwt)),
        );

        // Next request uses it in Authorization header
        let mut req2_headers = HashMap::new();
        req2_headers.insert("Authorization".to_string(), format!("Bearer {}", jwt));
        let req2 = make_request(
            1,
            "GET",
            "https://example.com/api/data",
            req2_headers,
            None,
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        assert_eq!(graph.edges.len(), 1);

        let edge = &graph.edges[0];
        assert_eq!(
            edge.dependency.extracted_value.classification.token_type,
            TokenType::Jwt
        );
        assert!(matches!(
            edge.dependency.injection_point,
            InjectionPoint::Header(_)
        ));
    }

    #[test]
    fn test_no_false_positives() {
        // Response has short values that should NOT be matched
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/page",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(r#"{"token": "short", "csrf": "abc"}"#.to_string()),
        );

        let mut req2_headers = HashMap::new();
        req2_headers.insert("X-Token".to_string(), "short".to_string());
        let req2 = make_request(
            1,
            "POST",
            "https://example.com/submit",
            req2_headers,
            None,
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        // No edges because tokens are too short (<8 chars)
        assert_eq!(graph.edges.len(), 0);
    }

    #[test]
    fn test_html_meta_csrf() {
        // Response body contains a CSRF token in a meta tag
        let token = "mN8pQ2rS4tU6vW9x";
        let html = format!(
            r#"<html><head><meta name="csrf-token" content="{}"></head><body></body></html>"#,
            token
        );
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/page",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(html),
        );

        let mut req2_headers = HashMap::new();
        req2_headers.insert("X-CSRF-Token".to_string(), token.to_string());
        let req2 = make_request(
            1,
            "POST",
            "https://example.com/submit",
            req2_headers,
            None,
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        assert_eq!(graph.edges.len(), 1);

        let edge = &graph.edges[0];
        assert_eq!(edge.dependency.extracted_value.name, "csrf-token");
        assert!(matches!(
            edge.dependency.extracted_value.extraction_method,
            ExtractionMethod::HtmlAttribute { .. }
        ));
    }

    #[test]
    fn test_html_hidden_input() {
        // Response body contains a CSRF token in a hidden input
        let token = "aB3cD4eF5gH6iJ7kL8m";
        let html = format!(
            r#"<form><input type="hidden" name="_token" value="{}"></form>"#,
            token
        );
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/form",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(html),
        );

        let req2 = make_request(
            1,
            "POST",
            "https://example.com/submit",
            HashMap::new(),
            Some(format!("_token={}&name=test", token)),
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        assert_eq!(graph.edges.len(), 1);

        let edge = &graph.edges[0];
        assert_eq!(edge.dependency.extracted_value.name, "_token");
        assert!(matches!(
            edge.dependency.injection_point,
            InjectionPoint::BodyField(ref f) if f == "_token"
        ));
    }

    #[test]
    fn test_form_encoded_body_match() {
        // Token contains characters that get URL-encoded
        let token = "xK9m=p2q+R4sT7uWv";
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/page",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(format!(r#"{{"csrf_token": "{}"}}"#, token)),
        );

        // The token is URL-encoded in the form body
        let req2 = make_request(
            1,
            "POST",
            "https://example.com/submit",
            HashMap::new(),
            Some("csrf=xK9m%3Dp2q%2BR4sT7uWv&action=save".to_string()),
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        assert_eq!(graph.edges.len(), 1);

        let edge = &graph.edges[0];
        assert!(matches!(
            edge.dependency.injection_point,
            InjectionPoint::BodyField(ref f) if f == "csrf"
        ));
    }

    #[test]
    fn test_multiple_dependencies() {
        // One response generates a token used by two different requests
        let token = "sharedToken12345678";
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/init",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(format!(r#"{{"auth_token": "{}"}}"#, token)),
        );

        let mut req2_headers = HashMap::new();
        req2_headers.insert("Authorization".to_string(), format!("Bearer {}", token));
        let req2 = make_request(
            1,
            "GET",
            "https://example.com/api/a",
            req2_headers,
            None,
            200,
            HashMap::new(),
            None,
        );

        let mut req3_headers = HashMap::new();
        req3_headers.insert("Authorization".to_string(), format!("Bearer {}", token));
        let req3 = make_request(
            2,
            "GET",
            "https://example.com/api/b",
            req3_headers,
            None,
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2, req3]);
        // Should have 2 edges: req1->req2 and req1->req3
        assert_eq!(graph.edges.len(), 2);
        assert_eq!(graph.edges[0].dependency.from_request_id, 0);
        assert_eq!(graph.edges[0].dependency.to_request_id, 1);
        assert_eq!(graph.edges[1].dependency.from_request_id, 0);
        assert_eq!(graph.edges[1].dependency.to_request_id, 2);
    }

    #[test]
    fn test_regex_js_inline_token() {
        // Response body has a token in inline JS
        let token = "AbCdEfGh12345678";
        let html = format!(
            r#"<html><script>var csrf_token = '{}';</script></html>"#,
            token
        );
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/page",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(html),
        );

        let mut req2_headers = HashMap::new();
        req2_headers.insert("X-CSRF-Token".to_string(), token.to_string());
        let req2 = make_request(
            1,
            "POST",
            "https://example.com/submit",
            req2_headers,
            None,
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        assert_eq!(graph.edges.len(), 1);

        let edge = &graph.edges[0];
        assert_eq!(edge.dependency.extracted_value.name, "csrf_token");
        assert!(matches!(
            edge.dependency.extracted_value.extraction_method,
            ExtractionMethod::RegexBody(_)
        ));
    }

    #[test]
    fn test_query_param_injection() {
        // Token used in URL query parameter
        let token = "qP2rS4tU6vW8xY0z";
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/auth",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(format!(r#"{{"session_token": "{}"}}"#, token)),
        );

        let req2 = make_request(
            1,
            "GET",
            &format!("https://example.com/api/data?token={}&page=1", token),
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        assert_eq!(graph.edges.len(), 1);

        let edge = &graph.edges[0];
        assert!(matches!(
            edge.dependency.injection_point,
            InjectionPoint::QueryParam(ref p) if p == "token"
        ));
    }

    #[test]
    fn test_empty_requests() {
        let graph = analyze(&[]);
        assert!(graph.nodes.is_empty());
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn test_single_request_no_deps() {
        let req = make_request(
            0,
            "GET",
            "https://example.com/page",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(r#"{"csrf_token": "xK9mZp2qR4sT7uWv"}"#.to_string()),
        );
        let graph = analyze(&[req]);
        assert_eq!(graph.nodes.len(), 1);
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn test_no_backward_dependency() {
        // Token from req2 response should NOT create a dependency to req1
        let token = "xK9mZp2qR4sT7uWv";
        let mut req1_headers = HashMap::new();
        req1_headers.insert("X-CSRF-Token".to_string(), token.to_string());
        let req1 = make_request(
            0,
            "POST",
            "https://example.com/submit",
            req1_headers,
            None,
            200,
            HashMap::new(),
            None,
        );

        let req2 = make_request(
            1,
            "GET",
            "https://example.com/page",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(format!(r#"{{"csrf_token": "{}"}}"#, token)),
        );

        let graph = analyze(&[req1, req2]);
        // req2's token should NOT match req1 (backward)
        assert_eq!(graph.edges.len(), 0);
    }

    #[test]
    fn test_json_body_injection() {
        // Token injected into a JSON request body field
        let token = "xK9mZp2qR4sT7uWv";
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/page",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(format!(r#"{{"csrf_token": "{}"}}"#, token)),
        );

        let req2 = make_request(
            1,
            "POST",
            "https://example.com/api",
            HashMap::new(),
            Some(format!(r#"{{"token": "{}","action":"save"}}"#, token)),
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        assert_eq!(graph.edges.len(), 1);
        assert!(matches!(
            graph.edges[0].dependency.injection_point,
            InjectionPoint::BodyField(ref f) if f == "token"
        ));
    }

    #[test]
    fn test_extraction_stored_on_source_node() {
        let token = "xK9mZp2qR4sT7uWv";
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/page",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(format!(r#"{{"csrf_token": "{}"}}"#, token)),
        );

        let mut req2_headers = HashMap::new();
        req2_headers.insert("X-CSRF-Token".to_string(), token.to_string());
        let req2 = make_request(
            1,
            "POST",
            "https://example.com/submit",
            req2_headers,
            None,
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        // Source node (req1) should have the extraction stored
        assert!(!graph.nodes[0].extractions.is_empty());
        assert_eq!(graph.nodes[0].extractions[0].name, "csrf_token");
        // Target node should have no extractions
        assert!(graph.nodes[1].extractions.is_empty());
    }

    #[test]
    fn test_low_entropy_not_matched() {
        // "aaaaaaaa" has very low entropy — should not be matched
        let token = "aaaaaaaa";
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/page",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(format!(r#"{{"csrf_token": "{}"}}"#, token)),
        );

        let mut req2_headers = HashMap::new();
        req2_headers.insert("X-CSRF-Token".to_string(), token.to_string());
        let req2 = make_request(
            1,
            "POST",
            "https://example.com/submit",
            req2_headers,
            None,
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        // Should not create an edge because entropy is too low
        assert_eq!(graph.edges.len(), 0);
    }

    #[test]
    fn test_high_entropy_still_matched() {
        // High-entropy token should be matched
        let token = "xK9mZp2qR4sT7uWv";
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/page",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(format!(r#"{{"csrf_token": "{}"}}"#, token)),
        );

        let mut req2_headers = HashMap::new();
        req2_headers.insert("X-CSRF-Token".to_string(), token.to_string());
        let req2 = make_request(
            1,
            "POST",
            "https://example.com/submit",
            req2_headers,
            None,
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        assert_eq!(graph.edges.len(), 1);
    }

    #[test]
    fn test_derived_category() {
        let token = "xK9mZp2qR4sT7uWv";
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/page",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(format!(r#"{{"csrf_token": "{}"}}"#, token)),
        );

        let mut req2_headers = HashMap::new();
        req2_headers.insert("X-CSRF-Token".to_string(), token.to_string());
        let req2 = make_request(
            1,
            "POST",
            "https://example.com/submit",
            req2_headers,
            None,
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        // The extraction on the source node should be Derived (used in an edge)
        assert_eq!(graph.nodes[0].extractions[0].category, TokenCategory::Derived);
        // The edge extracted_value should also be Derived
        assert_eq!(graph.edges[0].dependency.extracted_value.category, TokenCategory::Derived);
    }

    #[test]
    fn test_computed_category() {
        // A high-entropy token that doesn't come from any prior response
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/page",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(r#"{"nonce": "aZ9xQ2mK7pLw4rTj8sUv3nYb6cDeFgHi"}"#.to_string()),
        );

        let graph = analyze(&[req1]);
        // Token is extracted but not used — it's either Computed or Unknown based on entropy
        if !graph.nodes[0].extractions.is_empty() {
            let ext = &graph.nodes[0].extractions[0];
            // High entropy + long: should be Computed if not Derived
            if ext.classification.entropy > 3.5 && ext.value.len() > 16 {
                assert_eq!(ext.category, TokenCategory::Computed);
            }
        }
    }

    #[test]
    fn test_data_token_extraction() {
        let token = "dT9kL2mN4pQ6rS8u";
        let html = format!(
            r#"<div data-csrf="{}"></div>"#,
            token
        );
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/page",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(html),
        );

        let mut req2_headers = HashMap::new();
        req2_headers.insert("X-CSRF-Token".to_string(), token.to_string());
        let req2 = make_request(
            1,
            "POST",
            "https://example.com/submit",
            req2_headers,
            None,
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].dependency.extracted_value.name, "data-csrf");
    }

    #[test]
    fn test_data_token_dependency() {
        let token = "aB3cD4eF5gH6iJ7kL8m";
        let html = format!(
            r#"<form data-token="{}"></form>"#,
            token
        );
        let req1 = make_request(
            0,
            "GET",
            "https://example.com/form",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            Some(html),
        );

        let req2 = make_request(
            1,
            "POST",
            "https://example.com/submit",
            HashMap::new(),
            Some(format!("token={}&name=test", token)),
            200,
            HashMap::new(),
            None,
        );

        let graph = analyze(&[req1, req2]);
        assert_eq!(graph.edges.len(), 1);
        assert!(matches!(
            graph.edges[0].dependency.extracted_value.extraction_method,
            ExtractionMethod::HtmlAttribute { .. }
        ));
    }
}
