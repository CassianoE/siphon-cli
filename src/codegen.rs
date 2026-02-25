//! Module 6: Code Generator
//!
//! Responsibilities:
//! - Take dependency graph and generate replay scripts
//! - Support Python (requests) and curl output
//! - Resolve dependencies into variable extraction + injection
//! - Use Tera templates for output formatting

use crate::types::{ActionParameter, DependencyGraph, ExtractionMethod, InjectionPoint, OutputFormat};
use serde::Serialize;
use tera::{Context, Tera};

const SKIP_HEADERS: &[&str] = &[
    "accept-encoding",
    "accept-language",
    "connection",
    "cookie", // managed by requests.Session() / curl cookie jar
    "host",
    "origin",
    "referer",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "upgrade-insecure-requests",
    "user-agent",
    "cache-control",
    "pragma",
    "content-length",
];

#[derive(Debug, Serialize)]
struct TemplateHeader {
    name: String,
    value: String,
    is_dynamic: bool,
    python_value: String,
    curl_value: String,
}

#[derive(Debug, Serialize)]
struct TemplateExtraction {
    variable_name: String,
    method: String, // "json", "header", "cookie", "html", "regex"
    path: String,
    regex_pattern: Option<String>,
    /// Bash-safe regex: quotes replaced with \x22/\x27 hex escapes for use in single-quoted strings
    bash_regex_pattern: Option<String>,
}

#[derive(Debug, Serialize)]
struct TemplateInjection {
    target: String, // "header", "query", "body", "cookie", "url_segment"
    key: String,
    variable_name: String,
}

#[derive(Debug, Serialize)]
struct TemplateRequest {
    order: usize,
    method: String,
    url: String,
    python_url: String,
    curl_url: String,
    headers: Vec<TemplateHeader>,
    has_body: bool,
    python_body: Option<String>,
    curl_body: Option<String>,
    is_json_body: bool,
    body_has_variables: bool,
    extractions: Vec<TemplateExtraction>,
    injections: Vec<TemplateInjection>,
    has_injections: bool,
    expected_status: u16,
    is_redirect: bool,
}

#[derive(Debug, Serialize)]
struct TemplateParameter {
    name: String,
    var_name: String,
    default_value: Option<String>,
}

#[derive(Debug, Serialize)]
struct TemplateContext {
    requests: Vec<TemplateRequest>,
    base_url: String,
    needs_regex: bool,
    parameters: Vec<TemplateParameter>,
    has_parameters: bool,
}

pub fn generate(
    graph: &DependencyGraph,
    format: &OutputFormat,
    output_path: &str,
    parameters: &[ActionParameter],
) -> Result<(), Box<dyn std::error::Error>> {
    let rendered = generate_to_string(graph, format, parameters)?;
    std::fs::write(output_path, rendered)?;
    Ok(())
}

pub fn generate_to_string(
    graph: &DependencyGraph,
    format: &OutputFormat,
    parameters: &[ActionParameter],
) -> Result<String, Box<dyn std::error::Error>> {
    // JSON output: serialize the graph directly
    if *format == OutputFormat::Json {
        return Ok(serde_json::to_string_pretty(graph)?);
    }

    let template_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/templates/**/*");
    let tera = Tera::new(template_dir)?;
    let template_ctx = build_template_context(graph, parameters);
    let mut context = Context::new();
    context.insert("ctx", &template_ctx);
    Ok(tera.render(format.template_name(), &context)?)
}

// ─── Helper Functions ──────────────────────────────────────────

fn json_path_to_python(path: &str) -> String {
    let mut result = String::new();
    for segment in path.split('.') {
        if segment == "$" {
            continue;
        }
        if let Some(bracket_pos) = segment.find('[') {
            let key = &segment[..bracket_pos];
            let rest = &segment[bracket_pos..];
            if !key.is_empty() && key != "$" {
                result.push_str(&format!("[\"{}\"]", key));
            }
            result.push_str(rest);
        } else if segment == "$" {
            continue;
        } else {
            result.push_str(&format!("[\"{}\"]", segment));
        }
    }
    result
}

/// Names reserved by generated scripts (would shadow important variables)
const RESERVED_VAR_NAMES: &[&str] = &["session", "requests", "re", "json", "os", "sys"];

fn sanitize_var_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect::<String>()
        .to_lowercase();
    if sanitized.is_empty() {
        "_var".to_string()
    } else if sanitized.as_bytes()[0].is_ascii_digit() {
        format!("_{}", sanitized)
    } else if RESERVED_VAR_NAMES.contains(&sanitized.as_str()) {
        format!("{}_value", sanitized)
    } else {
        sanitized
    }
}

fn escape_python_body(body: &str) -> String {
    body.replace('\\', "\\\\").replace("\"\"\"", "\\\"\\\"\\\"")
}

fn escape_curl_body(body: &str) -> String {
    body.replace('\'', "'\\''")
}

fn escape_curl_body_double_quoted(body: &str) -> String {
    body.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('`', "\\`")
}

/// URL-encode the special characters in parameter patterns as browsers do
fn url_encode_braces(s: &str) -> String {
    s.replace('{', "%7B")
        .replace('}', "%7D")
        .replace(':', "%3A")
}

fn html_selector_to_regex(selector: &str, attribute: &str) -> String {
    // Extract name value from selector like meta[name="csrf-token"] or input[name="_token"]
    let name_value = extract_selector_name(selector);
    if let Some(name_val) = name_value {
        format!(
            r#"name=["\']{}["\'][^>]*{}=["\']([^"\']+)["\']"#,
            regex::escape(&name_val),
            regex::escape(attribute)
        )
    } else {
        // Fallback: generic pattern for the attribute
        format!(r#"{}=["\']([^"\']+)["\']"#, regex::escape(attribute))
    }
}

fn extract_selector_name(selector: &str) -> Option<String> {
    // Parse name="VALUE" or name='VALUE' from CSS selector
    let re = regex::Regex::new(r#"name\s*=\s*["']([^"']+)["']"#).ok()?;
    re.captures(selector).map(|c| c[1].to_string())
}

/// Convert a Python regex to a bash-safe version by replacing quote characters with hex escapes.
/// This allows embedding the regex in bash single-quoted strings (python3 -c '...').
/// Must handle escaped quotes (\' and \") from the original regex pattern first.
fn regex_to_bash_safe(regex: &str) -> String {
    regex
        .replace("\\'", "\\x27") // \' → \x27 (escaped quote sequence, must come first)
        .replace("\\\"", "\\x22") // \" → \x22 (escaped double quote)
        .replace('"', "\\x22") // bare " → \x22
        .replace('\'', "\\x27") // bare ' → \x27
}

fn regex_pattern_for_extraction(pattern_name: &str, token_name: &str) -> String {
    let escaped_name = regex::escape(token_name);
    match pattern_name {
        "regex_json_token" => {
            format!(
                r#"["\']{escaped_name}["\']\s*:\s*["\']([^"\']+)["\']"#
            )
        }
        "regex_js_token" => {
            format!(
                r#"{escaped_name}\s*=\s*["\']([^"\']+)["\']"#
            )
        }
        _ => {
            r#"["\']([^"\']+)["\']"#.to_string()
        }
    }
}

fn is_json_body(body: &str, headers: &[(String, String)]) -> bool {
    // Check Content-Type header first
    for (name, value) in headers {
        if name.to_lowercase() == "content-type" && value.contains("application/json") {
            return true;
        }
    }
    // Try parsing as JSON
    serde_json::from_str::<serde_json::Value>(body).is_ok()
}

// ─── Template Context Builder ──────────────────────────────────

fn build_template_context(graph: &DependencyGraph, parameters: &[ActionParameter]) -> TemplateContext {
    let base_url = graph
        .nodes
        .first()
        .map(|n| {
            url::Url::parse(&n.request.url)
                .ok()
                .map(|u| format!("{}://{}", u.scheme(), u.host_str().unwrap_or("localhost")))
                .unwrap_or_default()
        })
        .unwrap_or_default();

    let requests: Vec<TemplateRequest> = graph
        .nodes
        .iter()
        .map(|node| {
            // Collect injections for this request from edges
            let injections: Vec<TemplateInjection> = graph
                .edges
                .iter()
                .filter(|e| e.dependency.to_request_id == node.order)
                .map(|e| {
                    let (target, key) = match &e.dependency.injection_point {
                        InjectionPoint::Header(h) => ("header".to_string(), h.clone()),
                        InjectionPoint::QueryParam(q) => ("query".to_string(), q.clone()),
                        InjectionPoint::BodyField(f) => ("body".to_string(), f.clone()),
                        InjectionPoint::Cookie(c) => ("cookie".to_string(), c.clone()),
                        InjectionPoint::UrlSegment(idx) => {
                            ("url_segment".to_string(), idx.to_string())
                        }
                    };
                    TemplateInjection {
                        target,
                        key,
                        variable_name: sanitize_var_name(&e.dependency.extracted_value.name),
                    }
                })
                .collect();

            // Build a map from (target, key) -> (variable_name, token_value) for injection resolution
            let injection_map: Vec<(&str, &str, String, String)> = graph
                .edges
                .iter()
                .filter(|e| e.dependency.to_request_id == node.order)
                .map(|e| {
                    let (target, key) = match &e.dependency.injection_point {
                        InjectionPoint::Header(h) => ("header", h.as_str()),
                        InjectionPoint::QueryParam(q) => ("query", q.as_str()),
                        InjectionPoint::BodyField(f) => ("body", f.as_str()),
                        InjectionPoint::Cookie(c) => ("cookie", c.as_str()),
                        InjectionPoint::UrlSegment(_) => ("url_segment", ""),
                    };
                    (
                        target,
                        key,
                        sanitize_var_name(&e.dependency.extracted_value.name),
                        e.dependency.extracted_value.value.clone(),
                    )
                })
                .collect();

            // Filter and process headers
            let raw_headers: Vec<(String, String)> = node
                .request
                .headers
                .iter()
                .filter(|(k, _)| !SKIP_HEADERS.contains(&k.to_lowercase().as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            let mut sorted_headers: Vec<(String, String)> = raw_headers;
            sorted_headers.sort_by(|a, b| a.0.cmp(&b.0));

            let headers: Vec<TemplateHeader> = sorted_headers
                .iter()
                .map(|(name, value)| {
                    // Check if there's an injection targeting this header
                    let injection = injection_map.iter().find(|(target, key, _, _)| {
                        *target == "header" && key.to_lowercase() == name.to_lowercase()
                    });

                    if let Some((_, _, var_name, token_value)) = injection {
                        let python_value =
                            value.replace(token_value.as_str(), &format!("{{{}}}", var_name));
                        let curl_value = value.replace(
                            token_value.as_str(),
                            &format!("${}", var_name.to_uppercase()),
                        );
                        TemplateHeader {
                            name: name.clone(),
                            value: value.clone(),
                            is_dynamic: true,
                            python_value,
                            curl_value,
                        }
                    } else {
                        TemplateHeader {
                            name: name.clone(),
                            value: value.clone(),
                            is_dynamic: false,
                            python_value: value.clone(),
                            curl_value: value.clone(),
                        }
                    }
                })
                .collect();

            // Process URL for query param injections
            let mut python_url = node.request.url.clone();
            let mut curl_url = node.request.url.clone();
            let mut param_substituted = false;
            for (target, _key, var_name, token_value) in &injection_map {
                if *target == "query" {
                    python_url =
                        python_url.replace(token_value.as_str(), &format!("{{{}}}", var_name));
                    curl_url = curl_url.replace(
                        token_value.as_str(),
                        &format!("${}", var_name.to_uppercase()),
                    );
                }
            }

            // Apply parameter substitutions in URL
            for param in parameters {
                let raw_pattern = if let Some(ref default) = param.default_value {
                    format!("{{{{{}:{}}}}}", param.name, default)
                } else {
                    format!("{{{{{}}}}}", param.name)
                };
                let encoded_pattern = url_encode_braces(&raw_pattern);

                for pattern in [&encoded_pattern, &raw_pattern] {
                    if python_url.contains(pattern.as_str()) {
                        python_url = python_url.replace(pattern.as_str(), &format!("{{{}}}", param.var_name));
                        curl_url = curl_url.replace(pattern.as_str(), &format!("${}", param.var_name));
                        param_substituted = true;
                    }
                }
            }

            // Process body
            let has_body = node.request.body.is_some();
            let body_is_json = node
                .request
                .body
                .as_ref()
                .map(|b| is_json_body(b, &sorted_headers))
                .unwrap_or(false);

            let mut body_has_variables = false;
            let (python_body, curl_body) = if let Some(ref body) = node.request.body {
                let mut py_body = body.clone();
                let mut cu_body = body.clone();

                // Apply body field injections
                for (target, _key, var_name, token_value) in &injection_map {
                    if *target == "body" {
                        py_body =
                            py_body.replace(token_value.as_str(), &format!("{{{}}}", var_name));
                        cu_body = cu_body.replace(
                            token_value.as_str(),
                            &format!("${}", var_name.to_uppercase()),
                        );
                        body_has_variables = true;
                    }
                }

                // Apply parameter substitutions in body
                for param in parameters {
                    let raw_pattern = if let Some(ref default) = param.default_value {
                        format!("{{{{{}:{}}}}}", param.name, default)
                    } else {
                        format!("{{{{{}}}}}", param.name)
                    };
                    let encoded_pattern = url_encode_braces(&raw_pattern);

                    let py_replacement = format!("{{{}}}", param.var_name);
                    let cu_replacement = format!("${}", param.var_name);

                    // Replace URL-encoded form first (more specific), then raw form
                    for pattern in [&encoded_pattern, &raw_pattern] {
                        if py_body.contains(pattern.as_str()) {
                            py_body = py_body.replace(pattern.as_str(), &py_replacement);
                            param_substituted = true;
                            body_has_variables = true;
                        }
                        if cu_body.contains(pattern.as_str()) {
                            cu_body = cu_body.replace(pattern.as_str(), &cu_replacement);
                            param_substituted = true;
                            body_has_variables = true;
                        }
                    }
                }

                // Apply escaping after injection placeholder insertion
                let py_body = escape_python_body(&py_body);
                let cu_body = if body_has_variables {
                    escape_curl_body_double_quoted(&cu_body)
                } else {
                    escape_curl_body(&cu_body)
                };

                (Some(py_body), Some(cu_body))
            } else {
                (None, None)
            };

            // Convert extractions
            let extractions: Vec<TemplateExtraction> = node
                .extractions
                .iter()
                .map(|e| {
                    let var_name = sanitize_var_name(&e.name);
                    match &e.extraction_method {
                        ExtractionMethod::JsonPath(p) => TemplateExtraction {
                            variable_name: var_name,
                            method: "json".to_string(),
                            path: json_path_to_python(p),
                            regex_pattern: None,
                            bash_regex_pattern: None,
                        },
                        ExtractionMethod::Header(h) => TemplateExtraction {
                            variable_name: var_name,
                            method: "header".to_string(),
                            path: h.clone(),
                            regex_pattern: None,
                            bash_regex_pattern: None,
                        },
                        ExtractionMethod::Cookie(c) => TemplateExtraction {
                            variable_name: var_name,
                            method: "cookie".to_string(),
                            path: c.clone(),
                            regex_pattern: None,
                            bash_regex_pattern: None,
                        },
                        ExtractionMethod::HtmlAttribute {
                            selector,
                            attribute,
                        } => {
                            let pattern = html_selector_to_regex(selector, attribute);
                            let bash_pattern = regex_to_bash_safe(&pattern);
                            TemplateExtraction {
                                variable_name: var_name,
                                method: "html".to_string(),
                                path: String::new(),
                                regex_pattern: Some(pattern),
                                bash_regex_pattern: Some(bash_pattern),
                            }
                        },
                        ExtractionMethod::RegexBody(pattern_name) => {
                            let pattern = regex_pattern_for_extraction(
                                pattern_name,
                                &e.name,
                            );
                            let bash_pattern = regex_to_bash_safe(&pattern);
                            TemplateExtraction {
                                variable_name: var_name,
                                method: "regex".to_string(),
                                path: String::new(),
                                regex_pattern: Some(pattern),
                                bash_regex_pattern: Some(bash_pattern),
                            }
                        },
                    }
                })
                .collect();

            let has_injections = !injections.is_empty() || param_substituted;

            TemplateRequest {
                order: node.order,
                method: node.request.method.clone(),
                url: node.request.url.clone(),
                python_url,
                curl_url,
                headers,
                has_body,
                python_body,
                curl_body,
                is_json_body: body_is_json,
                body_has_variables,
                extractions,
                injections,
                has_injections,
                expected_status: node.request.response_status,
                is_redirect: (300..400).contains(&node.request.response_status),
            }
        })
        .collect();

    let needs_regex = requests
        .iter()
        .any(|r| r.extractions.iter().any(|e| e.method == "html" || e.method == "regex"));

    let template_params: Vec<TemplateParameter> = parameters
        .iter()
        .map(|p| TemplateParameter {
            name: p.name.clone(),
            var_name: p.var_name.clone(),
            default_value: p.default_value.clone(),
        })
        .collect();
    let has_parameters = !template_params.is_empty();

    TemplateContext {
        requests,
        base_url,
        needs_regex,
        parameters: template_params,
        has_parameters,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::collections::HashMap;

    // ─── Unit Tests: Helper Functions ──────────────────────────

    #[test]
    fn test_json_path_simple() {
        assert_eq!(json_path_to_python("$.csrf_token"), "[\"csrf_token\"]");
    }

    #[test]
    fn test_json_path_nested() {
        assert_eq!(
            json_path_to_python("$.data.token"),
            "[\"data\"][\"token\"]"
        );
    }

    #[test]
    fn test_json_path_array() {
        assert_eq!(
            json_path_to_python("$.items[0].token"),
            "[\"items\"][0][\"token\"]"
        );
    }

    #[test]
    fn test_json_path_root_array() {
        assert_eq!(json_path_to_python("$[0].token"), "[0][\"token\"]");
    }

    #[test]
    fn test_sanitize_normal() {
        assert_eq!(sanitize_var_name("csrf_token"), "csrf_token");
    }

    #[test]
    fn test_sanitize_digit_prefix() {
        assert_eq!(sanitize_var_name("2fa_token"), "_2fa_token");
    }

    #[test]
    fn test_sanitize_special_chars() {
        assert_eq!(sanitize_var_name("csrf-token"), "csrf_token");
    }

    #[test]
    fn test_sanitize_empty() {
        assert_eq!(sanitize_var_name(""), "_var");
    }

    #[test]
    fn test_escape_python_body() {
        let input = r#"{"key": "val\"\"\"ue"}"#;
        let escaped = escape_python_body(input);
        assert!(!escaped.contains("\"\"\""));
    }

    #[test]
    fn test_url_encode_braces() {
        assert_eq!(url_encode_braces("{{username:testuser}}"), "%7B%7Busername%3Atestuser%7D%7D");
        assert_eq!(url_encode_braces("{{password}}"), "%7B%7Bpassword%7D%7D");
        assert_eq!(url_encode_braces("plain"), "plain");
    }

    #[test]
    fn test_escape_curl_body() {
        let input = "it's a test";
        let escaped = escape_curl_body(input);
        assert_eq!(escaped, "it'\\''s a test");
    }

    #[test]
    fn test_header_filtering() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer tok".to_string());
        headers.insert("Sec-Fetch-Mode".to_string(), "cors".to_string());
        headers.insert("User-Agent".to_string(), "Mozilla/5.0".to_string());
        headers.insert("Accept".to_string(), "application/json".to_string());

        let filtered: Vec<_> = headers
            .iter()
            .filter(|(k, _)| !SKIP_HEADERS.contains(&k.to_lowercase().as_str()))
            .collect();

        assert!(filtered.iter().any(|(k, _)| k == &"Authorization"));
        assert!(filtered.iter().any(|(k, _)| k == &"Accept"));
        assert!(!filtered.iter().any(|(k, _)| k == &"Sec-Fetch-Mode"));
        assert!(!filtered.iter().any(|(k, _)| k == &"User-Agent"));
    }

    // ─── Helper: Build test requests ──────────────────────────

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

    // ─── End-to-End Tests ─────────────────────────────────────

    #[test]
    fn test_python_simple_get() {
        let req = make_request(
            0,
            "GET",
            "https://example.com/api",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req]);
        let output = generate_to_string(&graph, &OutputFormat::Python, &[]).unwrap();

        assert!(output.contains("import requests"));
        assert!(output.contains("session.get("));
        assert!(output.contains("https://example.com/api"));
        assert!(output.contains("print("));
    }

    #[test]
    fn test_python_csrf_flow() {
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
        let graph = crate::analyzer::analyze(&[req1, req2]);
        let output = generate_to_string(&graph, &OutputFormat::Python, &[]).unwrap();

        assert!(output.contains(".json()"));
        assert!(output.contains("[\"csrf_token\"]"));
        assert!(output.contains("csrf_token"));
        // Should use f-string for the dynamic header
        assert!(output.contains("f\""));
    }

    #[test]
    fn test_python_cookie_flow() {
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
        let graph = crate::analyzer::analyze(&[req1, req2]);
        let output = generate_to_string(&graph, &OutputFormat::Python, &[]).unwrap();

        assert!(output.contains("session_value = session.cookies.get("));
    }

    #[test]
    fn test_python_jwt_bearer() {
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
        let graph = crate::analyzer::analyze(&[req1, req2]);
        let output = generate_to_string(&graph, &OutputFormat::Python, &[]).unwrap();

        assert!(output.contains("access_token"));
        assert!(output.contains(".json()"));
        // Should have dynamic header with f-string containing the variable
        assert!(output.contains("{access_token}"));
    }

    #[test]
    fn test_python_json_body() {
        let req = make_request(
            0,
            "POST",
            "https://example.com/api",
            HashMap::new(),
            Some(r#"{"name": "test", "value": 42}"#.to_string()),
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req]);
        let output = generate_to_string(&graph, &OutputFormat::Python, &[]).unwrap();

        assert!(output.contains("json="));
        assert!(!output.contains("data=body_"));
    }

    #[test]
    fn test_python_html_extraction() {
        let token = "mN8pQ2rS4tU6vW9x";
        let html = format!(
            r#"<html><head><meta name="csrf-token" content="{}"></head></html>"#,
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
        let graph = crate::analyzer::analyze(&[req1, req2]);
        let output = generate_to_string(&graph, &OutputFormat::Python, &[]).unwrap();

        assert!(output.contains("import re"));
        assert!(output.contains("re.search("));
        assert!(output.contains("csrf"));
    }

    #[test]
    fn test_python_body_injection() {
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
            "https://example.com/submit",
            HashMap::new(),
            Some(format!("_token={}&action=save", token)),
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req1, req2]);
        let output = generate_to_string(&graph, &OutputFormat::Python, &[]).unwrap();

        // The token value should be replaced with a placeholder in the body
        assert!(output.contains("{csrf_token}"));
        assert!(!output.contains(token));
    }

    #[test]
    fn test_curl_simple_get() {
        let req = make_request(
            0,
            "GET",
            "https://example.com/api",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req]);
        let output = generate_to_string(&graph, &OutputFormat::Curl, &[]).unwrap();

        assert!(output.contains("#!/usr/bin/env bash"));
        assert!(output.contains("curl"));
        assert!(output.contains("https://example.com/api"));
        assert!(output.contains("set -euo pipefail"));
    }

    #[test]
    fn test_curl_csrf_flow() {
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
        let graph = crate::analyzer::analyze(&[req1, req2]);
        let output = generate_to_string(&graph, &OutputFormat::Curl, &[]).unwrap();

        assert!(output.contains("$CSRF_TOKEN"));
        assert!(output.contains("python3 -c"));
        assert!(output.contains("[\"csrf_token\"]"));
        // python3 -c must use single quotes to avoid collision with ["key"] double quotes
        assert!(output.contains("python3 -c '"));
    }

    #[test]
    fn test_html_selector_to_regex() {
        let regex = html_selector_to_regex(r#"meta[name="csrf-token"]"#, "content");
        // regex::escape turns - into \-, so check for escaped form
        assert!(regex.contains("csrf\\-token"));
        assert!(regex.contains("content"));
    }

    #[test]
    fn test_regex_pattern_for_extraction_js() {
        let pattern = regex_pattern_for_extraction("regex_js_token", "csrf_token");
        assert!(pattern.contains("csrf_token"));
        assert!(pattern.contains("="));
    }

    #[test]
    fn test_regex_pattern_for_extraction_json() {
        let pattern = regex_pattern_for_extraction("regex_json_token", "token");
        assert!(pattern.contains("token"));
        assert!(pattern.contains(":"));
    }

    #[test]
    fn test_is_json_body_by_content() {
        assert!(is_json_body(r#"{"key": "value"}"#, &[]));
        assert!(!is_json_body("name=value&other=test", &[]));
    }

    #[test]
    fn test_is_json_body_by_header() {
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        assert!(is_json_body("not valid json", &headers));
    }

    #[test]
    fn test_curl_body_injection() {
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
            "https://example.com/submit",
            HashMap::new(),
            Some(format!("_token={}&action=save", token)),
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req1, req2]);
        let output = generate_to_string(&graph, &OutputFormat::Curl, &[]).unwrap();

        assert!(output.contains("$CSRF_TOKEN"));
        assert!(!output.contains(token));
        // Body with dependency injection must use double quotes for bash expansion
        assert!(output.contains("-d \"_token=$CSRF_TOKEN&action=save\""), "Dependency-injected body should use double quotes");
    }

    #[test]
    fn test_python_query_param_injection() {
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
        let graph = crate::analyzer::analyze(&[req1, req2]);
        let output = generate_to_string(&graph, &OutputFormat::Python, &[]).unwrap();

        // URL in the actual request call should use f-string with the variable
        assert!(output.contains("{session_token}"));
        // The f-string URL line should not have the raw token
        assert!(output.contains("f\"https://example.com/api/data?token={session_token}&page=1\""));
    }

    #[test]
    fn test_generate_empty_graph() {
        let graph = DependencyGraph::new();
        let output = generate_to_string(&graph, &OutputFormat::Python, &[]).unwrap();
        assert!(output.contains("import requests"));
        assert!(output.contains("Flow complete!"));
    }

    #[test]
    fn test_curl_no_fixme() {
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
        let graph = crate::analyzer::analyze(&[req1, req2]);
        let output = generate_to_string(&graph, &OutputFormat::Curl, &[]).unwrap();

        assert!(!output.contains("FIXME"));
    }

    #[test]
    fn test_json_output_format() {
        let req = make_request(
            0,
            "GET",
            "https://example.com/api",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req]);
        let output = generate_to_string(&graph, &OutputFormat::Json, &[]).unwrap();

        // Should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed["nodes"].is_array());
        assert!(parsed["edges"].is_array());
    }

    #[test]
    fn test_json_output_with_dependencies() {
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
        let mut req2_headers = HashMap::new();
        req2_headers.insert("X-CSRF-Token".to_string(), "xK9mZp2qR4sT7uWv".to_string());
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
        let graph = crate::analyzer::analyze(&[req1, req2]);
        let output = generate_to_string(&graph, &OutputFormat::Json, &[]).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["edges"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_python_status_assertion() {
        let req = make_request(
            0,
            "GET",
            "https://example.com/api",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req]);
        let output = generate_to_string(&graph, &OutputFormat::Python, &[]).unwrap();

        assert!(output.contains("assert response_0.status_code == 200"));
    }

    #[test]
    fn test_curl_status_assertion() {
        let req = make_request(
            0,
            "GET",
            "https://example.com/api",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req]);
        let output = generate_to_string(&graph, &OutputFormat::Curl, &[]).unwrap();

        assert!(output.contains("200"));
    }

    #[test]
    fn test_python_with_parameters() {
        let req = make_request(
            0,
            "GET",
            "https://example.com/api",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req]);
        let params = vec![ActionParameter {
            name: "username".to_string(),
            var_name: "USERNAME".to_string(),
            default_value: Some("testuser".to_string()),
        }];
        let output = generate_to_string(&graph, &OutputFormat::Python, &params).unwrap();

        assert!(output.contains("USERNAME"));
        assert!(output.contains("testuser"));
    }

    #[test]
    fn test_curl_with_parameters() {
        let req = make_request(
            0,
            "GET",
            "https://example.com/api",
            HashMap::new(),
            None,
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req]);
        let params = vec![ActionParameter {
            name: "username".to_string(),
            var_name: "USERNAME".to_string(),
            default_value: Some("testuser".to_string()),
        }];
        let output = generate_to_string(&graph, &OutputFormat::Curl, &params).unwrap();

        assert!(output.contains("USERNAME"));
        assert!(output.contains("testuser"));
    }

    #[test]
    fn test_python_parameter_body_substitution() {
        let req = make_request(
            0,
            "POST",
            "https://example.com/submit",
            HashMap::new(),
            Some("custname=%7B%7Busername%3Atestuser%7D%7D&other=value".to_string()),
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req]);
        let params = vec![ActionParameter {
            name: "username".to_string(),
            var_name: "USERNAME".to_string(),
            default_value: Some("testuser".to_string()),
        }];
        let output = generate_to_string(&graph, &OutputFormat::Python, &params).unwrap();

        assert!(output.contains("{USERNAME}"), "Should contain {{USERNAME}} variable reference");
        assert!(!output.contains("%7B%7Busername"), "Should NOT contain URL-encoded parameter pattern");
        // has_injections should be true, so body uses f-string
        assert!(output.contains("f\"\"\""), "Should use f-string for body with parameter substitution");
    }

    #[test]
    fn test_curl_parameter_body_substitution() {
        let req = make_request(
            0,
            "POST",
            "https://example.com/submit",
            HashMap::new(),
            Some("custname=%7B%7Busername%3Atestuser%7D%7D&other=value".to_string()),
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req]);
        let params = vec![ActionParameter {
            name: "username".to_string(),
            var_name: "USERNAME".to_string(),
            default_value: Some("testuser".to_string()),
        }];
        let output = generate_to_string(&graph, &OutputFormat::Curl, &params).unwrap();

        assert!(output.contains("$USERNAME"), "Should contain $USERNAME variable reference");
        assert!(!output.contains("%7B%7Busername"), "Should NOT contain URL-encoded parameter pattern");
        // Body with variables must use double quotes for bash expansion
        assert!(output.contains("-d \"custname=$USERNAME&other=value\""), "Should use double quotes around body with variables");
        assert!(!output.contains("-d 'custname=$USERNAME"), "Should NOT use single quotes around body with variables");
    }

    #[test]
    fn test_curl_body_no_variables_uses_single_quotes() {
        let req = make_request(
            0,
            "POST",
            "https://example.com/submit",
            HashMap::new(),
            Some("custname=test&other=value".to_string()),
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req]);
        let output = generate_to_string(&graph, &OutputFormat::Curl, &[]).unwrap();

        // No variables → single quotes (safer against special chars)
        assert!(output.contains("-d 'custname=test&other=value'"), "Should use single quotes for body without variables");
    }

    #[test]
    fn test_curl_body_double_quote_escaping() {
        let req = make_request(
            0,
            "POST",
            "https://example.com/api",
            HashMap::new(),
            Some(r#"{"name": "{{username:testuser}}"}"#.to_string()),
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req]);
        let params = vec![ActionParameter {
            name: "username".to_string(),
            var_name: "USERNAME".to_string(),
            default_value: Some("testuser".to_string()),
        }];
        let output = generate_to_string(&graph, &OutputFormat::Curl, &params).unwrap();

        // Body has variables → double quotes, internal quotes escaped
        assert!(output.contains("$USERNAME"), "Should contain $USERNAME");
        assert!(output.contains(r#"\""#), "Should escape internal double quotes");
        assert!(!output.contains("-d '"), "Should NOT use single quotes for body with variables");
    }

    #[test]
    fn test_parameter_body_raw_json() {
        let req = make_request(
            0,
            "POST",
            "https://example.com/api",
            HashMap::new(),
            Some(r#"{"name": "{{username:testuser}}"}"#.to_string()),
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req]);
        let params = vec![ActionParameter {
            name: "username".to_string(),
            var_name: "USERNAME".to_string(),
            default_value: Some("testuser".to_string()),
        }];
        let output = generate_to_string(&graph, &OutputFormat::Python, &params).unwrap();

        assert!(output.contains("{USERNAME}"), "Should replace raw parameter pattern with variable");
        assert!(!output.contains("{{username:testuser}}"), "Should NOT contain raw parameter pattern");
    }

    #[test]
    fn test_parameter_no_default_substitution() {
        let req = make_request(
            0,
            "POST",
            "https://example.com/submit",
            HashMap::new(),
            Some("pass=%7B%7Bpassword%7D%7D&user=test".to_string()),
            200,
            HashMap::new(),
            None,
        );
        let graph = crate::analyzer::analyze(&[req]);
        let params = vec![ActionParameter {
            name: "password".to_string(),
            var_name: "PASSWORD".to_string(),
            default_value: None,
        }];
        let output = generate_to_string(&graph, &OutputFormat::Python, &params).unwrap();

        assert!(output.contains("{PASSWORD}"), "Should contain {{PASSWORD}} variable reference");
        assert!(!output.contains("%7B%7Bpassword%7D%7D"), "Should NOT contain URL-encoded parameter pattern");
    }
}
