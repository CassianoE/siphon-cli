use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Action Types ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionType {
    Click,
    Type,
    Navigate,
    Wait,
    WaitFor,
    Select,
    Scroll,
    Submit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub action_type: ActionType,
    pub selector: Option<String>,
    pub value: Option<String>,
    pub description: String,
    pub is_parameterized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionParameter {
    pub name: String,
    pub var_name: String,
    pub default_value: Option<String>,
}

// ─── Captured HTTP Data ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedRequest {
    pub id: usize,
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub response_status: u16,
    pub response_headers: HashMap<String, String>,
    pub response_body: Option<String>,
    pub timestamp: u64,
    pub initiator: Option<String>,
    pub resource_type: String,
    pub stack_trace: Option<String>,
    pub triggered_by_action: Option<String>,
}

// ─── Token Classification ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    CsrfToken,
    SessionCookie,
    Jwt,
    OAuthToken,
    ApiKey,
    Nonce,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClassification {
    pub token_type: TokenType,
    pub confidence: f64,
    pub name: String,
    pub value: String,
    pub entropy: f64,
}

// ─── Token Categories ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenCategory {
    Derived,
    Computed,
    Static,
    Unknown,
}

// ─── Dependency Analysis ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtractionMethod {
    JsonPath(String),
    Header(String),
    Cookie(String),
    RegexBody(String),
    HtmlAttribute { selector: String, attribute: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedValue {
    pub name: String,
    pub value: String,
    pub source_request_id: usize,
    pub extraction_method: ExtractionMethod,
    pub classification: TokenClassification,
    pub category: TokenCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub from_request_id: usize,
    pub to_request_id: usize,
    pub extracted_value: ExtractedValue,
    pub injection_point: InjectionPoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InjectionPoint {
    Header(String),
    QueryParam(String),
    BodyField(String),
    Cookie(String),
    UrlSegment(usize),
}

// ─── Dependency Graph ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestNode {
    pub request: CapturedRequest,
    pub order: usize,
    pub extractions: Vec<ExtractedValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub dependency: Dependency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyGraph {
    pub nodes: Vec<RequestNode>,
    pub edges: Vec<DependencyEdge>,
}

impl DependencyGraph {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }
}

// ─── Output Config ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OutputFormat {
    Python,
    Curl,
    Json,
}

impl OutputFormat {
    pub fn parse_or_default(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "curl" => OutputFormat::Curl,
            "json" => OutputFormat::Json,
            _ => OutputFormat::Python,
        }
    }

    pub fn template_name(&self) -> &str {
        match self {
            OutputFormat::Python => "python.tera",
            OutputFormat::Curl => "curl.tera",
            OutputFormat::Json => "json",
        }
    }

    pub fn default_filename(&self) -> &str {
        match self {
            OutputFormat::Python => "flow.py",
            OutputFormat::Curl => "flow.sh",
            OutputFormat::Json => "flow.json",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_from_str_python() {
        assert!(matches!(OutputFormat::parse_or_default("python"), OutputFormat::Python));
    }

    #[test]
    fn test_output_format_from_str_curl() {
        assert!(matches!(OutputFormat::parse_or_default("curl"), OutputFormat::Curl));
    }

    #[test]
    fn test_output_format_json() {
        assert!(matches!(OutputFormat::parse_or_default("json"), OutputFormat::Json));
        assert!(matches!(OutputFormat::parse_or_default("JSON"), OutputFormat::Json));
    }

    #[test]
    fn test_output_format_from_str_case_insensitive() {
        assert!(matches!(OutputFormat::parse_or_default("CURL"), OutputFormat::Curl));
        assert!(matches!(OutputFormat::parse_or_default("Python"), OutputFormat::Python));
    }

    #[test]
    fn test_output_format_from_str_unknown_defaults_python() {
        assert!(matches!(OutputFormat::parse_or_default("xml"), OutputFormat::Python));
        assert!(matches!(OutputFormat::parse_or_default(""), OutputFormat::Python));
    }

    #[test]
    fn test_output_format_default_filename() {
        assert_eq!(OutputFormat::Python.default_filename(), "flow.py");
        assert_eq!(OutputFormat::Curl.default_filename(), "flow.sh");
        assert_eq!(OutputFormat::Json.default_filename(), "flow.json");
    }

    #[test]
    fn test_output_format_template_name() {
        assert_eq!(OutputFormat::Python.template_name(), "python.tera");
        assert_eq!(OutputFormat::Curl.template_name(), "curl.tera");
        assert_eq!(OutputFormat::Json.template_name(), "json");
    }

    #[test]
    fn test_dependency_graph_new() {
        let graph = DependencyGraph::new();
        assert!(graph.nodes.is_empty());
        assert!(graph.edges.is_empty());
    }
}
