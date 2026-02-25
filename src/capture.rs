//! Module 4: Request Store & Filter
//!
//! Responsibilities:
//! - Store captured requests
//! - Filter by domain, resource type, status code
//! - Deduplicate requests
//! - Sort by timestamp

use crate::types::CapturedRequest;
use std::collections::HashSet;
use url::Url;

/// Filter captured requests based on criteria
pub struct RequestFilter {
    pub domain_filter: Option<String>,
    pub exclude_static: bool,
    pub exclude_tracking: bool,
}

/// Static resource extensions to filter out
const STATIC_EXTENSIONS: &[&str] = &[
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
    ".eot", ".map", ".webp", ".avif",
];

/// Static resource types to filter out
const STATIC_RESOURCE_TYPES: &[&str] = &[
    "Stylesheet",
    "Script",
    "Image",
    "Font",
    "Media",
    "Manifest",
    "Other",
];

/// Known tracking/analytics domains to filter out
const TRACKING_DOMAINS: &[&str] = &[
    "google-analytics.com",
    "googletagmanager.com",
    "analytics.google.com",
    "facebook.net",
    "facebook.com/tr",
    "connect.facebook.net",
    "hotjar.com",
    "fullstory.com",
    "mixpanel.com",
    "segment.io",
    "segment.com",
    "amplitude.com",
    "heapanalytics.com",
    "newrelic.com",
    "sentry.io",
    "doubleclick.net",
    "googlesyndication.com",
    "googleadservices.com",
    "intercom.io",
    "intercomcdn.com",
    "clarity.ms",
];

/// Content-type prefixes for binary/media responses to filter out
const MEDIA_CONTENT_TYPES: &[&str] = &[
    "image/",
    "audio/",
    "video/",
    "font/",
];

impl RequestFilter {
    pub fn new(domain_filter: Option<String>) -> Self {
        Self {
            domain_filter,
            exclude_static: true,
            exclude_tracking: true,
        }
    }

    /// Apply all filters to a list of captured requests
    pub fn apply(&self, requests: &[CapturedRequest]) -> Vec<CapturedRequest> {
        let mut filtered: Vec<CapturedRequest> = requests
            .iter()
            .filter(|r| self.passes(r))
            .cloned()
            .collect();

        // Sort by timestamp
        filtered.sort_by_key(|r| r.timestamp);

        // Deduplicate (same method + url + body) — keep first occurrence
        let mut seen = HashSet::new();
        filtered.retain(|r| {
            let key = (r.method.clone(), r.url.clone(), r.body.clone());
            seen.insert(key)
        });

        filtered
    }

    fn passes(&self, request: &CapturedRequest) -> bool {
        // Filter by domain
        if let Some(ref domain) = self.domain_filter {
            if let Ok(url) = Url::parse(&request.url) {
                if let Some(host) = url.host_str() {
                    if !host.contains(domain.as_str()) {
                        return false;
                    }
                }
            }
        }

        // Filter out tracking domains
        if self.exclude_tracking {
            if let Ok(url) = Url::parse(&request.url) {
                if let Some(host) = url.host_str() {
                    if TRACKING_DOMAINS.iter().any(|td| host.contains(td)) {
                        return false;
                    }
                }
            }
        }

        // Filter out static resources by type
        if self.exclude_static && STATIC_RESOURCE_TYPES.contains(&request.resource_type.as_str()) {
            return false;
        }

        // Filter out static resources by extension
        if self.exclude_static && is_static_url(&request.url) {
            return false;
        }

        // Filter out media/binary content-type responses
        if self.exclude_static {
            if let Some(ct) = request.response_headers.get("content-type") {
                let ct_lower = ct.to_lowercase();
                if MEDIA_CONTENT_TYPES.iter().any(|prefix| ct_lower.starts_with(prefix)) {
                    return false;
                }
            }
        }

        true
    }
}

fn is_static_url(url: &str) -> bool {
    let path = url.split('?').next().unwrap_or(url).to_lowercase();
    STATIC_EXTENSIONS.iter().any(|ext| path.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_request(method: &str, url: &str, resource_type: &str) -> CapturedRequest {
        CapturedRequest {
            id: 0,
            method: method.to_string(),
            url: url.to_string(),
            headers: HashMap::new(),
            body: None,
            response_status: 200,
            response_headers: HashMap::new(),
            response_body: None,
            timestamp: 0,
            initiator: None,
            resource_type: resource_type.to_string(),
            stack_trace: None,
            triggered_by_action: None,
        }
    }

    #[test]
    fn test_filters_static_resources() {
        let filter = RequestFilter::new(None);
        let requests = vec![
            make_request("GET", "https://example.com/api/login", "XHR"),
            make_request("GET", "https://example.com/style.css", "Stylesheet"),
            make_request("GET", "https://example.com/logo.png", "Image"),
        ];
        let filtered = filter.apply(&requests);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].url.contains("api/login"));
    }

    #[test]
    fn test_domain_filter() {
        let filter = RequestFilter::new(Some("example.com".to_string()));
        let requests = vec![
            make_request("GET", "https://example.com/api/data", "XHR"),
            make_request("GET", "https://cdn.other.com/api/lib", "XHR"),
        ];
        let filtered = filter.apply(&requests);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_deduplication() {
        let filter = RequestFilter::new(None);
        let requests = vec![
            make_request("GET", "https://example.com/api/data", "XHR"),
            make_request("GET", "https://example.com/api/data", "XHR"),
        ];
        let filtered = filter.apply(&requests);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_url_extension_filtering() {
        let filter = RequestFilter::new(None);
        let requests = vec![
            make_request("GET", "https://example.com/app.js", "Script"),
            make_request("GET", "https://example.com/font.woff2", "Font"),
            make_request("GET", "https://example.com/bg.webp", "Image"),
            make_request("GET", "https://example.com/api/data", "XHR"),
        ];
        let filtered = filter.apply(&requests);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].url.contains("api/data"));
    }

    #[test]
    fn test_sort_by_timestamp() {
        let filter = RequestFilter::new(None);
        let mut req1 = make_request("GET", "https://example.com/api/first", "XHR");
        req1.timestamp = 300;
        let mut req2 = make_request("GET", "https://example.com/api/second", "XHR");
        req2.timestamp = 100;
        let mut req3 = make_request("GET", "https://example.com/api/third", "XHR");
        req3.timestamp = 200;

        let filtered = filter.apply(&[req1, req2, req3]);
        assert_eq!(filtered.len(), 3);
        assert!(filtered[0].url.contains("second"));
        assert!(filtered[1].url.contains("third"));
        assert!(filtered[2].url.contains("first"));
    }

    #[test]
    fn test_query_string_static_url() {
        let filter = RequestFilter::new(None);
        let requests = vec![
            make_request("GET", "https://example.com/style.css?v=123", "Stylesheet"),
            make_request("GET", "https://example.com/api/data?page=1", "XHR"),
        ];
        let filtered = filter.apply(&requests);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].url.contains("api/data"));
    }

    #[test]
    fn test_passes_fetch_and_document() {
        let filter = RequestFilter::new(None);
        let requests = vec![
            make_request("GET", "https://example.com/api", "Fetch"),
            make_request("GET", "https://example.com/page", "Document"),
            make_request("GET", "https://example.com/ws", "Manifest"),
        ];
        let filtered = filter.apply(&requests);
        // Fetch and Document pass, Manifest is filtered
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_non_consecutive_dedup() {
        let filter = RequestFilter::new(None);
        let mut req_a1 = make_request("GET", "https://example.com/api", "XHR");
        req_a1.timestamp = 100;
        let mut req_b = make_request("GET", "https://example.com/other", "XHR");
        req_b.timestamp = 200;
        let mut req_a2 = make_request("GET", "https://example.com/api", "XHR");
        req_a2.timestamp = 300;
        let filtered = filter.apply(&[req_a1, req_b, req_a2]);
        assert_eq!(filtered.len(), 2); // A + B, second A removed
    }

    #[test]
    fn test_different_methods_not_deduplicated() {
        let filter = RequestFilter::new(None);
        let requests = vec![
            make_request("GET", "https://example.com/api/data", "XHR"),
            make_request("POST", "https://example.com/api/data", "XHR"),
        ];
        let filtered = filter.apply(&requests);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filters_tracking_domains() {
        let filter = RequestFilter::new(None);
        let requests = vec![
            make_request("GET", "https://example.com/api/data", "XHR"),
            make_request("GET", "https://www.google-analytics.com/collect", "XHR"),
            make_request("GET", "https://connect.facebook.net/en_US/sdk.js", "XHR"),
            make_request("POST", "https://api.mixpanel.com/track", "XHR"),
        ];
        let filtered = filter.apply(&requests);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].url.contains("example.com"));
    }

    #[test]
    fn test_tracking_filter_disabled() {
        let mut filter = RequestFilter::new(None);
        filter.exclude_tracking = false;
        let requests = vec![
            make_request("GET", "https://example.com/api/data", "XHR"),
            make_request("GET", "https://www.google-analytics.com/collect", "XHR"),
        ];
        let filtered = filter.apply(&requests);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filters_media_content_type() {
        let filter = RequestFilter::new(None);
        let mut req_img = make_request("GET", "https://example.com/api/photo", "XHR");
        req_img.response_headers.insert("content-type".to_string(), "image/jpeg".to_string());
        let mut req_audio = make_request("GET", "https://example.com/api/audio", "XHR");
        req_audio.response_headers.insert("content-type".to_string(), "audio/mpeg".to_string());
        let req_json = make_request("GET", "https://example.com/api/data", "XHR");
        let filtered = filter.apply(&[req_img, req_audio, req_json]);
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].url.contains("api/data"));
    }

    #[test]
    fn test_passes_json_content_type() {
        let filter = RequestFilter::new(None);
        let mut req = make_request("GET", "https://example.com/api/data", "XHR");
        req.response_headers.insert("content-type".to_string(), "application/json".to_string());
        let filtered = filter.apply(&[req]);
        assert_eq!(filtered.len(), 1);
    }
}
