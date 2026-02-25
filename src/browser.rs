//! Module 1: CDP Engine — Browser automation via Chrome DevTools Protocol
//!
//! Responsibilities:
//! - Launch headless Chrome via chromiumoxide
//! - Navigate to URLs with JS hook injection
//! - Capture all HTTP traffic via CDP Network events
//! - Execute user-defined actions (click, type, navigate, wait, waitfor, etc.)
//! - Click via coordinate dispatch for realistic interaction
//! - Type with random per-character delay
//! - Per-action request polling for attribution
//! - Collect and return CapturedRequest data

use crate::hooks;
use crate::types::{Action, ActionType, CapturedRequest};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use chromiumoxide::cdp::browser_protocol::input::{
    DispatchKeyEventParams, DispatchKeyEventType, DispatchMouseEventParams, DispatchMouseEventType,
    MouseButton,
};
use chromiumoxide::cdp::browser_protocol::network::{
    EnableParams, EventLoadingFinished, EventRequestWillBeSent, EventResponseReceived,
    GetResponseBodyParams, RequestId, ResourceType,
};
use chromiumoxide::{Browser as CdpBrowser, BrowserConfig, Page};
use futures::StreamExt;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Tracked request data assembled from multiple CDP events
#[derive(Debug, Clone)]
struct PendingRequest {
    request_id: String,
    method: String,
    url: String,
    headers: HashMap<String, String>,
    post_data: Option<String>,
    resource_type: Option<ResourceType>,
    initiator_url: Option<String>,
    timestamp: f64,
    response_status: Option<u16>,
    response_headers: HashMap<String, String>,
    loading_finished: bool,
    /// Response body fetched eagerly on LoadingFinished to prevent Chrome discarding it
    response_body: Option<String>,
    /// True for entries preserved from redirect (their request_id was reused by the target)
    is_redirect_preserved: bool,
}

/// Shared state between event listeners
type RequestStore = Arc<Mutex<HashMap<String, PendingRequest>>>;
type ActionRequestMap = Arc<Mutex<Vec<(String, Vec<String>)>>>;

pub struct SiphonBrowser {
    browser: CdpBrowser,
    page: Arc<Page>,
    request_store: RequestStore,
    _handler_handle: JoinHandle<()>,
    _request_listener: JoinHandle<()>,
    _response_listener: JoinHandle<()>,
    _loading_listener: JoinHandle<()>,
    debug: bool,
    action_request_map: ActionRequestMap,
}

/// Escape a string for safe use inside a JS single-quoted string literal
fn escape_js_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\0', "\\0")
}

impl SiphonBrowser {
    /// Launch a headless Chrome browser and set up network capture
    pub async fn launch(debug: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let config = BrowserConfig::builder()
            .no_sandbox()
            .disable_cache()
            .window_size(1920, 1080)
            .build()
            .map_err(|e| format!("BrowserConfig error: {}", e))?;

        let (browser, mut handler) = CdpBrowser::launch(config).await?;

        // The handler must be polled continuously
        let handler_handle = tokio::spawn(async move {
            loop {
                match handler.next().await {
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                    None => break,
                }
            }
        });

        // Create a new page
        let page = Arc::new(browser.new_page("about:blank").await?);

        // Enable Network domain for event capture
        page.execute(EnableParams::default()).await?;

        // Inject JS hooks before any page loads
        page.evaluate_on_new_document(hooks::all_hooks()).await?;

        // Set up shared request store
        let request_store: RequestStore = Arc::new(Mutex::new(HashMap::new()));

        // Listen for request events
        let req_listener = {
            let store = request_store.clone();
            let mut events = page.event_listener::<EventRequestWillBeSent>().await?;
            let dbg = debug;
            tokio::spawn(async move {
                while let Some(event) = events.next().await {
                    let req_id = event.request_id.inner().to_string();

                    let mut headers: HashMap<String, String> = HashMap::new();
                    if let Some(obj) = event.request.headers.inner().as_object() {
                        for (k, v) in obj {
                            if let Some(val) = v.as_str() {
                                headers.insert(k.to_string(), val.to_string());
                            }
                        }
                    }

                    // Get post data from post_data_entries if available
                    // CDP sends PostDataEntry.bytes as base64-encoded strings
                    let post_data: Option<String> =
                        event
                            .request
                            .post_data_entries
                            .as_ref()
                            .and_then(|entries| {
                                let combined: String = entries
                                    .iter()
                                    .filter_map(|e| {
                                        e.bytes.as_ref().map(|b| {
                                            let raw: &str = b.as_ref();
                                            // Try base64 decode, fallback to raw string
                                            BASE64_STANDARD
                                                .decode(raw)
                                                .ok()
                                                .and_then(|bytes| String::from_utf8(bytes).ok())
                                                .unwrap_or_else(|| raw.to_string())
                                        })
                                    })
                                    .collect();
                                if combined.is_empty() {
                                    None
                                } else {
                                    Some(combined)
                                }
                            });

                    let pending = PendingRequest {
                        request_id: req_id.clone(),
                        method: event.request.method.clone(),
                        url: event.request.url.clone(),
                        headers,
                        post_data,
                        resource_type: event.r#type.clone(),
                        initiator_url: event.initiator.url.clone(),
                        timestamp: *event.wall_time.inner(),
                        response_status: None,
                        response_headers: HashMap::new(),
                        loading_finished: false,
                        response_body: None,
                        is_redirect_preserved: false,
                    };

                    if dbg {
                        eprintln!(
                            "    [cdp] Request: {} {} ({:?})",
                            pending.method, pending.url, pending.resource_type
                        );
                    }

                    let mut store_lock = store.lock().await;

                    // Handle redirect: preserve the original request before it's overwritten
                    // CDP reuses the same request_id for redirect chains, so the new
                    // EventRequestWillBeSent (for the redirect target) would overwrite the
                    // original request (e.g. a POST with form data). We save it under a
                    // unique "{id}_redirected" key with status/headers from the redirect response.
                    if let Some(ref redirect_resp) = event.redirect_response {
                        if let Some(mut original) = store_lock.remove(&req_id) {
                            original.response_status = Some(redirect_resp.status as u16);
                            if let Some(obj) = redirect_resp.headers.inner().as_object() {
                                for (k, v) in obj {
                                    if let Some(val) = v.as_str() {
                                        original
                                            .response_headers
                                            .insert(k.to_string(), val.to_string());
                                    }
                                }
                            }
                            original.loading_finished = true;
                            original.is_redirect_preserved = true;
                            let redirect_id = format!("{}_redirected", req_id);
                            if dbg {
                                eprintln!(
                                    "    [cdp] Redirect: preserving {} {} as {}",
                                    original.method, original.url, redirect_id
                                );
                            }
                            store_lock.insert(redirect_id, original);
                        }
                    }

                    store_lock.insert(req_id, pending);
                }
            })
        };

        // Listen for response events
        let resp_listener = {
            let store = request_store.clone();
            let mut events = page.event_listener::<EventResponseReceived>().await?;
            tokio::spawn(async move {
                while let Some(event) = events.next().await {
                    let req_id = event.request_id.inner().to_string();
                    let mut store = store.lock().await;
                    if let Some(pending) = store.get_mut(&req_id) {
                        pending.response_status = Some(event.response.status as u16);
                        if let Some(obj) = event.response.headers.inner().as_object() {
                            for (k, v) in obj {
                                if let Some(val) = v.as_str() {
                                    pending
                                        .response_headers
                                        .insert(k.to_string(), val.to_string());
                                }
                            }
                        }
                    }
                }
            })
        };

        // Listen for loading finished events — eagerly fetch response bodies
        // so Chrome doesn't discard them before collect_requests runs.
        let loading_listener = {
            let store = request_store.clone();
            let page_clone = page.clone();
            let dbg = debug;
            let mut events = page.event_listener::<EventLoadingFinished>().await?;
            tokio::spawn(async move {
                while let Some(event) = events.next().await {
                    let req_id = event.request_id.inner().to_string();

                    // Mark as finished
                    {
                        let mut store_lock = store.lock().await;
                        if let Some(pending) = store_lock.get_mut(&req_id) {
                            pending.loading_finished = true;
                        }
                    }

                    // Eagerly fetch response body (outside lock to avoid blocking)
                    let params = GetResponseBodyParams::new(RequestId::from(req_id.clone()));
                    let body = match page_clone.execute(params).await {
                        Ok(response) => {
                            let b = &response.result.body;
                            if b.is_empty() {
                                None
                            } else if response.result.base64_encoded {
                                BASE64_STANDARD
                                    .decode(b)
                                    .ok()
                                    .and_then(|bytes| String::from_utf8(bytes).ok())
                            } else {
                                Some(b.clone())
                            }
                        }
                        Err(e) => {
                            if dbg {
                                eprintln!(
                                    "    [cdp] Eager body fetch failed for {}: {}",
                                    req_id, e
                                );
                            }
                            None
                        }
                    };

                    // Cache body in the pending request
                    if body.is_some() {
                        let mut store_lock = store.lock().await;
                        if let Some(pending) = store_lock.get_mut(&req_id) {
                            pending.response_body = body;
                        }
                    }
                }
            })
        };

        Ok(Self {
            browser,
            page,
            request_store,
            _handler_handle: handler_handle,
            _request_listener: req_listener,
            _response_listener: resp_listener,
            _loading_listener: loading_listener,
            debug,
            action_request_map: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Navigate to a URL and wait for the page to load
    pub async fn navigate(&self, url: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.page.goto(url).await?.wait_for_navigation().await?;
        Ok(())
    }

    /// Execute a list of user-defined actions with per-action request tracking
    pub async fn execute_actions(
        &self,
        actions: &[Action],
        wait_between_ms: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for action in actions {
            // Snapshot current request IDs before action
            let before_ids: Vec<String> = {
                let store = self.request_store.lock().await;
                store.keys().cloned().collect()
            };

            self.execute_action(action).await?;

            if wait_between_ms > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(wait_between_ms)).await;
            }

            // Collect new request IDs after action
            let new_ids: Vec<String> = {
                let store = self.request_store.lock().await;
                store
                    .keys()
                    .filter(|k| !before_ids.contains(k))
                    .cloned()
                    .collect()
            };

            if !new_ids.is_empty() {
                let mut map = self.action_request_map.lock().await;
                map.push((action.description.clone(), new_ids));
            }
        }
        Ok(())
    }

    async fn execute_action(&self, action: &Action) -> Result<(), Box<dyn std::error::Error>> {
        let selector = action.selector.as_deref().unwrap_or("");

        match action.action_type {
            ActionType::Click => {
                if self.debug {
                    eprintln!("    [action] Click: {}", selector);
                }
                // Try click via coordinates first, fallback to simple click
                if self.click_via_coordinates(selector).await.is_err() {
                    self.page
                        .find_element(selector)
                        .await
                        .map_err(|_| format!("Element not found: '{}'", selector))?
                        .click()
                        .await?;
                }
            }
            ActionType::Type => {
                let value = action.value.as_deref().unwrap_or("");
                if self.debug {
                    eprintln!("    [action] Type '{}' into {}", value, selector);
                }
                // Click the element first
                self.page
                    .find_element(selector)
                    .await
                    .map_err(|_| format!("Element not found: '{}'", selector))?
                    .click()
                    .await?;
                // Type with random delay per character
                self.type_with_delay(value).await?;
            }
            ActionType::Navigate => {
                if self.debug {
                    eprintln!("    [action] Navigate to {}", selector);
                }
                self.page
                    .goto(selector)
                    .await?
                    .wait_for_navigation()
                    .await?;
            }
            ActionType::Wait => {
                let ms: u64 = selector.parse().unwrap_or(1000);
                if self.debug {
                    eprintln!("    [action] Wait {}ms", ms);
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(ms)).await;
            }
            ActionType::WaitFor => {
                let timeout_ms: u64 = action.value.as_deref()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(10000);
                if self.debug {
                    eprintln!("    [action] WaitFor '{}' (timeout: {}ms)", selector, timeout_ms);
                }
                let escaped = escape_js_string(selector);
                let start = tokio::time::Instant::now();
                loop {
                    let js = format!(
                        "!!document.querySelector('{}')",
                        escaped
                    );
                    let found = self.page.evaluate(js).await
                        .ok()
                        .and_then(|v| v.into_value::<bool>().ok())
                        .unwrap_or(false);
                    if found {
                        break;
                    }
                    if start.elapsed().as_millis() as u64 >= timeout_ms {
                        return Err(format!(
                            "WaitFor timeout: element '{}' not found after {}ms",
                            selector, timeout_ms
                        ).into());
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                }
            }
            ActionType::Select => {
                let value = action.value.as_deref().unwrap_or("");
                if self.debug {
                    eprintln!("    [action] Select '{}' in {}", value, selector);
                }
                let js = format!(
                    r#"(() => {{
                        const el = document.querySelector('{}');
                        if (el) {{
                            el.value = '{}';
                            el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                        }}
                    }})()"#,
                    escape_js_string(selector),
                    escape_js_string(value)
                );
                self.page.evaluate(js).await?;
            }
            ActionType::Scroll => {
                if self.debug {
                    eprintln!("    [action] Scroll to {}", selector);
                }
                self.page
                    .find_element(selector)
                    .await
                    .map_err(|_| format!("Element not found: '{}'", selector))?
                    .scroll_into_view()
                    .await?;
            }
            ActionType::Submit => {
                if self.debug {
                    eprintln!("    [action] Submit {}", selector);
                }
                let js = format!(
                    r#"(() => {{
                        const form = document.querySelector('{}');
                        if (form) form.submit();
                    }})()"#,
                    escape_js_string(selector)
                );
                self.page.evaluate(js).await?;
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        }

        Ok(())
    }

    /// Click an element via coordinate dispatch for more realistic interaction
    async fn click_via_coordinates(&self, selector: &str) -> Result<(), Box<dyn std::error::Error>> {
        let escaped = escape_js_string(selector);
        let js = format!(
            r#"(() => {{
                const el = document.querySelector('{}');
                if (!el) return null;
                const rect = el.getBoundingClientRect();
                return {{ x: rect.x + rect.width / 2, y: rect.y + rect.height / 2 }};
            }})()"#,
            escaped
        );

        let result = self.page.evaluate(js).await?;
        let coords: serde_json::Value = result.into_value()?;

        if coords.is_null() {
            return Err(format!("Element not found: '{}'", selector).into());
        }

        let x = coords["x"].as_f64().ok_or("Invalid x coordinate")?;
        let y = coords["y"].as_f64().ok_or("Invalid y coordinate")?;

        // Mouse pressed
        let press = DispatchMouseEventParams::builder()
            .r#type(DispatchMouseEventType::MousePressed)
            .x(x)
            .y(y)
            .button(MouseButton::Left)
            .click_count(1)
            .build()
            .map_err(|e| format!("Failed to build mouse press event: {}", e))?;
        self.page.execute(press).await?;

        // Mouse released
        let release = DispatchMouseEventParams::builder()
            .r#type(DispatchMouseEventType::MouseReleased)
            .x(x)
            .y(y)
            .button(MouseButton::Left)
            .click_count(1)
            .build()
            .map_err(|e| format!("Failed to build mouse release event: {}", e))?;
        self.page.execute(release).await?;

        Ok(())
    }

    /// Type text with random delay between characters for realistic input
    async fn type_with_delay(&self, text: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        for ch in text.chars() {
            let key_text = ch.to_string();
            // KeyDown
            let key_down = DispatchKeyEventParams::builder()
                .r#type(DispatchKeyEventType::KeyDown)
                .text(key_text.clone())
                .build()
                .map_err(|e| format!("Failed to build key down event: {}", e))?;
            self.page.execute(key_down).await?;

            // KeyUp
            let key_up = DispatchKeyEventParams::builder()
                .r#type(DispatchKeyEventType::KeyUp)
                .text(key_text)
                .build()
                .map_err(|e| format!("Failed to build key up event: {}", e))?;
            self.page.execute(key_up).await?;

            // Random delay 50-150ms
            let delay: u64 = rng.gen_range(50..=150);
            tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
        }
        Ok(())
    }

    /// Collect all captured requests, fetching response bodies where possible
    pub async fn collect_requests(
        &self,
        wait_after_secs: u64,
    ) -> Result<Vec<CapturedRequest>, Box<dyn std::error::Error>> {
        // Wait for pending requests to complete
        tokio::time::sleep(tokio::time::Duration::from_secs(wait_after_secs)).await;

        // Collect JS-intercepted requests
        let js_requests = self.collect_js_requests().await;

        // Build action attribution map
        let action_map = self.action_request_map.lock().await;

        let store = self.request_store.lock().await;
        let mut requests: Vec<CapturedRequest> = Vec::new();
        let mut id_counter: usize = 0;

        // Sort by timestamp
        let mut entries: Vec<&PendingRequest> = store.values().collect();
        entries.sort_by(|a, b| {
            a.timestamp
                .partial_cmp(&b.timestamp)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for pending in entries {
            // Use eagerly-cached body first (fetched in EventLoadingFinished handler).
            // Fall back to live fetch only for non-redirect entries that have a response
            // but missed the eager fetch. Skip redirect-preserved entries because their
            // request_id was reused by the redirect target — getResponseBody would
            // return the wrong body.
            let response_body = if pending.response_body.is_some() {
                pending.response_body.clone()
            } else if pending.response_status.is_some() && !pending.is_redirect_preserved {
                self.get_response_body(&pending.request_id, self.debug).await
            } else {
                None
            };

            let resource_type_str = pending
                .resource_type
                .as_ref()
                .map(|rt| format!("{:?}", rt))
                .unwrap_or_else(|| "Other".to_string());

            // Determine which action triggered this request
            let triggered_by = action_map
                .iter()
                .find(|(_, req_ids)| req_ids.contains(&pending.request_id))
                .map(|(desc, _)| desc.clone());

            requests.push(CapturedRequest {
                id: id_counter,
                method: pending.method.clone(),
                url: pending.url.clone(),
                headers: pending.headers.clone(),
                body: pending.post_data.clone(),
                response_status: pending.response_status.unwrap_or(0),
                response_headers: pending.response_headers.clone(),
                response_body,
                timestamp: (pending.timestamp * 1000.0) as u64,
                initiator: pending.initiator_url.clone(),
                resource_type: resource_type_str,
                stack_trace: None, // CDP doesn't provide stack traces directly
                triggered_by_action: triggered_by,
            });
            id_counter += 1;
        }

        // Merge JS-intercepted requests not in CDP events
        for js_req in js_requests {
            let already_captured = requests
                .iter()
                .any(|r| r.url == js_req.url && r.method == js_req.method);

            if !already_captured {
                let mut req = js_req;
                req.id = id_counter;
                requests.push(req);
                id_counter += 1;
            }
        }

        Ok(requests)
    }

    /// Get response body for a request via CDP
    async fn get_response_body(&self, request_id: &str, debug: bool) -> Option<String> {
        let params = GetResponseBodyParams::new(RequestId::from(request_id.to_string()));
        match self.page.execute(params).await {
            Ok(response) => {
                let body = &response.result.body;
                if body.is_empty() {
                    return None;
                }
                if response.result.base64_encoded {
                    // Decode base64, only keep if it's valid UTF-8 text
                    match BASE64_STANDARD.decode(body) {
                        Ok(bytes) => String::from_utf8(bytes).ok(),
                        Err(_) => None, // binary content, skip
                    }
                } else {
                    Some(body.clone())
                }
            }
            Err(e) => {
                if debug {
                    eprintln!("    [cdp] Failed to get body for {}: {}", request_id, e);
                }
                None
            }
        }
    }

    /// Collect requests captured by JS hooks (fetch/XHR interception)
    async fn collect_js_requests(&self) -> Vec<CapturedRequest> {
        let result = self.page.evaluate(hooks::COLLECT_SCRIPT).await;

        let json_str = match result {
            Ok(eval) => match eval.into_value::<String>() {
                Ok(s) => s,
                Err(_) => return Vec::new(),
            },
            Err(_) => return Vec::new(),
        };

        let js_entries: Vec<serde_json::Value> = match serde_json::from_str(&json_str) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };

        let mut requests = Vec::new();
        for (i, entry) in js_entries.iter().enumerate() {
            let method = entry["method"].as_str().unwrap_or("GET").to_string();
            let url_str = entry["url"].as_str().unwrap_or("").to_string();
            let body = entry["body"].as_str().map(|s| s.to_string());
            let timestamp = entry["timestamp"].as_u64().unwrap_or(0);
            let response_status = entry["responseStatus"].as_u64().unwrap_or(0) as u16;
            let response_body = entry["responseBody"].as_str().map(|s| s.to_string());
            let req_type = entry["type"].as_str().unwrap_or("fetch").to_string();
            let stack_trace = entry["stackTrace"].as_str().map(|s| s.to_string());

            let mut headers = HashMap::new();
            if let Some(obj) = entry["headers"].as_object() {
                for (k, v) in obj {
                    if let Some(val) = v.as_str() {
                        headers.insert(k.clone(), val.to_string());
                    }
                }
            }

            requests.push(CapturedRequest {
                id: i,
                method,
                url: url_str,
                headers,
                body,
                response_status,
                response_headers: HashMap::new(),
                response_body,
                timestamp,
                initiator: Some(format!("js-{}", req_type)),
                resource_type: if req_type == "xhr" {
                    "Xhr".to_string()
                } else {
                    "Fetch".to_string()
                },
                stack_trace,
                triggered_by_action: None,
            });
        }

        requests
    }

    /// Close the browser gracefully
    pub async fn close(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.browser.close().await?;
        self._request_listener.abort();
        self._response_listener.abort();
        self._loading_listener.abort();
        self._handler_handle.abort();
        Ok(())
    }
}
