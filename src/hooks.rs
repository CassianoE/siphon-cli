//! Module 2: Hook Injector — JavaScript hooks for in-browser interception
//!
//! Responsibilities:
//! - Inject JS to intercept fetch/XHR
//! - Capture request/response pairs from inside the page
//! - Hook form submissions
//! - Track dynamic token insertion
//! - Capture stack traces for debugging
//! - Hook document.cookie reads
//! - Support per-action request snapshots

/// JavaScript to intercept all fetch() calls (with stack trace)
pub const FETCH_HOOK: &str = r#"
(function() {
    const originalFetch = window.fetch;
    window.__siphon_requests = window.__siphon_requests || [];
    window.fetch = function(...args) {
        const request = {
            url: typeof args[0] === 'string' ? args[0] : args[0].url,
            method: (args[1] && args[1].method) || 'GET',
            headers: (() => {
                const h = (args[1] && args[1].headers) || {};
                if (h instanceof Headers) {
                    const obj = {};
                    h.forEach((v, k) => { obj[k] = v; });
                    return obj;
                }
                return h;
            })(),
            body: (args[1] && args[1].body) || null,
            timestamp: Date.now(),
            type: 'fetch',
            stackTrace: new Error().stack
        };
        return originalFetch.apply(this, args).then(response => {
            const clone = response.clone();
            clone.text().then(body => {
                request.responseStatus = response.status;
                request.responseBody = body;
                window.__siphon_requests.push(request);
            }).catch(() => {});
            return response;
        });
    };
})();
"#;

/// JavaScript to intercept XMLHttpRequest (with stack trace)
pub const XHR_HOOK: &str = r#"
(function() {
    const originalOpen = XMLHttpRequest.prototype.open;
    const originalSend = XMLHttpRequest.prototype.send;
    const originalSetHeader = XMLHttpRequest.prototype.setRequestHeader;
    window.__siphon_requests = window.__siphon_requests || [];

    XMLHttpRequest.prototype.open = function(method, url) {
        this.__siphon = {
            method, url, headers: {}, timestamp: Date.now(), type: 'xhr',
            stackTrace: new Error().stack
        };
        return originalOpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
        if (this.__siphon) {
            this.__siphon.headers[name] = value;
        }
        return originalSetHeader.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function(body) {
        if (this.__siphon) {
            this.__siphon.body = body;
            this.addEventListener('load', function() {
                this.__siphon.responseStatus = this.status;
                this.__siphon.responseBody = this.responseText;
                window.__siphon_requests.push(this.__siphon);
            });
        }
        return originalSend.apply(this, arguments);
    };
})();
"#;

/// JavaScript to intercept document.cookie reads
pub const COOKIE_HOOK: &str = r#"
(function() {
    window.__siphon_cookie_reads = window.__siphon_cookie_reads || [];
    const desc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie') ||
                 Object.getOwnPropertyDescriptor(HTMLDocument.prototype, 'cookie');
    if (desc && desc.get) {
        const originalGet = desc.get;
        Object.defineProperty(document, 'cookie', {
            get: function() {
                const value = originalGet.call(this);
                window.__siphon_cookie_reads.push({
                    value: value,
                    timestamp: Date.now(),
                    stackTrace: new Error().stack
                });
                return value;
            },
            set: desc.set,
            configurable: true
        });
    }
})();
"#;

/// JavaScript to intercept form submissions
pub const FORM_SUBMIT_HOOK: &str = r#"
(function() {
    window.__siphon_requests = window.__siphon_requests || [];
    const originalSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function() {
        try {
            const formData = new FormData(this);
            const params = new URLSearchParams(formData).toString();
            window.__siphon_requests.push({
                url: this.action || window.location.href,
                method: (this.method || 'GET').toUpperCase(),
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: params,
                timestamp: Date.now(),
                type: 'form',
                stackTrace: new Error().stack
            });
        } catch(e) {}
        return originalSubmit.apply(this, arguments);
    };
})();
"#;

/// JavaScript to collect all intercepted requests
pub const COLLECT_SCRIPT: &str = r#"
JSON.stringify(window.__siphon_requests || [])
"#;

/// JavaScript to snapshot and clear intercepted requests (for per-action tracking)
#[allow(dead_code)]
pub const SNAPSHOT_REQUESTS_SCRIPT: &str = r#"
(function() {
    const snapshot = JSON.stringify(window.__siphon_requests || []);
    window.__siphon_requests = [];
    return snapshot;
})()
"#;

/// Combine all hooks into a single injection script
pub fn all_hooks() -> String {
    format!(
        "{}\n{}\n{}\n{}",
        FETCH_HOOK, XHR_HOOK, COOKIE_HOOK, FORM_SUBMIT_HOOK
    )
}
