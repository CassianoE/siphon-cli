# Siphon — Technical Specification

## Overview
CLI em Rust para engenharia reversa automática de fluxos HTTP. Aponta-se uma URL, descreve-se ações, e gera um script Python, curl, ou JSON que replica o fluxo do browser com dependências entre requests resolvidas automaticamente.

## Architecture: 6 Modules

### Module 1: CDP Engine (`browser.rs`)
- Headless Chrome via `chromiumoxide` (v0.9, tokio is built-in — no feature flag needed)
- Network capture via CDP `Network.enable` + event listeners
- Response body fetching via `Network.getResponseBody`
- JS hook injection via `evaluate_on_new_document`
- Action execution (click, type, navigate, wait, waitfor, select, scroll, submit)
- Click via coordinate dispatch (getBoundingClientRect + CDP Input.dispatchMouseEvent)
- Type with random delay per character (50-150ms)
- Per-action request polling for triggered_by_action tracking
- Dual capture: CDP network events + JS-intercepted fetch/XHR

### Module 2: Hook Injector (`hooks.rs`)
- JavaScript injection to intercept `fetch()` and `XMLHttpRequest`
- Stack traces captured on every intercepted request
- Cookie getter interception via `Object.defineProperty`
- Form submit interception via `HTMLFormElement.prototype.submit`
- Per-action request snapshot/clear for attribution

### Module 3: Action Parser (`actions.rs`)
- Parses CLI action strings: `"verb:selector=value"`
- Supported verbs: click, type/fill, navigate/goto/nav, wait/sleep, waitfor/wait_for, select, scroll, submit
- `{{var}}` and `{{var:default}}` parameterization in values
- Comma-separated actions, bracket-aware value splitting

### Module 4: Request Store & Filter (`capture.rs`)
- Filters by domain, resource type, URL extension, content-type
- Excludes static assets and tracking domains (configurable)
- Deduplicates by method+url+body, sorts by timestamp

### Module 5: Dependency Analyzer (`analyzer.rs` + `classifier.rs`)
- Extracts tokens from response headers, JSON bodies, HTML (meta, hidden inputs, data-* attrs)
- Token classification via heuristics + entropy filter (min 2.0 Shannon entropy)
- Token categories: Derived, Computed, Static, Unknown
- Matches tokens to subsequent requests with minimum 8-char length

### Module 6: Code Generator (`codegen.rs` + `templates/`)
- Tera templates for Python, curl, and JSON output
- Configurable parameters from `{{var}}` action values
- Status code assertions in generated scripts

## Data Pipeline (types.rs)
```
Action → CapturedRequest → TokenClassification → ExtractedValue → Dependency → DependencyGraph → Generated Script
```

## CLI Arguments
- `url` (positional): Target URL
- `--actions / -a`: Browser actions
- `--output / -o`: Format (python|curl|json), default: python
- `--outfile / -f`: Output path (default: flow.py|flow.sh|flow.json)
- `--filter-domain / -d`: Domain filter
- `--include-tracking`: Include tracking domain requests
- `--include-static`: Include static assets
- `--timeout`: Browser timeout (30s)
- `--wait-after`: Post-action wait (3s)
- `--wait-between`: Ms between actions (500ms)
- `--verify`: Run generated script (dual-pass with token classification)
- `--debug`: Debug output + save debug JSON files
- `--verbose / -v`: Verbose output

## Build & Run
```bash
cargo build
cargo run -- https://example.com --verbose
cargo test
cargo test -- --ignored   # integration tests (need Chrome)
```

## Tech Stack
- Rust 2021 edition
- chromiumoxide 0.9 (tokio built-in, no feature flag)
- tokio 1 (full)
- clap 4 (derive)
- serde/serde_json 1
- tera 1 (templates)
- shannon-entropy 1 (takes &str, returns f32)
- colored 2, regex 1, url 2, futures 0.3
- base64 0.22, rand 0.8

## Implementation Checklist

### Core Pipeline (Done)
- [x] Project setup & Cargo.toml
- [x] Types (types.rs)
- [x] CLI parsing (main.rs)
- [x] Action parser (actions.rs) — with tests
- [x] Request filter (capture.rs) — with tests
- [x] Token classifier (classifier.rs) — with tests
- [x] Dependency analyzer (analyzer.rs) — with tests
- [x] Code generator (codegen.rs) — with tests
- [x] Templates (python.tera, curl.tera)
- [x] Hook injector (hooks.rs)
- [x] Browser module (browser.rs) — full CDP implementation
- [x] End-to-end tested with httpbin.org
- [x] Verify flag, base64 body decoding, error handling

### Phase 1: Filters & JSON Output
- [x] F-03: JSON output format
- [x] F-05: Entropy filter on correlations (min 2.0)
- [x] F-10: Tracking domain exclusion list
- [x] F-11: Content-type based filtering

### Phase 2: New Actions & Parameterization
- [x] F-01: `waitfor:SELECTOR` action with timeout
- [x] F-02: `{{var}}` / `{{var:default}}` parameterization

### Phase 3: Advanced Hooks & Debug
- [x] F-06: Stack traces in hooks
- [x] F-12: `--debug` saves JSON files
- [x] F-14: Cookie getter hook
- [x] F-15: Form submit hook

### Phase 4: Advanced Classification & Codegen
- [x] F-04: TokenCategory (Derived/Computed/Static/Unknown)
- [x] F-13: Extract `data-*` attributes from HTML
- [x] F-20: Status code assertions in scripts

### Phase 5: Browser Improvements
- [x] F-07: Click via coordinates (CDP Input.dispatchMouseEvent)
- [x] F-08: Type with random delay (50-150ms per char)
- [x] F-09: Per-action request polling (triggered_by_action)

### Phase 6: Tests & Documentation
- [x] F-16: README.md
- [x] F-18: Integration tests (axum server, #[ignore])

### Phase 7: CI/CD & Publishing
- [x] F-17: GitHub Actions CI
- [x] F-19: `--verify` dual-pass token classification
- [x] F-21: Publish metadata & CHANGELOG
