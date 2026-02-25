# Changelog

## [0.1.0] - 2026-02-25

### Added
- Core HTTP flow capture via CDP (Chrome DevTools Protocol)
- Browser actions: click, type, navigate, wait, waitfor, select, scroll, submit
- Dependency analysis: CSRF tokens, JWT, session cookies, OAuth tokens, API keys
- Code generation: Python (requests), curl (bash), JSON output
- Token classification with Shannon entropy heuristics
- Tracking domain filtering (Google Analytics, Facebook, etc.)
- Content-type based filtering (excludes binary/media responses)
- Parameterized actions with `{{var}}` and `{{var:default}}` syntax
- Status code assertions in generated scripts
- Stack trace capture in JS hooks
- Click via coordinate dispatch for realistic interaction
- Per-character typing delay (50-150ms) for human-like input
- Per-action request attribution tracking
- `--debug` flag saves JSON debug files
- `--verify` flag runs generated scripts
- Data attribute (`data-*`) token extraction from HTML
