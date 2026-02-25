# Siphon

> Automatic HTTP flow reverse engineering & replay script generator

Point Siphon at a URL, describe browser actions, and it generates a Python or curl script that replays the HTTP flow with all dependencies (CSRF tokens, cookies, JWTs) resolved automatically.

## Install

```bash
cargo install siphon
```

Or build from source:

```bash
git clone https://github.com/your-user/siphon.git
cd siphon
cargo build --release
```

Requires Chrome/Chromium installed on your system.

## Quick Start

```bash
# Capture a simple GET flow
siphon https://httpbin.org/get --verbose

# Fill a form and submit
siphon https://example.com/login \
  -a "type:input[name=email]=user@test.com,type:input[name=password]=secret,submit:form"

# Generate curl script instead of Python
siphon https://example.com/api --output curl

# Export raw dependency graph as JSON
siphon https://example.com/api --output json

# Use parameterized values
siphon https://example.com/login \
  -a "type:#email={{username:testuser}},type:#pass={{password}},submit:form"
```

## Actions

| Action | Format | Description |
|--------|--------|-------------|
| `click` | `click:SELECTOR` | Click an element |
| `type` / `fill` | `type:SELECTOR=VALUE` | Type text into an input |
| `navigate` / `goto` / `nav` | `navigate:URL` | Navigate to a URL |
| `wait` / `sleep` | `wait:MS` | Wait for milliseconds |
| `waitfor` / `wait_for` | `waitfor:SELECTOR=TIMEOUT_MS` | Wait for element to appear |
| `select` | `select:SELECTOR=VALUE` | Select dropdown option |
| `scroll` | `scroll:SELECTOR` | Scroll element into view |
| `submit` | `submit:SELECTOR` | Submit a form |

Actions are comma-separated: `-a "type:#email=user,click:#submit"`

## Output Formats

| Format | Flag | Default File | Description |
|--------|------|-------------|-------------|
| Python | `--output python` | `flow.py` | Python `requests` library script |
| Curl | `--output curl` | `flow.sh` | Bash script with curl commands |
| JSON | `--output json` | `flow.json` | Raw dependency graph as JSON |

## CLI Reference

```
siphon [URL] [OPTIONS]

Arguments:
  <URL>                    Target URL to start the flow

Options:
  -a, --actions <ACTIONS>  Browser actions to perform
  -o, --output <FORMAT>    Output format: python, curl, json (default: python)
  -f, --outfile <PATH>     Output file path
  -d, --filter-domain <D>  Filter requests to this domain only
      --include-tracking   Include tracking domain requests
      --include-static     Include static assets
      --timeout <SECS>     Browser timeout (default: 30)
      --wait-after <SECS>  Post-action wait (default: 3)
      --wait-between <MS>  Delay between actions (default: 500)
      --verify             Run generated script after generation
      --debug              Save debug JSON files
  -v, --verbose            Verbose output
  -h, --help               Print help
  -V, --version            Print version
```

## How It Works

1. Launches headless Chrome via CDP (Chrome DevTools Protocol)
2. Injects JS hooks to intercept fetch/XHR/form submissions
3. Navigates to the target URL and executes actions
4. Captures all HTTP requests and responses
5. Analyzes token dependencies (CSRF, JWT, cookies, OAuth)
6. Generates a replay script with dependency resolution

## Limitations

- Requires Chrome/Chromium installed
- WebSocket traffic is not captured
- Complex SPAs with shadow DOM may need manual action tuning
- Generated scripts use `requests` (Python) or `curl` (bash)

## License

MIT
