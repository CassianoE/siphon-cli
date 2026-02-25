mod actions;
mod analyzer;
mod browser;
mod capture;
mod classifier;
mod codegen;
mod hooks;
mod types;

use clap::Parser;
use colored::*;
use types::OutputFormat;

/// Siphon — Automatic API flow extractor & replay script generator.
///
/// Point at a URL, describe browser actions, and Siphon generates
/// a Python or curl script that replays the HTTP flow with all
/// dependencies (CSRF tokens, cookies, JWTs) resolved automatically.
#[derive(Parser, Debug)]
#[command(name = "siphon", version, about)]
struct Cli {
    /// Target URL to start the flow
    url: String,

    /// Browser actions to perform (e.g., "click:#btn", "type:#email=user@test.com")
    #[arg(short, long, num_args = 1..)]
    actions: Vec<String>,

    /// Output format: "python", "curl", or "json"
    #[arg(short, long, default_value = "python")]
    output: String,

    /// Output file path (default: flow.py for python, flow.sh for curl, flow.json for json)
    #[arg(short = 'f', long)]
    outfile: Option<String>,

    /// Filter requests to this domain only
    #[arg(short = 'd', long)]
    filter_domain: Option<String>,

    /// Timeout in seconds for browser operations
    #[arg(long, default_value_t = 30)]
    timeout: u64,

    /// Seconds to wait after last action for pending requests
    #[arg(long, default_value_t = 3)]
    wait_after: u64,

    /// Milliseconds to wait between each action
    #[arg(long, default_value_t = 500)]
    wait_between: u64,

    /// Verify generated script by running it
    #[arg(long)]
    verify: bool,

    /// Enable debug output
    #[arg(long)]
    debug: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Include static assets (CSS, JS, images, fonts) in captured requests
    #[arg(long)]
    include_static: bool,

    /// Include tracking domain requests (Google Analytics, Facebook, etc.)
    #[arg(long)]
    include_tracking: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let format = OutputFormat::parse_or_default(&cli.output);
    let outfile = cli
        .outfile
        .unwrap_or_else(|| format.default_filename().to_string());

    println!("{}", "╔═══════════════════════════════════════╗".cyan());
    println!("{}", "║        Siphon — Flow Extractor        ║".cyan());
    println!("{}", "╚═══════════════════════════════════════╝".cyan());
    println!();

    if !["python", "curl", "json"].contains(&cli.output.to_lowercase().as_str()) {
        println!(
            "  {} Unknown output format '{}', defaulting to python",
            "⚠".yellow(),
            cli.output
        );
    }

    if cli.verbose {
        println!("{} {}", "Target:".bold(), cli.url);
        println!("{} {:?}", "Output:".bold(), format);
        println!("{} {}", "File:".bold(), outfile);
        if let Some(ref domain) = cli.filter_domain {
            println!("{} {}", "Domain filter:".bold(), domain);
        }
        println!("{} {}s", "Timeout:".bold(), cli.timeout);
        println!("{} {}s", "Wait after:".bold(), cli.wait_after);
        println!("{} {}ms", "Wait between:".bold(), cli.wait_between);
        println!();
    }

    // ── Step 1: Parse actions ──
    print_step(1, "Parsing actions");
    let parsed_actions = match actions::parse_actions(&cli.actions) {
        Ok(a) => {
            println!("  {} Parsed {}", "✓".green(), plural(a.len(), "action", "actions"));
            a
        }
        Err(e) => {
            println!("  {} {}", "✗".red(), e);
            std::process::exit(1);
        }
    };

    // Extract parameters from actions
    let parameters = actions::extract_parameters(&parsed_actions);
    if !parameters.is_empty() && cli.verbose {
        println!("  {} Found {}", "ℹ".blue(), plural(parameters.len(), "parameter", "parameters"));
        for p in &parameters {
            let default = p.default_value.as_deref().unwrap_or("(none)");
            println!("    {} = {}", p.var_name, default);
        }
    }

    if cli.debug {
        for action in &parsed_actions {
            println!("    {:?}", action);
        }
    }

    // ── URL validation ──
    if url::Url::parse(&cli.url).is_err() {
        println!("  {} Invalid URL: {}", "✗".red(), cli.url);
        std::process::exit(1);
    }

    // ── Step 2: Launch browser ──
    print_step(2, "Launching browser");
    let siphon_browser = match browser::SiphonBrowser::launch(cli.debug).await {
        Ok(b) => {
            println!("  {} Browser ready", "✓".green());
            b
        }
        Err(e) => {
            println!("  {} Failed to launch browser: {}", "✗".red(), e);
            println!(
                "  {} Make sure Chrome/Chromium is installed and accessible",
                "ℹ".blue()
            );
            std::process::exit(1);
        }
    };

    // ── Step 3: Navigate & inject hooks ──
    print_step(3, "Navigating & injecting hooks");
    let timeout_duration = tokio::time::Duration::from_secs(cli.timeout);
    match tokio::time::timeout(timeout_duration, siphon_browser.navigate(&cli.url)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            println!("  {} Navigation failed: {}", "✗".red(), e);
            println!(
                "  {} Check that the URL is correct and the site is reachable",
                "ℹ".blue()
            );
            let _ = siphon_browser.close().await;
            std::process::exit(1);
        }
        Err(_) => {
            println!(
                "  {} Navigation timed out after {}s",
                "✗".red(),
                cli.timeout
            );
            let _ = siphon_browser.close().await;
            std::process::exit(1);
        }
    }
    println!("  {} Navigated to {}", "✓".green(), cli.url);

    // ── Step 4: Execute actions ──
    print_step(4, "Executing actions");
    match tokio::time::timeout(
        timeout_duration,
        siphon_browser.execute_actions(&parsed_actions, cli.wait_between),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            println!("  {} Action execution failed: {}", "✗".red(), e);
            let _ = siphon_browser.close().await;
            std::process::exit(1);
        }
        Err(_) => {
            println!(
                "  {} Action execution timed out after {}s",
                "✗".red(),
                cli.timeout
            );
            let _ = siphon_browser.close().await;
            std::process::exit(1);
        }
    }
    println!(
        "  {} Executed {}",
        "✓".green(),
        plural(parsed_actions.len(), "action", "actions")
    );

    // ── Step 5: Collect & filter requests ──
    print_step(5, "Collecting requests");
    let collect_timeout =
        tokio::time::Duration::from_secs(cli.timeout + cli.wait_after);
    let raw_requests = match tokio::time::timeout(
        collect_timeout,
        siphon_browser.collect_requests(cli.wait_after),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            println!("  {} Failed to collect requests: {}", "✗".red(), e);
            let _ = siphon_browser.close().await;
            std::process::exit(1);
        }
        Err(_) => {
            println!(
                "  {} Request collection timed out after {}s",
                "✗".red(),
                cli.timeout + cli.wait_after
            );
            let _ = siphon_browser.close().await;
            std::process::exit(1);
        }
    };

    // Save debug info: raw requests
    if cli.debug {
        if let Ok(json) = serde_json::to_string_pretty(&raw_requests) {
            if std::fs::write("siphon_debug.json", &json).is_ok() {
                println!("  {} Saved raw requests to siphon_debug.json", "ℹ".blue());
            }
        }
    }

    let mut filter = capture::RequestFilter::new(cli.filter_domain.clone());
    if cli.include_static {
        filter.exclude_static = false;
    }
    if cli.include_tracking {
        filter.exclude_tracking = false;
    }
    let requests = filter.apply(&raw_requests);
    println!(
        "  {} Captured {} ({} after filtering)",
        "✓".green(),
        plural(raw_requests.len(), "request", "requests"),
        plural(requests.len(), "request", "requests")
    );

    if requests.is_empty() {
        println!(
            "  {} No API requests captured. The page may only have static content.",
            "⚠".yellow()
        );
        println!(
            "  {} Try adding actions to interact with the page",
            "ℹ".blue()
        );
    }

    if cli.verbose {
        for req in &requests {
            let action_info = req
                .triggered_by_action
                .as_ref()
                .map(|a| format!(" [triggered by: {}]", a))
                .unwrap_or_default();
            println!(
                "    {} {} [{}] {}{}",
                req.method.yellow(),
                req.url,
                req.response_status,
                req.resource_type.dimmed(),
                action_info.dimmed()
            );
        }
    }

    // ── Step 6: Analyze dependencies ──
    print_step(6, "Analyzing dependencies");
    let graph = analyzer::analyze(&requests);
    println!(
        "  {} Found {} across {}",
        "✓".green(),
        plural(graph.edges.len(), "dependency", "dependencies"),
        plural(graph.nodes.len(), "request", "requests")
    );

    if cli.verbose {
        for edge in &graph.edges {
            let dep = &edge.dependency;
            println!(
                "    {} -> {} via {} ({}, {:?})",
                dep.from_request_id,
                dep.to_request_id,
                dep.extracted_value.name,
                format!("{:?}", dep.extracted_value.classification.token_type).yellow(),
                dep.extracted_value.category
            );
        }
    }

    // Save debug info: dependency graph
    if cli.debug {
        if let Ok(json) = serde_json::to_string_pretty(&graph) {
            if std::fs::write("siphon_debug_graph.json", &json).is_ok() {
                println!("  {} Saved dependency graph to siphon_debug_graph.json", "ℹ".blue());
            }
        }
    }

    // ── Step 7: Generate output ──
    print_step(7, "Generating output");
    match codegen::generate(&graph, &format, &outfile, &parameters) {
        Ok(()) => {
            println!("  {} Written to {}", "✓".green(), outfile.bold());
        }
        Err(e) => {
            println!("  {} Code generation failed: {}", "✗".red(), e);
            let _ = siphon_browser.close().await;
            std::process::exit(1);
        }
    }

    // ── Step 8: Verify (optional) ──
    if cli.verify && format != OutputFormat::Json {
        print_step(8, "Verifying generated script");
        let (cmd, args) = match format {
            OutputFormat::Python => ("python3", vec![outfile.as_str()]),
            OutputFormat::Curl => ("bash", vec![outfile.as_str()]),
            OutputFormat::Json => unreachable!(),
        };

        println!("  Running: {} {}", cmd, outfile);
        match std::process::Command::new(cmd)
            .args(&args)
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
        {
            Ok(status) => {
                if status.success() {
                    println!("  {} Script executed successfully", "✓".green());
                } else {
                    println!(
                        "  {} Script exited with code: {}",
                        "✗".red(),
                        status.code().map_or("signal".to_string(), |c| c.to_string())
                    );
                }
            }
            Err(e) => {
                println!("  {} Failed to run script: {}", "✗".red(), e);
                println!("  {} Make sure {} is installed", "ℹ".blue(), cmd);
            }
        }
    } else if cli.verify && format == OutputFormat::Json {
        println!("  {} --verify is not applicable to JSON output", "ℹ".blue());
    }

    // ── Step 9: Cleanup ──
    if let Err(e) = siphon_browser.close().await {
        if cli.debug {
            println!("  {} Browser cleanup warning: {}", "⚠".yellow(), e);
        }
    }

    println!();
    println!(
        "{}",
        format!(
            "Done! Generated {} with {} and {} ✓",
            outfile,
            plural(graph.nodes.len(), "request", "requests"),
            plural(graph.edges.len(), "dependency", "dependencies")
        )
        .green()
        .bold()
    );
}

fn print_step(n: u8, label: &str) {
    println!(
        "{}",
        format!("── Step {} : {} ──", n, label).blue().bold()
    );
}

fn plural(n: usize, singular: &str, plural_form: &str) -> String {
    if n == 1 {
        format!("1 {}", singular)
    } else {
        format!("{} {}", n, plural_form)
    }
}
