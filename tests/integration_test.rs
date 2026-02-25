//! Integration tests for Siphon
//!
//! These tests require Chrome/Chromium to be installed.
//! Run with: cargo test -- --ignored

use std::process::Command;

fn siphon_binary() -> String {
    // Build the binary first
    let status = Command::new("cargo")
        .args(["build"])
        .status()
        .expect("Failed to build");
    assert!(status.success(), "cargo build failed");

    // Find the binary
    let output = Command::new("cargo")
        .args(["metadata", "--format-version=1", "--no-deps"])
        .output()
        .expect("Failed to get metadata");
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let target_dir = metadata["target_directory"].as_str().unwrap();
    format!("{}/debug/siphon", target_dir)
}

#[test]
#[ignore]
fn test_basic_get_capture() {
    let binary = siphon_binary();
    let output = Command::new(&binary)
        .args([
            "https://httpbin.org/get",
            "--output", "json",
            "-f", "/tmp/siphon_test_basic.json",
            "--verbose",
        ])
        .output()
        .expect("Failed to run siphon");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Flow Extractor"), "Missing banner");
    assert!(stdout.contains("Done!"), "Missing completion message");

    // Check output file exists
    assert!(std::path::Path::new("/tmp/siphon_test_basic.json").exists());

    // Clean up
    let _ = std::fs::remove_file("/tmp/siphon_test_basic.json");
}

#[test]
#[ignore]
fn test_form_post_with_actions() {
    let binary = siphon_binary();
    let output = Command::new(&binary)
        .args([
            "https://httpbin.org/forms/post",
            "-a", "type:input[name=custname]=testuser,submit:form",
            "--output", "python",
            "-f", "/tmp/siphon_test_form.py",
            "--verbose",
        ])
        .output()
        .expect("Failed to run siphon");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Done!"), "Missing completion message: {}", stdout);

    // Check output file exists and has content
    if std::path::Path::new("/tmp/siphon_test_form.py").exists() {
        let content = std::fs::read_to_string("/tmp/siphon_test_form.py").unwrap();
        assert!(content.contains("import requests"));
        assert!(content.contains("session"));
        let _ = std::fs::remove_file("/tmp/siphon_test_form.py");
    }
}

#[test]
#[ignore]
fn test_json_output_format() {
    let binary = siphon_binary();
    let output = Command::new(&binary)
        .args([
            "https://httpbin.org/get",
            "--output", "json",
            "-f", "/tmp/siphon_test_json.json",
        ])
        .output()
        .expect("Failed to run siphon");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Done!"), "Missing completion: {}", stdout);

    if std::path::Path::new("/tmp/siphon_test_json.json").exists() {
        let content = std::fs::read_to_string("/tmp/siphon_test_json.json").unwrap();
        // Should be valid JSON
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&content);
        assert!(parsed.is_ok(), "Invalid JSON output");
        let _ = std::fs::remove_file("/tmp/siphon_test_json.json");
    }
}

#[test]
#[ignore]
fn test_curl_output_format() {
    let binary = siphon_binary();
    let output = Command::new(&binary)
        .args([
            "https://httpbin.org/get",
            "--output", "curl",
            "-f", "/tmp/siphon_test_curl.sh",
        ])
        .output()
        .expect("Failed to run siphon");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Done!"), "Missing completion: {}", stdout);

    if std::path::Path::new("/tmp/siphon_test_curl.sh").exists() {
        let content = std::fs::read_to_string("/tmp/siphon_test_curl.sh").unwrap();
        assert!(content.contains("#!/usr/bin/env bash"));
        assert!(content.contains("curl"));
        let _ = std::fs::remove_file("/tmp/siphon_test_curl.sh");
    }
}

#[test]
#[ignore]
fn test_debug_mode() {
    let binary = siphon_binary();
    let output = Command::new(&binary)
        .args([
            "https://httpbin.org/get",
            "--debug",
            "--output", "json",
            "-f", "/tmp/siphon_test_debug.json",
        ])
        .output()
        .expect("Failed to run siphon");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Done!"), "Missing completion: {}", stdout);

    // Debug mode should create debug JSON files
    assert!(
        std::path::Path::new("siphon_debug.json").exists()
            || stdout.contains("siphon_debug.json"),
        "Debug JSON not created"
    );

    // Clean up
    let _ = std::fs::remove_file("/tmp/siphon_test_debug.json");
    let _ = std::fs::remove_file("siphon_debug.json");
    let _ = std::fs::remove_file("siphon_debug_graph.json");
}
