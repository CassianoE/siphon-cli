//! Module 3: Action Parser & Executor
//!
//! Responsibilities:
//! - Parse action strings from CLI (e.g., "click:#login-btn", "type:#email=user@test.com")
//! - Validate selectors
//! - Convert to Action structs

use crate::types::{Action, ActionParameter, ActionType};
use regex::Regex;
use std::sync::LazyLock;

static PARAM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\{\{(\w+)(?::([^}]+))?\}\}").unwrap()
});

/// Parse a single action string into an Action struct.
///
/// Format: "verb:selector" or "verb:selector=value"
/// Examples:
///   "click:#login-btn"
///   "type:#email=user@example.com"
///   "navigate:https://example.com/dashboard"
///   "wait:2000"
///   "select:#country=Brazil"
pub fn parse_action(input: &str) -> Result<Action, String> {
    let (verb, rest) = input
        .split_once(':')
        .ok_or_else(|| format!("Invalid action format '{}'. Expected 'verb:target'", input))?;

    let action_type = match verb.to_lowercase().as_str() {
        "click" => ActionType::Click,
        "type" | "fill" => ActionType::Type,
        "navigate" | "goto" | "nav" => ActionType::Navigate,
        "wait" | "sleep" => ActionType::Wait,
        "waitfor" | "wait_for" => ActionType::WaitFor,
        "select" => ActionType::Select,
        "scroll" => ActionType::Scroll,
        "submit" => ActionType::Submit,
        _ => return Err(format!("Unknown action verb: '{}'", verb)),
    };

    // For actions that take a value (type, select, waitfor), split selector from value
    // using the last '=' that's outside CSS brackets
    let (selector, value) = if matches!(action_type, ActionType::Type | ActionType::Select | ActionType::WaitFor) {
        split_selector_value(rest)
    } else {
        (Some(rest.to_string()), None)
    };

    // Check if value contains parameterized placeholders {{var}} or {{var:default}}
    let is_parameterized = value.as_ref().is_some_and(|v| PARAM_RE.is_match(v));

    Ok(Action {
        description: input.to_string(),
        action_type,
        selector,
        value,
        is_parameterized,
    })
}

/// Split "selector=value" respecting CSS bracket syntax.
/// The value separator is the last '=' that is outside of [] brackets.
/// Examples:
///   "#email=user@test.com"          -> ("#email", "user@test.com")
///   "input[name=email]=test"        -> ("input[name=email]", "test")
///   "input[name=email]"             -> ("input[name=email]", None)
fn split_selector_value(s: &str) -> (Option<String>, Option<String>) {
    let mut bracket_depth = 0;
    let mut last_eq_outside = None;

    for (i, ch) in s.char_indices() {
        match ch {
            '[' => bracket_depth += 1,
            ']' => {
                if bracket_depth > 0 {
                    bracket_depth -= 1;
                }
            }
            '=' if bracket_depth == 0 => {
                last_eq_outside = Some(i);
            }
            _ => {}
        }
    }

    if let Some(pos) = last_eq_outside {
        let sel = &s[..pos];
        let val = &s[pos + 1..];
        (Some(sel.to_string()), Some(val.to_string()))
    } else {
        (Some(s.to_string()), None)
    }
}

/// Split actions by comma, but only when the next segment looks like a new action (contains ':')
fn smart_split_actions(input: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();

    for part in input.split(',') {
        if current.is_empty() {
            current = part.to_string();
        } else if part.trim().contains(':') {
            // Looks like a new action (has verb:target format)
            result.push(current);
            current = part.to_string();
        } else {
            // No colon — this is a continuation of the previous value (comma in value)
            current.push(',');
            current.push_str(part);
        }
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}

/// Extract parameterized variables from actions
pub fn extract_parameters(actions: &[Action]) -> Vec<ActionParameter> {
    let mut params = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for action in actions {
        if let Some(ref value) = action.value {
            for caps in PARAM_RE.captures_iter(value) {
                let name = caps[1].to_string();
                if seen.insert(name.clone()) {
                    let default_value = caps.get(2).map(|m| m.as_str().to_string());
                    let var_name = name.to_uppercase();
                    params.push(ActionParameter {
                        name,
                        var_name,
                        default_value,
                    });
                }
            }
        }
    }
    params
}

/// Parse multiple action strings (comma-separated or from a list)
pub fn parse_actions(inputs: &[String]) -> Result<Vec<Action>, String> {
    let mut actions = Vec::new();
    for input in inputs {
        for part in smart_split_actions(input) {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                actions.push(parse_action(trimmed)?);
            }
        }
    }
    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_click() {
        let action = parse_action("click:#login-btn").unwrap();
        assert!(matches!(action.action_type, ActionType::Click));
        assert_eq!(action.selector.unwrap(), "#login-btn");
        assert!(action.value.is_none());
    }

    #[test]
    fn test_parse_type_with_value() {
        let action = parse_action("type:#email=user@test.com").unwrap();
        assert!(matches!(action.action_type, ActionType::Type));
        assert_eq!(action.selector.unwrap(), "#email");
        assert_eq!(action.value.unwrap(), "user@test.com");
    }

    #[test]
    fn test_parse_navigate() {
        let action = parse_action("navigate:https://example.com").unwrap();
        assert!(matches!(action.action_type, ActionType::Navigate));
    }

    #[test]
    fn test_parse_wait() {
        let action = parse_action("wait:2000").unwrap();
        assert!(matches!(action.action_type, ActionType::Wait));
        assert_eq!(action.selector.unwrap(), "2000");
    }

    #[test]
    fn test_invalid_format() {
        assert!(parse_action("invalid").is_err());
    }

    #[test]
    fn test_unknown_verb() {
        assert!(parse_action("dance:#element").is_err());
    }

    #[test]
    fn test_parse_multiple() {
        let inputs = vec![
            "click:#btn,type:#name=John".to_string(),
            "submit:#form".to_string(),
        ];
        let actions = parse_actions(&inputs).unwrap();
        assert_eq!(actions.len(), 3);
    }

    #[test]
    fn test_parse_type_with_css_brackets() {
        let action = parse_action("type:input[name=email]=user@test.com").unwrap();
        assert!(matches!(action.action_type, ActionType::Type));
        assert_eq!(action.selector.unwrap(), "input[name=email]");
        assert_eq!(action.value.unwrap(), "user@test.com");
    }

    #[test]
    fn test_parse_click_with_brackets() {
        let action = parse_action("click:button[type=submit]").unwrap();
        assert!(matches!(action.action_type, ActionType::Click));
        assert_eq!(action.selector.unwrap(), "button[type=submit]");
        assert!(action.value.is_none());
    }

    #[test]
    fn test_parse_select_with_brackets() {
        let action = parse_action("select:select[name=country]=Brazil").unwrap();
        assert!(matches!(action.action_type, ActionType::Select));
        assert_eq!(action.selector.unwrap(), "select[name=country]");
        assert_eq!(action.value.unwrap(), "Brazil");
    }

    #[test]
    fn test_parse_fill_alias() {
        let action = parse_action("fill:#name=John").unwrap();
        assert!(matches!(action.action_type, ActionType::Type));
        assert_eq!(action.selector.unwrap(), "#name");
        assert_eq!(action.value.unwrap(), "John");
    }

    #[test]
    fn test_parse_goto_alias() {
        let action = parse_action("goto:https://example.com").unwrap();
        assert!(matches!(action.action_type, ActionType::Navigate));

        let action = parse_action("nav:https://example.com").unwrap();
        assert!(matches!(action.action_type, ActionType::Navigate));
    }

    #[test]
    fn test_parse_sleep_alias() {
        let action = parse_action("sleep:1000").unwrap();
        assert!(matches!(action.action_type, ActionType::Wait));
        assert_eq!(action.selector.unwrap(), "1000");
    }

    #[test]
    fn test_parse_scroll() {
        let action = parse_action("scroll:#section").unwrap();
        assert!(matches!(action.action_type, ActionType::Scroll));
        assert_eq!(action.selector.unwrap(), "#section");
    }

    #[test]
    fn test_parse_submit() {
        let action = parse_action("submit:#myform").unwrap();
        assert!(matches!(action.action_type, ActionType::Submit));
        assert_eq!(action.selector.unwrap(), "#myform");
    }

    #[test]
    fn test_parse_empty_list() {
        let inputs: Vec<String> = vec![];
        let actions = parse_actions(&inputs).unwrap();
        assert!(actions.is_empty());
    }

    #[test]
    fn test_parse_type_without_value() {
        // type with just selector, no =value — selector should be the whole rest
        let action = parse_action("type:#search").unwrap();
        assert!(matches!(action.action_type, ActionType::Type));
        assert_eq!(action.selector.unwrap(), "#search");
        assert!(action.value.is_none());
    }

    #[test]
    fn test_description_preserved() {
        let action = parse_action("click:#btn").unwrap();
        assert_eq!(action.description, "click:#btn");
    }

    #[test]
    fn test_parse_comma_with_spaces() {
        let inputs = vec!["click:#a , click:#b".to_string()];
        let actions = parse_actions(&inputs).unwrap();
        assert_eq!(actions.len(), 2);
    }

    #[test]
    fn test_comma_in_value() {
        let inputs = vec!["type:#email=test@test,com".to_string()];
        let actions = parse_actions(&inputs).unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].value.as_deref(), Some("test@test,com"));
    }

    #[test]
    fn test_comma_split_with_new_action() {
        let inputs = vec!["type:#email=test,click:#btn".to_string()];
        let actions = parse_actions(&inputs).unwrap();
        assert_eq!(actions.len(), 2);
    }

    #[test]
    fn test_parse_waitfor() {
        let action = parse_action("waitfor:#results").unwrap();
        assert!(matches!(action.action_type, ActionType::WaitFor));
        assert_eq!(action.selector.unwrap(), "#results");
        assert!(action.value.is_none());
    }

    #[test]
    fn test_parse_waitfor_with_timeout() {
        let action = parse_action("waitfor:#results=5000").unwrap();
        assert!(matches!(action.action_type, ActionType::WaitFor));
        assert_eq!(action.selector.unwrap(), "#results");
        assert_eq!(action.value.unwrap(), "5000");
    }

    #[test]
    fn test_parse_wait_for_alias() {
        let action = parse_action("wait_for:.loaded").unwrap();
        assert!(matches!(action.action_type, ActionType::WaitFor));
        assert_eq!(action.selector.unwrap(), ".loaded");
    }

    #[test]
    fn test_detect_parameterized_action() {
        let action = parse_action("type:#email={{username}}").unwrap();
        assert!(action.is_parameterized);

        let action2 = parse_action("type:#email=test@test.com").unwrap();
        assert!(!action2.is_parameterized);
    }

    #[test]
    fn test_extract_parameters() {
        let inputs = vec![
            "type:#email={{username:testuser}},type:#pass={{password}}".to_string(),
        ];
        let actions = parse_actions(&inputs).unwrap();
        let params = extract_parameters(&actions);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name, "username");
        assert_eq!(params[0].var_name, "USERNAME");
        assert_eq!(params[0].default_value.as_deref(), Some("testuser"));
        assert_eq!(params[1].name, "password");
        assert!(params[1].default_value.is_none());
    }
}
