//! The .env reader must return exactly what was written, and must not leak it in errors.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use proptest::prelude::*;
use apikeybin_core::envfile::{self, EnvError, blocked_names, is_code_execution_vector, parse};

fn one(line: &str) -> String {
    let v = parse(line.as_bytes()).unwrap();
    assert_eq!(v.len(), 1, "{line}");
    v[0].value.to_string()
}

#[test]
fn dollar_signs_are_values_not_syntax() {
    // Each of these came back wrong from the parser the spec first named.
    assert_eq!(one("JWT_SECRET=$abc123"), "$abc123");
    assert_eq!(one("PW=pa$$word"), "pa$$word");
    assert_eq!(one("TOKEN=abc$def"), "abc$def");
    assert_eq!(one("DOUBLE=\"pa$$word\""), "pa$$word");
    assert_eq!(one("SINGLE='pa$$word'"), "pa$$word");
    assert_eq!(one("BRACED=${HOME}"), "${HOME}");
}

#[test]
fn the_local_environment_is_never_read() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/nonexistent-home".to_owned());
    let v = one("LEAK=$HOME");
    assert_eq!(v, "$HOME");
    assert_ne!(v, home);
    assert_eq!(one("LEAK2=${HOME}/x"), "${HOME}/x");
}

#[test]
fn common_forms() {
    let text = "# comment\n\nA=1\nexport B=2\n  C = 3  \nD=\"x y\"\nE='x # y'\nF=x # trailing\nG=\nH=a=b\r\n";
    let v = parse(text.as_bytes()).unwrap();
    let got: Vec<(&str, &str)> = v
        .iter()
        .map(|e| (e.name.as_str(), e.value.as_str()))
        .collect();
    assert_eq!(
        got,
        vec![
            ("A", "1"),
            ("B", "2"),
            ("C", "3"),
            ("D", "x y"),
            ("E", "x # y"),
            ("F", "x"),
            ("G", ""),
            ("H", "a=b"),
        ]
    );
}

#[test]
fn hash_inside_an_unquoted_token_is_kept() {
    assert_eq!(one("URL=https://x.test/#frag"), "https://x.test/#frag");
    assert_eq!(one("KEY=ab#cd"), "ab#cd");
}

#[test]
fn errors_name_the_line_and_never_the_content() {
    let cases = [
        (
            "OK=1\nfake_SECRETVALUE",
            EnvError::MissingEquals { line: 2 },
        ),
        (
            "BAD NAME fake_SECRETVALUE=x",
            EnvError::BadName { line: 1 },
        ),
        (
            "KEY='fake_SECRETVALUE",
            EnvError::UnterminatedQuote { line: 1 },
        ),
        (
            "KEY=\"fake_SECRETVALUE",
            EnvError::UnterminatedQuote { line: 1 },
        ),
        (
            "KEY='a' fake_SECRETVALUE",
            EnvError::TextAfterQuote { line: 1 },
        ),
        (
            "A=1\nA=fake_SECRETVALUE",
            EnvError::DuplicateName { line: 2 },
        ),
    ];
    for (input, expected) in cases {
        let e = parse(input.as_bytes()).err().unwrap();
        assert_eq!(e, expected, "{input}");
        for shown in [e.to_string(), format!("{e:?}")] {
            assert!(!shown.contains("SECRETVALUE"), "leaked in: {shown}");
        }
    }
    assert_eq!(parse(&[0xFF, 0xFE]).err(), Some(EnvError::NotUtf8));
}

#[test]
fn debug_hides_values() {
    let v = parse(b"KEY=fake_SECRETVALUE").unwrap();
    let shown = format!("{:?}", v[0]);
    assert!(
        shown.contains("KEY") && !shown.contains("SECRETVALUE"),
        "{shown}"
    );
}

#[test]
fn a_bom_does_not_become_part_of_the_first_name() {
    let v = parse("\u{feff}A=1".as_bytes()).unwrap();
    assert_eq!(v[0].name, "A");
}

#[test]
fn code_execution_variables_are_blocked_in_any_case() {
    for name in [
        "NODE_OPTIONS",
        "node_options",
        "PATH",
        "Path",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "BASH_ENV",
        "BASH_FUNC_x%%",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "RUBYOPT",
        "PERL5OPT",
        "JAVA_TOOL_OPTIONS",
        "GIT_SSH_COMMAND",
        "NPM_CONFIG_SCRIPT_SHELL",
        "RUSTC_WRAPPER",
        "COMSPEC",
        "DOTNET_STARTUP_HOOKS",
    ] {
        assert!(is_code_execution_vector(name), "{name}");
    }
    for name in [
        "STRIPE_KEY",
        "DATABASE_URL",
        "OPENAI_API_KEY",
        "PORT",
        "NODE_ENV",
        "APP_PATH",
    ] {
        assert!(
            !is_code_execution_vector(name),
            "{name} is ordinary configuration"
        );
    }
}

#[test]
fn blocked_names_can_only_be_allowed_one_by_one() {
    let vars = parse(b"STRIPE_KEY=a\nNODE_OPTIONS=--import=data:x\nPATH=/evil\n").unwrap();
    assert_eq!(blocked_names(&vars, &[]), vec!["NODE_OPTIONS", "PATH"]);
    assert_eq!(blocked_names(&vars, &["PATH"]), vec!["NODE_OPTIONS"]);
    assert!(blocked_names(&vars, &["PATH", "NODE_OPTIONS"]).is_empty());
}

proptest! {
    #[test]
    fn never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = envfile::parse(&data);
    }

    #[test]
    fn any_quoted_value_round_trips(value in "[^'\\r\\n]{0,200}") {
        let line = format!("K='{value}'");
        let v = parse(line.as_bytes()).unwrap();
        prop_assert_eq!(v[0].value.as_str(), value.as_str());
    }

    #[test]
    fn unquoted_dollars_survive(value in "[A-Za-z0-9$]{1,200}") {
        let line = format!("K={value}");
        let v = parse(line.as_bytes()).unwrap();
        prop_assert_eq!(v[0].value.as_str(), value.as_str());
    }
}
