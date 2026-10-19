//! Process-level CLI tests: exit codes, stream separation, and JSON validity.
//!
//! These spawn the real binary (`CARGO_BIN_EXE_state-witness`) instead of calling
//! library functions, because the regression they guard against lived in `main`:
//! the JSON path printed the report and returned before the exit code was
//! computed, so `--json` always exited `0` even when findings failed.
//!
//! They are deterministic on any host: instead of assuming a particular finding
//! set, each test asserts that the process exit code agrees with the report the
//! process itself produced.

use std::process::{Command, Output};

/// Every audit subcommand, in the order the CLI exposes them.
const CHECKS: [&str; 5] = ["ssh", "atomic", "sysctl", "firewall", "users"];

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_state-witness"))
        .args(args)
        .output()
        .expect("failed to spawn the state-witness binary")
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).expect("stdout must be valid UTF-8")
}

#[test]
fn version_exits_zero() {
    let out = run(&["version"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout_of(&out).starts_with("state-witness "));
}

#[test]
fn json_output_is_a_valid_array_on_stdout() {
    for cmd in CHECKS {
        let out = run(&[cmd, "--json"]);
        let stdout = stdout_of(&out);
        let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|err| {
            panic!("`{cmd} --json` wrote non-JSON to stdout: {err}\n--- stdout ---\n{stdout}")
        });
        assert!(
            parsed.is_array(),
            "`{cmd} --json` must emit a JSON array, got: {parsed}"
        );
        assert!(
            !parsed.as_array().expect("array").is_empty(),
            "`{cmd} --json` must never emit an empty report"
        );
        assert!(
            out.stderr.is_empty(),
            "`{cmd} --json` wrote diagnostics to stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn exit_code_follows_the_documented_contract_for_json() {
    // 0 when every status is pass/warn/skip, 1 as soon as one finding is a fail.
    for cmd in CHECKS {
        let out = run(&[cmd, "--json"]);
        let parsed: serde_json::Value = serde_json::from_str(&stdout_of(&out)).expect("valid JSON");
        let any_fail = parsed
            .as_array()
            .expect("array")
            .iter()
            .any(|finding| finding["status"] == "fail");
        let expected = if any_fail { 1 } else { 0 };

        assert_eq!(
            out.status.code(),
            Some(expected),
            "`{cmd} --json`: report contains a fail = {any_fail}, expected exit {expected}"
        );
    }
}

#[test]
fn text_and_json_exit_codes_agree() {
    // The original bug was a divergence between the two output paths; this is
    // the direct regression test for it.
    for cmd in CHECKS {
        let text = run(&[cmd]);
        let json = run(&[cmd, "--json"]);
        assert_eq!(
            text.status.code(),
            json.status.code(),
            "`{cmd}`: text and JSON exit codes disagree (text={:?}, json={:?})",
            text.status.code(),
            json.status.code()
        );
    }
}

#[test]
fn text_output_still_renders_findings() {
    // Guards against a refactor that silences the text path while fixing JSON.
    for cmd in CHECKS {
        let out = run(&[cmd]);
        assert!(
            !stdout_of(&out).trim().is_empty(),
            "`{cmd}` produced no text output"
        );
    }
}
