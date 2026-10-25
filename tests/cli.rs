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
//!
//! `stub_*` tests go one step further and force a known verdict: they put a stub
//! `nft` first on PATH, so the `firewall` check produces a `Fail` (or a `Pass`)
//! on any machine — including CI runners that have no packet filter at all.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

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

// ---------------------------------------------------------------------------
// Deterministic verdicts: a stub `nft` on PATH decides the firewall outcome.
//
// The tests above compare the exit code with whatever report this host produced.
// That covers the wiring, but on a machine with no failing finding they never
// exercise "a Fail must exit 1" — which is exactly the path the original bug was
// in. These tests remove the ambiguity: the stub makes the verdict a fixture.
//
// No CLI surface is added and nothing on the host is changed: PATH is set for
// the spawned child only, and the stub lives in a temporary directory.
// ---------------------------------------------------------------------------

/// A temporary directory holding an executable `nft`, removed on drop.
struct StubDir(PathBuf);

impl Drop for StubDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

static STUB_SEQ: AtomicUsize = AtomicUsize::new(0);

/// Write an executable `nft` script into a fresh temp directory.
fn stub_nft(body: &str) -> StubDir {
    let dir = std::env::temp_dir().join(format!(
        "state-witness-stub-{}-{}",
        std::process::id(),
        STUB_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).expect("create stub directory");
    let file = dir.join("nft");
    fs::write(&file, body).expect("write stub");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&file).expect("stat stub").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&file, perms).expect("chmod stub");
    }

    StubDir(dir)
}

/// Run the CLI with the stub directory first on PATH.
fn run_with_stub(args: &[&str], stub: &StubDir) -> Output {
    let path = format!(
        "{}:{}",
        stub.0.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    Command::new(env!("CARGO_BIN_EXE_state-witness"))
        .args(args)
        .env("PATH", path)
        .output()
        .expect("failed to spawn the state-witness binary")
}

/// `nft` succeeds and reports nothing: `FW-001` is a Fail.
const NFT_NO_RULES: &str = "#!/bin/sh\nexit 0\n";

/// `nft` succeeds and reports a chain: `FW-001` is a Pass.
const NFT_WITH_RULES: &str =
    "#!/bin/sh\necho 'table inet filter {'\necho '  chain input {'\nexit 0\n";

fn json_report(out: &Output, label: &str) -> serde_json::Value {
    let stdout = String::from_utf8(out.stdout.clone()).expect("stdout must be UTF-8");
    serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("{label}: stdout is not valid JSON ({err}):\n{stdout}"))
}

#[test]
fn a_failing_finding_exits_one_in_text_and_json() {
    let stub = stub_nft(NFT_NO_RULES);

    let text = run_with_stub(&["firewall"], &stub);
    assert_eq!(
        text.status.code(),
        Some(1),
        "text: a report with a Fail must exit 1, got {:?} (stderr: {})",
        text.status.code(),
        String::from_utf8_lossy(&text.stderr)
    );

    let json = run_with_stub(&["firewall", "--json"], &stub);
    assert_eq!(
        json.status.code(),
        Some(1),
        "json: a report with a Fail must exit 1, got {:?} (stderr: {})",
        json.status.code(),
        String::from_utf8_lossy(&json.stderr)
    );
    assert!(
        json.stderr.is_empty(),
        "json: stderr must stay empty, got: {}",
        String::from_utf8_lossy(&json.stderr)
    );

    let parsed = json_report(&json, "json");
    let findings = parsed.as_array().expect("report must be a JSON array");
    assert!(
        findings.iter().any(|f| f["status"] == "fail"),
        "json: the report must contain at least one fail, got: {parsed}"
    );
}

#[test]
fn a_report_without_failures_exits_zero_in_text_and_json() {
    let stub = stub_nft(NFT_WITH_RULES);

    let text = run_with_stub(&["firewall"], &stub);
    assert_eq!(
        text.status.code(),
        Some(0),
        "text: pass/warn/skip only must exit 0, got {:?}",
        text.status.code()
    );

    let json = run_with_stub(&["firewall", "--json"], &stub);
    assert_eq!(
        json.status.code(),
        Some(0),
        "json: pass/warn/skip only must exit 0, got {:?}",
        json.status.code()
    );

    let parsed = json_report(&json, "json");
    let findings = parsed.as_array().expect("report must be a JSON array");
    assert!(
        findings.iter().all(|f| f["status"] != "fail"),
        "json: expected no fail with a reporting nft, got: {parsed}"
    );
}
