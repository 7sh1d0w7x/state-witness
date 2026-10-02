//! state-witness — effective-state Linux security audit with provenance.
//!
//! Library: the core logic (probes, facts, findings).
//! CLI entry point is in `main.rs`.

use serde::Serialize;

/// The outcome of a single check.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The effective state is secure.
    Pass,
    /// Partially secure / worth attention (not a hard failure).
    Warn,
    /// The effective state is insecure.
    Fail,
    /// Could not be determined (requires root, unsupported, etc.).
    Skip,
}

/// Where an effective value came from (file + line), when known.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Provenance {
    pub path: String,
    pub line: Option<u32>,
}

/// A single finding: what we checked, the effective value, and the verdict.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub status: Status,
    pub value: Option<String>,
    pub provenance: Option<Provenance>,
}

impl Finding {
    pub fn pass(id: impl Into<String>, title: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            status: Status::Pass,
            value: Some(value.into()),
            provenance: None,
        }
    }

    pub fn fail(id: impl Into<String>, title: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            status: Status::Fail,
            value: Some(value.into()),
            provenance: None,
        }
    }

    pub fn warn(id: impl Into<String>, title: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            status: Status::Warn,
            value: Some(value.into()),
            provenance: None,
        }
    }

    pub fn skip(
        id: impl Into<String>,
        title: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            status: Status::Skip,
            value: Some(reason.into()),
            provenance: None,
        }
    }
}

/// Run the SSH effective-state checks.
///
/// v0.0.1: reads the effective config of the running OpenSSH daemon via
/// `sshd -T` (not the on-disk file), and reports the key authentication knobs.
///
/// NOTE: `sshd -T` typically requires root to read host keys. If it fails,
/// we return `Skip` findings rather than false results.
pub fn ssh_effective() -> Vec<Finding> {
    let output = std::process::Command::new("sshd").arg("-T").output();

    let Ok(out) = output else {
        return vec![Finding::skip(
            "SSH-000",
            "SSH effective config",
            "sshd not available",
        )];
    };

    if !out.status.success() {
        return vec![Finding::skip(
            "SSH-000",
            "SSH effective config",
            "sshd -T failed (try as root)",
        )];
    }

    let cfg = String::from_utf8_lossy(&out.stdout);
    let get = |key: &str| -> Option<String> {
        cfg.lines()
            .find_map(|l| l.strip_prefix(key)?.trim().to_string().into())
    };

    let mut findings = Vec::new();

    if let Some(v) = get("permitrootlogin") {
        // no = best; prohibit-password / without-password = key-only (warn); yes = fail
        let mut f = match v.as_str() {
            "no" => Finding::pass("SSH-001", "PermitRootLogin", v.clone()),
            "prohibit-password" | "without-password" => {
                Finding::warn("SSH-001", "PermitRootLogin", v.clone())
            }
            _ => Finding::fail("SSH-001", "PermitRootLogin", v.clone()),
        };
        f.provenance = Some(Provenance {
            path: "(effective, sshd -T)".into(),
            line: None,
        });
        findings.push(f);
    }

    if let Some(v) = get("passwordauthentication") {
        let mut f = if v == "no" {
            Finding::pass("SSH-002", "PasswordAuthentication", v.clone())
        } else {
            Finding::fail("SSH-002", "PasswordAuthentication", v.clone())
        };
        f.provenance = Some(Provenance {
            path: "(effective, sshd -T)".into(),
            line: None,
        });
        findings.push(f);
    }

    if findings.is_empty() {
        findings.push(Finding::skip(
            "SSH-000",
            "SSH effective config",
            "no known keys parsed",
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_constructors_set_status() {
        assert_eq!(Finding::pass("a", "t", "v").status, Status::Pass);
        assert_eq!(Finding::fail("a", "t", "v").status, Status::Fail);
        assert_eq!(Finding::warn("a", "t", "v").status, Status::Warn);
        assert_eq!(Finding::skip("a", "t", "v").status, Status::Skip);
    }

    #[test]
    fn warn_serializes_to_json() {
        let f = Finding::warn("SSH-001", "PermitRootLogin", "prohibit-password");
        let j = serde_json::to_string(&f).unwrap();
        assert!(j.contains("\"status\":\"warn\""));
    }

    #[test]
    fn finding_serializes_to_json() {
        let f = Finding::pass("SSH-001", "PermitRootLogin", "no");
        let j = serde_json::to_string(&f).unwrap();
        assert!(j.contains("\"status\":\"pass\""));
        assert!(j.contains("SSH-001"));
    }

    #[test]
    fn ssh_effective_returns_findings_or_skip() {
        // On CI/dev machines sshd may be missing or may fail without root;
        // either way we must return at least one finding, never panic.
        let findings = ssh_effective();
        assert!(!findings.is_empty());
    }
}
