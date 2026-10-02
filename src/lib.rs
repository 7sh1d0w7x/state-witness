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

/// Facts about an ostree/bootc deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployment {
    pub image: Option<String>,
    pub version: Option<String>,
    pub signed: bool,
    pub pinned: bool,
}

/// Parse `rpm-ostree status` text into deployment facts (pure; testable).
///
/// We parse defensively: real output varies by version, so we pick out the
/// keys we recognize and ignore the rest. When several deployments are listed,
/// the **booted** one (marked `●`) is preferred; otherwise the first.
/// Returns `None` if the text doesn't look like a deployment listing.
pub fn parse_rpm_ostree_status(text: &str) -> Option<Deployment> {
    let mut deployments: Vec<(bool, Deployment)> = Vec::new();
    let mut cur_booted = false;
    let mut cur: Option<Deployment> = None;

    for raw in text.lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let booted = trimmed.starts_with('●');
        let cleaned = trimmed.trim_start_matches('●').trim();

        // A deployment image/ref line, e.g.
        //   "ostree-image-signed:docker://ghcr.io/ublue-os/bazzite:stable"
        //   "fedora:fedora/41/x86_64/silverblue"
        // Heuristic: no whitespace, contains both ':' and '/'.
        if cleaned.contains('/') && cleaned.contains(':') && !cleaned.contains(char::is_whitespace)
        {
            if let Some(d) = cur.take() {
                deployments.push((cur_booted, d));
            }
            cur_booted = booted;
            cur = Some(Deployment {
                // "ostree-image-signed:" / "ostree-unverified-registry:" are
                // container-image deployments; the prefix records signature state.
                signed: cleaned.starts_with("ostree-image-signed:"),
                image: Some(cleaned.to_string()),
                version: None,
                pinned: false,
            });
            continue;
        }

        if let Some(d) = cur.as_mut() {
            if let Some(v) = cleaned.strip_prefix("Version:") {
                d.version = Some(v.trim().to_string());
            } else if let Some(v) = cleaned.strip_prefix("GPGSignature:") {
                d.signed = v.trim().to_ascii_lowercase().starts_with("valid");
            } else if let Some(v) = cleaned.strip_prefix("Pinned:") {
                d.pinned = v.trim().eq_ignore_ascii_case("yes");
            }
        }
    }
    if let Some(d) = cur.take() {
        deployments.push((cur_booted, d));
    }

    match deployments.iter().find(|(booted, _)| *booted) {
        Some((_, d)) => Some(d.clone()),
        None => deployments.first().map(|(_, d)| d.clone()),
    }
}

/// Parse `ostree admin config-diff` output into a list of drifted `/etc` paths.
///
/// Output lines look like `M   /etc/ssh/sshd_config` (M/A/D/T + path).
pub fn parse_config_diff(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|raw| {
            let line = raw.trim_start();
            let mut chars = line.chars();
            match chars.next() {
                Some('M') | Some('A') | Some('D') | Some('T') => {
                    let rest = chars.as_str().trim();
                    if rest.is_empty() {
                        None
                    } else {
                        Some(rest.to_string())
                    }
                }
                _ => None,
            }
        })
        .collect()
}

/// Run the immutable/atomic (ostree / bootc) checks.
///
/// Detects whether the running host is an ostree-based (immutable) deployment
/// and, if so, reports deployment facts with provenance: the image, whether it
/// is signed, whether it is pinned, and any preserved `/etc` drift.
///
/// On mutable hosts this returns a single `Skip` finding.
pub fn ostree_effective() -> Vec<Finding> {
    use std::path::Path;

    if !Path::new("/run/ostree-booted").exists() {
        return vec![Finding::skip(
            "OSTREE-000",
            "Immutable/atomic host",
            "not an ostree/bootc host (mutable)",
        )];
    }

    let provenance = |p: &str| {
        Some(Provenance {
            path: p.into(),
            line: None,
        })
    };
    let mut findings = Vec::new();

    // Deployment facts from `rpm-ostree status`.
    if let Ok(out) = std::process::Command::new("rpm-ostree")
        .arg("status")
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(d) = parse_rpm_ostree_status(&text) {
                let mut f = Finding::pass(
                    "OSTREE-001",
                    "Deployment",
                    d.image.clone().unwrap_or_else(|| "unknown".into()),
                );
                f.provenance = provenance("(effective, rpm-ostree status)");
                findings.push(f);

                let mut sig = if d.signed {
                    Finding::pass("OSTREE-002", "Deployment signature", "valid")
                } else {
                    Finding::warn(
                        "OSTREE-002",
                        "Deployment signature",
                        "unverified (no valid GPG signature)",
                    )
                };
                sig.provenance = provenance("(effective, rpm-ostree status)");
                findings.push(sig);

                if d.pinned {
                    let mut p = Finding::warn(
                        "OSTREE-003",
                        "Deployment pinned",
                        "pinned to this version (rollback target)",
                    );
                    p.provenance = provenance("(effective, rpm-ostree status)");
                    findings.push(p);
                }
            }
        }
    }

    // `/etc` drift vs the deployment (`/usr/etc`).
    if let Ok(out) = std::process::Command::new("ostree")
        .args(["admin", "config-diff"])
        .output()
    {
        if out.status.success() {
            let drift = parse_config_diff(&String::from_utf8_lossy(&out.stdout));
            let mut f = if drift.is_empty() {
                Finding::pass("OSTREE-004", "Preserved /etc drift", "none")
            } else {
                Finding::warn(
                    "OSTREE-004",
                    "Preserved /etc drift",
                    format!("{} modified path(s) vs /usr/etc", drift.len()),
                )
            };
            f.provenance = provenance("(effective, ostree admin config-diff)");
            findings.push(f);
        }
    }

    if findings.is_empty() {
        findings.push(Finding::skip(
            "OSTREE-000",
            "Immutable/atomic host",
            "ostree-booted, but no facts gathered (try as root)",
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

    #[test]
    fn parses_signed_pinned_deployment() {
        let sample = "\
State: idle
Deployments:
● fedora:fedora/41/x86_64/silverblue
                  Version: 41.20241020.0 (2024-10-20T00:31:29Z)
               BaseCommit: abcdef123456
             GPGSignature: Valid signature by 1234567890ABCDEF
                   Pinned: yes
";
        let d = parse_rpm_ostree_status(sample).expect("should parse");
        assert_eq!(
            d.image.as_deref(),
            Some("fedora:fedora/41/x86_64/silverblue")
        );
        assert_eq!(
            d.version.as_deref(),
            Some("41.20241020.0 (2024-10-20T00:31:29Z)")
        );
        assert!(d.signed);
        assert!(d.pinned);
    }

    #[test]
    fn parses_unverified_registry_image() {
        let sample = "\
Deployments:
● ostree-unverified-registry:ghcr.io/ublue-os/bazzite:stable
                  Version: 40.20241010.0
             GPGSignature: (unsigned)
";
        let d = parse_rpm_ostree_status(sample).expect("should parse");
        assert_eq!(
            d.image.as_deref(),
            Some("ostree-unverified-registry:ghcr.io/ublue-os/bazzite:stable")
        );
        assert!(!d.signed);
        assert!(!d.pinned);
    }

    #[test]
    fn parses_container_image_signed_deployment() {
        let sample = "\
State: idle
Deployments:
  ostree-image-signed:docker://ghcr.io/ublue-os/bazzite:stable
                   Digest: sha256:aaaa
                  Version: 44.20260929 (2026-09-29T20:03:27Z)
● ostree-image-signed:docker://ghcr.io/ublue-os/bazzite:stable
                   Digest: sha256:bbbb
                  Version: 44.20260928.1 (2026-09-28T17:21:46Z)
";
        let d = parse_rpm_ostree_status(sample).expect("should parse");
        // container-image signature prefix counts as signed
        assert!(d.signed);
        // the booted (●) deployment is preferred
        assert_eq!(
            d.version.as_deref(),
            Some("44.20260928.1 (2026-09-28T17:21:46Z)")
        );
    }

    #[test]
    fn parse_status_rejects_non_deployment_text() {
        assert!(parse_rpm_ostree_status("random text\nwith no keys").is_none());
    }

    #[test]
    fn parses_config_diff_entries() {
        let sample = "\
M   /etc/ssh/sshd_config
A   /etc/motd.d/99-brand
D   /etc/issue
not a diff line
";
        let drift = parse_config_diff(sample);
        assert_eq!(
            drift,
            vec![
                "/etc/ssh/sshd_config".to_string(),
                "/etc/motd.d/99-brand".to_string(),
                "/etc/issue".to_string(),
            ]
        );
    }

    #[test]
    fn config_diff_empty_is_empty() {
        assert!(parse_config_diff("").is_empty());
    }

    #[test]
    fn ostree_effective_returns_findings_or_skip() {
        // On a mutable host this is a single Skip; on an atomic host it must
        // return facts. Either way: never panic, never empty.
        let findings = ostree_effective();
        assert!(!findings.is_empty());
    }
}
