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
    /// `Some(true)` signed, `Some(false)` unsigned, `None` unknown.
    pub signed: Option<bool>,
    pub pinned: bool,
    /// Command this came from (effective provenance).
    pub source: String,
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
                signed: Some(cleaned.starts_with("ostree-image-signed:")),
                image: Some(cleaned.to_string()),
                version: None,
                pinned: false,
                source: "(effective, rpm-ostree status)".to_string(),
            });
            continue;
        }

        if let Some(d) = cur.as_mut() {
            if let Some(v) = cleaned.strip_prefix("Version:") {
                d.version = Some(v.trim().to_string());
            } else if let Some(v) = cleaned.strip_prefix("GPGSignature:") {
                d.signed = Some(v.trim().to_ascii_lowercase().starts_with("valid"));
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

/// Parse `bootc status --json` output into deployment facts (pure; testable).
///
/// Schema (org.containers.bootc): `status.booted.image.image.image` is the
/// image ref, `status.booted.image.version` the version, `status.booted.pinned`
/// the pin flag. Signature state is only reported when present.
pub fn parse_bootc_status_json(text: &str) -> Option<Deployment> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    let booted = &v["status"]["booted"];
    if booted.is_null() {
        return None;
    }
    let img = &booted["image"];
    let image = img["image"]["image"].as_str().map(String::from);
    let version = img["version"].as_str().map(String::from);
    let pinned = booted["pinned"].as_bool().unwrap_or(false);
    // Optional: some versions expose a signature status object/string.
    let signed = img
        .get("signature")
        .and_then(|s| {
            s.get("status")
                .and_then(|x| x.as_str())
                .or_else(|| s.as_str())
        })
        .map(|s| {
            let l = s.to_ascii_lowercase();
            l.contains("signed") && !l.contains("un")
        });

    if image.is_none() && version.is_none() {
        return None;
    }
    Some(Deployment {
        image,
        version,
        signed,
        pinned,
        source: "(effective, bootc status --json)".to_string(),
    })
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

    // Deployment facts: prefer `rpm-ostree status`, fall back to `bootc status`.
    let deployment: Option<Deployment> = std::process::Command::new("rpm-ostree")
        .arg("status")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| parse_rpm_ostree_status(&String::from_utf8_lossy(&o.stdout)))
        .or_else(|| {
            std::process::Command::new("bootc")
                .args(["status", "--json"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| parse_bootc_status_json(&String::from_utf8_lossy(&o.stdout)))
        });

    if let Some(d) = deployment {
        let mut f = Finding::pass(
            "OSTREE-001",
            "Deployment",
            d.image.clone().unwrap_or_else(|| "unknown".into()),
        );
        f.provenance = provenance(&d.source);
        findings.push(f);

        match d.signed {
            Some(true) => {
                let mut sig = Finding::pass("OSTREE-002", "Deployment signature", "valid");
                sig.provenance = provenance(&d.source);
                findings.push(sig);
            }
            Some(false) => {
                let mut sig = Finding::warn(
                    "OSTREE-002",
                    "Deployment signature",
                    "unverified (no valid signature)",
                );
                sig.provenance = provenance(&d.source);
                findings.push(sig);
            }
            None => {
                let mut sig = Finding::skip(
                    "OSTREE-002",
                    "Deployment signature",
                    "unknown (not reported by this tool/version)",
                );
                sig.provenance = provenance(&d.source);
                findings.push(sig);
            }
        }

        if d.pinned {
            let mut p = Finding::warn(
                "OSTREE-003",
                "Deployment pinned",
                "pinned to this version (rollback target)",
            );
            p.provenance = provenance(&d.source);
            findings.push(p);
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

/// Run the sysctl effective-state checks.
///
/// Reads the *runtime* kernel parameters via `sysctl -n <key>` (what the kernel
/// actually enforces now), not the on-disk config, and reports the key knobs.
///
/// A mismatch is reported as `Fail`; an unreadable/missing key as `Skip`.
pub fn sysctl_effective() -> Vec<Finding> {
    // (sysctl key, finding id, title, expected-good value)
    let checks: &[(&str, &str, &str, &str)] = &[
        ("net.ipv4.ip_forward", "SYS-001", "IP forwarding", "0"),
        (
            "kernel.randomize_va_space",
            "SYS-002",
            "ASLR (randomize_va_space)",
            "2",
        ),
        (
            "net.ipv4.conf.all.rp_filter",
            "SYS-003",
            "Reverse-path filtering",
            "1",
        ),
        ("kernel.dmesg_restrict", "SYS-004", "dmesg restrict", "1"),
        (
            "kernel.kptr_restrict",
            "SYS-005",
            "kptr_restrict (hide kernel pointers)",
            "1",
        ),
        (
            "kernel.yama.ptrace_scope",
            "SYS-006",
            "Yama ptrace scope (block ptrace)",
            "1",
        ),
        (
            "net.ipv4.tcp_syncookies",
            "SYS-007",
            "TCP SYN cookies (SYN-flood protection)",
            "1",
        ),
    ];

    let mut findings = Vec::new();

    for (key, id, title, good) in checks {
        let output = std::process::Command::new("sysctl")
            .arg("-n")
            .arg(key)
            .output();

        let Ok(out) = output else {
            findings.push(Finding::skip(*id, *title, "sysctl not available"));
            continue;
        };

        if !out.status.success() {
            findings.push(Finding::skip(*id, *title, format!("{key} not readable")));
            continue;
        }

        let value = String::from_utf8_lossy(&out.stdout).trim().to_string();

        let mut f = if value == *good {
            Finding::pass(*id, *title, format!("{key} = {value}"))
        } else {
            Finding::fail(*id, *title, format!("{key} = {value} (expected {good})"))
        };
        f.provenance = Some(Provenance {
            path: "(effective, sysctl -n)".into(),
            line: None,
        });
        findings.push(f);
    }

    findings
}

/// Run the firewall effective-state checks.
///
/// Detects the active packet filter (nftables / ufw / firewalld) and reports
/// whether the host has an active ruleset. Reports `Skip` if none is found.
pub fn firewall_effective() -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. nftables (the modern default on Fedora/Atomic)
    if let Ok(out) = std::process::Command::new("nft")
        .arg("list")
        .arg("ruleset")
        .output()
    {
        if out.status.success() {
            let ruleset = String::from_utf8_lossy(&out.stdout);
            let rules = ruleset
                .lines()
                .filter(|l| {
                    let t = l.trim();
                    !t.is_empty() && !t.starts_with("table")
                })
                .count();
            let mut f = if rules > 0 {
                Finding::pass(
                    "FW-001",
                    "nftables ruleset",
                    format!("{rules} rules active"),
                )
            } else {
                Finding::fail("FW-001", "nftables ruleset", "no rules (inactive)")
            };
            f.provenance = Some(Provenance {
                path: "(effective, nft list ruleset)".into(),
                line: None,
            });
            findings.push(f);
            return findings;
        }
    }

    // 2. ufw (Ubuntu/Debian)
    if let Ok(out) = std::process::Command::new("ufw").arg("status").output() {
        if out.status.success() {
            let status = String::from_utf8_lossy(&out.stdout);
            let active = status.to_lowercase().contains("status: active");
            let mut f = if active {
                Finding::pass("FW-002", "ufw", "active")
            } else {
                Finding::fail("FW-002", "ufw", "inactive")
            };
            f.provenance = Some(Provenance {
                path: "(effective, ufw status)".into(),
                line: None,
            });
            findings.push(f);
            return findings;
        }
    }

    // 3. firewalld (RHEL/CentOS)
    if let Ok(out) = std::process::Command::new("firewall-cmd")
        .arg("--state")
        .output()
    {
        if out.status.success() {
            let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let running = state == "running";
            let mut f = if running {
                Finding::pass("FW-003", "firewalld", "running")
            } else {
                Finding::fail("FW-003", "firewalld", &state)
            };
            f.provenance = Some(Provenance {
                path: "(effective, firewall-cmd --state)".into(),
                line: None,
            });
            findings.push(f);
            return findings;
        }
    }

    // 4. Nothing detected
    findings.push(Finding::skip(
        "FW-000",
        "Firewall",
        "no known firewall detected (nft/ufw/firewalld)",
    ));
    findings
}

/// Run the users & sudo effective-state checks.
///
/// Detects: extra uid-0 accounts, `NOPASSWD` sudoers entries, and empty
/// password fields in `/etc/shadow`. Reports `Skip` where unreadable.
pub fn users_effective() -> Vec<Finding> {
    let mut findings = Vec::new();

    // 1. Extra uid-0 accounts (only "root" should have uid 0)
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        let extra: Vec<&str> = passwd
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter(|l| l.split(':').nth(2) == Some("0"))
            .filter_map(|l| l.split(':').next())
            .filter(|name| *name != "root")
            .collect();

        let mut f = if extra.is_empty() {
            Finding::pass("USR-001", "uid 0 accounts", "only root")
        } else {
            Finding::fail(
                "USR-001",
                "uid 0 accounts",
                format!("extra uid-0: {}", extra.join(", ")),
            )
        };
        f.provenance = Some(Provenance {
            path: "/etc/passwd".into(),
            line: None,
        });
        findings.push(f);
    } else {
        findings.push(Finding::skip(
            "USR-001",
            "uid 0 accounts",
            "/etc/passwd unreadable",
        ));
    }

    // 2. NOPASSWD sudoers entries
    let mut nopasswd = Vec::new();
    if let Ok(sudoers) = std::fs::read_to_string("/etc/sudoers") {
        for line in sudoers.lines() {
            let t = line.trim();
            if !t.starts_with('#') && t.contains("NOPASSWD") {
                nopasswd.push(t.to_string());
            }
        }
    }
    let mut f = if nopasswd.is_empty() {
        Finding::pass("USR-002", "sudoers NOPASSWD", "none")
    } else {
        Finding::warn(
            "USR-002",
            "sudoers NOPASSWD",
            format!("{} entr(y/ies)", nopasswd.len()),
        )
    };
    f.provenance = Some(Provenance {
        path: "/etc/sudoers".into(),
        line: None,
    });
    findings.push(f);

    // 3. Empty password fields in /etc/shadow (needs root)
    match std::fs::read_to_string("/etc/shadow") {
        Ok(shadow) => {
            let empty: Vec<&str> = shadow
                .lines()
                .filter(|l| {
                    let mut it = l.split(':');
                    it.next(); // user
                    it.next() == Some("") // empty password field
                })
                .filter_map(|l| l.split(':').next())
                .collect();
            let mut f = if empty.is_empty() {
                Finding::pass("USR-003", "empty passwords", "none")
            } else {
                Finding::fail(
                    "USR-003",
                    "empty passwords",
                    format!("{} account(s)", empty.len()),
                )
            };
            f.provenance = Some(Provenance {
                path: "/etc/shadow".into(),
                line: None,
            });
            findings.push(f);
        }
        Err(_) => {
            let mut f = Finding::skip(
                "USR-003",
                "empty passwords",
                "/etc/shadow unreadable (try as root)",
            );
            f.provenance = Some(Provenance {
                path: "/etc/shadow".into(),
                line: None,
            });
            findings.push(f);
        }
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
        assert_eq!(d.signed, Some(true));
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
        assert_eq!(d.signed, Some(false));
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
        assert_eq!(d.signed, Some(true));
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
    fn parses_bootc_status_json() {
        let sample = r#"{
    "apiVersion":"org.containers.bootc/v1",
    "kind":"BootcHost",
    "status":{
        "staged": null,
        "booted":{
            "image":{
                "image":{"image":"quay.io/fedora/fedora-bootc:41","transport":"registry"},
                "version":"41.20241020.0",
                "timestamp": null
            },
            "incompatible":false,
            "pinned":true
        }
    }
}"#;
        let d = parse_bootc_status_json(sample).expect("should parse");
        assert_eq!(d.image.as_deref(), Some("quay.io/fedora/fedora-bootc:41"));
        assert_eq!(d.version.as_deref(), Some("41.20241020.0"));
        assert!(d.pinned);
        assert_eq!(d.signed, None); // not reported in this schema version
        assert!(d.source.contains("bootc"));
    }

    #[test]
    fn bootc_json_without_booted_returns_none() {
        let sample = r#"{"status":{"staged":null,"booted":null}}"#;
        assert!(parse_bootc_status_json(sample).is_none());
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

    #[test]
    fn sysctl_effective_returns_findings() {
        // Must always return one finding per checked key; never panic, never empty.
        let findings = sysctl_effective();
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| f.provenance.is_some()));
    }

    #[test]
    fn firewall_effective_returns_findings() {
        // Always at least one finding; never panic, never empty.
        let findings = firewall_effective();
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| f.provenance.is_some()));
    }

    #[test]
    fn users_effective_returns_findings() {
        // Always findings (or skips); never panic, never empty.
        let findings = users_effective();
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| f.provenance.is_some()));
    }
}
