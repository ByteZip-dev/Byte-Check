use std::net::ToSocketAddrs;

use super::CheckReport;

/// Ocean domain access — FIXABLE.
///
/// Ocean must reach its servers (anticheat.ac / api.anticheat.ac) to upload
/// scan results. A hosts-file block or DNS-level block would break the scan.
pub fn run() -> CheckReport {
    let name = "Ocean domain access";

    let findings = scan_hosts();

    // A DNS resolution failure (with no hosts block explaining it) suggests a
    // DNS-level block or connectivity issue. Report as a warning so it doesn't
    // hard-block eligibility, but the user is told about it.
    let mut warning: Option<String> = None;
    if findings.is_empty() && !resolves() {
        warning = Some(
            "anticheat.ac does not resolve - a DNS-level block or network issue may be present.".into(),
        );
    }

    match (findings.is_empty(), warning) {
        (true, None) => CheckReport::pass("ocean", name, "Ocean's domains are reachable."),
        (true, Some(w)) => CheckReport::warning("ocean", name, w),
        (false, _) => CheckReport::fail("ocean", name, true, findings.join("; ")),
    }
}

pub fn fix() -> bool {
    // Remove hosts-file entries that block Ocean's domains.

    #[cfg(target_os = "linux")]
    {
        // sed -i on the hosts file; requires root, so elevate per-operation.
        let pattern = r"/anticheat\.ac/d";
        super::run_privileged("sed", &["-i", pattern, "/etc/hosts"])
    }

    #[cfg(target_os = "windows")]
    {
        let path = r"C:\Windows\System32\drivers\etc\hosts";
        let Ok(content) = std::fs::read_to_string(path) else {
            return false;
        };
        let kept: Vec<&str> = content
            .lines()
            .filter(|l| {
                let low = l.trim().to_ascii_lowercase();
                !crate::signatures::OCEAN_DOMAINS.iter().any(|d| low.contains(d))
            })
            .collect();
        let new = kept.join("\n");
        std::fs::write(path, new).is_ok()
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

fn hosts_path() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        r"C:\Windows\System32\drivers\etc\hosts"
    }
    #[cfg(target_os = "linux")]
    {
        "/etc/hosts"
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        "/etc/hosts"
    }
}

fn scan_hosts() -> Vec<String> {
    let mut found = Vec::new();
    let Ok(content) = std::fs::read_to_string(hosts_path()) else {
        return found;
    };
    for line in content.lines() {
        let low = line.trim().to_ascii_lowercase();
        if low.is_empty() || low.starts_with('#') {
            continue;
        }
        if crate::signatures::OCEAN_DOMAINS.iter().any(|d| low.contains(d)) {
            found.push(format!("hosts file blocks an Ocean domain: '{line}'"));
        }
    }
    found
}

fn resolves() -> bool {
    ("anticheat.ac", 443)
        .to_socket_addrs()
        .map(|mut it| it.next().is_some())
        .unwrap_or(false)
}