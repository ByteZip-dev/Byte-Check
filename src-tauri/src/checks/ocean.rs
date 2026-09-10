use std::net::ToSocketAddrs;

use super::CheckReport;

/// Ocean domain access — FIXABLE.
///
/// Ocean must reach its servers (anticheat.ac / api.anticheat.ac) to upload
/// scan results. Causes of a broken handshake, per Ocean's own docs:
/// - hosts-file block of the domain (Ocean detects it as a bypass and crashes)
/// - broken DNS (typically a VPN that changes the resolver) → TLS handshake crash
/// - unstable connection / firewall → handshake crash
pub fn run() -> CheckReport {
    let name = "Ocean domain access";

    let hosts_findings = scan_hosts();
    if !hosts_findings.is_empty() {
        return CheckReport::fail(
            "ocean",
            name,
            true,
            format!(
                "{} Ocean detects this as a bypass method and refuses to run - Byte Check will remove the entry.",
                hosts_findings.join("; ")
            ),
        );
    }

    if !resolves() {
        return CheckReport::fail(
            "ocean",
            name,
            true,
            "anticheat.ac does not resolve. A misconfigured DNS (often a VPN) breaks Ocean's TLS handshake. Byte Check will flush DNS caches and restart the resolver.",
        );
    }

    if !tls_reachable() {
        return CheckReport::warning(
            "ocean",
            name,
            "anticheat.ac resolves but port 443 is unreachable - a VPN, firewall or unstable connection may block Ocean's TLS handshake.",
        );
    }

    CheckReport::pass("ocean", name, "Ocean's domains resolve and are reachable.")
}

pub fn fix() -> bool {
    let hosts_fixed = fix_hosts();
    let dns_fixed = flush_dns();
    hosts_fixed || dns_fixed
}

fn fix_hosts() -> bool {
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

fn flush_dns() -> bool {
    #[cfg(target_os = "linux")]
    {
        // systemd-resolved (most distros). Restarting the resolver also picks
        // up VPN DNS changes; both need root so they elevate per-operation.
        let _ = super::run_privileged("resolvectl", &["flush-caches"]);
        super::run_privileged("systemctl", &["restart", "systemd-resolved"])
    }

    #[cfg(target_os = "windows")]
    {
        // App runs elevated on Windows.
        std::process::Command::new("ipconfig")
            .arg("/flushdns")
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
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

/// Try to open a TCP connection to Ocean's TLS endpoint. A resolvable domain
/// that can't connect means a VPN, firewall or unstable connection is blocking
/// the handshake — per Ocean's docs this crashes the scan.
fn tls_reachable() -> bool {
    use std::net::TcpStream;
    use std::time::Duration;

    let Ok(mut addrs) = ("anticheat.ac", 443).to_socket_addrs() else {
        return false;
    };
    let Some(addr) = addrs.next() else {
        return false;
    };
    TcpStream::connect_timeout(&addr, Duration::from_secs(4)).is_ok()
}