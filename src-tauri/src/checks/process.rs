use super::CheckReport;

/// Scan interference sweep — NON-FIXABLE.
///
/// Running processes that block or kill the scan itself: anti-screenshare
/// tools, streamproof/capture blockers, and tools that force-close Ocean.
/// Detecting cheats (loaders, ghost clients, clickers) is Ocean's job — Byte
/// Check only guards the scan.
pub fn run() -> CheckReport {
    let name = "Scan interference sweep";

    #[cfg(target_os = "linux")]
    let findings = scan_linux();

    #[cfg(target_os = "windows")]
    let findings = scan_windows();

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let findings: Vec<String> = Vec::new();

    if findings.is_empty() {
        CheckReport::pass("process", name, "No scan-blocking or scan-killing processes.")
    } else {
        CheckReport::fail("process", name, false, findings.join("; "))
    }
}

#[cfg(target_os = "linux")]
fn scan_linux() -> Vec<String> {
    use crate::signatures::{SUSPICIOUS_PROCESSES, SUSPICIOUS_TOKENS};
    let mut found: Vec<String> = Vec::new();

    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid = entry.file_name();
            let pid = pid.to_string_lossy();
            if !pid.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let path = format!("/proc/{pid}");

            let name = std::fs::read_to_string(format!("{path}/comm"))
                .ok()
                .map(|s| s.trim().to_ascii_lowercase())
                .unwrap_or_default();

            if SUSPICIOUS_PROCESSES.iter().any(|s| name == *s)
                || SUSPICIOUS_TOKENS.iter().any(|t| name.contains(t))
            {
                found.push(format!("process '{name}' (pid {pid})"));
            }
        }
    }

    found
}

#[cfg(target_os = "windows")]
fn scan_windows() -> Vec<String> {
    use crate::signatures::{SUSPICIOUS_PROCESSES, SUSPICIOUS_TOKENS};
    use sysinfo::{ProcessesToUpdate, System};

    let mut found: Vec<String> = Vec::new();
    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_ascii_lowercase();
        if SUSPICIOUS_PROCESSES.iter().any(|s| name == *s)
            || SUSPICIOUS_TOKENS.iter().any(|t| name.contains(t))
        {
            found.push(format!("process '{name}' (pid {pid})"));
        }
    }

    found
}