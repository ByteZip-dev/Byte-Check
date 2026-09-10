use super::CheckReport;

/// Tamper log trace — NON-FIXABLE.
///
/// Historical evidence of bypass / anti-forensics: cleared prefetch, deleted
/// USN journal, cleared event logs, execution laundering traces, etc. These
/// cannot be undone - attempting to "fix" them would itself be more tampering.
pub fn run() -> CheckReport {
    let name = "Tamper log trace";

    #[cfg(target_os = "linux")]
    let findings = scan_linux();

    #[cfg(target_os = "windows")]
    let findings = scan_windows();

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let findings: Vec<String> = Vec::new();

    if findings.is_empty() {
        CheckReport::pass("trace", name, "No tamper or laundering traces found.")
    } else {
        CheckReport::fail("trace", name, false, findings.join("; "))
    }
}

#[cfg(target_os = "linux")]
fn scan_linux() -> Vec<String> {
    use crate::signatures::HISTORY_PATTERNS;
    let mut found: Vec<String> = Vec::new();
    let home = super::home_dir();

    for hist in [".bash_history", ".zsh_history"] {
        let path = format!("{home}/{hist}");
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        for line in content.lines() {
            let lower = line.to_ascii_lowercase();
            for pat in HISTORY_PATTERNS {
                if lower.contains(pat) {
                    found.push(format!("shell history shows: '{line}'"));
                    break;
                }
            }
        }
    }

    // A shell history that is empty while the shell is actively used is a weak
    // signal of clearing - report as a warning-tier detail, not a hard fail.
    found
}

#[cfg(target_os = "windows")]
fn scan_windows() -> Vec<String> {
    let mut found: Vec<String> = Vec::new();

    // 1. Prefetch folder missing or empty -> deletion.
    let prefetch = r"C:\Windows\Prefetch";
    match std::fs::read_dir(prefetch) {
        Ok(entries) => {
            let pf_count = entries.flatten().filter(|e| e.path().extension().map(|x| x == "pf").unwrap_or(false)).count();
            if pf_count == 0 {
                found.push("Prefetch directory is empty (all .pf files deleted).".into());
            }
        }
        Err(_) => {
            found.push("Prefetch directory is missing or inaccessible.".into());
        }
    }

    // 2. Prefetch disabled via registry.
    if let Ok(hklm) = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters")
    {
        if let Ok(v) = hklm.get_value::<u32, _>("EnablePrefetcher") {
            if v == 0 {
                found.push("EnablePrefetcher is 0 (prefetch recording disabled).".into());
            }
        }
    }

    // 3. USN journal deleted/disabled.
    let usn = std::process::Command::new("fsutil")
        .args(["usn", "queryjournal", "C:"])
        .output();
    if let Ok(out) = usn {
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if text.to_ascii_lowercase().contains("not found")
            || text.to_ascii_lowercase().contains("is not enabled")
        {
            found.push("USN journal is missing or disabled (journal deletion / anti-forensics).".into());
        }
    }

    // 4. Event log cleared recently (System log cleared -> Event ID 104).
    let evt = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-WinEvent -FilterHashtable @{LogName='System';Id=104} -MaxEvents 1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TimeCreated",
        ])
        .output();
    if let Ok(out) = evt {
        let text = String::from_utf8_lossy(&out.stdout);
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            found.push(format!("System event log was cleared (Event 104, {trimmed})."));
        }
    }

    found
}