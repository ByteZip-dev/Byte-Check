use super::CheckReport;

/// Antivirus mode — FIXABLE (Windows only).
///
/// Ocean's own guidance recommends disabling antivirus for an accurate scan:
/// AV can block Ocean from running and blinds the AV-correlation detection
/// module. Byte Check can pause Windows Defender's realtime monitoring and
/// re-enable it afterwards. Third-party AV cannot be safely automated, so it
/// is reported as a warning with instructions instead.
pub fn run() -> CheckReport {
    let name = "Antivirus mode";

    #[cfg(target_os = "windows")]
    {
        match detect_av() {
            AvState::Defender { realtime_on } => {
                if realtime_on {
                    CheckReport::fail(
                        "av",
                        name,
                        true,
                        "Windows Defender realtime protection is on. Ocean recommends disabling it for an accurate scan. Byte Check will pause it and re-enable it afterwards.",
                    )
                } else {
                    CheckReport::pass(
                        "av",
                        name,
                        "Windows Defender realtime protection is off (as Ocean recommends).",
                    )
                }
            }
            AvState::ThirdParty { names } => CheckReport::warning(
                "av",
                name,
                format!(
                    "Third-party antivirus detected ({}). Ocean recommends disabling it for an accurate scan - disable it manually and re-enable it afterwards.",
                    names.join(", ")
                ),
            ),
            AvState::None => CheckReport::pass("av", name, "No antivirus interference detected."),
        }
    }

    #[cfg(target_os = "linux")]
    {
        CheckReport::pass("av", name, "N/A on Linux - antivirus does not interfere.")
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        CheckReport::pass("av", name, "N/A.")
    }
}

pub fn fix() -> bool {
    #[cfg(target_os = "windows")]
    {
        // Pause Windows Defender realtime monitoring (requires admin).
        std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Set-MpPreference -DisableRealtimeMonitoring $true",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

/// Re-enable Windows Defender realtime monitoring (called after the scan).
pub fn restore() -> bool {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Set-MpPreference -DisableRealtimeMonitoring $false",
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "windows"))]
    {
        true
    }
}

#[cfg(target_os = "windows")]
enum AvState {
    Defender { realtime_on: bool },
    ThirdParty { names: Vec<String> },
    None,
}

#[cfg(target_os = "windows")]
fn detect_av() -> AvState {
    use crate::signatures::KNOWN_AV_PROCESSES;
    use sysinfo::{ProcessesToUpdate, System};

    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let mut defender = false;
    let mut third_party: Vec<String> = Vec::new();

    for process in sys.processes().values() {
        let name = process.name().to_string_lossy().to_ascii_lowercase();
        if name == "msmpeng.exe" {
            defender = true;
        } else if KNOWN_AV_PROCESSES.iter().any(|a| *a == name.as_str()) {
            third_party.push(name);
        }
    }

    if defender {
        let realtime_on = realtime_monitoring_enabled();
        AvState::Defender { realtime_on }
    } else if !third_party.is_empty() {
        AvState::ThirdParty { names: third_party }
    } else {
        AvState::None
    }
}

#[cfg(target_os = "windows")]
fn realtime_monitoring_enabled() -> bool {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-MpPreference).DisableRealtimeMonitoring",
        ])
        .output();
    match out {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout).trim().to_string();
            text.is_empty() || text.eq_ignore_ascii_case("false") || text == "0"
        }
        Err(_) => true,
    }
}