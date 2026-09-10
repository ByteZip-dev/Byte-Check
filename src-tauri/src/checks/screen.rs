use super::CheckReport;

/// Screen access permission — FIXABLE.
///
/// Ocean is a screenshare tool: it must be able to capture the screen. On
/// Windows this means desktop capture is not blocked; on Linux it means the
/// XDG ScreenCast portal / display session is available.
pub fn run() -> CheckReport {
    let name = "Screen access permission";

    #[cfg(target_os = "linux")]
    let state = scan_linux();

    #[cfg(target_os = "windows")]
    let state = scan_windows();

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let state = Err("unsupported platform".to_string());

    match state {
        Ok(()) => CheckReport::pass(name_value(), name, "Screen capture is available."),
        Err(detail) => CheckReport::fail(name_value(), name, true, detail),
    }
}

fn name_value() -> &'static str {
    "screen"
}

pub fn fix() -> bool {
    #[cfg(target_os = "linux")]
    {
        fix_linux()
    }
    #[cfg(target_os = "windows")]
    {
        fix_windows()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

#[cfg(target_os = "linux")]
fn scan_linux() -> Result<(), String> {
    let has_display = std::env::var("DISPLAY").map(|d| !d.is_empty()).unwrap_or(false);
    let has_wayland = std::env::var("WAYLAND_DISPLAY")
        .map(|d| !d.is_empty())
        .unwrap_or(false);

    if !has_display && !has_wayland {
        return Err("No display session detected; screenshare would be impossible.".into());
    }

    // The XDG desktop portal is what grants screencast permission on Wayland.
    // On a plain X11 session capture works directly, so the portal is optional.
    if has_wayland {
        let portal_running = process_running("xdg-desktop-portal");
        if !portal_running {
            return Err(
                "Wayland session detected but the XDG desktop portal is not running, so screen capture permission cannot be granted."
                    .into(),
            );
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn fix_linux() -> bool {
    // Restart the core portal; it spawns whichever backend is installed
    // (gtk/hyprland/wlr/gnome/kde). Missing backends must NOT count as failure.
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "restart", "xdg-desktop-portal"])
        .status();
    std::thread::sleep(std::time::Duration::from_millis(900));
    process_running("xdg-desktop-portal")
}

#[cfg(target_os = "windows")]
fn scan_windows() -> Result<(), String> {
    // Desktop Window Manager + an active Explorer session indicate a capturable
    // desktop. (Deep graphics-capture probing is out of scope for the pre-scan.)
    if !process_running("dwm.exe") {
        return Err("Desktop Window Manager is not running; screen capture unavailable.".into());
    }
    if !process_running("explorer.exe") {
        return Err("No active desktop session detected.".into());
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn fix_windows() -> bool {
    // DWM/Explorer cannot be force-restarted safely here; report as not
    // auto-fixable by restarting services is not attempted. If this branch is
    // reached the user is told to restart their session.
    false
}

fn process_running(target: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        use sysinfo::{ProcessesToUpdate, System};
        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::All, true);
        sys.processes()
            .values()
            .any(|p| p.name().to_string_lossy().to_ascii_lowercase() == target)
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let pid = entry.file_name();
                let pid = pid.to_string_lossy();
                if !pid.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
                    if comm.trim() == target {
                        return true;
                    }
                }
            }
        }
        false
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        false
    }
}