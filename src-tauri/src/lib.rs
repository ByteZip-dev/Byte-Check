use serde::Serialize;

pub mod checks;
mod signatures;

/// Elevation model:
/// - **Windows:** the whole app runs elevated via the UAC `requireAdministrator`
///   manifest embedded by `build.rs`.
/// - **Linux:** the GUI runs as the user (root GUIs are unreliable on
///   Wayland/X11); privileged *fix* actions elevate per-operation via pkexec.
///   If the app is launched as root already, everything runs elevated directly.
pub fn ensure_elevated() -> bool {
    true
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CmdResult {
    ok: bool,
    message: String,
}

#[tauri::command]
fn run_checks(app: tauri::AppHandle) -> checks::FinalSummary {
    checks::run_all(&app)
}

#[tauri::command]
fn restore_av() -> CmdResult {
    if checks::av::restore() {
        CmdResult { ok: true, message: "Antivirus realtime protection re-enabled.".into() }
    } else {
        CmdResult {
            ok: false,
            message: "Could not re-enable antivirus realtime protection. Re-enable it manually.".into(),
        }
    }
}

#[tauri::command]
fn start_scan() -> CmdResult {
    // Local-only mode: Byte Check hands off to the user, who opens Ocean and
    // enters their PIN. Nothing more to do on the client side.
    CmdResult { ok: true, message: "Open Ocean Anticheat and enter your PIN to scan.".into() }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            run_checks,
            restore_av,
            start_scan
        ])
        .run(tauri::generate_context!())
        .expect("error while running Byte Check");
}