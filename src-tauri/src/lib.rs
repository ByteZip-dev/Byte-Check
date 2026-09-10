use serde::Serialize;

pub mod checks;
mod signatures;

/// Elevation model:
/// - **Windows:** the app relaunches itself elevated through UAC
///   (`ShellExecuteW` with the "runas" verb) if it isn't already, then runs.
/// - **Linux:** the GUI runs as the user (root GUIs are unreliable on
///   Wayland/X11); privileged *fix* actions elevate per-operation via pkexec.
///   If the app is launched as root already, everything runs elevated directly.
///
/// Returns `true` when this process should continue (i.e. it is elevated), and
/// `false` when it relaunched an elevated copy and should exit.
pub fn ensure_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        if is_elevated() {
            return true;
        }
        if relaunch_elevated() {
            // The elevated copy is now running; the original exits.
            return false;
        }
        // Fall back to running unprivileged if UAC couldn't be triggered.
        true
    }
    #[cfg(not(target_os = "windows"))]
    {
        true
    }
}

#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = 0 as windows_sys::Win32::Foundation::HANDLE;
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevated: u32 = 0;
        let mut len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevated as *mut u32 as *mut _,
            std::mem::size_of::<u32>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && elevated != 0
    }
}

#[cfg(target_os = "windows")]
fn relaunch_elevated() -> bool {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let exe = exe.to_string_lossy();
    let mut args = String::new();
    for a in std::env::args().skip(1) {
        args.push_str(&a);
        args.push(' ');
    }

    let verb = wide("runas");
    let exe_w = wide(&exe);
    let args_w = wide(&args);
    let params = if args_w.len() > 1 { args_w.as_ptr() } else { std::ptr::null() };

    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            exe_w.as_ptr(),
            params,
            std::ptr::null(),
            SW_SHOWNORMAL as i32,
        )
    };
    // HINSTANCE values above 32 indicate success.
    (result as usize) > 32
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