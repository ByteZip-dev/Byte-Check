#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Some Wayland compositors (e.g. Hyprland) disconnect GTK clients during
    // init. Prefer the X11 backend (XWayland) whenever a display is available,
    // even if GDK_BACKEND is pre-set to "wayland" in the environment. Pure
    // Wayland sessions without DISPLAY keep auto-detection.
    #[cfg(target_os = "linux")]
    {
        let forced_wayland = std::env::var("GDK_BACKEND")
            .map(|v| v.eq_ignore_ascii_case("wayland"))
            .unwrap_or(false);
        let has_display = std::env::var("DISPLAY")
            .map(|d| !d.is_empty())
            .unwrap_or(false);
        let backend_unset = std::env::var("GDK_BACKEND").is_err();
        if (backend_unset || forced_wayland) && has_display {
            std::env::set_var("GDK_BACKEND", "x11");
        }
    }

    // WebKitGTK fails to paint on some compositors (blank window) due to
    // DMABUF/GPU-compositing issues. Fall back to software rendering unless the
    // user explicitly set a rendering mode.
    #[cfg(target_os = "linux")]
    {
        for (k, v) in [
            ("WEBKIT_DISABLE_DMABUF_RENDERER", "1"),
            ("WEBKIT_DISABLE_COMPOSITING_MODE", "1"),
        ] {
            if std::env::var(k).is_err() {
                std::env::set_var(k, v);
            }
        }
    }

    if !byte_check_lib::ensure_elevated() {
        // An elevated copy was relaunched (Windows); the original exits.
        std::process::exit(0);
    }
    byte_check_lib::run();
}