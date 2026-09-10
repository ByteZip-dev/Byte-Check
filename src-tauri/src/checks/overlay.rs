use super::CheckReport;

/// Overlay & injection sweep — FIXABLE.
///
/// Injected modules, LD_PRELOAD/LD_AUDIT hijacks, AppInit_DLLs, IFEO hijacks
/// and streamproof/overlay processes corrupt the scan's view of the system
/// (they trigger integrity findings or block capture). We neutralize them and
/// re-verify. Named-cheat modules are Ocean's job; this sweep targets the
/// injection mechanism itself.
pub fn run() -> CheckReport {
    let name = "Injection & hook sweep";

    #[cfg(target_os = "linux")]
    let findings = scan_linux();

    #[cfg(target_os = "windows")]
    let findings = scan_windows();

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let findings: Vec<String> = Vec::new();

    if findings.is_empty() {
        CheckReport::pass("overlay", name, "No injected modules, overlays or loader hijacks.")
    } else {
        CheckReport::fail("overlay", name, true, findings.join("; "))
    }
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

// ---------------------------------------------------------------- Linux ----

#[cfg(target_os = "linux")]
fn preload_entry_suspicious(entry: &str) -> bool {
    use crate::signatures::{PRELOAD_WHITELIST, SUSPICIOUS_MODULES};
    let e = entry.to_ascii_lowercase();
    if PRELOAD_WHITELIST.iter().any(|w| e.contains(w)) {
        return false;
    }
    let base = e.rsplit('/').next().unwrap_or(&e);
    if SUSPICIOUS_MODULES.iter().any(|m| base.contains(m)) {
        return true;
    }
    // Bare name with no path resolves from system library paths (e.g. Firefox's
    // `libmozsandbox.so`) — legitimate unless it matched a cheat signature.
    if !e.contains('/') {
        return false;
    }
    // Entries in system library paths are legitimate.
    for sys in ["/usr/local/lib", "/usr/lib", "/lib64", "/lib/"] {
        if e.starts_with(sys) {
            return false;
        }
    }
    true
}

#[cfg(target_os = "linux")]
fn preload_env_suspicious(kv: &str) -> bool {
    if let Some(eq) = kv.find('=') {
        return kv[eq + 1..].split(':').any(preload_entry_suspicious);
    }
    false
}

#[cfg(target_os = "linux")]
fn scan_linux() -> Vec<String> {
    use crate::signatures::{PRELOAD_WHITELIST, SUSPICIOUS_MODULES, SHELL_RC_FILES};
    let mut found: Vec<String> = Vec::new();
    let home = super::home_dir();

    // /etc/ld.so.preload — any non-system entry is suspicious.
    if let Ok(content) = std::fs::read_to_string("/etc/ld.so.preload") {
        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() && preload_entry_suspicious(line) {
                found.push(format!("unexpected entry in /etc/ld.so.preload: '{line}'"));
            }
        }
    }

    // Shell rc files exporting LD_PRELOAD / LD_AUDIT to suspicious paths.
    for rc in SHELL_RC_FILES {
        let path = format!("{home}/{rc}");
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines() {
                let l = line.to_ascii_lowercase();
                if (l.contains("ld_preload") || l.contains("ld_audit"))
                    && !l.trim_start().starts_with('#')
                {
                    if let Some(eq) = line.find('=') {
                        if preload_env_suspicious(&line[eq + 1..]) {
                            found.push(format!("{rc} sets LD_PRELOAD/LD_AUDIT: '{line}'"));
                        }
                    }
                }
            }
        }
    }

    // Running processes: suspicious preload in environ, and executable
    // anonymous/memfd mappings in java (Minecraft) processes.
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid = entry.file_name();
            let pid = pid.to_string_lossy();
            if !pid.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let path = format!("/proc/{pid}");

            if let Ok(environ) = std::fs::read(format!("{path}/environ")) {
                for kv in environ.split(|&b| b == 0) {
                    if let Ok(kv) = std::str::from_utf8(kv) {
                        let k = kv.to_ascii_lowercase();
                        if (k.starts_with("ld_preload=") || k.starts_with("ld_audit="))
                            && !PRELOAD_WHITELIST.iter().any(|w| k.contains(w))
                            && preload_env_suspicious(kv)
                        {
                            found.push(format!("pid {pid} runs with {kv}"));
                        }
                    }
                }
            }

            // Java (Minecraft) processes: scan maps for injected regions.
            let is_java = std::fs::read_to_string(format!("{path}/comm"))
                .map(|c| c.trim() == "java" || c.trim() == "javaw")
                .unwrap_or(false);
            if is_java {
                if let Ok(maps) = std::fs::read_to_string(format!("{path}/maps")) {
                    for line in maps.lines() {
                        let lower = line.to_ascii_lowercase();
                        if lower.contains("memfd:") && line.contains("x")
                            || (lower.contains("(deleted)") && line.contains("x"))
                        {
                            found.push(format!(
                                "pid {pid} has executable anonymous/memfd region: {}",
                                line.split_whitespace().last().unwrap_or("")
                            ));
                        }
                        // suspicious named shared object loaded into the JVM
                        if let Some(modname) =
                            lower.split('/').last().map(|s| s.to_string())
                        {
                            if modname.ends_with(".so")
                                && SUSPICIOUS_MODULES.iter().any(|m| modname.contains(m))
                            {
                                found.push(format!("pid {pid} loaded suspicious module: {modname}"));
                            }
                        }
                    }
                }
            }
        }
    }

    found
}

#[cfg(target_os = "linux")]
fn fix_linux() -> bool {
    use crate::signatures::{
        PRELOAD_WHITELIST, SHELL_RC_FILES, SUSPICIOUS_MODULES, SUSPICIOUS_PROCESSES,
        SUSPICIOUS_TOKENS,
    };
    let mut ok = true;

    // Clear /etc/ld.so.preload of suspicious entries (needs root).
    if let Ok(content) = std::fs::read_to_string("/etc/ld.so.preload") {
        let has_suspicious = content.lines().any(|l| {
            let t = l.trim();
            !t.is_empty() && preload_entry_suspicious(t)
        });
        if has_suspicious {
            if !super::run_privileged("sh", &["-c", "printf '' > /etc/ld.so.preload"]) {
                ok = false;
            }
        }
    }

    // Strip suspicious LD_PRELOAD/LD_AUDIT lines from shell rc files.
    let home = super::home_dir();
    for rc in SHELL_RC_FILES {
        let path = format!("{home}/{rc}");
        if let Ok(content) = std::fs::read_to_string(&path) {
            let kept: Vec<&str> = content
                .lines()
                .filter(|l| {
                    let low = l.to_ascii_lowercase();
                    if !(low.contains("ld_preload") || low.contains("ld_audit"))
                        || PRELOAD_WHITELIST.iter().any(|w| low.contains(w))
                    {
                        return true;
                    }
                    l.find('=')
                        .map(|eq| !preload_env_suspicious(&l[eq + 1..]))
                        .unwrap_or(true)
                })
                .collect();
            let new = kept.join("\n");
            if new != content && std::fs::write(&path, new).is_err() {
                ok = false;
            }
        }
    }

    // Kill processes running suspicious preloads or with injected java regions.
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid = entry.file_name();
            let pid = pid.to_string_lossy();
            if !pid.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let path = format!("/proc/{pid}");
            let bad_preload = std::fs::read(format!("{path}/environ"))
                .ok()
                .map(|raw| {
                    raw.split(|&b| b == 0).any(|kv| {
                        let Ok(kv) = std::str::from_utf8(kv) else {
                            return false;
                        };
                        let k = kv.to_ascii_lowercase();
                        (k.starts_with("ld_preload=") || k.starts_with("ld_audit="))
                            && !PRELOAD_WHITELIST.iter().any(|w| k.contains(w))
                            && preload_env_suspicious(kv)
                    })
                })
                .unwrap_or(false);

            let comm = std::fs::read_to_string(format!("{path}/comm"))
                .map(|c| c.trim().to_ascii_lowercase())
                .unwrap_or_default();

            let known_bad = SUSPICIOUS_PROCESSES.iter().any(|s| comm == *s)
                || SUSPICIOUS_TOKENS.iter().any(|t| comm.contains(t));

            let injected = if comm == "java" || comm == "javaw" {
                std::fs::read_to_string(format!("{path}/maps"))
                    .map(|maps| {
                        maps.lines().any(|l| {
                            let lower = l.to_ascii_lowercase();
                            (lower.contains("memfd:") && l.contains('x'))
                                || (lower.contains("(deleted)") && l.contains('x'))
                        }) || maps.lines().any(|l| {
                            let lower = l.to_ascii_lowercase();
                            lower.ends_with(".so")
                                && SUSPICIOUS_MODULES.iter().any(|m| lower.contains(m))
                        })
                    })
                    .unwrap_or(false)
            } else {
                false
            };

            if bad_preload || known_bad || injected {
                let _ = super::run_privileged("kill", &["-9", pid.as_ref()]);
            }
        }
    }

    ok
}

// -------------------------------------------------------------- Windows ----

#[cfg(target_os = "windows")]
fn scan_windows() -> Vec<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let mut found: Vec<String> = Vec::new();

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    if let Ok(appinit) = hklm.open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows") {
        if let Ok(val) = appinit.get_value::<String, _>("AppInit_DLLs") {
            if !val.trim().is_empty() {
                found.push(format!("AppInit_DLLs is set: '{val}'"));
            }
        }
    }

    if let Ok(ifeo) = hklm.open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options") {
        if let Ok(keys) = ifeo.enum_keys().collect::<Result<Vec<_>, _>>() {
            for k in keys {
                if let Ok(sub) = ifeo.open_subkey(&k) {
                    if let Ok(debugger) = sub.get_value::<String, _>("Debugger") {
                        if !debugger.trim().is_empty() {
                            found.push(format!("IFEO '{k}' has a Debugger set: '{debugger}'"));
                        }
                    }
                }
            }
        }
    }

    found
}

#[cfg(target_os = "windows")]
fn fix_windows() -> bool {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut ok = true;

    if let Ok(appinit) = hklm.open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        winreg::enums::KEY_SET_VALUE,
    ) {
        if let Ok(val) = appinit.get_value::<String, _>("AppInit_DLLs") {
            if !val.trim().is_empty() && appinit.delete_value("AppInit_DLLs").is_err() {
                ok = false;
            }
        }
    }

    if let Ok(ifeo) = hklm.open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        winreg::enums::KEY_SET_VALUE | winreg::enums::KEY_READ,
    ) {
        if let Ok(keys) = ifeo.enum_keys().collect::<Result<Vec<_>, _>>() {
            for k in keys {
                if let Ok(sub) = ifeo.open_subkey_with_flags(&k, winreg::enums::KEY_SET_VALUE) {
                    if let Ok(_) = sub.get_value::<String, _>("Debugger") {
                        let _ = sub.delete_value("Debugger");
                    }
                }
            }
        }
    }

    ok
}