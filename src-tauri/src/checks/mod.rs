use serde::Serialize;
use tauri::{AppHandle, Emitter};

pub mod av;
pub mod clock;
pub mod ocean;
pub mod overlay;
pub mod process;
pub mod screen;
pub mod trace;

#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Pass,
    Fixed,
    Fail { fixable: bool },
    Warning,
}

pub struct CheckReport {
    pub key: &'static str,
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

impl CheckReport {
    pub fn pass(key: &'static str, name: &'static str, detail: impl Into<String>) -> Self {
        CheckReport { key, name, status: Status::Pass, detail: detail.into() }
    }

    pub fn fail(
        key: &'static str,
        name: &'static str,
        fixable: bool,
        detail: impl Into<String>,
    ) -> Self {
        CheckReport { key, name, status: Status::Fail { fixable }, detail: detail.into() }
    }

    pub fn warning(key: &'static str, name: &'static str, detail: impl Into<String>) -> Self {
        CheckReport { key, name, status: Status::Warning, detail: detail.into() }
    }

    pub fn status_str(&self) -> &'static str {
        match self.status {
            Status::Pass => "pass",
            Status::Fixed => "fixed",
            Status::Fail { .. } => "fail",
            Status::Warning => "warning",
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckEvent {
    pub key: &'static str,
    pub name: &'static str,
    pub status: &'static str,
    pub detail: String,
}

fn emit(app: &AppHandle, event: &CheckEvent) {
    let _ = app.emit("check-update", event);
}

/// TEMP DEBUG: append a line to /tmp/byte-check-debug.log so a scan can be
/// audited after the fact. Remove once verification is done.
fn debug_log(msg: &str) {
    use std::io::Write;
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = std::env::temp_dir().join("byte-check-debug.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "[{secs}] {msg}");
    }
    eprintln!("[byte-check-debug] {msg}");
}

fn all_checks() -> Vec<(&'static str, &'static str, fn() -> CheckReport, bool)> {
    vec![
        ("process", "Scan interference sweep", process::run, false),
        ("overlay", "Injection & hook sweep", overlay::run, true),
        ("clock", "System clock sync", clock::run, true),
        ("screen", "Screen access permission", screen::run, true),
        ("ocean", "Ocean domain access", ocean::run, true),
        ("av", "Antivirus mode", av::run, true),
        ("trace", "Tamper log trace", trace::run, false),
    ]
}

fn apply_fix(key: &'static str) -> bool {
    match key {
        "overlay" => overlay::fix(),
        "clock" => clock::fix(),
        "screen" => screen::fix(),
        "ocean" => ocean::fix(),
        "av" => av::fix(),
        _ => false,
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalSummary {
    pub outcome: &'static str,
    pub fixed: Vec<&'static str>,
    pub hard_fails: Vec<&'static str>,
    pub detail: String,
}

pub fn run_all(app: &AppHandle) -> FinalSummary {
    let mut fixed = Vec::new();
    let mut hard_fails = Vec::new();

    debug_log("=== scan start ===");

    for (key, name, run, _fixable) in all_checks() {
        let mut report = run();
        debug_log(&format!("[{key}] initial -> {:?}: {}", report.status, report.detail));

        emit(
            app,
            &CheckEvent {
                key,
                name,
                status: "running",
                detail: "Checking".to_string(),
            },
        );

        match report.status {
            Status::Pass | Status::Warning => {}
            Status::Fail { fixable: true } => {
                emit(
                    app,
                    &CheckEvent {
                        key,
                        name,
                        status: "fail",
                        detail: report.detail.clone(),
                    },
                );
                let fix_ok = apply_fix(key);
                debug_log(&format!("[{key}] fix returned {fix_ok}; re-running check"));
                let recheck = run();
                debug_log(&format!("[{key}] recheck -> {:?}: {}", recheck.status, recheck.detail));
                // The re-check is the source of truth: even if the fix reported
                // failure, the condition may now be satisfied.
                match recheck.status {
                    Status::Pass | Status::Warning => {
                        report = CheckReport {
                            status: Status::Fixed,
                            detail: format!("Auto-fixed: {}", recheck.detail),
                            ..recheck
                        };
                        fixed.push(key);
                    }
                    _ => {
                        hard_fails.push(key);
                        report = recheck;
                    }
                }
            }
            Status::Fail { fixable: false } => {
                debug_log(&format!("[{key}] hard fail (non-fixable)"));
                hard_fails.push(key);
            }
            _ => {}
        }

        emit(
            app,
            &CheckEvent {
                key,
                name,
                status: report.status_str(),
                detail: report.detail.clone(),
            },
        );
    }

    let outcome = if !hard_fails.is_empty() {
        "ineligible"
    } else if !fixed.is_empty() {
        "fixable"
    } else {
        "eligible"
    };

    let detail = match outcome {
        "eligible" => "Every check passed. You can start your scan now - no changes needed."
            .to_string(),
        "fixable" => format!(
            "{} were corrected automatically, so your scan will still be accurate.",
            fixed
                .iter()
                .map(|k| k.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        _ => "A non-correctable issue was found. A scan run now would not be accurate. Contact staff before continuing.".to_string(),
    };

    debug_log(&format!(
        "=== scan end -> outcome={outcome} fixed={fixed:?} hard_fails={hard_fails:?} ==="
    ));

    FinalSummary { outcome, fixed, hard_fails, detail }
}

pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Run a command that needs privileges. On Linux the GUI runs as the user, so
/// privileged fix actions are elevated per-operation via pkexec. If the app is
/// already running as root, the command runs directly.
pub fn run_privileged(cmd: &str, args: &[&str]) -> bool {
    if is_root() {
        return std::process::Command::new(cmd)
            .args(args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    }
    let mut p = std::process::Command::new("pkexec");
    p.arg(cmd);
    for a in args {
        p.arg(a);
    }
    p.status().map(|s| s.success()).unwrap_or(false)
}

/// Home directory of the *original* user. When Byte Check relaunches itself
/// elevated via `pkexec`, `$HOME` becomes `/root`; the pre-elevation home is
/// carried over in `BYTE_CHECK_HOME` so user-visible checks still read the
/// right files (shell history, rc files, etc.).
pub fn home_dir() -> String {
    std::env::var("BYTE_CHECK_HOME")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_else(|_| "/root".to_string())
}