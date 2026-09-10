// Curated signature lists. Keep these conservative to limit false positives:
// exact-name (case-insensitive) matches first, then a small set of high-confidence
// substring tokens. This is a pre-scan gate, not a verdict.

/// Process names (basename, case-insensitive) that BLOCK or interfere with the
/// scan itself. Detecting cheats (loaders, ghost clients, clickers) is Ocean's
/// job — Byte Check only cares about things that prevent an accurate scan:
/// anti-screenshare tools, streamproof/capture blockers, and tools that
/// force-close Ocean.
pub const SUSPICIOUS_PROCESSES: &[&str] = &[
    // anti-screenshare / streamproof (block the screenshare/scan)
    "antisstool", "anti-ss", "antiss", "streamproof", "ssblocker", "screenblocker",
    "captureblocker", "ss-protector",
    // anti-ocean / force-close tools (Ocean's docs: "Ocean just closes or
    // crashes" is a sign of a bypass that forcefully closes Ocean)
    "processkiller", "taskkiller", "killswitch", "oceanblocker", "antiocean",
    "sskiller", "forceclose", "crashinjector", "anticrash",
];

/// Substring tokens with very high confidence (contained anywhere in the name).
pub const SUSPICIOUS_TOKENS: &[&str] = &[
    "antiscreenshare", "killocean", "processkiller", "streamproof", "ssblocker",
];

/// Names that are always legitimate overlay/injection mechanisms that must be
/// whitelisted (e.g. Steam overlay on Linux).
pub const PRELOAD_WHITELIST: &[&str] = &["gameoverlayrenderer", "steamoverlayvulkanlayer"];

/// Executable/dll/shared-object filename fragments that indicate injected
/// modules or overlay/hook code corrupting the scan environment. Generic on
/// purpose — named cheat modules are Ocean's job to identify.
pub const SUSPICIOUS_MODULES: &[&str] = &[
    "inject", "hook", "overlay", "loader", "bypass",
];

/// Tokens searched in shell history on Linux — execution laundering and cheat
/// auth services (bypass methods that corrupt the scan's view of execution).
/// Named-cheat detection is Ocean's job; Byte Check only flags the laundering
/// pattern itself.
pub const HISTORY_PATTERNS: &[&str] = &[
    "rar x", "unrar", "7z x", "unzip", "keyauth", "eauth",
];

/// Known antivirus process names for the Windows AV check.
#[cfg(target_os = "windows")]
pub const KNOWN_AV_PROCESSES: &[&str] = &[
    "msmpeng.exe",  // Windows Defender
    "avguard.exe",  // Avira
    "avgnt.exe",    // Avast
    "avastui.exe",  // Avast UI
    "avp.exe",      // Kaspersky
    "kavsvc.exe",   // Kaspersky service
    "ekrn.exe",     // ESET
    "bdagent.exe",  // Bitdefender
    "mbamservice.exe", // Malwarebytes
    "360tray.exe",  // 360 Total Security
    "nortonsecurity.exe",
    "mcafee.exe",
];

/// Common shell rc files on Linux that may inject LD_PRELOAD.
pub const SHELL_RC_FILES: &[&str] = &[
    ".bashrc",
    ".profile",
    ".zshrc",
    ".bash_profile",
    ".xprofile",
];

/// Ocean Anticheat domains that must resolve for a scan to upload results.
pub const OCEAN_DOMAINS: &[&str] = &["anticheat.ac", "api.anticheat.ac"];