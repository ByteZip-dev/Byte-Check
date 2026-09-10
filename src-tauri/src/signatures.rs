// Curated signature lists. Keep these conservative to limit false positives:
// exact-name (case-insensitive) matches first, then a small set of high-confidence
// substring tokens. This is a pre-scan gate, not a verdict.

/// Process names (basename, case-insensitive) that indicate cheat loaders,
/// ghost clients, autoclickers, injectors, debuggers or anti-screenshare tools.
pub const SUSPICIOUS_PROCESSES: &[&str] = &[
    // ghost clients / external cheats
    "slinky", "kauri", "vape", "intent", "rise", "flux", "novoline", "exhibition", "whiteout",
    "impact", "sigma", "future", "moze", "raw", "lunarplus",
    // autoclickers
    "toadclicker", "tclicker", "blazeclicker", "autoclicker", "cpsmax", "butterflyclicker",
    // injectors / tools
    "extremeinjector", "xenos", "processhacker", "injector", "phantom-injector",
    // debuggers / reverse engineering
    "cheatengine", "x64dbg", "x32dbg", "ollydbg", "windbg", "ida", "ida64",
    // anti-screenshare / streamproof
    "antisstool", "anti-ss", "antiss", "streamproof", "ssblocker",
    // generic loaders
    "loader", "cracked-client",
];

/// Substring tokens with very high confidence (contained anywhere in the name).
pub const SUSPICIOUS_TOKENS: &[&str] = &["autoclicker", "cheatengine", "x64dbg", "antiscreenshare"];

/// Names that are always legitimate overlay/injection mechanisms that must be
/// whitelisted (e.g. Steam overlay on Linux).
pub const PRELOAD_WHITELIST: &[&str] = &["gameoverlayrenderer", "steamoverlayvulkanlayer"];

/// Executable/dll/shared-object filename fragments that indicate injected or
/// overlay cheat modules.
pub const SUSPICIOUS_MODULES: &[&str] = &[
    "slinky", "kauri", "vape", "rise", "intent", "whiteout", "novoline", "exhibition", "sigma",
    "clicker", "inject", "hook", "overlay", "ghost", "esp", "aim",
];

/// Tokens searched in shell history on Linux (execution laundering / cheat pulls).
pub const HISTORY_PATTERNS: &[&str] = &[
    "slinky", "kauri", "vape", "rise", "intent", "whiteout", "novoline", "exhibition", "sigma",
    "ghostclient", "keyauth", "eauth", "rar x", "unrar", "7z x", "unzip",
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