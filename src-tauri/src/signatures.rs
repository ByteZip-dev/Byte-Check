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

/// Known antivirus process names for the Windows AV check (fallback for AVs
/// not registered with Windows Security Center). The primary source is the
/// Security Center registration itself (see checks/av.rs).
#[cfg(target_os = "windows")]
pub const KNOWN_AV_PROCESSES: &[&str] = &[
    // Windows Defender / MSE
    "msmpeng.exe", "msseces.exe",
    // Norton / Symantec
    "nortonsecurity.exe", "ccsvchst.exe", "navw32.exe",
    // McAfee
    "mcafee.exe", "mcshield.exe", "mfehcs.exe", "frameworkservice.exe",
    "mfemms.exe", "mcapexe.exe", "mfefire.exe", "aemservice.exe",
    // Kaspersky
    "avp.exe", "kavsvc.exe", "ksde.exe", "kaspersky.exe",
    // ESET
    "ekrn.exe", "eguiproxy.exe",
    // Bitdefender
    "bdagent.exe", "bdservicehost.exe", "bdscan.exe",
    // Avast
    "avastui.exe", "avastsvc.exe", "aswidsagenta.exe",
    // AVG
    "avgnt.exe", "avgui.exe", "avgsvc.exe", "avgemc.exe", "avgtray.exe",
    // Avira
    "avguard.exe", "avshadow.exe",
    // Malwarebytes
    "mbamservice.exe", "mbamtray.exe",
    // 360 Total Security
    "360tray.exe", "360sd.exe", "360safe.exe", "zhudongfangyu.exe",
    // Trend Micro
    "pccntmon.exe", "tmbmsrv.exe", "tmccsf.exe", "ccevtmgr.exe", "tmproxy.exe",
    // Sophos
    "sophosui.exe", "swi_service.exe", "sophosfs.exe",
    // Webroot
    "wrsa.exe",
    // Comodo
    "cmdagent.exe",
    // ZoneAlarm
    "vsmon.exe",
    // Panda
    "psanhost.exe", "pavfwsrv.exe", "pavprsrv.exe",
    // F-Secure
    "fsaua.exe", "fssm32.exe", "fshoster32.exe",
    // G Data
    "avkcl.exe", "avktray.exe",
    // Emsisoft
    "a2service.exe", "a2guard.exe",
    // Huorong (火绒)
    "hipstray.exe", "wsctrl.exe", "usysdiag.exe",
    // TotalAV / BullGuard / VIPRE / Adaware
    "totalav.exe", "bullguard.exe", "vipremgr.exe", "adaware_service.exe",
    "adawaretray.exe",
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