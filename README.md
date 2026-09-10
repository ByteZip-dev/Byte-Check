<div align="center">

<svg width="560" height="230" viewBox="0 0 560 230" xmlns="http://www.w3.org/2000/svg" font-family="Inter, system-ui, sans-serif">
  <defs>
    <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" stop-color="#5b8def">
        <animate attributeName="stop-color" values="#5b8def;#4ade80;#fbbf24;#f87171;#5b8def" dur="8s" repeatCount="indefinite"/>
      </stop>
      <stop offset="50%" stop-color="#4ade80">
        <animate attributeName="stop-color" values="#4ade80;#fbbf24;#f87171;#5b8def;#4ade80" dur="8s" repeatCount="indefinite"/>
      </stop>
      <stop offset="100%" stop-color="#5b8def">
        <animate attributeName="stop-color" values="#f87171;#5b8def;#4ade80;#fbbf24;#f87171" dur="8s" repeatCount="indefinite"/>
      </stop>
    </linearGradient>
  </defs>

  <g transform="translate(250 22)">
    <rect x="-46" y="0" width="92" height="92" rx="20" fill="#16181f" stroke="#5b8def" stroke-width="4">
      <animate attributeName="stroke-opacity" values="0.25;1;0.25" dur="2.4s" repeatCount="indefinite"/>
    </rect>
    <polygon points="-28,68 0,14 28,68 17,68 0,40 -17,68" fill="#5b8def">
      <animate attributeName="opacity" values="0.7;1;0.7" dur="2.4s" repeatCount="indefinite"/>
    </polygon>
  </g>

  <text x="280" y="162" text-anchor="middle" font-size="56" font-weight="800" fill="url(#grad)">Byte Check</text>

  <text x="280" y="198" text-anchor="middle" font-size="16" fill="#8b93a1">pre-scan verification for Ocean Anticheat</text>
  <rect x="455" y="182" width="3" height="15" fill="#5b8def">
    <animate attributeName="opacity" values="0;1;0" dur="1s" repeatCount="indefinite"/>
  </rect>
</svg>

<p style="margin:16px 0 0;">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-5b8def?style=for-the-badge&logo=windowsterminal&logoColor=white">
  <img alt="Stack" src="https://img.shields.io/badge/Rust%20%2B%20Tauri-v2-4ade80?style=for-the-badge&logo=rust&logoColor=white">
  <img alt="Version" src="https://img.shields.io/github/v/release/ByteZip-dev/Byte-Check?style=for-the-badge&color=fbbf24">
  <img alt="For" src="https://img.shields.io/badge/for-Ocean%20Anticheat-8b93a1?style=for-the-badge">
</p>

</div>

---

## ✨ What is Byte Check?

**Byte Check** is the gatekeeper that runs *before* an Ocean Anticheat scan. It inspects the
system for anything that would make the scan **inaccurate** — bypass methods, broken scan
prerequisites, tampering — **auto-fixes what's safely fixable**, and only then tells you if
you're ready to scan.

A small, frameless, always-on-top overlay. No install required.

<div style="display:flex; flex-wrap:wrap; gap:14px; margin:18px 0;">

<div style="flex:1 1 220px; background:#16181f; border:1px solid #2a2e37; border-radius:12px; padding:16px 18px;">
  <div style="font-size:22px;">🔍</div>
  <div style="font-weight:700; font-size:15px; margin:8px 0 4px;">Detects</div>
  <div style="font-size:13px; color:#8b93a1; line-height:1.55;">Cheat loaders, injected modules, loader hijacks, clock tampering, blocked screen capture, domain blocks, anti-forensics.</div>
</div>

<div style="flex:1 1 220px; background:#16181f; border:1px solid #2a2e37; border-radius:12px; padding:16px 18px;">
  <div style="font-size:22px;">🛠️</div>
  <div style="font-weight:700; font-size:15px; margin:8px 0 4px;">Auto-fixes</div>
  <div style="font-size:13px; color:#8b93a1; line-height:1.55;">Kills overlay/injector processes, clears <code>LD_PRELOAD</code>/<code>AppInit_DLLs</code> hijacks, resyncs the clock, restores the screencast portal, removes hosts blocks, pauses AV per Ocean's guidance.</div>
</div>

<div style="flex:1 1 220px; background:#16181f; border:1px solid #2a2e37; border-radius:12px; padding:16px 18px;">
  <div style="font-size:22px;">🔄</div>
  <div style="font-weight:700; font-size:15px; margin:8px 0 4px;">Re-verifies</div>
  <div style="font-size:13px; color:#8b93a1; line-height:1.55;">Every fix is followed by a fresh re-check. Only a passing re-check grants eligibility — no blind fixes.</div>
</div>

<div style="flex:1 1 220px; background:#16181f; border:1px solid #2a2e37; border-radius:12px; padding:16px 18px;">
  <div style="font-size:22px;">⚖️</div>
  <div style="font-weight:700; font-size:15px; margin:8px 0 4px;">Fair</div>
  <div style="font-size:13px; color:#8b93a1; line-height:1.55;">Never deletes evidence, never hides history. Non-fixable tampering means <b>Ineligible</b> — full stop.</div>
</div>

</div>

---

## 🧪 The Seven Checks

| # | Check | Auto-fix | What it looks for |
|---|---|---:|---|
| 1 | **Process integrity** | — | Cheat loaders, ghost clients, autoclickers, injectors, debuggers, anti-SS tools, attached debuggers (`TracerPid`) |
| 2 | **Overlay & injection sweep** | ✅ | Injected modules / `memfd` trampolines in the JVM, `LD_PRELOAD`/`LD_AUDIT` hijacks, `AppInit_DLLs`, IFEO `Debugger` keys, streamproof/overlay processes |
| 3 | **System clock sync** | ✅ | Clock skew vs real NTP (`time.google.com` → `pool.ntp.org` → `cloudflare`) |
| 4 | **Screen access permission** | ✅ | Wayland XDG screencast portal, X11 session, DWM/Explorer on Windows |
| 5 | **Ocean domain access** | ✅ | `anticheat.ac` / `api.anticheat.ac` blocked in the hosts file (removed); DNS-level blocks reported as a warning |
| 6 | **Antivirus mode** *(Windows)* | ✅ | Pauses Defender realtime protection per Ocean's recommendation, re-enables it after the scan; 3rd-party AV → warning |
| 7 | **Tamper log trace** | — | Cleared prefetch, deleted USN journal, cleared event logs, `EnablePrefetcher=0`, execution-laundering history |

---

## 🎯 Outcomes

<p style="margin:8px 0;">
  <span style="font-family:monospace; font-size:12.5px; padding:7px 15px; border-radius:999px; border:1px solid #2e5a3f; background:#10241a;">✓&nbsp; Eligible</span>
  <span style="font-family:monospace; font-size:12.5px; padding:7px 15px; border-radius:999px; border:1px solid #5a4a26; background:#241b10;">↻&nbsp; Eligible after auto-fix</span>
  <span style="font-family:monospace; font-size:12.5px; padding:7px 15px; border-radius:999px; border:1px solid #5a2e2e; background:#241414;">✕&nbsp; Ineligible</span>
</p>

<div style="background:#0d1117; border:1px solid #2a2e37; border-radius:12px; overflow:hidden; font-family:monospace; font-size:12.5px; margin:16px 0;">
  <div style="display:flex; gap:6px; align-items:center; padding:8px 12px; background:#161b22; border-bottom:1px solid #2a2e37;">
    <span style="width:10px; height:10px; border-radius:50%; background:#f87171; display:inline-block;"></span>
    <span style="width:10px; height:10px; border-radius:50%; background:#fbbf24; display:inline-block;"></span>
    <span style="width:10px; height:10px; border-radius:50%; background:#4ade80; display:inline-block;"></span>
    <span style="color:#484f58; margin-left:6px;">byte-check — live demo</span>
  </div>
<pre>
<span style="color:#484f58;">$</span> <span>Byte Check</span> — pre-scan

<span style="color:#4ade80;">✓</span> Process integrity            <span style="color:#484f58;">no suspicious processes</span>
<span style="color:#4ade80;">✓</span> Overlay &amp; injection sweep    <span style="color:#484f58;">no injected modules</span>
<span style="color:#4ade80;">✓</span> System clock sync            <span style="color:#484f58;">within 60s of network time</span>
<span style="color:#fbbf24;">↻</span> Screen access permission     <span style="color:#484f58;">portal restarted → re-checked → clear</span>
<span style="color:#4ade80;">✓</span> Ocean domain access          <span style="color:#484f58;">anticheat.ac reachable</span>
<span style="color:#4ade80;">✓</span> Antivirus mode               <span style="color:#484f58;">ready for scan</span>
<span style="color:#4ade80;">✓</span> Tamper log trace             <span style="color:#484f58;">clean</span>

<span style="color:#4ade80; font-weight:700;">OUTCOME: ELIGIBLE — you can start your scan.</span>
</pre>
</div>

---

## 🚀 Get it — portable, no install

| Platform | File | How to run |
|---|---|---|
| 🪟 Windows | **`Byte-Check-portable.exe`** | Download → double-click → approve UAC → done |
| 🐧 Linux | **`Byte-Check-portable`** | `chmod +x Byte-Check-portable && ./Byte-Check-portable` |
| 🪟 Windows | `.msi` / `setup.exe` | Classic installers |
| 🐧 Linux | `.AppImage` / `.deb` / `.rpm` | AppImage = single-file; deb/rpm = install |

> Everything is built automatically on native GitHub runners — Windows binaries are
> compiled, linked and bundled on a real Windows machine, every single release.

<p>
<a href="https://github.com/ByteZip-dev/Byte-Check/releases/latest">
  <img alt="Download" src="https://img.shields.io/badge/⬇ DOWNLOAD%20LATEST%20RELEASE-5b8def?style=for-the-badge">
</a>
</p>

---

## 🛠️ Build it yourself

Requires **Rust**, **Node.js**, and (on Linux) `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`,
`libsoup-3.0-dev`, `javascriptcoregtk-4.1-dev`.

```bash
npm install
npm run tauri dev      # dev mode (Vite + app)
npm run tauri build    # release bundles
```

Testing the checks without the GUI:

```bash
cd src-tauri
cargo test --test engine_smoke -- --nocapture
```

---

## 🏗️ Architecture

```
src-tauri/
├── src/
│   ├── lib.rs            Tauri wiring, UAC/pkexec elevation, commands
│   ├── checks/mod.rs     runner: detect → fix → re-verify → outcome
│   ├── checks/*.rs       the seven checks
│   ├── signatures.rs     cheat/bypass signature lists
│   └── main.rs           entry point, X11/WebKit fallbacks
├── tests/engine_smoke.rs no-GUI check engine test
├── capabilities/         Tauri v2 permissions
└── build.rs              tauri-build
.github/workflows/        CI: Windows + Linux build & release on tag push
```

**Elevation model**

- 🪟 **Windows** — relaunches itself elevated through UAC (`ShellExecuteW` "runas")
  when the token isn't elevated.
- 🐧 **Linux** — GUI runs as the user (root GUIs are unreliable on Wayland/X11);
  privileged fixes elevate per-operation via `pkexec`.

---

## 📊 Debug audit log

Every scan writes its per-check results so it can be audited afterwards:

```
Linux:   /tmp/byte-check-debug.log
Windows: %TEMP%\byte-check-debug.log
```

---

## ⚠️ Known limitations

- **Local-only trust.** A determined cheater can tamper with any client-side tool —
  server-side attestation (via the anticheat.ac Enterprise API) is the hardening path.
- **Signature lists** are deliberately conservative to limit false positives and need
  tuning against real Ocean behaviour.
- Byte Check mirrors Ocean's documented detection systems — it is a **pre-scan gate**,
  not a substitute for the Ocean scan itself.

---

<p align="center" style="margin-top:36px; font-size:12px; color:#8b93a1; border-top:1px solid #2a2e37; padding-top:14px;">
  Built with 🦀 Rust + Tauri &nbsp;·&nbsp; for <a href="https://anticheat.ac">Ocean Anticheat</a>
  &nbsp;·&nbsp; <a href="https://github.com/ByteZip-dev/Byte-Check/releases">Releases</a>
  &nbsp;·&nbsp; <a href="https://github.com/ByteZip-dev/Byte-Check/issues">Issues</a>
</p>