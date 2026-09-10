<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&family=JetBrains+Mono:wght@400;700&display=swap');

:root {
  --accent: #5b8def;
  --ok: #4ade80;
  --warn: #fbbf24;
  --bad: #f87171;
  --text: #e7e9ec;
  --dim: #8b93a1;
  --panel: #16181f;
  --border: #2a2e37;
}

/* ---------- hero ---------- */
.hero { text-align: center; padding: 40px 0 8px; }

.gradient-title {
  font-family: 'Inter', sans-serif;
  font-weight: 800;
  font-size: 52px;
  letter-spacing: -1px;
  background: linear-gradient(90deg, #5b8def, #4ade80, #fbbf24, #f87171, #5b8def);
  background-size: 300% 100%;
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  animation: gradient-slide 6s linear infinite;
}
@keyframes gradient-slide { 0% { background-position: 0% 50%; } 100% { background-position: 300% 50%; } }

.typewriter {
  font-family: 'JetBrains Mono', monospace;
  font-size: 15px;
  color: var(--dim);
  display: inline-block;
  overflow: hidden;
  white-space: nowrap;
  border-right: 2px solid var(--accent);
  width: 0;
  animation: typing 3.5s steps(46) forwards, blink 0.8s step-end infinite;
}
@keyframes typing { to { width: 46ch; } }
@keyframes blink { 50% { border-color: transparent; } }

.logo {
  width: 110px; height: 110px;
  animation: pulse 2.4s ease-in-out infinite;
}
@keyframes pulse {
  0%, 100% { filter: drop-shadow(0 0 6px rgba(91,141,239,0.35)); }
  50% { filter: drop-shadow(0 0 22px rgba(91,141,239,0.85)); }
}

.badges { margin: 22px 0 6px; }
.badges img { margin: 2px 3px; transition: transform .2s ease; }
.badges img:hover { transform: translateY(-3px) scale(1.06); }

/* ---------- feature cards ---------- */
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
  gap: 14px;
  margin: 20px 0;
}
.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 18px 18px 16px;
  transition: transform .25s ease, border-color .25s ease, box-shadow .25s ease;
}
.card:hover {
  transform: translateY(-4px);
  border-color: var(--accent);
  box-shadow: 0 10px 30px -8px rgba(91,141,239,0.35);
}
.card .ico { font-size: 22px; }
.card .t { font-family: 'Inter', sans-serif; font-weight: 700; font-size: 15px; margin: 8px 0 4px; color: var(--text); }
.card .d { font-size: 13px; color: var(--dim); line-height: 1.55; }

/* ---------- outcome pills ---------- */
.pills { display: flex; flex-wrap: wrap; gap: 10px; justify-content: center; margin: 14px 0 4px; }
.pill {
  font-family: 'JetBrains Mono', monospace;
  font-size: 12.5px;
  padding: 8px 16px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--panel);
  color: var(--text);
  transition: transform .2s ease;
}
.pill:hover { transform: scale(1.05); }
.pill.ok { border-color: #2e5a3f; background: #10241a; }
.pill.ok::before { content: "✓  "; color: var(--ok); font-weight: 700; }
.pill.fix { border-color: #5a4a26; background: #241b10; }
.pill.fix::before { content: "↻  "; color: var(--warn); font-weight: 700; }
.pill.bad { border-color: #5a2e2e; background: #241414; }
.pill.bad::before { content: "✕  "; color: var(--bad); font-weight: 700; }

/* ---------- terminal ---------- */
.term {
  background: #0d1117;
  border: 1px solid var(--border);
  border-radius: 12px;
  overflow: hidden;
  font-family: 'JetBrains Mono', monospace;
  font-size: 12.5px;
  margin: 18px 0;
}
.term .bar {
  display: flex; gap: 6px; align-items: center;
  padding: 8px 12px;
  background: #161b22;
  border-bottom: 1px solid var(--border);
}
.term .bar i { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
.term .bar .r { background: #f87171; } .term .bar .y { background: #fbbf24; } .term .bar .g { background: #4ade80; }
.term pre { margin: 0; padding: 14px 16px; color: var(--dim); line-height: 1.7; white-space: pre-wrap; }
.term .ok  { color: var(--ok); }
.term .warn { color: var(--warn); }
.term .bad { color: var(--bad); }
.term .dim { color: #484f58; }

/* ---------- footer ---------- */
.foot {
  margin-top: 40px;
  text-align: center;
  font-size: 12px;
  color: var(--dim);
  border-top: 1px solid var(--border);
  padding-top: 16px;
}
.foot a { color: var(--accent); text-decoration: none; }
</style>

<div class="hero">

<svg class="logo" viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect x="8" y="8" width="496" height="496" rx="96" fill="#16181f" stroke="#2a2e37" stroke-width="8"/>
  <polygon points="96,360 256,96 416,360 316,360 256,236 196,360" fill="#5b8def">
    <animate attributeName="opacity" values="0.75;1;0.75" dur="2.4s" repeatCount="indefinite"/>
  </polygon>
</svg>

<div class="gradient-title">Byte Check</div>

<p><span class="typewriter">pre-scan verification for Ocean Anticheat</span></p>

<div class="badges">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-5b8def?style=for-the-badge&logo=windowsterminal&logoColor=white">
  <img alt="Stack" src="https://img.shields.io/badge/Rust%20%2B%20Tauri-v2-4ade80?style=for-the-badge&logo=rust&logoColor=white">
  <img alt="Version" src="https://img.shields.io/github/v/release/ByteZip-dev/Byte-Check?style=for-the-badge&color=fbbf24">
  <img alt="For" src="https://img.shields.io/badge/for-Ocean%20Anticheat-8b93a1?style=for-the-badge&logo=shield&logoColor=white">
</div>

</div>

---

## ✨ What is Byte Check?

**Byte Check** is the gatekeeper that runs *before* an Ocean Anticheat scan. It inspects the
system for anything that would make the scan **inaccurate** — bypass methods, broken scan
prerequisites, tampering — **auto-fixes what's safely fixable**, and only then tells you if
you're ready to scan.

A small, frameless, always-on-top overlay. No install required.

<div class="cards">

<div class="card">
  <div class="ico">🔍</div>
  <div class="t">Detects</div>
  <div class="d">Cheat loaders, injected modules, loader hijacks, clock tampering, blocked screen capture, domain blocks, anti-forensics.</div>
</div>

<div class="card">
  <div class="ico">🛠️</div>
  <div class="t">Auto-fixes</div>
  <div class="d">Kills overlay/injector processes, clears <code>LD_PRELOAD</code>/<code>AppInit_DLLs</code> hijacks, resyncs the clock, restores the screencast portal, removes hosts blocks, pauses AV per Ocean's guidance.</div>
</div>

<div class="card">
  <div class="ico">🔄</div>
  <div class="t">Re-verifies</div>
  <div class="d">Every fix is followed by a fresh re-check. Only a passing re-check grants eligibility — no blind fixes.</div>
</div>

<div class="card">
  <div class="ico">⚖️</div>
  <div class="t">Fair</div>
  <div class="d">Never deletes evidence, never hides history. Non-fixable tampering means <b>Ineligible</b> — full stop.</div>
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

<div class="pills">
  <span class="pill ok">Eligible</span>
  <span class="pill fix">Eligible after auto-fix</span>
  <span class="pill bad">Ineligible</span>
</div>

<div class="term">
  <div class="bar"><i class="r"></i><i class="y"></i><i class="g"></i>&nbsp; byte-check — live demo</div>
<pre>
<span class="dim">$</span> <span style="color:var(--text)">Byte Check</span> — pre-scan

<span class="ok">✓</span> Process integrity            <span class="dim">no suspicious processes</span>
<span class="ok">✓</span> Overlay &amp; injection sweep    <span class="dim">no injected modules</span>
<span class="ok">✓</span> System clock sync            <span class="dim">within 60s of network time</span>
<span class="warn">↻</span> Screen access permission     <span class="dim">portal restarted → re-checked → clear</span>
<span class="ok">✓</span> Ocean domain access          <span class="dim">anticheat.ac reachable</span>
<span class="ok">✓</span> Antivirus mode               <span class="dim">ready for scan</span>
<span class="ok">✓</span> Tamper log trace            <span class="dim">clean</span>

<span style="color:var(--ok);font-weight:700">OUTCOME: ELIGIBLE — you can start your scan.</span>
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

<a href="https://github.com/ByteZip-dev/Byte-Check/releases/latest">
  <img alt="Download" src="https://img.shields.io/badge/⬇ DOWNLOAD%20LATEST%20RELEASE-5b8def?style=for-the-badge">
</a>

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

<div class="foot">
  Built with 🦀 Rust + Tauri · for <a href="https://anticheat.ac">Ocean Anticheat</a> ·
  <a href="https://github.com/ByteZip-dev/Byte-Check/releases">Releases</a> ·
  <a href="https://github.com/ByteZip-dev/Byte-Check/issues">Issues</a>
</div>