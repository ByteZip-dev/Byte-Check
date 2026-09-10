# Byte Check

Pre-scan verification for **Ocean Anticheat** (`anticheat.ac`). A small,
always-on-top, frameless overlay window that runs **before** an Ocean scan to
confirm the system can produce an accurate result — detecting bypass methods and
broken scan prerequisites, auto-fixing what's safely fixable, and reporting
**Eligible / Eligible after auto-fix / Ineligible**.

Built with **Rust + Tauri v2**. Cross-platform: **Windows** and **Linux**.

## What it checks

| Check | Fixable? | Detection summary |
|---|---|---|
| Process integrity | No | Cheat loaders, ghost clients, autoclickers, injectors, debuggers, anti-SS tools; attached debugger (`TracerPid`) |
| Overlay & injection sweep | Yes | Injected modules / `memfd` trampolines in the JVM, `LD_PRELOAD`/`LD_AUDIT` hijacks, `AppInit_DLLs`, IFEO `Debugger` keys, overlay/streamproof processes → neutralized + re-verified |
| System clock sync | Yes | Skew vs NTP (time.google / pool.ntp / cloudflare) → `w32tm /resync` / `timedatectl` |
| Screen access permission | Yes | Wayland XDG portal, X11 session, DWM/Explorer on Windows |
| Ocean domain access | Yes | Hosts-file block of `anticheat.ac` / `api.anticheat.ac` (removed); DNS-resolution failure reported as a warning |
| Antivirus mode | Yes* | **Windows only** — Ocean recommends disabling AV for an accurate scan. Byte Check pauses Windows Defender realtime protection and offers to re-enable it afterwards. Third-party AV → warning with instructions |
| Tamper log trace | No | Cleared prefetch, deleted USN journal, cleared event logs, `EnablePrefetcher=0`, execution-laundering history |

Non-fixable checks (process, trace) mean **Ineligible** — the scan environment is
already compromised and cannot be made accurate. Fixable checks are auto-fixed
and then **re-verified**; only a passing re-check grants eligibility.

## Outcomes

- **Eligible** → a single full-width **Start scan** button.
- **Eligible after auto-fix** → same button, plus a "Re-enable antivirus after
  scan" button when Windows Defender was paused.
- **Ineligible** → result banner + **Run check again** (no "contact staff" flow —
  staff handle escalation through their normal channels).

## Antivirus behavior (Windows)

Ocean recommends disabling antivirus for an accurate scan (AV blocks Ocean and
blinds its AV-correlation module). Byte Check:

1. Detects running antivirus (`MsMpEng.exe` = Defender, plus common third-party AV).
2. If **Windows Defender** realtime protection is on → auto-pauses it
   (`Set-MpPreference -DisableRealtimeMonitoring $true`).
3. Shows a **"Re-enable antivirus after scan"** button so protection is restored
   when the scan is done.
4. Third-party AV can't be automated safely → reported as a warning with manual instructions.

## Elevation

- **Windows:** the app requests UAC elevation on launch (`requireAdministrator`
  manifest embedded by `build.rs`).
- **Linux:** the GUI runs as the user (root GUIs are unreliable on
  Wayland/X11); privileged *fix* actions (process kill, clock resync,
  `/etc/ld.so.preload`, hosts file) elevate per-operation via `pkexec`.
- To test locally without a release build, note the debug binary expects the
  Vite dev server (`npm run tauri dev`); the **release** binary embeds the UI.

## Releases

Pre-built artifacts are produced by the GitHub Actions workflow
([`.github/workflows/release.yml`](.github/workflows/release.yml)) on native
runners whenever a tag like `v0.1.0` is pushed:

- **Windows:** `.msi` / `.exe` installers (single-file, UAC-elevated)
- **Linux:** AppImage (single-file, executable), `.deb`, `.rpm`

Artifacts are attached to a **draft release** for the tag. To build and upload
without a tag, trigger the workflow manually (`workflow_dispatch`).

> Windows binaries are built and signed-off by CI on `windows-latest` — the
> Windows-specific code (registry, Defender, event logs, hosts file) is compiled
> and exercised there.

## Building locally

Prerequisites:

- Rust (stable)
- Node.js + npm
- Linux: `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libsoup-3.0-dev`,
  `javascriptcoregtk-4.1-dev` (build deps)

```bash
npm install
npm run tauri dev      # development (Vite dev server + app)
npm run tauri build    # release bundles
```

Artifacts land in `src-tauri/target/release/bundle/`.

## Testing the checks without the GUI

```bash
cd src-tauri
cargo test --test engine_smoke -- --nocapture
```

## Debug audit log

Each scan appends its per-check results to a temporary audit file so a scan can
be verified after the fact:

```
Linux:  /tmp/byte-check-debug.log
Windows: %TEMP%\byte-check-debug.log
```

## Layout

```
src-tauri/
  src/
    lib.rs            Tauri wiring, elevation, commands
    checks/mod.rs     check runner (sequential, fix → re-verify, outcome)
    checks/*.rs       the seven checks
    signatures.rs     cheat/bypass signature lists
    build.rs          UAC manifest embedding (Windows)
  tests/engine_smoke.rs
  capabilities/       Tauri v2 permissions
src/                  frontend (adapted from the Byte Check mockup)
.github/workflows/    CI: build + release on Windows & Linux
```

## Known limitations

- **Local-only trust.** Results are displayed to the user; a determined cheater
  could tamper with any client-side tool. Server-side attestation (via the
  anticheat.ac Enterprise API) is the hardening path.
- **Signature lists** are conservative to limit false positives and need tuning
  against real Ocean behavior.
- Checks are heuristic (they mirror Ocean's documented detection systems) —
  they are a pre-scan gate, not a substitute for the Ocean scan itself.