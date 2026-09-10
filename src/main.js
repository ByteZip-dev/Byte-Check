import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

const rows = {
  process: { name: "Process integrity", fixable: false },
  overlay: { name: "Overlay & injection sweep", fixable: true },
  clock: { name: "System clock sync", fixable: true },
  screen: { name: "Screen access permission", fixable: true },
  ocean: { name: "Ocean domain access", fixable: true },
  av: { name: "Antivirus mode", fixable: true },
  trace: { name: "Tamper log trace", fixable: false },
};

const checklistEl = document.getElementById("checklist");
const resultEl = document.getElementById("result");
const resultLabel = document.getElementById("resultLabel");
const resultDetail = document.getElementById("resultDetail");
const runBtn = document.getElementById("runBtn");
const secondaryBtn = document.getElementById("secondaryBtn");
const restoreAvWrap = document.getElementById("restoreAvWrap");
const restoreAvBtn = document.getElementById("restoreAvBtn");

function setRowState(key, state, stateText) {
  const row = checklistEl.querySelector(`[data-key="${key}"]`);
  if (!row) return;
  row.className = "check-row state-" + state;
  row.querySelector(".state").textContent = stateText;
  const iconEl = row.querySelector(".icon");
  if (state === "running") {
    iconEl.innerHTML = '<div class="spinner"></div>';
  } else if (state === "pass") {
    iconEl.textContent = "✓";
  } else if (state === "fixed") {
    iconEl.textContent = "↻";
  } else if (state === "fail") {
    iconEl.textContent = "✕";
  } else if (state === "warning") {
    iconEl.textContent = "!";
  } else {
    iconEl.textContent = "●";
  }
}

function resetChecklist() {
  Object.keys(rows).forEach((key) => setRowState(key, "pending", "Queued"));
  resultEl.className = "result";
  secondaryBtn.style.display = "none";
  restoreAvWrap.style.display = "none";
  runBtn.style.display = "block";
  runBtn.textContent = "Run check";
}

function showResult(type, label, detail) {
  resultLabel.textContent = label;
  resultDetail.textContent = detail;
  resultEl.className = "result show " + type;
}

function setBusy(busy, text) {
  runBtn.disabled = busy;
  runBtn.textContent = text;
}

async function runRealCheck() {
  resetChecklist();
  setBusy(true, "Checking…");

  let summary;
  try {
    summary = await invoke("run_checks");
  } catch (e) {
    showResult("bad", "Error", String(e));
    setBusy(false, "Run check again");
    return;
  }

  if (summary.outcome === "eligible") {
    showResult("ok", "Eligible", summary.detail);
    runBtn.style.display = "none";
    secondaryBtn.className = "btn-primary";
    secondaryBtn.style.display = "block";
    secondaryBtn.textContent = "Start scan";
  } else if (summary.outcome === "fixable") {
    showResult("warn", "Eligible after auto-fix", summary.detail);
    runBtn.style.display = "none";
    secondaryBtn.className = "btn-primary";
    secondaryBtn.style.display = "block";
    secondaryBtn.textContent = "Start scan";
    if (summary.fixed.includes("av")) {
      restoreAvWrap.style.display = "flex";
    }
  } else {
    showResult("bad", "Ineligible", summary.detail);
    secondaryBtn.style.display = "none";
    runBtn.style.display = "block";
    runBtn.textContent = "Run check again";
  }

  setBusy(false, "Run check again");
}

// Wire up Tauri events.
listen("check-update", (e) => {
  const ev = e.payload;
  setRowState(ev.key, ev.status, ev.status === "running" ? "Checking" : humanState(ev.status));
});

function humanState(status) {
  switch (status) {
    case "pass": return "Clear";
    case "fixed": return "Auto-fixed";
    case "fail": return "Flagged";
    case "warning": return "Review";
    default: return "Queued";
  }
}

runBtn.addEventListener("click", runRealCheck);
secondaryBtn.addEventListener("click", async () => {
  await invoke("start_scan");
});
restoreAvBtn.addEventListener("click", async () => {
  const r = await invoke("restore_av");
  restoreAvWrap.style.display = "none";
  setRowState("av", "pass", "Restored");
  alert(r.message);
});