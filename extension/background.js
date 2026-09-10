// Maps tab groups titled "focus..." / "distract..." to renderer PIDs and sends
// them to focusd through the native host. chrome.processes (dev channel only)
// gives tab -> PID; without it, distract tabs are slowed in-browser via the
// DevTools protocol's CPU throttling instead.

const HOST = "dev.focussched.host";
const FOCUS_RE = /^\s*(focus|🎯)/i;
const DISTRACT_RE = /^\s*(distract|🚫)/i;
const THROTTLE_RATE = 6; // fallback: run distract tabs N times slower

let port = null;
let timer = null;
const throttled = new Set(); // tab ids we attached the debugger to
const dismissed = new Set(); // tab ids where the user cancelled the debugger bar

function connect() {
  port = chrome.runtime.connectNative(HOST);
  port.onMessage.addListener((msg) => {
    if (!msg.ok) console.warn("focusd:", msg.error ?? msg);
  });
  port.onDisconnect.addListener(() => {
    console.warn("native host disconnected:", chrome.runtime.lastError?.message);
    port = null;
    setTimeout(connect, 5000);
  });
  schedule();
}

function hasProcesses() {
  return typeof chrome.processes?.getProcessIdForTab === "function";
}

function osPidForTab(tabId) {
  return new Promise((resolve) => {
    chrome.processes.getProcessIdForTab(tabId, (procId) => {
      if (chrome.runtime.lastError || procId === undefined) return resolve(null);
      chrome.processes.getProcessInfo(procId, false, (info) => {
        resolve(chrome.runtime.lastError ? null : info?.[procId]?.osProcessId ?? null);
      });
    });
  });
}

async function tabsByRole() {
  const roles = new Map();
  for (const g of await chrome.tabGroups.query({})) {
    if (FOCUS_RE.test(g.title ?? "")) roles.set(g.id, "focus");
    else if (DISTRACT_RE.test(g.title ?? "")) roles.set(g.id, "distract");
  }
  const out = { focus: [], distract: [] };
  for (const tab of await chrome.tabs.query({})) {
    const role = roles.get(tab.groupId);
    if (role) out[role].push(tab);
  }
  return out;
}

async function setThrottle(tab, on) {
  const target = { tabId: tab.id };
  if (on) {
    if (throttled.has(tab.id) || dismissed.has(tab.id) || !/^https?:/.test(tab.url ?? "")) return;
    try {
      await chrome.debugger.attach(target, "1.3");
      await chrome.debugger.sendCommand(target, "Emulation.setCPUThrottlingRate", { rate: THROTTLE_RATE });
      throttled.add(tab.id);
    } catch (e) {
      console.warn("throttle failed for tab", tab.id, e.message);
    }
  } else if (throttled.delete(tab.id)) {
    try {
      await chrome.debugger.detach(target);
    } catch {}
  }
}

async function sync() {
  const { focus, distract } = await tabsByRole();

  if (hasProcesses()) {
    const focusPids = new Set((await Promise.all(focus.map((t) => osPidForTab(t.id)))).filter(Boolean));
    // renderers can be shared between tabs; shared ones count as focus
    const distractPids = (await Promise.all(distract.map((t) => osPidForTab(t.id))))
      .filter((p) => p && !focusPids.has(p));
    port?.postMessage({ focus_pids: [...focusPids], distract_pids: distractPids });
    return;
  }

  // fallback: no PIDs, throttle inside the browser
  const distractIds = new Set(distract.map((t) => t.id));
  for (const id of [...throttled]) {
    if (!distractIds.has(id)) await setThrottle({ id }, false);
  }
  for (const tab of distract) await setThrottle(tab, true);
  port?.postMessage({ focus_pids: [], distract_pids: [] });
}

function schedule() {
  clearTimeout(timer);
  timer = setTimeout(() => sync().catch((e) => console.error(e)), 300);
}

chrome.tabs.onUpdated.addListener((_id, change) => {
  if ("groupId" in change || "url" in change) schedule();
});
chrome.tabs.onCreated.addListener(schedule);
chrome.tabs.onRemoved.addListener((id) => {
  throttled.delete(id);
  dismissed.delete(id);
  schedule();
});
chrome.tabs.onReplaced.addListener(schedule);
chrome.tabGroups.onCreated.addListener(schedule);
chrome.tabGroups.onUpdated.addListener(schedule);
chrome.tabGroups.onRemoved.addListener(schedule);
chrome.debugger.onDetach.addListener(({ tabId }, reason) => {
  throttled.delete(tabId);
  if (reason === "canceled_by_user") dismissed.add(tabId);
});

connect();
