// Local persistence. Everything stays in the browser: this is a triage desk, not a
// system of record. Writes are wrapped so a full/disabled store degrades to a
// session-only desk instead of breaking the UI.

import { coalescePolicy, DEFAULT_POLICY } from './policy.js';

const KEY = 'vuln-priority-desk/v1';

function safeStorage() {
  try {
    const probe = '__vpd_probe__';
    localStorage.setItem(probe, '1');
    localStorage.removeItem(probe);
    return localStorage;
  } catch {
    return null;
  }
}

export function loadState() {
  const store = safeStorage();
  if (!store) return { vulns: null, policy: coalescePolicy(null), persisted: false };
  try {
    const raw = store.getItem(KEY);
    if (!raw) return { vulns: null, policy: coalescePolicy(null), persisted: true };
    const parsed = JSON.parse(raw);
    return {
      vulns: Array.isArray(parsed.vulns) ? parsed.vulns : null,
      policy: coalescePolicy(parsed.policy ?? DEFAULT_POLICY),
      persisted: true,
    };
  } catch {
    return { vulns: null, policy: coalescePolicy(null), persisted: true, error: '本地存储数据损坏，已忽略。' };
  }
}

export function saveState({ vulns, policy }) {
  const store = safeStorage();
  if (!store) return { ok: false, reason: '浏览器禁用了本地存储，本次更改仅保留在当前页面。' };
  try {
    store.setItem(KEY, JSON.stringify({ vulns, policy, savedAt: new Date().toISOString() }));
    return { ok: true };
  } catch (err) {
    return { ok: false, reason: `保存失败：${err.message}` };
  }
}

export function clearState() {
  const store = safeStorage();
  if (store) store.removeItem(KEY);
}

export function download(filename, text, mime = 'application/json') {
  const blob = new Blob([text], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function timestampedName(base, ext) {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  const stamp = `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}`;
  return `${base}-${stamp}.${ext}`;
}
