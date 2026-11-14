// Prioritisation and SLA policy.
//
// The fix order is a transparent weighted composite of three independently
// verifiable signals, all normalised to 0..1:
//
//   severity  — the CVSS v4.0 score for the vector as supplied (0..10 -> 0..1);
//               environmental metrics and threat metrics are already folded in,
//               so asset-specific modifications and exploit maturity count here.
//   epss      — FIRST EPSS probability that exploitation is observed in the wild
//               within 30 days (0..1).
//   asset     — business criticality of the affected asset (1..5 -> 0..1).
//
// riskScore = 100 * (wSeverity*severity + wEpss*epss + wAsset*asset) / sum(weights)
//
// When EPSS is unknown the EPSS term is dropped and the remaining weights are
// renormalised, so a missing feed cannot silently deflate a vulnerability's rank.

export const DEFAULT_RISK_WEIGHTS = { severity: 0.5, epss: 0.3, asset: 0.2 };

export const ASSET_IMPORTANCE_LEVELS = [
  { value: 1, label: '低', hint: '内部测试、可随时重建' },
  { value: 2, label: '一般', hint: '非关键内部系统' },
  { value: 3, label: '重要', hint: '承载常规业务' },
  { value: 4, label: '关键', hint: '承载核心业务，有合规要求' },
  { value: 5, label: '核心', hint: '停机即重大事故，如支付、身份认证' },
];

export const SEVERITY_SLA_DAYS = {
  Critical: 7,
  High: 14,
  Medium: 30,
  Low: 90,
  None: 180,
};

export const STATUSES = [
  { value: 'open', label: '待修复' },
  { value: 'in_progress', label: '修复中' },
  { value: 'resolved', label: '已修复' },
  { value: 'risk_accepted', label: '风险接受' },
  { value: 'false_positive', label: '误报' },
];

export const TERMINAL_STATUSES = ['resolved', 'risk_accepted', 'false_positive'];

export const PRIORITY_BANDS = [
  { id: 'P1', min: 80, label: 'P1 立即', tone: 'critical' },
  { id: 'P2', min: 60, label: 'P2 尽快', tone: 'high' },
  { id: 'P3', min: 40, label: 'P3 计划', tone: 'medium' },
  { id: 'P4', min: 0, label: 'P4 观察', tone: 'low' },
];

const clamp01 = (n) => Math.max(0, Math.min(1, n));

export function assetFactor(importance) {
  const value = Number(importance);
  if (!Number.isFinite(value)) return 0.5;
  return clamp01((Math.min(5, Math.max(1, value)) - 1) / 4);
}

export function normaliseWeights(weights = {}) {
  const merged = { ...DEFAULT_RISK_WEIGHTS, ...weights };
  const sum = merged.severity + merged.epss + merged.asset;
  if (!(sum > 0)) return { ...DEFAULT_RISK_WEIGHTS };
  return {
    severity: merged.severity / sum,
    epss: merged.epss / sum,
    asset: merged.asset / sum,
  };
}

/**
 * @param {object} input
 * @param {number} input.cvssScore      0..10, effective score for the chosen vector
 * @param {number|null} input.epss      0..1 or null when unknown
 * @param {number} input.assetImportance 1..5
 * @param {object} [input.weights]
 * @returns {{score:number, breakdown:object, weights:object}}
 */
export function computeRisk({ cvssScore, epss, assetImportance, weights }) {
  const w = normaliseWeights(weights);
  const severity01 = clamp01(Number(cvssScore) / 10);
  const asset01 = assetFactor(assetImportance);
  const hasEpss = epss !== null && epss !== undefined && Number.isFinite(Number(epss));
  const epss01 = hasEpss ? clamp01(Number(epss)) : null;

  let denom = w.severity + w.asset;
  let numerator = w.severity * severity01 + w.asset * asset01;
  if (hasEpss) {
    denom += w.epss;
    numerator += w.epss * epss01;
  }

  const raw = denom > 0 ? numerator / denom : 0;
  const score = Math.round(raw * 1000) / 10; // 0..100, one decimal

  const contributions = {
    severity: Math.round(((w.severity * severity01) / (denom || 1)) * 1000) / 10,
    epss: hasEpss ? Math.round(((w.epss * epss01) / (denom || 1)) * 1000) / 10 : null,
    asset: Math.round(((w.asset * asset01) / (denom || 1)) * 1000) / 10,
  };

  return {
    score,
    weights: w,
    epssKnown: hasEpss,
    contributions,
    inputs: { severity01, epss01, asset01 },
  };
}

export function priorityBand(score, bands = PRIORITY_BANDS) {
  return bands.find((b) => score >= b.min) ?? bands[bands.length - 1];
}

/** Parse a date-only or ISO string into a UTC-midnight Date (avoids TZ off-by-one). */
export function parseDateOnly(value) {
  if (!value) return null;
  const text = String(value).slice(0, 10);
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (!m) {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
  }
  return new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
}

export function todayUTC(now = new Date()) {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
}

export function addDays(date, days) {
  const d = new Date(date.getTime());
  d.setUTCDate(d.getUTCDate() + Number(days));
  return d;
}

export function formatDate(date) {
  if (!date) return '';
  return date.toISOString().slice(0, 10);
}

/**
 * SLA deadline and overdue state for one vulnerability.
 *
 * @param {object} input
 * @param {string} input.severity              Critical|High|Medium|Low|None
 * @param {string} input.discoveredAt          YYYY-MM-DD (or ISO)
 * @param {string} [input.status]              open|in_progress|resolved|...
 * @param {object} [input.slaDays]             severity -> days
 * @param {Date}   [input.now]                 injectable clock for tests
 */
export function computeSla({ severity, discoveredAt, status = 'open', slaDays = SEVERITY_SLA_DAYS, now = new Date() }) {
  const days = Number(slaDays[severity] ?? slaDays.Medium ?? 30);
  const start = parseDateOnly(discoveredAt);
  if (!start) {
    return { days, dueDate: null, dueDateText: '', overdue: false, daysRemaining: null, state: 'unknown' };
  }
  const due = addDays(start, days);
  const today = todayUTC(now);
  const msPerDay = 86400000;
  const daysRemaining = Math.round((due.getTime() - today.getTime()) / msPerDay);
  const terminal = TERMINAL_STATUSES.includes(status);
  const overdue = !terminal && daysRemaining < 0;
  const dueSoon = !terminal && !overdue && daysRemaining <= 3;

  let state = 'ok';
  if (terminal) state = 'closed';
  else if (overdue) state = 'overdue';
  else if (dueSoon) state = 'due_soon';

  return {
    days,
    dueDate: due,
    dueDateText: formatDate(due),
    overdue,
    dueSoon,
    daysRemaining,
    state,
  };
}

/**
 * Sort a list of enriched vulnerabilities for the triage queue.
 *
 * sort: 'priority' | 'due' | 'cvss' | 'epss' | 'discovered'
 * Overdue-but-open items are not silently promoted — ordering stays explainable —
 * but `overdue` is surfaced in the table and filters.
 */
export function sortVulns(list, sort = 'priority') {
  const copy = [...list];
  const tieBreak = (a, b) => {
    if (b.risk.score !== a.risk.score) return b.risk.score - a.risk.score;
    if (b.cvss.score !== a.cvss.score) return b.cvss.score - a.cvss.score;
    return String(a.dueDateText ?? '').localeCompare(String(b.dueDateText ?? ''));
  };
  switch (sort) {
    case 'due':
      return copy.sort((a, b) => {
        const aDue = a.sla.dueDate ? a.sla.dueDate.getTime() : Infinity;
        const bDue = b.sla.dueDate ? b.sla.dueDate.getTime() : Infinity;
        if (aDue !== bDue) return aDue - bDue;
        return tieBreak(a, b);
      });
    case 'cvss':
      return copy.sort((a, b) => b.cvss.score - a.cvss.score || tieBreak(a, b));
    case 'epss':
      return copy.sort((a, b) => (b.epss ?? -1) - (a.epss ?? -1) || tieBreak(a, b));
    case 'discovered':
      return copy.sort((a, b) => String(b.discoveredAt).localeCompare(String(a.discoveredAt)) || tieBreak(a, b));
    case 'priority':
    default:
      return copy.sort(tieBreak);
  }
}
