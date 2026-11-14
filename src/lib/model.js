// Vulnerability record model: validation, enrichment (CVSS + risk + SLA) and defaults.

import { scoreVector, parseVector, buildVector, severityRating } from './cvss/score.js';
import { SEVERITY_SLA_DAYS, computeRisk, computeSla, priorityBand, ASSET_IMPORTANCE_LEVELS } from './priority.js';

export const SCHEMA_VERSION = 1;

export const STATUS_VALUES = ['open', 'in_progress', 'resolved', 'risk_accepted', 'false_positive'];

export const SAMPLE_ASSETS = ASSET_IMPORTANCE_LEVELS.map((l) => `${l.label}(${l.value})`);

let idCounter = 0;

function newId() {
  idCounter += 1;
  const rand = Math.random().toString(36).slice(2, 8);
  return `v_${Date.now().toString(36)}_${idCounter}_${rand}`;
}

export function emptyVuln(overrides = {}) {
  return {
    id: newId(),
    title: '',
    cve: '',
    vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    epss: null,
    assetImportance: 3,
    assetName: '',
    discoveredAt: new Date().toISOString().slice(0, 10),
    status: 'open',
    notes: '',
    owner: '',
    source: 'manual',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  };
}

const clampNumber = (value, min, max, fallback) => {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
};

/**
 * Validate a raw vulnerability record (before scoring).
 * @returns {{ok:boolean, errors:Array<{field:string,message:string}>, value?:object}}
 */
export function validateVuln(raw) {
  const errors = [];
  if (!raw || typeof raw !== 'object') {
    return { ok: false, errors: [{ field: '_', message: '记录必须是对象。' }] };
  }

  const vector = String(raw.vector ?? '').trim();
  if (!vector) errors.push({ field: 'vector', message: '缺少 CVSS 向量。' });
  else {
    const parsed = parseVector(vector);
    if (!parsed.ok) {
      for (const e of parsed.errors) {
        errors.push({ field: 'vector', message: e.message, detail: e });
      }
    }
  }

  let epss = raw.epss;
  if (epss === '' || epss === undefined) epss = null;
  else if (epss === null) epss = null;
  else {
    const n = Number(epss);
    if (!Number.isFinite(n) || n < 0 || n > 1) {
      errors.push({ field: 'epss', message: `EPSS 必须在 0 到 1 之间（当前为 "${raw.epss}"）。` });
    } else epss = n;
  }

  const assetImportance = Number(raw.assetImportance ?? 3);
  if (!Number.isInteger(assetImportance) || assetImportance < 1 || assetImportance > 5) {
    errors.push({ field: 'assetImportance', message: '资产重要性必须是 1-5 的整数。' });
  }

  const discoveredAt = String(raw.discoveredAt ?? '').trim();
  if (discoveredAt && !/^\d{4}-\d{2}-\d{2}/.test(discoveredAt)) {
    errors.push({ field: 'discoveredAt', message: '发现日期格式应为 YYYY-MM-DD。' });
  }

  const status = String(raw.status ?? 'open');
  if (!STATUS_VALUES.includes(status)) {
    errors.push({ field: 'status', message: `未知状态 "${status}"。` });
  }

  if (errors.length) return { ok: false, errors };

  return {
    ok: true,
    value: {
      ...emptyVuln(),
      ...raw,
      id: raw.id || newId(),
      title: String(raw.title ?? '').trim(),
      cve: String(raw.cve ?? '').trim().toUpperCase(),
      vector,
      epss,
      assetImportance,
      assetName: String(raw.assetName ?? '').trim(),
      discoveredAt: discoveredAt ? discoveredAt.slice(0, 10) : new Date().toISOString().slice(0, 10),
      status,
      notes: String(raw.notes ?? ''),
      owner: String(raw.owner ?? '').trim(),
      source: String(raw.source ?? 'manual'),
    },
  };
}

/**
 * Annotate a stored vulnerability with its computed CVSS score, risk and SLA.
 * Pure function of the record plus policy, so the UI can recompute on every policy tweak.
 */
export function enrich(vuln, { now = new Date(), weights, slaDays = SEVERITY_SLA_DAYS } = {}) {
  const scored = scoreVector(vuln.vector);
  const cvss = scored.ok
    ? {
        ok: true,
        score: scored.score,
        severity: scored.severity,
        base: scored.base,
        threat: scored.threat,
        environmental: scored.environmental,
        macroVector: scored.macroVector,
        nomenclature: scored.nomenclature,
        canonical: scored.canonical,
        metrics: scored.metrics,
        supplied: scored.supplied,
        warnings: scored.warnings ?? [],
      }
    : { ok: false, score: null, severity: 'None', errors: scored.errors };

  const risk = computeRisk({
    cvssScore: cvss.ok ? cvss.score : 0,
    epss: vuln.epss,
    assetImportance: vuln.assetImportance,
    weights,
  });

  const sla = computeSla({
    severity: cvss.ok ? cvss.severity : 'None',
    discoveredAt: vuln.discoveredAt,
    status: vuln.status,
    slaDays,
    now,
  });

  return {
    ...vuln,
    cvss,
    risk,
    sla,
    priority: priorityBand(risk.score),
  };
}

export function enrichAll(list, options) {
  return list.map((v) => enrich(v, options));
}

/** Summarise a list for the dashboard. */
export function summarise(list, { now = new Date() } = {}) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, None: 0 };
  let overdue = 0;
  let open = 0;
  let dueSoon = 0;
  let riskSum = 0;
  let epssKnown = 0;
  for (const v of list) {
    if (!v.cvss.ok) continue;
    counts[v.cvss.severity] += 1;
    riskSum += v.risk.score;
    if (v.epss !== null && v.epss !== undefined) epssKnown += 1;
    if (v.status === 'open' || v.status === 'in_progress') {
      open += 1;
      if (v.sla.overdue) overdue += 1;
      else if (v.sla.dueSoon) dueSoon += 1;
    }
  }
  return {
    total: list.length,
    counts,
    open,
    overdue,
    dueSoon,
    epssKnown,
    averageRisk: list.length ? Math.round((riskSum / list.length) * 10) / 10 : 0,
  };
}

export { severityRating, buildVector };
