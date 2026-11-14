// Import / export.
//
// Supported formats:
//   * JSON  — native round-trip (schemaVersion, policy, vulnerabilities)
//   * CSV   — one row per vulnerability, RFC 4180 quoting, header-driven
//   * Vector text list — one "CVSS:4.0/..." per line, optionally with a trailing
//                         score, as found in FIRST/Red Hat reference test files
//
// Import is all-or-nothing per row: every row is validated and every problem is
// reported with the row number plus the offending metric, so a bad vector never
// gets silently dropped.

import { parseVector } from './cvss/parser.js';
import { scoreVector } from './cvss/score.js';
import { validateVuln, emptyVuln, SCHEMA_VERSION, STATUS_VALUES } from './model.js';
import { SEVERITY_SLA_DAYS } from './priority.js';

export const CSV_COLUMNS = [
  'id', 'title', 'cve', 'vector', 'epss', 'assetImportance', 'assetName',
  'discoveredAt', 'status', 'owner', 'notes', 'source',
];

export const CSV_HEADERS_ZH = {
  id: 'ID',
  title: '标题',
  cve: 'CVE',
  vector: 'CVSS向量',
  epss: 'EPSS',
  assetImportance: '资产重要性',
  assetName: '资产名称',
  discoveredAt: '发现日期',
  status: '状态',
  owner: '负责人',
  notes: '备注',
  source: '来源',
};

const HEADER_ALIASES = {
  'ID': 'id',
  '标题': 'title',
  'title': 'title',
  'CVE': 'cve',
  'cve': 'cve',
  'CVSS向量': 'vector',
  'vector': 'vector',
  '向量': 'vector',
  'EPSS': 'epss',
  'epss': 'epss',
  '资产重要性': 'assetImportance',
  'assetImportance': 'assetImportance',
  '资产名称': 'assetName',
  'assetName': 'assetName',
  '发现日期': 'discoveredAt',
  'discoveredAt': 'discoveredAt',
  '状态': 'status',
  'status': 'status',
  '负责人': 'owner',
  'owner': 'owner',
  '备注': 'notes',
  'notes': 'notes',
  '来源': 'source',
  'source': 'source',
};

function csvEscape(value) {
  const s = value === null || value === undefined ? '' : String(value);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** RFC 4180 compliant parse; tolerates a leading BOM and CRLF. */
export function parseCsv(text) {
  let src = text.replace(/^﻿/, '');
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;

  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (inQuotes) {
      if (c === '"') {
        if (src[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else field += c;
      continue;
    }
    if (c === '"') { inQuotes = true; continue; }
    if (c === ',') { row.push(field); field = ''; continue; }
    if (c === '\r') continue;
    if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; continue; }
    field += c;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  return rows;
}

export function exportCsv(vulns) {
  const lines = [CSV_COLUMNS.map((c) => csvEscape(CSV_HEADERS_ZH[c])).join(',')];
  for (const v of vulns) {
    lines.push(CSV_COLUMNS.map((c) => csvEscape(v[c])).join(','));
  }
  return lines.join('\n') + '\n';
}

export function exportJson(vulns, policy = {}) {
  return JSON.stringify(
    {
      schemaVersion: SCHEMA_VERSION,
      exportedAt: new Date().toISOString(),
      policy: {
        weights: policy.weights ?? { severity: 0.5, epss: 0.3, asset: 0.2 },
        slaDays: policy.slaDays ?? SEVERITY_SLA_DAYS,
      },
      vulnerabilities: vulns.map(({ id, title, cve, vector, epss, assetImportance, assetName, discoveredAt, status, owner, notes, source }) => ({
        id, title, cve, vector, epss, assetImportance, assetName, discoveredAt, status, owner, notes, source,
      })),
    },
    null,
    2,
  );
}

/**
 * Import JSON / CSV / plain vector list.
 *
 * @returns {{ok:true, records:object[], warnings:string[], detected:string}
 *          | {ok:false, errors:Array<{row:number, field:string, message:string}>}}
 */
export function importData(text, { format = 'auto', filename = '' } = {}) {
  if (typeof text !== 'string' || !text.trim()) {
    return { ok: false, errors: [{ row: 0, field: '_', message: '文件内容为空。' }] };
  }
  const kind = detectFormat(text, format, filename);
  if (kind === 'json') return importJson(text);
  if (kind === 'csv') return importCsv(text);
  if (kind === 'vectors') return importVectorList(text);
  return {
    ok: false,
    errors: [{ row: 0, field: '_', message: '无法识别文件格式，支持 JSON、CSV 或每行一条 CVSS 向量的文本。', }],
  };
}

function detectFormat(text, format, filename) {
  if (format && format !== 'auto') return format;
  if (/\.(json)$/i.test(filename)) return 'json';
  if (/\.(csv)$/i.test(filename)) return 'csv';
  const head = text.trimStart();
  if (head.startsWith('{') || head.startsWith('[')) return 'json';
  if (head.startsWith('CVSS:')) return 'vectors';
  if (head.includes(',') && head.split('\n')[0].includes(',')) return 'csv';
  return 'unknown';
}

function importJson(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    return { ok: false, errors: [{ row: 0, field: '_', message: `JSON 解析失败：${err.message}` }] };
  }
  let records;
  let policy = null;
  if (Array.isArray(parsed)) records = parsed;
  else if (parsed && Array.isArray(parsed.vulnerabilities)) {
    records = parsed.vulnerabilities;
    policy = parsed.policy ?? null;
  } else {
    return { ok: false, errors: [{ row: 0, field: '_', message: 'JSON 结构无效：应为记录数组，或含 vulnerabilities 数组的对象。' }] };
  }
  const out = [];
  const errors = [];
  records.forEach((raw, i) => {
    const validated = validateVuln(raw);
    if (!validated.ok) {
      for (const e of validated.errors) errors.push({ row: i + 2, field: e.field, message: e.message });
      return;
    }
    out.push(validated.value);
  });
  if (errors.length) return { ok: false, errors };
  return { ok: true, records: out, policy, warnings: [], detected: 'json' };
}

function importCsv(text) {
  const rows = parseCsv(text);
  if (rows.length < 2) {
    return { ok: false, errors: [{ row: 0, field: '_', message: 'CSV 至少需要表头和一行数据。' }] };
  }
  const header = rows[0].map((h) => h.trim());
  const map = header.map((h) => HEADER_ALIASES[h] ?? HEADER_ALIASES[h.toLowerCase()] ?? null);
  if (!map.includes('vector')) {
    return { ok: false, errors: [{ row: 1, field: 'vector', message: `表头缺少 CVSS 向量列（可用 "CVSS向量" 或 "vector"）。当前表头：${header.join('、')}` }] };
  }
  const out = [];
  const errors = [];
  for (let r = 1; r < rows.length; r++) {
    const cells = rows[r];
    if (!cells.some((c) => c.trim() !== '')) continue; // blank line
    const raw = {};
    for (let cIdx = 0; cIdx < map.length; cIdx++) {
      const key = map[cIdx];
      if (!key) continue;
      raw[key] = cells[cIdx] ?? '';
    }
    if (raw.epss === '') raw.epss = null;
    if (raw.assetImportance === '') raw.assetImportance = 3;
    if (raw.status === '') raw.status = 'open';

    const validated = validateVuln(raw);
    if (!validated.ok) {
      for (const e of validated.errors) errors.push({ row: r + 1, field: e.field, message: e.message, cve: raw.cve });
      continue;
    }
    out.push(validated.value);
  }
  if (errors.length) return { ok: false, errors };
  return { ok: true, records: out, policy: null, warnings: [], detected: 'csv' };
}

function importVectorList(text) {
  const out = [];
  const errors = [];
  const lines = text.split('\n');
  lines.forEach((line, i) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    let vector = trimmed;
    let expected = null;
    const sep = trimmed.indexOf(' - ');
    if (sep >= 0) {
      vector = trimmed.slice(0, sep).trim();
      // Reference files render the score as "(9.2,)" or plain "9.2".
      const scoreText = trimmed.slice(sep + 3).trim().replace(/[(),]/g, '');
      const n = Number(scoreText);
      expected = Number.isFinite(n) ? n : null;
    }
    const parsed = parseVector(vector);
    if (!parsed.ok) {
      for (const e of parsed.errors) errors.push({ row: i + 1, field: 'vector', message: e.message, detail: e, vector });
      return;
    }
    if (expected !== null) {
      const scored = scoreVector(vector);
      if (!scored.ok || Math.abs(scored.score - expected) > 1e-9) {
        errors.push({
          row: i + 1,
          field: 'vector',
          message: `向量评分 ${scored.ok ? scored.score : '错误'} 与文件中标注的 ${expected} 不一致。`,
          vector,
        });
        return;
      }
    }
    out.push(emptyVuln({
      title: '',
      cve: '',
      vector,
      source: 'vector-list',
      assetImportance: 3,
    }));
  });
  if (errors.length) return { ok: false, errors };
  return { ok: true, records: out, policy: null, warnings: [], detected: 'vectors' };
}

/** Downstream-friendly export for tickets: one line per vulnerability with risk + SLA. */
export function exportTriageList(enriched) {
  const lines = ['优先级,风险分,CVE,标题,CVSS(分),严重度,EPSS,资产,资产重要性,SLA截止,状态'];
  for (const v of enriched) {
    lines.push(
      [
        v.priority.label,
        v.risk.score,
        v.cve,
        v.title,
        v.cvss.score ?? '',
        v.cvss.severity,
        v.epss ?? '',
        v.assetName,
        v.assetImportance,
        v.sla.dueDateText,
        v.sla.state,
      ].map(csvEscape).join(','),
    );
  }
  return lines.join('\n') + '\n';
}

export { STATUS_VALUES };
