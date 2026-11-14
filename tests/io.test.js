import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { importData, exportJson, exportCsv, exportTriageList, parseCsv } from '../src/lib/io.js';
import { coalescePolicy } from '../src/lib/policy.js';
import { enrich } from '../src/lib/model.js';

const here = dirname(fileURLToPath(import.meta.url));
const OPEN = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';

describe('CSV parser', () => {
  it('handles quoted commas, escaped quotes and CRLF', () => {
    const rows = parseCsv('a,b\r\n"x,1","he said ""hi"""\r\n');
    expect(rows[0]).toEqual(['a', 'b']);
    expect(rows[1]).toEqual(['x,1', 'he said "hi"']);
  });
});

describe('import', () => {
  it('detects and imports native JSON', () => {
    const json = JSON.stringify({ schemaVersion: 1, vulnerabilities: [{ title: 'A', vector: OPEN, epss: 0.2, assetImportance: 3 }] });
    const r = importData(json);
    expect(r.ok).toBe(true);
    expect(r.detected).toBe('json');
    expect(r.records[0].title).toBe('A');
  });

  it('imports a bare JSON array', () => {
    const r = importData(JSON.stringify([{ vector: OPEN }]));
    expect(r.ok).toBe(true);
    expect(r.records.length).toBe(1);
  });

  it('reports the row and field for an invalid JSON record', () => {
    const json = JSON.stringify([{ vector: OPEN }, { vector: 'CVSS:4.0/AV:N' }]);
    const r = importData(json);
    expect(r.ok).toBe(false);
    expect(r.errors[0].row).toBe(3);
    expect(r.errors[0].field).toBe('vector');
    expect(r.errors[0].message).toMatch(/VC|缺少/);
  });

  it('imports CSV by Chinese header', () => {
    const csv = `标题,CVE,CVSS向量,EPSS,资产重要性,资产名称,发现日期\n"SQL 注入, 严重",CVE-2026-1,${OPEN},0.42,5,支付网关,2026-11-01\n`;
    const r = importData(csv);
    expect(r.ok).toBe(true);
    expect(r.detected).toBe('csv');
    expect(r.records[0].epss).toBe(0.42);
    expect(r.records[0].assetImportance).toBe(5);
    expect(r.records[0].title).toBe('SQL 注入, 严重');
  });

  it('imports CSV by English header', () => {
    const csv = `title,vector,epss,assetImportance\ndemo,${OPEN},0.1,2\n`;
    const r = importData(csv);
    expect(r.ok).toBe(true);
    expect(r.records[0].assetImportance).toBe(2);
  });

  it('reports the CSV row number when a vector is invalid', () => {
    const csv = `vector,title\n${OPEN},ok\nCVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N,bad\n`;
    const r = importData(csv);
    expect(r.ok).toBe(false);
    expect(r.errors[0].row).toBe(3);
    expect(r.errors[0].message).toContain('AV');
  });

  it('rejects a CSV whose header has no vector column, naming the headers seen', () => {
    const r = importData('标题,说明\nx,y\n');
    expect(r.ok).toBe(false);
    expect(r.errors[0].message).toContain('标题');
  });

  it('imports a plain vector list and checks scores that are given', () => {
    const r = importData(`${OPEN} - 9.3\n`);
    expect(r.ok).toBe(true);
    expect(r.detected).toBe('vectors');
    expect(r.records.length).toBe(1);
  });

  it('rejects a vector list line whose annotated score is wrong', () => {
    const r = importData(`${OPEN} - 1.0\n`);
    expect(r.ok).toBe(false);
    expect(r.errors[0].row).toBe(1);
    expect(r.errors[0].message).toContain('不一致');
  });

  it('imports the official fixture file verbatim and reproduces every score', () => {
    const file = join(here, 'fixtures', 'official-vectors.json');
    const { entries } = JSON.parse(readFileSync(file, 'utf8'));
    const r = importData(JSON.stringify(entries.map((e) => ({ vector: e.vector }))));
    expect(r.ok).toBe(true);
    expect(r.records.length).toBe(entries.length);
  });

  it('rejects an empty file', () => {
    expect(importData('   ').ok).toBe(false);
  });
});

describe('export', () => {
  const vulns = [
    {
      id: 'v1', title: 'A, with comma', cve: 'CVE-2026-1', vector: OPEN, epss: 0.5,
      assetImportance: 5, assetName: '支付网关', discoveredAt: '2026-11-01', status: 'open',
      owner: 'alice', notes: 'line1\nline2', source: 'manual',
    },
  ];

  it('round-trips through JSON export/import', () => {
    const json = exportJson(vulns, { weights: { severity: 0.5, epss: 0.3, asset: 0.2 } });
    const r = importData(json);
    expect(r.ok).toBe(true);
    expect(r.records[0].title).toBe('A, with comma');
    expect(r.records[0].notes).toBe('line1\nline2');
  });

  it('round-trips through CSV export/import', () => {
    const csv = exportCsv(vulns);
    const r = importData(csv);
    expect(r.ok).toBe(true);
    expect(r.records[0].title).toBe('A, with comma');
    expect(r.records[0].assetName).toBe('支付网关');
  });

  it('exports the triage list with priority and SLA columns', () => {
    const enriched = vulns.map((v) => enrich(v, { now: new Date('2026-11-15T00:00:00Z') }));
    const text = exportTriageList(enriched);
    const [header, row] = text.trim().split('\n');
    expect(header).toContain('优先级');
    expect(header).toContain('SLA截止');
    expect(row).toContain('2026-11-08');
  });
});

describe('policy', () => {
  it('coalesces partial policy with defaults and validates weights', () => {
    const p = coalescePolicy({ weights: { severity: 0.7, epss: 0.2, asset: 0.1 } });
    expect(p.weights.severity).toBe(0.7);
    expect(p.slaDays.Critical).toBe(7);
  });

  it('falls back to defaults for invalid weights', () => {
    const p = coalescePolicy({ weights: { severity: -1, epss: 0, asset: 0 } });
    expect(p.weights).toEqual({ severity: 0.5, epss: 0.3, asset: 0.2 });
  });

  it('accepts custom SLA day counts', () => {
    const p = coalescePolicy({ slaDays: { Critical: 1, High: 2 } });
    expect(p.slaDays).toEqual({ Critical: 1, High: 2, Medium: 30, Low: 90, None: 180 });
  });
});
