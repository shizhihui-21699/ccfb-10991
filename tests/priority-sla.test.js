import { describe, it, expect } from 'vitest';
import {
  computeRisk,
  computeSla,
  sortVulns,
  priorityBand,
  normaliseWeights,
  assetFactor,
  SEVERITY_SLA_DAYS,
  parseDateOnly,
} from '../src/lib/priority.js';
import { enrich, validateVuln, emptyVuln } from '../src/lib/model.js';

const OPEN = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';

describe('risk composite', () => {
  it('normalises weights to sum 1', () => {
    const w = normaliseWeights({ severity: 2, epss: 1, asset: 1 });
    expect(w.severity + w.epss + w.asset).toBeCloseTo(1, 10);
    expect(w.severity).toBeCloseTo(0.5, 10);
  });

  it('maps asset importance 1..5 onto 0..1', () => {
    expect(assetFactor(1)).toBe(0);
    expect(assetFactor(3)).toBe(0.5);
    expect(assetFactor(5)).toBe(1);
    expect(assetFactor(9)).toBe(1);
    expect(assetFactor('x')).toBe(0.5);
  });

  it('ranks a critical, exploited, crown-jewel asset above a theoretical one', () => {
    const hot = computeRisk({ cvssScore: 9.8, epss: 0.92, assetImportance: 5 });
    const cold = computeRisk({ cvssScore: 5.0, epss: 0.01, assetImportance: 1 });
    expect(hot.score).toBeGreaterThan(cold.score);
    expect(hot.score).toBeGreaterThan(80);
    expect(cold.score).toBeLessThan(40);
  });

  it('renormalises when EPSS is unknown instead of treating it as zero', () => {
    const known = computeRisk({ cvssScore: 8, epss: 0.5, assetImportance: 3 });
    const unknown = computeRisk({ cvssScore: 8, epss: null, assetImportance: 3 });
    expect(unknown.epssKnown).toBe(false);
    expect(unknown.contributions.epss).toBeNull();
    // A mid EPSS (0.5) should not dominate: unknown must stay in the same ballpark.
    expect(Math.abs(known.score - unknown.score)).toBeLessThan(15);
    expect(unknown.score).toBeGreaterThan(40);
  });

  it('breaks the score into contributions that sum to the total', () => {
    const r = computeRisk({ cvssScore: 9.3, epss: 0.7, assetImportance: 4 });
    const sum = r.contributions.severity + r.contributions.epss + r.contributions.asset;
    expect(sum).toBeCloseTo(r.score, 0);
  });

  it('is monotonic in each input', () => {
    const base = { cvssScore: 7, epss: 0.3, assetImportance: 3 };
    expect(computeRisk({ ...base, cvssScore: 9 }).score).toBeGreaterThan(computeRisk(base).score);
    expect(computeRisk({ ...base, epss: 0.9 }).score).toBeGreaterThan(computeRisk(base).score);
    expect(computeRisk({ ...base, assetImportance: 5 }).score).toBeGreaterThan(computeRisk(base).score);
  });

  it('assigns priority bands at boundaries', () => {
    expect(priorityBand(100).id).toBe('P1');
    expect(priorityBand(80).id).toBe('P1');
    expect(priorityBand(79.9).id).toBe('P2');
    expect(priorityBand(60).id).toBe('P2');
    expect(priorityBand(40).id).toBe('P3');
    expect(priorityBand(0).id).toBe('P4');
  });
});

describe('SLA deadlines', () => {
  const now = new Date('2026-11-15T12:00:00Z');

  it('uses the documented per-severity windows', () => {
    expect(SEVERITY_SLA_DAYS).toEqual({ Critical: 7, High: 14, Medium: 30, Low: 90, None: 180 });
  });

  it('computes a due date from the discovery date', () => {
    const sla = computeSla({ severity: 'Critical', discoveredAt: '2026-11-01', now });
    expect(sla.dueDateText).toBe('2026-11-08');
    expect(sla.days).toBe(7);
    expect(sla.overdue).toBe(true);
    expect(sla.daysRemaining).toBe(-7);
    expect(sla.state).toBe('overdue');
  });

  it('marks the due date itself as not overdue', () => {
    const sla = computeSla({ severity: 'Critical', discoveredAt: '2026-11-08', now });
    expect(sla.dueDateText).toBe('2026-11-15');
    expect(sla.overdue).toBe(false);
    expect(sla.daysRemaining).toBe(0);
    expect(sla.state).toBe('due_soon');
  });

  it('flags due-soon within three days', () => {
    // High = 14 days against today = 2026-11-15.
    expect(computeSla({ severity: 'High', discoveredAt: '2026-11-01', now }).state).toBe('due_soon'); // due today
    expect(computeSla({ severity: 'High', discoveredAt: '2026-11-03', now }).state).toBe('due_soon'); // 2 days left
    expect(computeSla({ severity: 'High', discoveredAt: '2026-11-10', now }).state).toBe('ok');       // 9 days left
  });

  it('does not mark closed items overdue', () => {
    const sla = computeSla({ severity: 'Critical', discoveredAt: '2026-01-01', status: 'resolved', now });
    expect(sla.overdue).toBe(false);
    expect(sla.state).toBe('closed');
    const accepted = computeSla({ severity: 'Critical', discoveredAt: '2026-01-01', status: 'risk_accepted', now });
    expect(accepted.state).toBe('closed');
  });

  it('accepts a per-policy SLA override', () => {
    const sla = computeSla({ severity: 'High', discoveredAt: '2026-11-01', slaDays: { High: 3 }, now });
    expect(sla.dueDateText).toBe('2026-11-04');
    expect(sla.overdue).toBe(true);
  });

  it('handles a bad discovery date as unknown rather than throwing', () => {
    const sla = computeSla({ severity: 'High', discoveredAt: '', now });
    expect(sla.state).toBe('unknown');
    expect(sla.dueDate).toBeNull();
  });

  it('parses dates without timezone drift', () => {
    expect(parseDateOnly('2026-11-15').toISOString()).toBe('2026-11-15T00:00:00.000Z');
  });
});

describe('enrichment and ordering', () => {
  const now = new Date('2026-11-15T00:00:00Z');

  const mk = (overrides) => enrich(emptyVuln({ vector: OPEN, title: 'x', ...overrides }), { now });

  const rows = [
    mk({ cve: 'CVE-2026-0001', epss: 0.95, assetImportance: 5, discoveredAt: '2026-10-01', status: 'open' }), // critical, overdue
    mk({ cve: 'CVE-2026-0002', epss: 0.02, assetImportance: 2, discoveredAt: '2026-11-14', status: 'open' }), // low priority, fresh
    mk({ cve: 'CVE-2026-0003', epss: 0.40, assetImportance: 4, discoveredAt: '2026-11-12', status: 'in_progress' }),
  ];

  it('sorts by risk by default with score descending', () => {
    const sorted = sortVulns(rows, 'priority');
    expect(sorted[0].cve).toBe('CVE-2026-0001');
    expect(sorted[0].risk.score).toBeGreaterThan(sorted[1].risk.score);
  });

    it('sorts by SLA due date', () => {
    const sorted = sortVulns(rows, 'due');
    expect(sorted[0].cve).toBe('CVE-2026-0001');
    const due = sorted.map((r) => r.sla.dueDateText);
    expect([...due].sort()).toEqual(due);
  });

  it('sorts by EPSS with unknown last', () => {
    const withUnknown = [...rows, mk({ cve: 'CVE-X', epss: null })];
    const sorted = sortVulns(withUnknown, 'epss');
    expect(sorted[0].cve).toBe('CVE-2026-0001');
    expect(sorted[sorted.length - 1].epss === null || sorted[sorted.length - 1].epss === undefined).toBe(true);
  });

  it('derives priority band and SLA from the computed severity', () => {
    const row = rows[0];
    expect(row.cvss.ok).toBe(true);
    expect(row.cvss.severity).toBe('Critical');
    expect(row.sla.days).toBe(7);
    expect(row.priority.id).toBe('P1');
    expect(row.sla.overdue).toBe(true);
  });

  it('does not throw on an invalid vector; it reports it', () => {
    const bad = enrich(emptyVuln({ vector: 'CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N' }), { now });
    expect(bad.cvss.ok).toBe(false);
    expect(bad.cvss.errors[0].key).toBe('AV');
    expect(bad.sla.state).toBeDefined();
  });
});

describe('record validation', () => {
  it('accepts a well-formed record and defaults missing fields', () => {
    const r = validateVuln({ title: 'SQL 注入', vector: OPEN, epss: 0.4, assetImportance: 4 });
    expect(r.ok).toBe(true);
    expect(r.value.status).toBe('open');
    expect(r.value.discoveredAt).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(r.value.cve).toBe('');
  });

  it('rejects an out-of-range EPSS with the field named', () => {
    const r = validateVuln({ vector: OPEN, epss: 4 });
    expect(r.ok).toBe(false);
    expect(r.errors[0].field).toBe('epss');
  });

  it('rejects an invalid asset importance', () => {
    expect(validateVuln({ vector: OPEN, assetImportance: 7 }).errors[0].field).toBe('assetImportance');
  });

  it('rejects a bad vector with the metric detail attached', () => {
    const r = validateVuln({ vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:Q' });
    expect(r.ok).toBe(false);
    expect(r.errors[0].detail.key).toBe('SA');
  });

  it('uppercases CVE identifiers', () => {
    expect(validateVuln({ vector: OPEN, cve: 'cve-2026-1234' }).value.cve).toBe('CVE-2026-1234');
  });
});
