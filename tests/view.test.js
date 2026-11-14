import { describe, it, expect } from 'vitest';
import { applyFilters, emptyFilters, severityCounts, countActiveFilters } from '../src/lib/view.js';
import { enrich, emptyVuln } from '../src/lib/model.js';

const V = (overrides) =>
  enrich(
    emptyVuln({
      vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
      discoveredAt: '2026-11-01',
      ...overrides,
    }),
    { now: new Date('2026-11-15T00:00:00Z') },
  );

const rows = [
  V({ id: 'a', title: 'SQL 注入', cve: 'CVE-2026-1', assetName: '支付网关', assetImportance: 5, epss: 0.9, status: 'open' }),
  V({ id: 'b', title: 'XSS', cve: 'CVE-2026-2', assetName: '门户', assetImportance: 2, epss: null, status: 'resolved' }),
  V({
    id: 'c',
    title: '路径穿越',
    cve: '',
    assetName: '报表服务',
    assetImportance: 3,
    epss: 0.2,
    status: 'in_progress',
    discoveredAt: '2026-11-14',
  }),
];

describe('queue filters', () => {
  it('returns everything with empty filters', () => {
    expect(applyFilters(rows, emptyFilters())).toHaveLength(3);
  });

  it('matches free text across title, CVE, asset and owner', () => {
    expect(applyFilters(rows, { text: 'sql' }).map((r) => r.id)).toEqual(['a']);
    expect(applyFilters(rows, { text: 'CVE-2026-2' }).map((r) => r.id)).toEqual(['b']);
    expect(applyFilters(rows, { text: '报表' }).map((r) => r.id)).toEqual(['c']);
  });

  it('filters by severity set', () => {
    expect(applyFilters(rows, { severities: ['Critical'] })).toHaveLength(3);
    expect(applyFilters(rows, { severities: ['Low'] })).toHaveLength(0);
  });

  it('filters overdue', () => {
    const overdue = applyFilters(rows, { slaState: 'overdue' }).map((r) => r.id);
    // Critical SLA is 7 days: discovered 11-01 is overdue, 11-14 is not.
    expect(overdue).toEqual(['a']);
  });

  it('treats resolved items as not overdue even when past the deadline', () => {
    expect(applyFilters(rows, { slaState: 'overdue' }).some((r) => r.id === 'b')).toBe(false);
  });

  it('filters by status, including the active shortcut', () => {
    expect(applyFilters(rows, { status: 'active' }).map((r) => r.id)).toEqual(['a', 'c']);
    expect(applyFilters(rows, { status: 'resolved' }).map((r) => r.id)).toEqual(['b']);
  });

  it('filters by asset importance floor', () => {
    expect(applyFilters(rows, { minAsset: 4 }).map((r) => r.id)).toEqual(['a']);
    expect(applyFilters(rows, { minAsset: 3 }).map((r) => r.id)).toEqual(['a', 'c']);
  });

  it('filters to rows with a known EPSS', () => {
    expect(applyFilters(rows, { epssOnly: true }).map((r) => r.id)).toEqual(['a', 'c']);
  });

  it('counts severity distribution', () => {
    expect(severityCounts(rows)).toEqual({ Critical: 3, High: 0, Medium: 0, Low: 0, None: 0 });
  });

  it('counts active filter groups', () => {
    expect(countActiveFilters(emptyFilters())).toBe(0);
    expect(countActiveFilters({ ...emptyFilters(), text: 'x', slaState: 'overdue' })).toBe(2);
  });
});
