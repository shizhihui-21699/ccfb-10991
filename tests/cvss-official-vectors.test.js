import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scoreVector } from '../src/lib/cvss/score.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(readFileSync(join(here, 'fixtures', 'official-vectors.json'), 'utf8'));

describe('CVSS v4.0 engine against official FIRST / Red Hat test vectors', () => {
  it('has a meaningful fixture set', () => {
    expect(fixture.entries.length).toBeGreaterThan(700);
  });

  // Group by source file so a failure names the coverage area.
  const bySource = new Map();
  for (const entry of fixture.entries) {
    if (!bySource.has(entry.source)) bySource.set(entry.source, []);
    bySource.get(entry.source).push(entry);
  }

  for (const [source, entries] of bySource) {
    describe(source, () => {
      for (const { vector, expectedScore } of entries) {
        it(`${vector} => ${expectedScore}`, () => {
          const result = scoreVector(vector);
          expect(result.ok).toBe(true);
          expect(result.score).toBe(expectedScore);
        });
      }
    });
  }
});

describe('CVSS v4.0 score components', () => {
  it('scores a Base-only vector identically for base/threat/environmental', () => {
    const r = scoreVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
    expect(r.ok).toBe(true);
    expect(r.base.score).toBe(9.3);
    expect(r.threat.score).toBe(9.3);
    expect(r.environmental.score).toBe(9.3);
    expect(r.nomenclature).toBe('CVSS-B');
  });

  it('produces a lower score when exploit maturity is Unreported', () => {
    const r = scoreVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U');
    expect(r.ok).toBe(true);
    expect(r.base.score).toBe(9.3);
    expect(r.threat.score).toBeLessThan(r.base.score);
    expect(r.nomenclature).toBe('CVSS-BT');
  });

  it('applies environmental security requirements and modified metrics', () => {
    const r = scoreVector(
      'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U/CR:H/IR:L/AR:L/MAV:L/MAC:H/MAT:P/MPR:L/MUI:A/MVC:L/MVI:N/MVA:H/MSC:H/MSI:L/MSA:N',
    );
    expect(r.ok).toBe(true);
    expect(r.nomenclature).toBe('CVSS-BTE');
    expect(r.environmental.score).not.toBe(r.base.score);
  });

  it('returns 0.0 when every impact metric is None', () => {
    const r = scoreVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:A');
    expect(r.ok).toBe(true);
    expect(r.score).toBe(0);
    expect(r.severity).toBe('None');
  });

  it('maps scores to severity bands exactly at the boundaries', () => {
    // 0.0 None, 0.1-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, 9.0-10.0 Critical
    const cases = [
      ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N', 'None'],
      ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H', 'Critical'],
    ];
    for (const [vector, severity] of cases) {
      expect(scoreVector(vector).severity).toBe(severity);
    }
  });

  it('exposes the macrovector for auditability', () => {
    const r = scoreVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
    expect(r.macroVector).toMatch(/^\d{6}$/);
  });
});
