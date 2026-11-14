import { describe, it, expect } from 'vitest';
import { parseVector, buildVector, ERROR_CODES } from '../src/lib/cvss/parser.js';
import { scoreVector } from '../src/lib/cvss/score.js';

const VALID = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';

function codes(result) {
  return result.ok ? [] : result.errors.map((e) => e.code);
}

describe('vector parser', () => {
  it('parses a valid base vector and canonicalises it', () => {
    const r = parseVector(VALID);
    expect(r.ok).toBe(true);
    expect(r.canonical).toBe(VALID);
    expect(r.metrics.AV).toBe('N');
    expect(r.supplied).toEqual(['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA']);
  });

  it('tolerates a leading # like the FIRST calculator', () => {
    expect(parseVector('#' + VALID).ok).toBe(true);
  });

  describe('reports exactly which item is wrong', () => {
    it('empty input', () => {
      const r = parseVector('   ');
      expect(codes(r)).toEqual([ERROR_CODES.EMPTY]);
    });

    it('non-string input', () => {
      expect(codes(parseVector(null))).toEqual([ERROR_CODES.INVALID_TYPE]);
    });

    it('missing prefix', () => {
      const r = parseVector('AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
      expect(codes(r)).toContain(ERROR_CODES.MISSING_PREFIX);
    });

    it('wrong version', () => {
      const r = parseVector(VALID.replace('4.0', '3.1'));
      expect(codes(r)).toEqual([ERROR_CODES.BAD_VERSION]);
      expect(r.errors[0].value).toBe('3.1');
      expect(r.errors[0].message).toContain('3.1');
    });

    it('invalid value names the metric, the value and the allowed set', () => {
      const r = parseVector(VALID.replace('AV:N', 'AV:X'));
      expect(r.ok).toBe(false);
      const err = r.errors.find((e) => e.code === ERROR_CODES.INVALID_VALUE);
      expect(err.key).toBe('AV');
      expect(err.value).toBe('X');
      expect(err.expectedValues).toEqual(['N', 'A', 'L', 'P']);
      expect(err.position).toBe(1);
      expect(err.message).toContain('AV');
      // A present-but-wrong metric must not also be reported as missing.
      expect(r.errors.map((e) => e.code)).toEqual([ERROR_CODES.INVALID_VALUE]);
    });

    it('suggests the fix for a lowercase value', () => {
      const r = parseVector(VALID.replace('AV:N', 'AV:n'));
      const err = r.errors.find((e) => e.code === ERROR_CODES.INVALID_VALUE);
      expect(err.hint).toContain('"N"');
    });

    it('unknown metric key suggests a near match', () => {
      const r = parseVector(VALID.replace('/SA:N', '/SA:N/XX:Y'));
      const err = r.errors.find((e) => e.code === ERROR_CODES.UNKNOWN_METRIC);
      expect(err.key).toBe('XX');
      // Still flags the missing base metrics count correctly (all base present).
      expect(err.position).toBe(12);
    });

    it('typo of a modified metric suggests the M-prefixed key', () => {
      const r = parseVector(`${VALID}/AV:L`);
      expect(codes(r)).toContain(ERROR_CODES.DUPLICATE);
    });

    it('duplicate metric names both positions', () => {
      const r = parseVector(`${VALID}/AV:N`);
      const err = r.errors.find((e) => e.code === ERROR_CODES.DUPLICATE);
      expect(err.key).toBe('AV');
      expect(err.position).toBe(12);
      expect(err.duplicateOf).toBe(1);
    });

    it('empty field from a double slash', () => {
      const r = parseVector(VALID.replace('/AC:L', '//AC:L'));
      expect(codes(r)).toContain(ERROR_CODES.EMPTY_FIELD);
    });

    it('field without a colon', () => {
      const r = parseVector(VALID.replace('/AC:L', '/ACL'));
      const err = r.errors.find((e) => e.code === ERROR_CODES.MALFORMED_FIELD);
      expect(err.field).toBe('ACL');
      expect(err.position).toBe(2);
    });

    it('field with multiple colons', () => {
      const r = parseVector(VALID.replace('/AC:L', '/AC:L:X'));
      expect(codes(r)).toContain(ERROR_CODES.MALFORMED_FIELD);
    });

    it('missing mandatory base metrics are listed by name', () => {
      const r = parseVector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N');
      const err = r.errors.find((e) => e.code === ERROR_CODES.MISSING_METRIC);
      expect(err.missing).toEqual(['VC', 'VI', 'VA', 'SC', 'SI', 'SA']);
      expect(err.message).toContain('VC');
    });

    it('trailing slash', () => {
      const r = parseVector(VALID + '/');
      expect(codes(r)).toContain(ERROR_CODES.TRAILING_SLASH);
    });

    it('leading/trailing whitespace is reported', () => {
      const r = parseVector(` ${VALID} `);
      expect(codes(r)).toContain(ERROR_CODES.WHITESPACE);
    });

    it('collects several independent problems at once', () => {
      const r = parseVector('CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:Z');
      expect(codes(r).filter((c) => c === ERROR_CODES.INVALID_VALUE).length).toBe(2);
      const keys = r.errors.filter((e) => e.code === ERROR_CODES.INVALID_VALUE).map((e) => e.key);
      expect(keys).toEqual(['AV', 'SA']);
    });
  });

  it('accepts optional metrics out of order but normalises them', () => {
    const r = parseVector(`${VALID}/E:A/CR:H`);
    expect(r.ok).toBe(true);
    expect(r.canonical).toBe(`${VALID}/E:A/CR:H`);
  });

  it('records a warning when metrics arrive unordered', () => {
    const r = parseVector(`${VALID}/CR:H/E:A`);
    expect(r.ok).toBe(true);
    expect(r.warnings.length).toBe(1);
    expect(r.canonical).toBe(`${VALID}/E:A/CR:H`);
  });

  it('buildVector omits undefined and X values', () => {
    const r = parseVector(VALID);
    expect(buildVector({ ...r.metrics, E: 'X', CR: 'X' })).toBe(VALID);
  });

  it('buildVector can exclude supplemental metrics', () => {
    const r = parseVector(`${VALID}/S:P/AU:Y`);
    expect(buildVector(r.metrics, { includeSupplemental: false })).toBe(VALID);
    expect(buildVector(r.metrics)).toBe(`${VALID}/S:P/AU:Y`);
  });

  it('scoreVector surfaces parser errors instead of a score', () => {
    const r = scoreVector('CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
    expect(r.ok).toBe(false);
    expect(r.errors[0].key).toBe('AV');
  });
});
