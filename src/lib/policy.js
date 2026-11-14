// Triage policy: risk weights and SLA windows, persisted alongside the data.
// Anything out of range falls back to the default rather than corrupting sorting.

import { DEFAULT_RISK_WEIGHTS, SEVERITY_SLA_DAYS } from './priority.js';

export const DEFAULT_POLICY = {
  weights: { ...DEFAULT_RISK_WEIGHTS },
  slaDays: { ...SEVERITY_SLA_DAYS },
};

const isFiniteNonNegative = (n) => Number.isFinite(Number(n)) && Number(n) >= 0;

export function coalescePolicy(raw) {
  const policy = { weights: { ...DEFAULT_POLICY.weights }, slaDays: { ...DEFAULT_POLICY.slaDays } };
  if (!raw || typeof raw !== 'object') return policy;

  if (raw.weights && typeof raw.weights === 'object') {
    const w = raw.weights;
    const sum = Number(w.severity) + Number(w.epss) + Number(w.asset);
    const valid = ['severity', 'epss', 'asset'].every((k) => isFiniteNonNegative(w[k])) && sum > 0;
    if (valid) {
      policy.weights = {
        severity: Number(w.severity),
        epss: Number(w.epss),
        asset: Number(w.asset),
      };
    }
  }

  if (raw.slaDays && typeof raw.slaDays === 'object') {
    for (const key of Object.keys(DEFAULT_POLICY.slaDays)) {
      const n = Number(raw.slaDays[key]);
      if (Number.isFinite(n) && n >= 0 && n <= 3650) policy.slaDays[key] = Math.round(n);
    }
  }

  return policy;
}

export function policyEquals(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

export { DEFAULT_RISK_WEIGHTS, SEVERITY_SLA_DAYS };
