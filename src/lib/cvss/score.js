// CVSS v4.0 scoring engine.
//
// Implements the FIRST CVSS v4.0 specification:
//   * equivalency classes (EQ1..EQ6) -> MacroVector
//   * MacroVector lookup score
//   * maximal scoring difference (MSD) + severity-distance interpolation
//   * 0.0 short-circuit when all impact metrics are None
//   * 1-decimal "round half up" finalisation
// Verified against the FIFTY official Red Hat / FIRST test-vector files
// (see tests/cvss-official-vectors.test.js).

import { METRIC_LEVELS, MAX_COMPOSED, MAX_SEVERITY, LOOKUP_TABLE } from './lookup.js';
import { parseVector, buildVector } from './parser.js';
import { DEFAULT_METRIC_VALUES, SUPPLEMENTAL_METRICS } from './metrics.js';

const NO_IMPACT_METRICS = ['VC', 'VI', 'VA', 'SC', 'SI', 'SA'];
const STEP = 0.1;

/** Round half up to one decimal place, tolerating float representation error. */
export function roundToDecimalPlaces(value, places = 1) {
  const factor = 10 ** places;
  const epsilon = 10 ** -6;
  return Math.round((value + epsilon) * factor) / factor;
}

/**
 * Effective value of a metric:
 *  - E defaults to A (worst case), CR/IR/AR default to H when the vector says X
 *  - a modified metric (Mxx) overrides its base metric when not X
 */
export function effectiveMetric(metrics, key) {
  if (metrics[key] === 'X') {
    if (key === 'E') return 'A';
    if (key === 'CR' || key === 'IR' || key === 'AR') return 'H';
  }
  const modified = metrics['M' + key];
  if (modified !== undefined && modified !== 'X') return modified;
  return metrics[key];
}

/** Equivalency classes EQ1..EQ6 concatenated, e.g. "002201". */
export function equivalentClasses(metrics) {
  const m = (key) => effectiveMetric(metrics, key);

  let eq1;
  if (m('AV') === 'N' && m('PR') === 'N' && m('UI') === 'N') eq1 = '0';
  else if ((m('AV') === 'N' || m('PR') === 'N' || m('UI') === 'N') && m('AV') !== 'P') eq1 = '1';
  else eq1 = '2';

  const eq2 = m('AC') === 'L' && m('AT') === 'N' ? '0' : '1';

  let eq3;
  if (m('VC') === 'H' && m('VI') === 'H') eq3 = '0';
  else if (m('VC') === 'H' || m('VI') === 'H' || m('VA') === 'H') eq3 = '1';
  else eq3 = '2';

  let eq4;
  if (m('MSI') === 'S' || m('MSA') === 'S') eq4 = '0';
  else if (m('SC') === 'H' || m('SI') === 'H' || m('SA') === 'H') eq4 = '1';
  else eq4 = '2';

  let eq5;
  if (m('E') === 'A') eq5 = '0';
  else if (m('E') === 'P') eq5 = '1';
  else eq5 = '2';

  const eq6 =
    (m('CR') === 'H' && m('VC') === 'H') ||
    (m('IR') === 'H' && m('VI') === 'H') ||
    (m('AR') === 'H' && m('VA') === 'H')
      ? '0'
      : '1';

  return eq1 + eq2 + eq3 + eq4 + eq5 + eq6;
}

function extractValueMetric(metric, str) {
  const start = str.indexOf(metric) + metric.length + 1;
  const rest = str.slice(start);
  const slash = rest.indexOf('/');
  return slash >= 0 ? rest.slice(0, slash) : rest;
}

function severityDistances(metrics, maxVector) {
  const distances = {};
  for (const metric of Object.keys(METRIC_LEVELS)) {
    const effective = effectiveMetric(metrics, metric);
    const extracted = extractValueMetric(metric, maxVector);
    distances[metric] =
      METRIC_LEVELS[metric][effective] - METRIC_LEVELS[metric][extracted];
  }
  return distances;
}

function maxSeverityVectors(macroVector, eqNumber) {
  return MAX_COMPOSED['eq' + eqNumber][macroVector[eqNumber - 1]];
}

/**
 * The full interpolation. `value` is the macrovector lookup score and `macroVector`
 * its 6-digit class; returns the 1-decimal score.
 */
function interpolate(metrics, macroVector, value) {
  const [eq1, eq2, eq3, eq4, eq5, eq6] = macroVector.split('').map(Number);

  // Next-lower macrovector for each EQ; EQ3/EQ6 are linked.
  const eq1Lower = `${eq1 + 1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
  const eq2Lower = `${eq1}${eq2 + 1}${eq3}${eq4}${eq5}${eq6}`;

  let eq3eq6Lower;
  let eq3eq6LowerLeft;
  let eq3eq6LowerRight;
  if (eq3 === 1 && eq6 === 1) eq3eq6Lower = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`;
  else if (eq3 === 0 && eq6 === 1) eq3eq6Lower = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`;
  else if (eq3 === 1 && eq6 === 0) eq3eq6Lower = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6 + 1}`;
  else if (eq3 === 0 && eq6 === 0) {
    eq3eq6LowerLeft = `${eq1}${eq2}${eq3}${eq4}${eq5}${eq6 + 1}`;
    eq3eq6LowerRight = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6}`;
  } else eq3eq6Lower = `${eq1}${eq2}${eq3 + 1}${eq4}${eq5}${eq6 + 1}`;

  const eq4Lower = `${eq1}${eq2}${eq3}${eq4 + 1}${eq5}${eq6}`;
  const eq5Lower = `${eq1}${eq2}${eq3}${eq4}${eq5 + 1}${eq6}`;

  const scoreEq1Lower = LOOKUP_TABLE[eq1Lower];
  const scoreEq2Lower = LOOKUP_TABLE[eq2Lower];
  let scoreEq3Eq6Lower;
  if (eq3 === 0 && eq6 === 0) {
    scoreEq3Eq6Lower = Math.max(
      LOOKUP_TABLE[eq3eq6LowerLeft],
      LOOKUP_TABLE[eq3eq6LowerRight],
    );
  } else {
    scoreEq3Eq6Lower = LOOKUP_TABLE[eq3eq6Lower];
  }
  const scoreEq4Lower = LOOKUP_TABLE[eq4Lower];
  const scoreEq5Lower = LOOKUP_TABLE[eq5Lower];

  // Highest-severity vector combinations inside this macrovector.
  const eqMaxes = [
    maxSeverityVectors(macroVector, 1),
    maxSeverityVectors(macroVector, 2),
    maxSeverityVectors(macroVector, 3)[eq6],
    maxSeverityVectors(macroVector, 4),
    maxSeverityVectors(macroVector, 5),
  ];
  const maxVectors = [];
  for (const a of eqMaxes[0])
    for (const b of eqMaxes[1])
      for (const c of eqMaxes[2])
        for (const d of eqMaxes[3])
          for (const e of eqMaxes[4]) maxVectors.push(a + b + c + d + e);

  let distances;
  for (const candidate of maxVectors) {
    const d = severityDistances(metrics, candidate);
    if (Object.values(d).every((x) => x >= 0)) {
      distances = d;
      break;
    }
  }
  // Fall back to the last candidate (cannot happen for valid macrovectors).
  if (!distances) distances = severityDistances(metrics, maxVectors[maxVectors.length - 1]);

  const distEq1 = distances.AV + distances.PR + distances.UI;
  const distEq2 = distances.AC + distances.AT;
  const distEq3Eq6 =
    distances.VC + distances.VI + distances.VA + distances.CR + distances.IR + distances.AR;
  const distEq4 = distances.SC + distances.SI + distances.SA;

  const availableEq1 = value - scoreEq1Lower;
  const availableEq2 = value - scoreEq2Lower;
  const availableEq3Eq6 = value - scoreEq3Eq6Lower;
  const availableEq4 = value - scoreEq4Lower;
  const availableEq5 = value - scoreEq5Lower;

  const maxSevEq1 = MAX_SEVERITY.eq1[eq1] * STEP;
  const maxSevEq2 = MAX_SEVERITY.eq2[eq2] * STEP;
  const maxSevEq3Eq6 = MAX_SEVERITY.eq3eq6[eq3][eq6] * STEP;
  const maxSevEq4 = MAX_SEVERITY.eq4[eq4] * STEP;

  let count = 0;
  let normalized = 0;

  if (!Number.isNaN(availableEq1)) {
    count += 1;
    normalized += availableEq1 * (distEq1 / maxSevEq1);
  }
  if (!Number.isNaN(availableEq2)) {
    count += 1;
    normalized += availableEq2 * (distEq2 / maxSevEq2);
  }
  if (!Number.isNaN(availableEq3Eq6)) {
    count += 1;
    normalized += availableEq3Eq6 * (distEq3Eq6 / maxSevEq3Eq6);
  }
  if (!Number.isNaN(availableEq4)) {
    count += 1;
    normalized += availableEq4 * (distEq4 / maxSevEq4);
  }
  if (!Number.isNaN(availableEq5)) {
    // EQ5 has no severity distance within a macrovector.
    count += 1;
  }

  const meanDistance = count === 0 ? 0 : normalized / count;
  return roundToDecimalPlaces(Math.max(0, Math.min(10, value - meanDistance)), 1);
}

/** Raw (unrounded) computation used for the audit trail. */
function scoreMetrics(metrics) {
  // Normalise: every metric the specification knows about must carry a value, and
  // omitted optional metrics behave exactly like X (unset). Without this, an
  // effective-value lookup on an absent CR/MSI would read undefined.
  metrics = { ...DEFAULT_METRIC_VALUES, ...metrics };
  if (NO_IMPACT_METRICS.every((k) => effectiveMetric(metrics, k) === 'N')) {
    return { score: 0, macroVector: equivalentClasses(metrics), noImpact: true };
  }
  const macroVector = equivalentClasses(metrics);
  const value = LOOKUP_TABLE[macroVector];
  if (value === undefined) {
    // Only reachable for E=X handled as A, MSI/MSA=S, etc.; all valid classes exist.
    return { score: 0, macroVector, noImpact: false, unknownMacroVector: true };
  }
  return { score: interpolate(metrics, macroVector, value), macroVector, noImpact: false, macroVectorScore: value };
}

export function severityRating(score) {
  if (score === 0.0) return 'None';
  if (score <= 3.9) return 'Low';
  if (score <= 6.9) return 'Medium';
  if (score <= 8.9) return 'High';
  return 'Critical';
}

/** Nomenclature for the metrics that are actually supplied (CVSS-B / -BT / -BE / -BTE). */
export function nomenclature(metrics, supplied = []) {
  const has = (list) => list.some((k) => supplied.includes(k) || (metrics[k] && metrics[k] !== 'X'));
  let name = 'CVSS-B';
  if (has(['E'])) name += 'T';
  if (has(['CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA'])) name += 'E';
  return name;
}

/**
 * Score a metric map.
 *
 * `base`   — score with threat/environmental metrics stripped: CVSS-B
 * `threat` — score with base + E: CVSS-BT
 * `environmental` — full score with base + E + all environmental metrics: CVSS-BTE
 * `overall` — the score for exactly what the user supplied, matching the
 *             reference calculator (a Base-only vector scores as CVSS-B).
 */
export function scoreMetricsFull(metrics, supplied = []) {
  const onlyBase = { ...metrics };
  for (const key of SUPPLEMENTAL_METRICS) delete onlyBase[key];
  const baseOnly = {};
  for (const key of ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA']) {
    baseOnly[key] = metrics[key];
  }
  const base = scoreMetrics(baseOnly);

  const withThreat = { ...baseOnly, E: metrics.E ?? 'X' };
  const threat = scoreMetrics(withThreat);

  const environmental = scoreMetrics({ ...metrics });

  const suppliedSet = new Set(supplied.filter(Boolean));
  const usesThreat = suppliedSet.has('E') && metrics.E !== 'X';
  const envKeys = ['CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA'];
  const usesEnv = envKeys.some((k) => suppliedSet.has(k) && metrics[k] !== 'X');

  let overall;
  if (!usesThreat && !usesEnv) overall = base;
  else if (usesThreat && !usesEnv) overall = threat;
  else overall = environmental;

  return {
    score: overall.score,
    severity: severityRating(overall.score),
    macroVector: overall.macroVector,
    base: { score: base.score, severity: severityRating(base.score), macroVector: base.macroVector },
    threat: { score: threat.score, severity: severityRating(threat.score), macroVector: threat.macroVector },
    environmental: {
      score: environmental.score,
      severity: severityRating(environmental.score),
      macroVector: environmental.macroVector,
    },
    nomenclature: nomenclature(metrics, supplied),
  };
}

/**
 * Score a vector string. Returns `{ ok: false, errors }` when the string is invalid.
 */
export function scoreVector(vectorString) {
  const parsed = parseVector(vectorString);
  if (!parsed.ok) return { ok: false, errors: parsed.errors, vector: vectorString };
  const result = scoreMetricsFull(parsed.metrics, parsed.supplied);
  return { ok: true, ...result, metrics: parsed.metrics, supplied: parsed.supplied, canonical: parsed.canonical, vector: buildVector(parsed.metrics) };
}

export { parseVector, buildVector };
