// Strict CVSS v4.0 vector-string parser with per-metric diagnostics.
//
// Every failure carries a machine-readable `code` plus the offending key/value and a
// human-readable Chinese explanation, so the UI can point at exactly which metric is
// wrong instead of failing the whole string with "invalid vector".

import {
  BASE_METRICS,
  METRIC_GROUP_BY_KEY,
  METRICS,
  METRIC_ORDER,
  SUPPLEMENTAL_METRICS,
  DEFAULT_METRIC_VALUES,
} from './metrics.js';

export const ERROR_CODES = {
  EMPTY: 'EMPTY_VECTOR',
  INVALID_TYPE: 'INVALID_TYPE',
  MISSING_PREFIX: 'MISSING_PREFIX',
  BAD_VERSION: 'UNSUPPORTED_VERSION',
  TRAILING_SLASH: 'TRAILING_SLASH',
  EMPTY_FIELD: 'EMPTY_FIELD',
  MALFORMED_FIELD: 'MALFORMED_FIELD',
  DUPLICATE: 'DUPLICATE_METRIC',
  UNKNOWN_METRIC: 'UNKNOWN_METRIC',
  INVALID_VALUE: 'INVALID_VALUE',
  OUT_OF_ORDER: 'OUT_OF_ORDER',
  MISSING_METRIC: 'MISSING_METRIC',
  WHITESPACE: 'WHITESPACE',
};

const ORDER_INDEX = Object.fromEntries(METRIC_ORDER.map((k, i) => [k, i]));

function allowedValues(key) {
  return METRICS[key].values.map((v) => v.value);
}

function makeError(code, message, extra = {}) {
  return { code, message, ...extra };
}

function caseHint(key, value) {
  const match = allowedValues(key).find((v) => v.toLowerCase() === String(value).toLowerCase());
  if (!match) return null;
  return `CVSS 取值区分大小写，是否想输入 "${match}"？`;
}

/**
 * Parse a CVSS v4.0 vector string.
 *
 * @param {string} input
 * @returns {{ok: true, metrics: Record<string,string>, canonical: string, supplied: string[]}
 *          | {ok: false, errors: Array<object>}}
 */
export function parseVector(input) {
  if (typeof input !== 'string') {
    return { ok: false, errors: [makeError(ERROR_CODES.INVALID_TYPE, '向量必须是字符串。')] };
  }

  let vector = input;
  // The FIRST reference calculator tolerates a leading '#', so accept it too.
  if (vector.startsWith('#')) vector = vector.slice(1);

  const errors = [];
  const warnings = [];

  if (vector.trim() === '') {
    return { ok: false, errors: [makeError(ERROR_CODES.EMPTY, '向量为空，无法解析。')] };
  }
  if (vector !== vector.trim()) {
    errors.push(makeError(ERROR_CODES.WHITESPACE, '向量首尾存在空白字符，请删除。'));
    vector = vector.trim();
  }
  if (vector.endsWith('/')) {
    errors.push(makeError(ERROR_CODES.TRAILING_SLASH, '向量以 "/" 结尾，末尾多了一个分隔符。'));
  }

  const segments = vector.split('/');
  const prefix = segments[0];
  if (!prefix.startsWith('CVSS:')) {
    errors.push(
      makeError(ERROR_CODES.MISSING_PREFIX, '向量缺少 "CVSS:4.0/" 前缀。', { expected: 'CVSS:4.0' }),
    );
  } else if (prefix !== 'CVSS:4.0') {
    const version = prefix.slice('CVSS:'.length);
    errors.push(
      makeError(ERROR_CODES.BAD_VERSION, `不支持的 CVSS 版本 "${version}"，本工具只支持 CVSS:4.0。`, {
        value: version,
        expected: 'CVSS:4.0',
      }),
    );
  }

  const metrics = { ...DEFAULT_METRIC_VALUES };
  const supplied = [];
  const seen = new Map();
  let lastIndex = -1;

  for (let i = 1; i < segments.length; i++) {
    const field = segments[i];
    const position = i;

    if (field === '') {
      errors.push(
        makeError(ERROR_CODES.EMPTY_FIELD, `第 ${position} 项为空（连续出现 "//" 或末尾分隔符）。`, {
          position,
        }),
      );
      continue;
    }

    const colonCount = (field.match(/:/g) || []).length;
    if (colonCount === 0) {
      errors.push(
        makeError(ERROR_CODES.MALFORMED_FIELD, `第 ${position} 项 "${field}" 缺少值分隔符 ":"。`, {
          position,
          field,
        }),
      );
      continue;
    }
    if (colonCount > 1) {
      errors.push(
        makeError(ERROR_CODES.MALFORMED_FIELD, `第 ${position} 项 "${field}" 含多个 ":"，格式应为 指标:取值。`, {
          position,
          field,
        }),
      );
      continue;
    }

    const [key, value] = field.split(':');

    if (!(key in METRICS)) {
      errors.push(
        makeError(ERROR_CODES.UNKNOWN_METRIC, `第 ${position} 项的指标名 "${key}" 不是合法的 CVSS v4.0 指标。`, {
          position,
          key,
          value,
          expectedValues: undefined,
          hint: suggestKey(key),
        }),
      );
      continue;
    }

    const allowed = allowedValues(key);
    if (!allowed.includes(value)) {
      errors.push(
        makeError(
          ERROR_CODES.INVALID_VALUE,
          `指标 ${key}（${METRICS[key].name}）的取值 "${value}" 非法。`,
          { position, key, value, expectedValues: allowed, hint: caseHint(key, value) },
        ),
      );
      // The metric is present, just wrong: don't also report it as missing below.
      seen.set(key, position);
      continue;
    }

    if (seen.has(key)) {
      errors.push(
        makeError(ERROR_CODES.DUPLICATE, `指标 ${key} 重复出现（第 ${seen.get(key)} 项和第 ${position} 项）。`, {
          position,
          key,
          value,
          duplicateOf: seen.get(key),
        }),
      );
      continue;
    }

    const index = ORDER_INDEX[key];
    if (index < lastIndex) {
      const expectedNext = METRIC_ORDER.find((k) => ORDER_INDEX[k] > lastIndex);
      // Ordering is not a validity error in CVSS v4.0: the official calculator and
      // the Red Hat reference parser both accept any order. Surface it as a warning
      // so the canonical vector can be normalised, but keep scoring the vector.
      warnings.push(
        `指标 ${key} 出现了乱序；已按 CVSS v4.0 规范顺序重新规范化${expectedNext ? `（此处规范顺序应为 ${expectedNext}）` : ''}。`,
      );
      seen.set(key, position);
      supplied.push(key);
      metrics[key] = value;
      continue;
    }

    lastIndex = index;
    seen.set(key, position);
    supplied.push(key);
    metrics[key] = value;
  }

  const missing = BASE_METRICS.filter((k) => !seen.has(k));
  if (missing.length) {
    errors.push(
      makeError(
        ERROR_CODES.MISSING_METRIC,
        `缺少必填的基础指标：${missing.join('、')}。`,
        { missing, expectedValues: missing.map((k) => `${k}:${allowedValues(k).join('|')}`) },
      ),
    );
  }

  if (errors.length) {
    return { ok: false, errors };
  }

  return { ok: true, metrics, canonical: buildVector(metrics), supplied, warnings };
}

function suggestKey(key) {
  const upper = key.toUpperCase();
  if (upper in METRICS) return `指标名区分大小写，是否想输入 "${upper}"？`;
  // Common typo: "M" + base metric for modified metrics.
  if (('M' + upper) in METRICS) return `是否想输入修改后指标 "M${upper}"？`;
  const near = METRIC_ORDER.filter((k) => k.startsWith(upper.slice(0, 1)));
  if (near.length) return `相近的合法指标：${near.join('、')}`;
  return undefined;
}

/**
 * Build a canonical vector string. Supplemental metrics are only emitted when the
 * caller asks for them (they never influence the score).
 */
export function buildVector(metrics, { includeSupplemental = true } = {}) {
  const parts = ['CVSS:4.0'];
  for (const key of METRIC_ORDER) {
    if (!includeSupplemental && SUPPLEMENTAL_METRICS.includes(key)) continue;
    const value = metrics[key];
    if (value && value !== 'X') parts.push(`${key}:${value}`);
  }
  return parts.join('/');
}

/**
 * Human-readable rendering of an error list, used for logs and clipboard output.
 */
export function formatErrors(errors) {
  return errors
    .map((e, i) => `${i + 1}. [${e.code}] ${e.message}${e.hint ? ` ${e.hint}` : ''}`)
    .join('\n');
}

export { METRIC_GROUP_BY_KEY };
