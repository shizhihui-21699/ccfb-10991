// CVSS v4.0 metric definitions, in the order defined by the FIRST specification.
// Labels are Chinese; the short codes are the canonical vector tokens.
// https://www.first.org/cvss/v4.0/specification-document

const val = (value, label, note = '') => ({ value, label, note });

export const METRICS = {
  // --- Base -----------------------------------------------------------------
  AV: {
    key: 'AV', name: '攻击途径', en: 'Attack Vector',
    values: [
      val('N', '网络', '可通过网络远程利用'),
      val('A', '相邻', '需要逻辑相邻的网络或共享环境'),
      val('L', '本地', '需要本地读写/执行能力'),
      val('P', '物理', '需要物理接触或操作'),
    ],
  },
  AC: {
    key: 'AC', name: '攻击复杂度', en: 'Attack Complexity',
    values: [val('L', '低', '无额外条件，可稳定复现'), val('H', '高', '依赖难以控制的外部条件')],
  },
  AT: {
    key: 'AT', name: '攻击要求', en: 'Attack Requirements',
    values: [val('N', '无', '无需特殊部署条件'), val('P', '存在', '需要目标系统存在特定配置/状态')],
  },
  PR: {
    key: 'PR', name: '所需权限', en: 'Privileges Required',
    values: [val('N', '无', '无需认证'), val('L', '低', '普通用户权限'), val('H', '高', '管理员权限')],
  },
  UI: {
    key: 'UI', name: '用户交互', en: 'User Interaction',
    values: [val('N', '无', '无需用户参与'), val('P', '被动', '用户被动触发，无需主动操作'), val('A', '主动', '需要用户主动操作')],
  },
  VC: {
    key: 'VC', name: '机密性影响', en: 'Confidentiality (Vulnerable System)',
    values: [val('H', '高', '完全丢失机密性'), val('L', '低', '部分丢失机密性'), val('N', '无', '无影响')],
  },
  VI: {
    key: 'VI', name: '完整性影响', en: 'Integrity (Vulnerable System)',
    values: [val('H', '高', '完全丧失完整性'), val('L', '低', '部分丧失完整性'), val('N', '无', '无影响')],
  },
  VA: {
    key: 'VA', name: '可用性影响', en: 'Availability (Vulnerable System)',
    values: [val('H', '高', '完全不可用'), val('L', '低', '部分降级'), val('N', '无', '无影响')],
  },
  SC: {
    key: 'SC', name: '后续系统机密性', en: 'Confidentiality (Subsequent System)',
    values: [val('N', '无', '无影响'), val('L', '低', '部分影响'), val('H', '高', '完全影响')],
  },
  SI: {
    key: 'SI', name: '后续系统完整性', en: 'Integrity (Subsequent System)',
    values: [val('N', '无', '无影响'), val('L', '低', '部分影响'), val('H', '高', '完全影响')],
  },
  SA: {
    key: 'SA', name: '后续系统可用性', en: 'Availability (Subsequent System)',
    values: [val('N', '无', '无影响'), val('L', '低', '部分影响'), val('H', '高', '完全影响')],
  },

  // --- Threat ---------------------------------------------------------------
  E: {
    key: 'E', name: '利用成熟度', en: 'Exploit Maturity',
    values: [
      val('X', '未定义', '不应用该指标，按最坏情况（Attacked）计'),
      val('A', '已利用', '已观察到实际攻击或公开的利用工具'),
      val('P', '概念验证', '存在公开 PoC，但未观察到实际利用'),
      val('U', '未报告', '无公开 PoC，也未观察到利用'),
    ],
  },

  // --- Environmental: security requirements --------------------------------
  CR: {
    key: 'CR', name: '机密性需求', en: 'Confidentiality Requirement',
    values: [val('X', '未定义', '不应用该指标，按 High 计'), val('H', '高', '机密性至关重要'), val('M', '中', '机密性较为重要'), val('L', '低', '机密性影响有限')],
  },
  IR: {
    key: 'IR', name: '完整性需求', en: 'Integrity Requirement',
    values: [val('X', '未定义', '不应用该指标，按 High 计'), val('H', '高', '完整性至关重要'), val('M', '中', '完整性较为重要'), val('L', '低', '完整性影响有限')],
  },
  AR: {
    key: 'AR', name: '可用性需求', en: 'Availability Requirement',
    values: [val('X', '未定义', '不应用该指标，按 High 计'), val('H', '高', '可用性至关重要'), val('M', '中', '可用性较为重要'), val('L', '低', '可用性影响有限')],
  },

  // --- Environmental: modified base metrics --------------------------------
  MAV: {
    key: 'MAV', name: '修正-攻击途径', en: 'Modified Attack Vector',
    values: [val('X', '未定义', '沿用基础指标'), val('N', '网络'), val('A', '相邻'), val('L', '本地'), val('P', '物理')],
  },
  MAC: {
    key: 'MAC', name: '修正-攻击复杂度', en: 'Modified Attack Complexity',
    values: [val('X', '未定义', '沿用基础指标'), val('L', '低'), val('H', '高')],
  },
  MAT: {
    key: 'MAT', name: '修正-攻击要求', en: 'Modified Attack Requirements',
    values: [val('X', '未定义', '沿用基础指标'), val('N', '无'), val('P', '存在')],
  },
  MPR: {
    key: 'MPR', name: '修正-所需权限', en: 'Modified Privileges Required',
    values: [val('X', '未定义', '沿用基础指标'), val('N', '无'), val('L', '低'), val('H', '高')],
  },
  MUI: {
    key: 'MUI', name: '修正-用户交互', en: 'Modified User Interaction',
    values: [val('X', '未定义', '沿用基础指标'), val('N', '无'), val('P', '被动'), val('A', '主动')],
  },
  MVC: {
    key: 'MVC', name: '修正-机密性影响', en: 'Modified Confidentiality',
    values: [val('X', '未定义', '沿用基础指标'), val('H', '高'), val('L', '低'), val('N', '无')],
  },
  MVI: {
    key: 'MVI', name: '修正-完整性影响', en: 'Modified Integrity',
    values: [val('X', '未定义', '沿用基础指标'), val('H', '高'), val('L', '低'), val('N', '无')],
  },
  MVA: {
    key: 'MVA', name: '修正-可用性影响', en: 'Modified Availability',
    values: [val('X', '未定义', '沿用基础指标'), val('H', '高'), val('L', '低'), val('N', '无')],
  },
  MSC: {
    key: 'MSC', name: '修正-后续系统机密性', en: 'Modified Confidentiality (Subsequent)',
    values: [val('X', '未定义', '沿用基础指标'), val('H', '高'), val('L', '低'), val('N', '无')],
  },
  MSI: {
    key: 'MSI', name: '修正-后续系统完整性', en: 'Modified Integrity (Subsequent)',
    values: [val('X', '未定义', '沿用基础指标'), val('S', '安全', '后续系统受到安全保护'), val('H', '高'), val('L', '低'), val('N', '无')],
  },
  MSA: {
    key: 'MSA', name: '修正-后续系统可用性', en: 'Modified Availability (Subsequent)',
    values: [val('X', '未定义', '沿用基础指标'), val('S', '安全', '后续系统受到安全保护'), val('H', '高'), val('L', '低'), val('N', '无')],
  },

  // --- Supplemental ---------------------------------------------------------
  S: {
    key: 'S', name: '安全性影响', en: 'Safety',
    values: [val('X', '未定义', '未评估'), val('N', '可忽略', '不构成安全后果'), val('P', '存在', '可能造成人身/环境安全后果')],
  },
  AU: {
    key: 'AU', name: '可自动化', en: 'Automatable',
    values: [val('X', '未定义', '未评估'), val('N', '否', '无法可靠自动化完成杀伤链'), val('Y', '是', '可自动化跨目标利用')],
  },
  R: {
    key: 'R', name: '恢复难度', en: 'Recovery',
    values: [val('X', '未定义', '未评估'), val('A', '自动', '可自动恢复'), val('U', '用户', '需用户干预恢复'), val('I', '不可恢复', '无法恢复')],
  },
  V: {
    key: 'V', name: '价值密度', en: 'Value Density',
    values: [val('X', '未定义', '未评估'), val('D', '分散', '单个目标价值有限'), val('C', '集中', '单个目标价值高')],
  },
  RE: {
    key: 'RE', name: '响应力度', en: 'Vulnerability Response Effort',
    values: [val('X', '未定义', '未评估'), val('L', '低', '官方修复，升级即可'), val('M', '中', '需临时缓解或配置调整'), val('H', '高', '无官方修复，需自行缓解')],
  },
  U: {
    key: 'U', name: '提供者紧迫度', en: 'Provider Urgency',
    values: [
      val('X', '未定义', '未评估'), val('Clear', '一般', '可常规处理'),
      val('Green', '低', '低紧迫度'), val('Amber', '中', '中紧迫度'), val('Red', '高', '高紧迫度'),
    ],
  },
};

export const METRIC_ORDER = [
  'AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA',
  'E',
  'CR', 'IR', 'AR',
  'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA',
  'S', 'AU', 'R', 'V', 'RE', 'U',
];

export const BASE_METRICS = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];
export const THREAT_METRICS = ['E'];
export const SECURITY_REQUIREMENT_METRICS = ['CR', 'IR', 'AR'];
export const MODIFIED_METRICS = ['MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA'];
export const ENVIRONMENTAL_METRICS = [...SECURITY_REQUIREMENT_METRICS, ...MODIFIED_METRICS];
export const SUPPLEMENTAL_METRICS = ['S', 'AU', 'R', 'V', 'RE', 'U'];

export const METRIC_GROUPS = [
  {
    id: 'base', title: '基础指标', en: 'Base', hint: '必填，决定基础分 CVSS-B', metrics: BASE_METRICS,
  },
  {
    id: 'threat', title: '威胁指标', en: 'Threat', hint: '可选，决定威胁分 CVSS-BT', metrics: THREAT_METRICS,
  },
  {
    id: 'environmental', title: '环境指标', en: 'Environmental', hint: '可选，决定环境分 CVSS-BTE',
    subgroups: [
      { id: 'modified', title: '修正基础指标', metrics: MODIFIED_METRICS },
      { id: 'reqs', title: '安全需求', metrics: SECURITY_REQUIREMENT_METRICS },
    ],
  },
  {
    id: 'supplemental', title: '补充指标', en: 'Supplemental', hint: '可选，不影响评分，仅供决策参考', metrics: SUPPLEMENTAL_METRICS,
  },
];

export const METRIC_GROUP_BY_KEY = Object.fromEntries(
  METRIC_GROUPS.flatMap((group) => {
    const lists = group.subgroups ? group.subgroups.map((s) => s.metrics) : [group.metrics];
    return lists.flat().map((key) => [key, group.id]);
  }),
);

export const DEFAULT_METRIC_VALUES = Object.fromEntries(
  METRIC_ORDER.map((key) => [key, METRICS[key].values[0].value]),
);

// Defaults used when building a new vector from scratch: a mild-but-valid base
// (all impacts None => score 0.0 until the user edits it).
export const BASE_BUILDER_DEFAULTS = {
  AV: 'N', AC: 'L', AT: 'N', PR: 'N', UI: 'N',
  VC: 'N', VI: 'N', VA: 'N', SC: 'N', SI: 'N', SA: 'N',
  ...Object.fromEntries([...ENVIRONMENTAL_METRICS, ...SUPPLEMENTAL_METRICS, ...THREAT_METRICS].map((k) => [k, 'X'])),
};

export function metricLabel(key) {
  const m = METRICS[key];
  return m ? `${m.name}（${key}）` : key;
}

export function valueLabel(key, value) {
  const m = METRICS[key];
  const v = m?.values.find((x) => x.value === value);
  return v ? `${value}（${v.label}）` : value;
}

export const SEVERITY_LABELS = {
  Critical: '严重',
  High: '高危',
  Medium: '中危',
  Low: '低危',
  None: '无',
};

export const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'None'];
