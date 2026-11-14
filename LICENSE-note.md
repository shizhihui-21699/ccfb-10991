# 第三方内容说明

- `src/lib/cvss/lookup.js` 的常量表（宏向量评分表、指标层级、最高严重度向量、最大严重度距离）
  提取自 FIRST / Red Hat 的 CVSS v4.0 计算器：
  https://github.com/RedHatProductSecurity/cvss-v4-calculator
  许可证：BSD-2-Clause。该实现本身依据 FIRST CVSS v4.0 规范：
  https://www.first.org/cvss/v4.0/specification-document

- `tests/fixtures/official-vectors.json` 的测试向量来自：
  https://github.com/RedHatProductSecurity/cvss/tree/master/tests
  许可证：MIT。仅用于评分正确性对照。

- 下载到 `tools/data/official/` 的完整向量集不纳入版本库，可用
  `tools/scripts/fetch-official-vectors.mjs` 重新获取。
