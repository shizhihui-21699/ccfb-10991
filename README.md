# 漏洞优先级排序台

一个纯前端的漏洞分诊工作台：按 **CVSS v4.0 完整规范**（基础 / 威胁 / 环境 / 补充四组指标，宏向量 + 插值评分）计算严重度，结合 **EPSS** 与**资产重要性**排出修复顺序，并按严重度给出 **SLA 截止日期**（逾期标红）。

用 Svelte 5 + Vite 编写，无后端、无外部依赖服务，数据保存在浏览器本地。

```bash
npm install
npm run dev      # http://localhost:5173
npm test         # 859 项测试，含官方向量对照
npm run build
```

## 功能

**评分：CVSS v4.0 全指标**
- 11 个基础指标（AV/AC/AT/PR/UI/VC/VI/VA/SC/SI/SA）
- 威胁指标 E（`X` 按最坏情况 `A` 处理，与规范一致）
- 14 个环境指标（CR/IR/AR 三个安全需求 + 11 个 M* 修正指标）
- 6 个补充指标（S/AU/R/V/RE/U，不参与评分，仅作决策参考）
- 同时给出 **CVSS-B / CVSS-BT / CVSS-BTE** 三个官方分数，并标出当前向量实际采用的是哪一个
- 评分严格按规范的等价类（EQ1–EQ6 → 宏向量）、宏向量查表、MSD 与严重度距离插值、`0.0` 短路径、1 位小数四舍五入实现
- 展示宏向量，便于人工复核

**向量字符串校验**
- 非法输入逐项报错：错误码、出错位置、指标名、非法取值、该指标的合法取值列表
- 覆盖：空向量、缺前缀、版本不符、空字段、缺 `:`、多 `:`、未知指标、非法取值、重复指标、缺必填指标、首尾空白、末尾 `/`
- 给出修正提示（大小写、`M` 前缀拼写、相近指标名）
- 指标顺序不影响合法性（与官方计算器一致），乱序时给出提示并把向量规范化后回写

**优先级排序**
```
风险分 = 100 × (w_严重度·CVSS/10 + w_EPSS·EPSS + w_资产·(重要性-1)/4) / Σw
```
- 权重可在界面调整并实时重算，默认 50% / 30% / 20%
- EPSS 缺失时按剩余权重重新归一化，而不是当 0 处理（避免因缺数据被压低排名）
- 分为 P1–P4 四档，列表可点列头按风险 / CVSS / EPSS / SLA 排序

**SLA**
- 默认窗口：严重 7 天、高危 14 天、中危 30 天、低危 90 天、无 180 天，可在策略面板中修改
- 截止日期 = 发现日期 + 窗口；逾期与即将到期（≤3 天）分别用红色 / 橙色标出
- 已修复、风险接受、误报不计逾期

**导入 / 导出**
- 导入：JSON（本工具格式）、CSV（中英文表头均可）、每行一条 `CVSS:4.0/...` 的向量清单
- 导入是全有或全无，逐行报告行号、字段与具体错误，不会静默丢弃
- 导出的 JSON 可原样回导；另提供含优先级与 SLA 的排期 CSV

## 评分实现如何验证

`src/lib/cvss/lookup.js` 中的常量表从 FIRST / Red Hat 官方计算器
（[RedHatProductSecurity/cvss-v4-calculator](https://github.com/RedHatProductSecurity/cvss-v4-calculator)，BSD-2-Clause）
提取，评分逻辑按 FIRST CVSS v4.0 规范独立实现。

对照测试使用 Red Hat 官方仓库 `tests/vectors_*4` 的全部测试向量：

| 测试集 | 向量数 | 覆盖 |
| --- | --- | --- |
| `vectors_base4` | 104,976 | 基础指标全组合 |
| `vectors_modified4` | 373,248 | 环境修正指标全组合 |
| `vectors_random4` | 100,000 | 全指标随机组合 |
| `vectors_simple4` | 1,058 | 各指标的代表性组合 |
| `vectors_threat4` / `vectors_security4` / `vectors_supplemental4` | 636 | E、CR/IR/AR、6 个补充指标全组合 |

```bash
node tools/scripts/fetch-official-vectors.mjs   # 下载官方数据（~74 MB，未入库）
node tools/scripts/verify-all-vectors.mjs       # 全量校验
```

实测结果：**579,918 / 579,918 全部一致**。

仓库内另有 `tests/fixtures/official-vectors.json`（776 条，从上述文件抽样 + 小文件全量），
`npm test` 无需下载即可跑这份对照。抽样规则见 `tools/scripts/make-fixtures.mjs`。

## 项目结构

```
src/
  App.svelte                  主界面（队列 + 详情/编辑面板 + 策略抽屉）
  components/
    VulnTable.svelte          队列表格（逾期标红）
    FilterBar.svelte          搜索 / 严重度 / SLA / 状态 / 资产 / EPSS 筛选
    SummaryStrip.svelte       概览指标与严重度分布
    VulnDetail.svelte         新增与编辑
    VectorField.svelte        向量输入（实时逐项校验）
    MetricBuilder.svelte      按指标逐项选择（四组指标）
    ScoreBoard.svelte         CVSS-B / BT / BTE 三档分数与宏向量
    RiskInputs.svelte         EPSS 与资产重要性（含风险分构成）
    SlaPanel.svelte           SLA 截止与处置状态
    PolicyPanel.svelte        权重与 SLA 策略
    DataDialog.svelte         导入 / 导出
  lib/
    cvss/metrics.js           指标定义（取值、中文标签、分组）
    cvss/parser.js            向量解析与逐项诊断
    cvss/score.js             等价类、宏向量、插值、三档评分
    cvss/lookup.js            官方常量表（脚本生成）
    priority.js               风险合成、SLA、排序
    model.js                  记录校验与派生字段
    policy.js                 策略合并与校验
    io.js                     导入导出（JSON / CSV / 向量清单）
    view.js                   筛选
    storage.js  sample.js     本地存储与示例数据
tests/                        Vitest 测试
tools/                        官方数据下载、常量提取、全量校验、浏览器交互脚本
```

## 说明与边界

- **补充指标不影响分数**，这是规范定义；界面上单独标注，避免误以为改了分会变。
- 向量中的指标顺序不参与合法性判定，但导出时统一规范化为规范顺序。
- 资产重要性 1–5 由使用者按资产登记信息填写，工具不做推测；EPSS 需从 FIRST EPSS 数据源获取后录入（未内置定时拉取）。
- 数据只存在浏览器 `localStorage`；存储不可用时降级为仅本页有效，并在顶部提示。
