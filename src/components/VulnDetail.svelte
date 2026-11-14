<script>
  import SeverityBadge from './SeverityBadge.svelte';
  import VectorField from './VectorField.svelte';
  import MetricBuilder from './MetricBuilder.svelte';
  import ScoreBoard from './ScoreBoard.svelte';
  import RiskInputs from './RiskInputs.svelte';
  import SlaPanel from './SlaPanel.svelte';
  import { SAMPLE_ASSETS_ZH } from '../lib/assets.js';
  import { STATUSES } from '../lib/priority.js';
  import { buildVector } from '../lib/cvss/parser.js';
  import { enrich } from '../lib/model.js';
  import { SEVERITY_LABELS } from '../lib/cvss/metrics.js';

  let {
    vuln,
    policy,
    mode = 'edit', // 'new' | 'edit'
    invalidFields = {},
    oncancel = () => {},
    onsavemetrics = () => {},
    onmeta = () => {},
    onrequestdelete = () => {},
  } = $props();

  // Live preview: enrich the record as it stands, so every edit shows its score,
  // risk rank and SLA deadline immediately.
  let preview = $derived(enrich(vuln, { weights: policy.weights, slaDays: policy.slaDays }));

  let builderOpen = $state(false);
  let saveError = $state('');

  function setMetric(nextMetrics) {
    onsavemetrics(buildVector(nextMetrics));
  }

  function handleVector(value) {
    onsavemetrics(value);
  }

  function patch(field, value) {
    onmeta({ [field]: value });
  }

  function save() {
    saveError = '';
    if (!preview.cvss.ok) {
      saveError = 'CVSS 向量无效，无法保存。请查看向量输入框中的具体错误。';
      return;
    }
    if (!vuln.title.trim() && !vuln.cve.trim()) {
      saveError = '请至少填写标题或 CVE 编号。';
      return;
    }
    onsavemetrics(vuln.vector, { commit: true });
  }
</script>

<div class="detail">
  <header>
    <div class="heading">
      <div class="meta-row">
        {#if mode === 'edit' && preview.cvss.ok}
          <SeverityBadge severity={preview.cvss.severity} score={preview.cvss.score} size="small" />
        {/if}
        {#if mode === 'new'}
          <span class="eyebrow">新增漏洞</span>
        {:else}
          <span class="eyebrow mono">{vuln.cve || '未登记 CVE'}</span>
          <span class="eyebrow">· {vuln.assetName || '未指定资产'}</span>
        {/if}
      </div>
      <div class="actions">
        {#if mode === 'edit'}
          <button class="danger" onclick={onrequestdelete}>删除</button>
        {/if}
        <button onclick={oncancel}>取消</button>
        <button class="primary" onclick={save}>{mode === 'new' ? '创建' : '保存'}</button>
      </div>
    </div>
    <h2>{vuln.title || '（未命名漏洞）'}</h2>
    {#if saveError}<p class="save-error">{saveError}</p>{/if}
  </header>

  <div class="meta-grid card">
    <div class="field wide">
      <label for="f-title">标题</label>
      <input
        id="f-title"
        type="text"
        placeholder="例如：内部 API 网关的 JWT 校验绕过"
        class:invalid={invalidFields.title}
        value={vuln.title}
        oninput={(e) => patch('title', e.currentTarget.value)}
      />
    </div>
    <div class="field">
      <label for="f-cve">CVE 编号</label>
      <input
        id="f-cve"
        type="text"
        placeholder="CVE-2026-12345"
        class="mono"
        value={vuln.cve}
        oninput={(e) => patch('cve', e.currentTarget.value)}
      />
    </div>
    <div class="field">
      <label for="f-discovered">发现日期</label>
      <input
        id="f-discovered"
        type="date"
        class:invalid={invalidFields.discoveredAt}
        value={vuln.discoveredAt}
        onchange={(e) => patch('discoveredAt', e.currentTarget.value)}
      />
    </div>
    <div class="field">
      <label for="f-owner">负责人</label>
      <input id="f-owner" type="text" placeholder="可选" value={vuln.owner} oninput={(e) => patch('owner', e.currentTarget.value)} />
    </div>
    <div class="field wide">
      <label for="f-notes">备注</label>
      <textarea id="f-notes" rows="2" placeholder="缓解措施、验证细节等" value={vuln.notes} oninput={(e) => patch('notes', e.currentTarget.value)}></textarea>
    </div>
  </div>

  <section class="card block">
    <div class="block-head">
      <h3>CVSS 4.0 向量</h3>
      <div class="head-actions">
        <span class="tag">基础 / 威胁 / 环境 / 补充</span>
        <button class="ghost" onclick={() => (builderOpen = !builderOpen)}>
          {builderOpen ? '收起指标选择器' : '按指标逐项选择'}
        </button>
      </div>
    </div>
    <VectorField id="f-vector" value={vuln.vector} onchange={handleVector} />
    {#if builderOpen}
      <div class="builder-wrap">
        <MetricBuilder
          metrics={preview.cvss.ok ? preview.cvss.metrics : {}}
          onchange={setMetric}
        />
      </div>
    {/if}
    <ScoreBoard cvss={preview.cvss} />
  </section>

  <div class="two-col">
    <section class="card block">
      <div class="block-head"><h3>优先级输入</h3></div>
      <RiskInputs
        epss={vuln.epss}
        assetImportance={vuln.assetImportance}
        assetName={vuln.assetName}
        risk={preview.risk}
        weights={policy.weights}
        onepss={(v) => patch('epss', v)}
        onasset={(v) => patch('assetImportance', v)}
        onassetName={(v) => patch('assetName', v)}
      />
    </section>

    <section class="card block">
      <div class="block-head">
        <h3>SLA 与处置</h3>
        {#if preview.priority}
          <span class="tag prio">{preview.priority.label} · 风险分 {preview.risk.score}</span>
        {/if}
      </div>
      <SlaPanel
        sla={{ ...preview.sla, severity: preview.cvss.severity }}
        status={vuln.status}
        onstatus={(v) => patch('status', v)}
        statuses={STATUSES}
      />
    </section>
  </div>

  {#if mode === 'edit' && !preview.cvss.ok}
    <p class="hint-inline">评分与 SLA 暂不可用：先修正向量错误。</p>
  {/if}
</div>

<style>
  .detail { display: flex; flex-direction: column; gap: 12px; padding: 14px 16px 22px; min-width: 0; }
  .detail > * { min-width: 0; }
  header { display: flex; flex-direction: column; gap: 6px; }
  .heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; min-width: 0; }
  .meta-row { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; min-width: 0; flex: 1; }
  .eyebrow { font-size: 10.5px; color: var(--text-faint); letter-spacing: 0.3px; }
  h2 { margin: 0; font-size: 16.5px; font-weight: 650; letter-spacing: -0.2px; line-height: 1.4; }
  .actions { display: flex; gap: 6px; flex-shrink: 0; align-items: center; }
  .save-error { margin: 0; font-size: 11.5px; color: var(--sev-critical); }
  .meta-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 9px 12px; padding: 11px 12px;
  }
  .field { display: flex; flex-direction: column; gap: 3px; }
  .field.wide { grid-column: span 2; }
  .field label { font-size: 11px; color: var(--text-dim); }
  .field input, .field textarea { width: 100%; }
  textarea { resize: vertical; min-height: 48px; }
  .block { padding: 11px 12px; display: flex; flex-direction: column; gap: 9px; }
  .block-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
  h3 { margin: 0; font-size: 12.5px; font-weight: 600; }
  .head-actions { display: flex; gap: 6px; align-items: center; }
  .builder-wrap { border-top: 1px dashed var(--border); padding-top: 9px; }
  .two-col { display: grid; grid-template-columns: minmax(0, 1fr); gap: 12px; }
  .tag.prio { color: var(--accent); border-color: var(--accent-dim); background: #16233a; }
  .hint-inline { margin: 0; font-size: 11.5px; color: var(--text-faint); }

  @media (max-width: 820px) {
    .field.wide { grid-column: span 1; }
  }
</style>
