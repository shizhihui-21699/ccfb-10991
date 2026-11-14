<script>
  import { ASSET_IMPORTANCE_LEVELS } from '../lib/priority.js';

  // Risk inputs: EPSS probability (with "unknown" as a first-class state) and asset
  // importance. Shows how the 0-100 risk score is composed so the rank is explainable.
  let {
    epss = null,
    assetImportance = 3,
    assetName = '',
    risk = null,
    weights,
    onepss = () => {},
    onasset = () => {},
    onassetName = () => {},
  } = $props();

  let epssKnown = $derived(epss !== null && epss !== undefined);
  let epssText = $derived(epssKnown ? Number(epss) : '');

  function handleEpss(event) {
    const raw = event.currentTarget.value.trim();
    if (raw === '') return onepss(null);
    const n = Number(raw);
    if (Number.isFinite(n)) onepss(Math.min(1, Math.max(0, n)));
  }

  function handlePercent(event) {
    const n = Number(event.currentTarget.value);
    if (Number.isFinite(n)) onepss(Math.round(n * 10) / 1000);
  }
</script>

<div class="risk-inputs">
  <div class="row">
    <label for="epss">EPSS 概率<span class="hint">30 天内被利用</span></label>
    <div class="epss-control">
      <input
        id="epss"
        type="number"
        min="0"
        max="1"
        step="0.001"
        placeholder="未知"
        value={epssText}
        onchange={handleEpss}
      />
      <input
        type="range"
        min="0"
        max="1"
        step="0.001"
        value={epssKnown ? Number(epss) : 0}
        oninput={handlePercent}
        aria-label="EPSS 滑块"
      />
      <span class="pct mono">{epssKnown ? `${(Number(epss) * 100).toFixed(1)}%` : '未获取'}</span>
    </div>
  </div>

  <div class="row">
    <label for="asset-importance">资产重要性</label>
    <div class="asset-control">
      <select id="asset-importance" value={assetImportance} onchange={(e) => onasset(Number(e.currentTarget.value))}>
        {#each ASSET_IMPORTANCE_LEVELS as level (level.value)}
          <option value={level.value}>{level.value} · {level.label} — {level.hint}</option>
        {/each}
      </select>
      <input
        type="text"
        placeholder="资产名称（可选）"
        value={assetName}
        oninput={(e) => onassetName(e.currentTarget.value)}
      />
    </div>
  </div>

  {#if risk}
    <div class="composition" aria-label="风险分构成">
      <div class="bar">
        {#if risk.contributions.severity > 0}
          <span class="seg sev" style:width="{risk.contributions.severity}%" title="严重度贡献 {risk.contributions.severity}"></span>
        {/if}
        {#if risk.contributions.epss !== null && risk.contributions.epss > 0}
          <span class="seg epss" style:width="{risk.contributions.epss}%" title="EPSS 贡献 {risk.contributions.epss}"></span>
        {/if}
        {#if risk.contributions.asset > 0}
          <span class="seg asset" style:width="{risk.contributions.asset}%" title="资产贡献 {risk.contributions.asset}"></span>
        {/if}
      </div>
      <div class="legend">
        <span><i class="sw sev"></i>严重度 {risk.contributions.severity}</span>
        <span><i class="sw epss"></i>EPSS {risk.contributions.epss ?? '未计入'}</span>
        <span><i class="sw asset"></i>资产 {risk.contributions.asset}</span>
        <span class="total">风险分 <strong>{risk.score}</strong></span>
      </div>
      {#if !risk.epssKnown}
        <p class="note">EPSS 未知：已按剩余权重归一化，不会因缺数据被压低排名。</p>
      {/if}
      <p class="weights mono">
        权重 严重度 {Math.round(risk.weights.severity * 100)}% / EPSS {Math.round(risk.weights.epss * 100)}% / 资产 {Math.round(risk.weights.asset * 100)}%
      </p>
    </div>
  {/if}
</div>

<style>
  .risk-inputs { display: flex; flex-direction: column; gap: 9px; min-width: 0; }
  .row { display: flex; flex-direction: column; gap: 4px; }
  label { font-size: 11.5px; color: var(--text-dim); display: flex; gap: 6px; align-items: baseline; }
  .hint { font-size: 10px; color: var(--text-faint); }
  .epss-control { display: grid; grid-template-columns: 78px minmax(40px, 1fr) 54px; gap: 8px; align-items: center; min-width: 0; }
  .epss-control input[type="number"] { font-family: var(--mono); font-size: 12px; }
  .pct { font-size: 11.5px; color: var(--text-dim); text-align: right; }
  .asset-control { display: grid; grid-template-columns: minmax(0, 3fr) minmax(0, 2fr); gap: 8px; }
  .composition { background: var(--bg-sunken); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 7px 9px; }
  .bar { display: flex; height: 7px; border-radius: 4px; overflow: hidden; background: #1a2029; }
  .seg.sev { background: var(--sev-critical); }
  .seg.epss { background: var(--accent); }
  .seg.asset { background: var(--sev-low); }
  .legend { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 5px; font-size: 10.5px; color: var(--text-dim); }
  .legend .total { margin-left: auto; color: var(--text); }
  .legend strong { font-family: var(--mono); font-size: 13px; }
  .sw { display: inline-block; width: 7px; height: 7px; border-radius: 2px; margin-right: 3px; vertical-align: middle; }
  .sw.sev { background: var(--sev-critical); }
  .sw.epss { background: var(--accent); }
  .sw.asset { background: var(--sev-low); }
  .note { margin: 4px 0 0; font-size: 10.5px; color: var(--sev-medium); }
  .weights { margin: 3px 0 0; font-size: 10px; color: var(--text-faint); }
</style>
