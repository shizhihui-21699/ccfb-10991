<script>
  import { SEVERITY_SLA_DAYS } from '../lib/priority.js';
  import { SEVERITY_LABELS, SEVERITY_ORDER } from '../lib/cvss/metrics.js';

  // Policy editor: weights for the risk composite and per-severity SLA windows.
  // Everything recomputes live in the queue underneath.
  let { policy, onchange = () => {}, onreset = () => {} } = $props();

  let weights = $derived(policy.weights);
  let total = $derived(weights.severity + weights.epss + weights.asset);
  let pct = (n) => (total > 0 ? Math.round((n / total) * 100) : 0);

  function setWeight(key, value) {
    const n = Math.max(0, Number(value));
    onchange({ ...policy, weights: { ...weights, [key]: Number.isFinite(n) ? n : 0 } });
  }

  function setDays(sev, value) {
    const n = Number(value);
    onchange({
      ...policy,
      slaDays: { ...policy.slaDays, [sev]: Number.isFinite(n) && n >= 0 ? Math.round(n) : SEVERITY_SLA_DAYS[sev] },
    });
  }
</script>

<div class="policy">
  <section>
    <h4>风险权重</h4>
    <p class="hint">三项权重会自动归一化；EPSS 缺失时按剩余权重重新归一，不会压低排名。</p>
    {#each [['severity', '严重度（CVSS）'], ['epss', 'EPSS 概率'], ['asset', '资产重要性']] as [key, label]}
      <div class="weight-row">
        <label for="w-{key}">{label}</label>
        <input
          type="range" min="0" max="1" step="0.05"
          value={weights[key]}
          oninput={(e) => setWeight(key, e.currentTarget.value)}
          aria-label="{label} 权重"
        />
        <input
          id="w-{key}"
          type="number" min="0" max="1" step="0.05"
          value={weights[key]}
          onchange={(e) => setWeight(key, e.currentTarget.value)}
        />
        <span class="pct mono">{pct(weights[key])}%</span>
      </div>
    {/each}
  </section>

  <section>
    <h4>SLA 窗口（天）</h4>
    <p class="hint">截止日期 = 发现日期 + 该严重度对应的天数；逾期在列表中实时标红。</p>
    <div class="days-grid">
      {#each SEVERITY_ORDER as sev}
        <div class="day-row">
          <span class="sev-dot {sev}"></span>
          <label for="sla-{sev}">{SEVERITY_LABELS[sev]}</label>
          <input
            id="sla-{sev}"
            type="number" min="0" max="3650" step="1"
            value={policy.slaDays[sev]}
            onchange={(e) => setDays(sev, e.currentTarget.value)}
          />
        </div>
      {/each}
    </div>
  </section>

  <div class="footer">
    <button class="ghost" onclick={onreset}>恢复默认策略</button>
  </div>
</div>

<style>
  .policy { display: flex; flex-direction: column; gap: 12px; }
  section { display: flex; flex-direction: column; gap: 5px; }
  h4 { margin: 0; font-size: 12px; }
  .hint { margin: 0 0 3px; font-size: 10.5px; color: var(--text-faint); }
  .weight-row { display: grid; grid-template-columns: 108px 1fr 56px 36px; gap: 7px; align-items: center; }
  .weight-row label { font-size: 11.5px; color: var(--text-dim); }
  .weight-row input[type="number"] { font-family: var(--mono); font-size: 11.5px; width: 100%; }
  .pct { font-size: 10.5px; color: var(--text-faint); text-align: right; }
  .days-grid { display: flex; flex-direction: column; gap: 4px; }
  .day-row { display: grid; grid-template-columns: 8px 1fr 62px; gap: 7px; align-items: center; }
  .day-row label { font-size: 11.5px; }
  .day-row input { font-family: var(--mono); font-size: 11.5px; }
  .sev-dot { width: 6px; height: 6px; border-radius: 50%; }
  .sev-dot.Critical { background: var(--sev-critical); }
  .sev-dot.High { background: var(--sev-high); }
  .sev-dot.Medium { background: var(--sev-medium); }
  .sev-dot.Low { background: var(--sev-low); }
  .sev-dot.None { background: var(--sev-none); }
  .footer { border-top: 1px solid var(--border); padding-top: 8px; }
  .footer button { font-size: 11px; }
</style>
