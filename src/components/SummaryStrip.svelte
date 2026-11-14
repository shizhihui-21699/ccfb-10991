<script>
  import { SEVERITY_LABELS, SEVERITY_ORDER } from '../lib/cvss/metrics.js';

  // Dashboard strip: queue health at a glance, with overdue as a first-class metric.
  let { summary = null, counts = {} } = $props();

  let items = $derived([
    { id: 'total', label: '漏洞总数', value: summary?.total ?? 0, tone: '' },
    { id: 'open', label: '待处置', value: summary?.open ?? 0, tone: 'neutral' },
    { id: 'overdue', label: 'SLA 逾期', value: summary?.overdue ?? 0, tone: summary?.overdue > 0 ? 'bad' : 'good' },
    { id: 'due_soon', label: '即将到期', value: summary?.dueSoon ?? 0, tone: summary?.dueSoon > 0 ? 'warn' : '' },
    { id: 'avg', label: '平均风险分', value: summary?.averageRisk ?? 0, tone: '' },
  ]);
</script>

<div class="dashboard">
  <div class="stats">
    {#each items as item (item.id)}
      <div class="stat {item.tone}">
        <span class="value">{item.value}</span>
        <span class="label">{item.label}</span>
      </div>
    {/each}
  </div>

  <div class="severity-strip" aria-label="严重度分布">
    {#each SEVERITY_ORDER as sev}
      {#if counts[sev]}
        <span class="sev-slice {sev}" style:flex="{counts[sev]}" title="{SEVERITY_LABELS[sev]} {counts[sev]} 条"></span>
      {/if}
    {/each}
  </div>
</div>

<style>
  .dashboard { display: flex; flex-direction: column; gap: 8px; }
  .stats { display: flex; gap: 6px; flex-wrap: wrap; }
  .stat {
    display: flex; flex-direction: column; gap: 0; min-width: 82px;
    background: var(--bg-sunken); border: 1px solid var(--border);
    border-radius: var(--radius-sm); padding: 5px 9px;
  }
  .value { font-family: var(--mono); font-size: 17px; font-weight: 600; line-height: 1.2; }
  .label { font-size: 10.5px; color: var(--text-faint); }
  .stat.bad { border-color: #5c2020; background: var(--tone-critical-bg); }
  .stat.bad .value { color: var(--sev-critical); }
  .stat.warn { border-color: #55460f; background: var(--tone-medium-bg); }
  .stat.warn .value { color: var(--sev-medium); }
  .stat.good .value { color: var(--sev-low); }
  .severity-strip { display: flex; height: 5px; border-radius: 3px; overflow: hidden; background: #1a2029; }
  .sev-slice { display: block; min-width: 3px; }
  .sev-slice.Critical { background: var(--sev-critical); }
  .sev-slice.High { background: var(--sev-high); }
  .sev-slice.Medium { background: var(--sev-medium); }
  .sev-slice.Low { background: var(--sev-low); }
  .sev-slice.None { background: var(--sev-none); }
</style>
