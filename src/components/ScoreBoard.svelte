<script>
  import SeverityBadge from './SeverityBadge.svelte';

  // Score dashboard: the three official CVSS v4.0 scores (Base / Threat / Environmental),
  // which one the queue actually ranks on, and the macrovector audit trail.
  let { cvss = null } = $props();

  let ok = $derived(cvss?.ok === true);

  let rows = $derived(
    ok
      ? [
          { id: 'base', label: '基础', en: 'CVSS-B', ...cvss.base },
          { id: 'threat', label: '威胁', en: 'CVSS-BT', ...cvss.threat },
          { id: 'environmental', label: '环境', en: 'CVSS-BTE', ...cvss.environmental },
        ]
      : [],
  );

  // Which of the three scores the supplied vector actually resolves to.
  let activeId = $derived(
    cvss?.nomenclature === 'CVSS-BTE' ? 'environmental'
      : cvss?.nomenclature === 'CVSS-BT' ? 'threat'
        : 'base',
  );
</script>

{#if !ok}
  <div class="card invalid">
    <h3>向量无法评分</h3>
    {#if cvss?.errors?.length}
      <ul>
        {#each cvss.errors as e}
          <li><code>{e.code}</code> {e.message}</li>
        {/each}
      </ul>
    {:else}
      <p>尚未提供有效的 CVSS 向量。</p>
    {/if}
  </div>
{:else}
  <div class="scores">
    {#each rows as row (row.id)}
      <div class="score-cell" class:active={row.id === activeId}>
        <span class="label">
          {row.label}<span class="en">{row.en}</span>
          {#if row.id === activeId}<span class="used">排序采用</span>{/if}
        </span>
        <span class="num" style:color="var(--sev-{(row.severity ?? 'none').toLowerCase()})">{row.score.toFixed(1)}</span>
        <SeverityBadge severity={row.severity} score={null} size="small" />
        <span class="macro mono" title="等价类（宏向量）">{row.macro}</span>
      </div>
    {/each}
  </div>

  <div class="audit">
    <span class="tag">按实际提供的指标计分：<strong class="mono">{cvss.nomenclature}</strong></span>
    <span class="tag">最终分 <strong class="mono">{cvss.score.toFixed(1)}</strong></span>
    {#each cvss.warnings ?? [] as w}<span class="tag warn">{w}</span>{/each}
  </div>
{/if}

<style>
  .scores { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 7px; }
  .score-cell {
    background: var(--bg-sunken);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 7px 9px;
    display: flex;
    flex-direction: column;
    gap: 2px;
    position: relative;
    min-width: 0;
  }
  .score-cell.active { border-color: #2a4a7a; background: #141c28; }
  .score-cell.active::before {
    content: ''; position: absolute; left: 0; top: 8px; bottom: 8px; width: 2px;
    background: var(--accent); border-radius: 2px;
  }
  .label { font-size: 11px; color: var(--text-dim); display: flex; gap: 5px; align-items: baseline; flex-wrap: wrap; }
  .label .en { font-size: 9.5px; color: var(--text-faint); letter-spacing: 0.3px; }
  .used { font-size: 9px; color: var(--accent); border: 1px solid var(--accent-dim); border-radius: 3px; padding: 0 3px; }
  .num { font-family: var(--mono); font-size: 21px; font-weight: 600; line-height: 1.1; letter-spacing: -0.5px; }
  .macro { font-size: 10px; color: var(--text-faint); font-family: var(--mono); }
  .audit { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 7px; }
  .audit strong { color: var(--text); }
  .tag.warn { color: var(--sev-medium); border-color: #55460f; background: var(--tone-medium-bg); }
  .invalid { padding: 10px 12px; border-color: #5c2020; }
  .invalid h3 { margin: 0 0 5px; font-size: 12.5px; color: var(--sev-critical); }
  .invalid ul { margin: 0; padding-left: 16px; font-size: 11.5px; color: #ffc9c4; }
  .invalid code { font-family: var(--mono); font-size: 10px; }
</style>
