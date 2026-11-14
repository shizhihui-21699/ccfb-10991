<script>
  import { SEVERITY_ORDER, SEVERITY_LABELS } from '../lib/cvss/metrics.js';
  import { STATUSES } from '../lib/priority.js';

  // Filter rail above the queue: free-text, severity, SLA state, status, asset
  // importance floor, EPSS-known toggle. All client-side, no server.
  let {
    filters = {},
    onChange = () => {},
    total = 0,
    shown = 0,
    severityCounts = {},
  } = $props();

  const set = (patch) => onChange({ ...filters, ...patch });
  const countFor = (sev) => severityCounts[sev] ?? 0;

  function toggleSeverity(sev) {
    const current = new Set(filters.severities ?? []);
    if (current.has(sev)) current.delete(sev);
    else current.add(sev);
    set({ severities: [...current] });
  }

  let activeCount = $derived(
    (filters.text ? 1 : 0) +
      (filters.severities?.length ? 1 : 0) +
      (filters.slaState && filters.slaState !== 'any' ? 1 : 0) +
      (filters.status && filters.status !== 'any' ? 1 : 0) +
      (filters.minAsset && filters.minAsset > 1 ? 1 : 0) +
      (filters.epssOnly ? 1 : 0),
  );
</script>

<div class="filters">
  <div class="search">
    <input
      type="search"
      placeholder="搜索标题 / CVE / 资产 / 负责人"
      value={filters.text ?? ''}
      oninput={(e) => set({ text: e.currentTarget.value })}
      aria-label="搜索漏洞"
    />
  </div>

  <div class="chips" role="group" aria-label="按严重度筛选">
    {#each SEVERITY_ORDER as sev}
      <button
        class="chip {sev}"
        class:on={(filters.severities ?? []).includes(sev)}
        onclick={() => toggleSeverity(sev)}
      >
        {SEVERITY_LABELS[sev]}
        <span class="count">{countFor(sev)}</span>
      </button>
    {/each}
  </div>

  <div class="selects">
    <select value={filters.slaState ?? 'any'} onchange={(e) => set({ slaState: e.currentTarget.value })} aria-label="按 SLA 状态筛选">
      <option value="any">SLA：全部</option>
      <option value="overdue">仅逾期</option>
      <option value="due_soon">即将到期（≤3 天）</option>
      <option value="not_overdue">未逾期</option>
    </select>

    <select value={filters.status ?? 'any'} onchange={(e) => set({ status: e.currentTarget.value })} aria-label="按处置状态筛选">
      <option value="any">状态：全部</option>
      <option value="active">仅待处置</option>
      {#each STATUSES as s (s.value)}
        <option value={s.value}>{s.label}</option>
      {/each}
    </select>

    <select value={filters.minAsset ?? 1} onchange={(e) => set({ minAsset: Number(e.currentTarget.value) })} aria-label="资产重要性下限">
      {#each [1, 2, 3, 4, 5] as n}
        <option value={n}>资产 ≥ {n}</option>
      {/each}
    </select>

    <label class="toggle">
      <input type="checkbox" checked={filters.epssOnly ?? false} onchange={(e) => set({ epssOnly: e.currentTarget.checked })} />
      仅已知 EPSS
    </label>
  </div>

  <div class="summary">
    <span>{shown} / {total} 条</span>
    {#if activeCount > 0}
      <button class="ghost" onclick={() => onChange({})}>清除筛选（{activeCount}）</button>
    {/if}
  </div>
</div>

<style>
  .filters { display: flex; flex-wrap: wrap; gap: 7px 10px; align-items: center; padding: 8px 12px; border-bottom: 1px solid var(--border); background: var(--bg-raised); }
  .search input { width: 220px; }
  .chips { display: flex; gap: 4px; }
  .chip {
    font-size: 11px; padding: 2px 7px; border-radius: 20px; border: 1px solid var(--border);
    background: var(--bg-sunken); color: var(--text-faint); display: inline-flex; gap: 5px; align-items: center;
  }
  .chip:hover { border-color: var(--border-strong); color: var(--text-dim); }
  .chip.critical.on { color: var(--sev-critical); border-color: #5c2020; background: var(--tone-critical-bg); }
  .chip.high.on { color: var(--sev-high); border-color: #5a3a18; background: var(--tone-high-bg); }
  .chip.medium.on { color: var(--sev-medium); border-color: #55460f; background: var(--tone-medium-bg); }
  .chip.low.on { color: var(--sev-low); border-color: #1d4327; background: var(--tone-low-bg); }
  .chip.none.on { color: var(--text-dim); border-color: var(--border-strong); background: #1c2129; }
  .count { font-size: 9.5px; opacity: 0.75; font-family: var(--mono); }
  .selects { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; font-size: 11.5px; }
  .selects select { font-size: 11.5px; padding: 3px 5px; }
  .toggle { display: inline-flex; gap: 4px; align-items: center; font-size: 11.5px; color: var(--text-dim); cursor: pointer; }
  .summary { display: flex; gap: 6px; align-items: center; font-size: 11px; color: var(--text-faint); margin-left: auto; }
  .summary button { font-size: 10.5px; padding: 1px 5px; }
</style>
