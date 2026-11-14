<script>
  import SeverityBadge from './SeverityBadge.svelte';
  import { STATUSES } from '../lib/priority.js';
  import { SEVERITY_LABELS } from '../lib/cvss/metrics.js';

  let {
    rows = [],
    sort = 'priority',
    selectedId = null,
    onsort = () => {},
    onselect = () => {},
    onopen = () => {},
  } = $props();

  const statusLabel = (value) => STATUSES.find((s) => s.value === value)?.label ?? value;

  let columns = $derived([
    { id: 'priority', label: '优先级', sortable: true },
    { id: 'risk', label: '风险分', sortable: true },
    { id: 'cve', label: '漏洞', sortable: false },
    { id: 'cvss', label: 'CVSS', sortable: true },
    { id: 'epss', label: 'EPSS', sortable: true },
    { id: 'asset', label: '资产', sortable: false },
    { id: 'due', label: 'SLA 截止', sortable: true },
    { id: 'status', label: '状态', sortable: false },
  ]);

  function sortKey(columnId) {
    if (columnId === 'risk') return 'priority';
    if (columnId === 'cvss') return 'cvss';
    if (columnId === 'epss') return 'epss';
    if (columnId === 'due') return 'due';
    return 'priority';
  }
</script>

<div class="table-wrap">
  <table>
    <thead>
      <tr>
        {#each columns as col}
          <th class={col.id}>
            {#if col.sortable}
              <button class="sort" class:active={sort === sortKey(col.id)} onclick={() => onsort(sortKey(col.id))}>
                {col.label}
                <span class="arrow">{sort === sortKey(col.id) ? '↓' : ''}</span>
              </button>
            {:else}
              {col.label}
            {/if}
          </th>
        {/each}
      </tr>
    </thead>
    <tbody>
      {#each rows as row (row.id)}
        <tr
          class:selected={row.id === selectedId}
          class:overdue={row.sla.state === 'overdue'}
          class:closed={row.sla.state === 'closed'}
          onclick={() => onselect(row.id)}
          ondblclick={() => onopen(row.id)}
          tabindex="0"
          onkeydown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              onselect(row.id);
            }
          }}
        >
          <td class="priority">
            <span class="prio {row.priority.tone}">{row.priority.id}</span>
            <span class="prio-label">{row.priority.label.split(' ')[1] ?? ''}</span>
          </td>
          <td class="num">
            <div class="risk-cell">
              <span class="risk-value">{row.risk.score}</span>
              <span class="risk-bar"><i style:width="{row.risk.score}%"></i></span>
            </div>
          </td>
          <td class="vuln-cell">
            <div class="vuln-title" title={row.title}>{row.title || '（未命名漏洞）'}</div>
            <div class="vuln-sub">
              {#if row.cve}<span class="mono cve">{row.cve}</span>{/if}
              {#if !row.cvss.ok}<span class="invalid-flag" title={row.cvss.errors?.[0]?.message ?? ''}>向量无效</span>{/if}
            </div>
          </td>
          <td>
            {#if row.cvss.ok}
              <SeverityBadge severity={row.cvss.severity} score={row.cvss.score} />
            {:else}
              <span class="muted">—</span>
            {/if}
          </td>
          <td class="num mono">{row.epss === null || row.epss === undefined ? '—' : (Number(row.epss) * 100).toFixed(1) + '%'}</td>
          <td class="asset-cell">
            <div class="asset-name" title={row.assetName}>{row.assetName || '未指定'}</div>
            <div class="asset-imp">重要性 {row.assetImportance}</div>
          </td>
          <td class="due">
            <div class="mono" class:overdue-text={row.sla.state === 'overdue'} class:due-soon-text={row.sla.state === 'due_soon'}>
              {row.sla.dueDateText || '—'}
            </div>
            {#if row.sla.state === 'overdue'}
              <div class="due-sub overdue-text">逾期 {Math.abs(row.sla.daysRemaining)} 天</div>
            {:else if row.sla.state === 'due_soon'}
              <div class="due-sub due-soon-text">剩 {row.sla.daysRemaining} 天</div>
            {:else if row.sla.state === 'closed'}
              <div class="due-sub muted">已关闭</div>
            {:else if row.sla.state !== 'unknown'}
              <div class="due-sub muted">剩 {row.sla.daysRemaining} 天</div>
            {/if}
          </td>
          <td class="status-cell">
            <span class="status {row.status}">{statusLabel(row.status)}</span>
          </td>
        </tr>
      {:else}
        <tr class="empty-row">
          <td colspan={columns.length}>
            <p>没有匹配的漏洞。调整筛选条件，或导入 / 新增一条记录。</p>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .table-wrap { overflow: auto; height: 100%; }
  table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 12.5px; }
  thead th {
    position: sticky; top: 0; z-index: 2;
    background: var(--bg-raised);
    border-bottom: 1px solid var(--border-strong);
    text-align: left; padding: 0; height: 30px;
    font-size: 11px; font-weight: 600; color: var(--text-dim);
    letter-spacing: 0.3px; white-space: nowrap;
  }
  thead th:not(:first-child) { padding: 0 8px; }
  thead th:first-child { padding-left: 12px; }
  .sort {
    background: none; border: none; padding: 6px 0; color: inherit;
    font-size: 11px; font-weight: 600; display: inline-flex; gap: 3px; align-items: center;
  }
  .sort:hover { color: var(--text); }
  .sort.active { color: var(--accent); }
  .arrow { font-size: 9px; }
  tbody tr { border-bottom: 1px solid var(--border); cursor: pointer; }
  tbody tr:hover { background: #171d25; }
  tbody tr.selected { background: #16233a; box-shadow: inset 2px 0 0 var(--accent); }
  tbody tr.closed { opacity: 0.55; }
  tbody tr.overdue td { background: rgba(248, 81, 73, 0.045); }
  tbody tr.overdue.selected { background: #2a1a22; }
  td { padding: 7px 8px; vertical-align: middle; border-bottom: 1px solid var(--border); }
  td:first-child { padding-left: 12px; }
  .num { font-family: var(--mono); text-align: right; }
  thead th.num { text-align: right; }
  .priority { white-space: nowrap; }
  .prio {
    display: inline-block; font-family: var(--mono); font-size: 11px; font-weight: 700;
    padding: 0 5px; border-radius: 3px; margin-right: 4px;
  }
  .prio.critical { color: #ffd9d6; background: #6b1d1d; }
  .prio.high { color: #ffe2bf; background: #5e3d14; }
  .prio.medium { color: #f4e4b0; background: #55460f; }
  .prio.low { color: var(--sev-low); background: #1a3323; }
  .prio-label { font-size: 10px; color: var(--text-faint); }
  .risk-cell { display: flex; flex-direction: column; align-items: flex-end; gap: 2px; min-width: 54px; }
  .risk-value { font-size: 12.5px; font-weight: 600; }
  .risk-bar { width: 46px; height: 3px; background: #1a2029; border-radius: 2px; overflow: hidden; }
  .risk-bar i { display: block; height: 100%; background: linear-gradient(90deg, var(--sev-medium), var(--sev-critical)); }
  .vuln-cell { max-width: 320px; }
  .vuln-title { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-weight: 500; }
  .vuln-sub { display: flex; gap: 6px; align-items: center; margin-top: 1px; }
  .cve { font-size: 10.5px; color: var(--text-dim); }
  .invalid-flag {
    font-size: 10px; color: var(--sev-critical); background: var(--tone-critical-bg);
    border: 1px solid #5c2020; border-radius: 3px; padding: 0 4px;
  }
  .asset-cell { max-width: 150px; }
  .asset-name { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .asset-imp { font-size: 10px; color: var(--text-faint); }
  .due { white-space: nowrap; }
  .due-sub { font-size: 10px; }
  .status { font-size: 11px; }
  .status.resolved { color: var(--sev-low); }
  .status.in_progress { color: var(--accent); }
  .status.risk_accepted { color: var(--sev-medium); }
  .status.false_positive { color: var(--text-faint); text-decoration: line-through; }
  .muted { color: var(--text-faint); }
  .empty-row td { padding: 40px 12px; text-align: center; color: var(--text-faint); }
</style>
