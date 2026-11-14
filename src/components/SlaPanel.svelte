<script>
  import { STATUSES } from '../lib/priority.js';

  // SLA window per severity, and the deadline for this finding. Overdue rows are
  // shown in red everywhere in the desk; this panel states the numbers.
  let { sla = null, status = 'open', onstatus = () => {}, statuses = STATUSES } = $props();

  let stateText = $derived(
    sla?.state === 'overdue'
      ? `已逾期 ${Math.abs(sla.daysRemaining)} 天`
      : sla?.state === 'due_soon'
        ? `剩 ${sla.daysRemaining} 天`
        : sla?.state === 'closed'
          ? '已关闭'
          : sla?.state === 'unknown'
            ? '发现日期缺失'
            : `剩 ${sla?.daysRemaining ?? '—'} 天`,
  );
</script>

<div class="sla-panel">
  <div class="grid">
    <div>
      <span class="k">SLA 窗口</span>
      <span class="v">{sla?.days ?? '—'} 天</span>
    </div>
    <div>
      <span class="k">截止日期</span>
      <span class="v mono" class:overdue-text={sla?.state === 'overdue'} class:due-soon-text={sla?.state === 'due_soon'}>
        {sla?.dueDateText || '—'}
      </span>
    </div>
    <div>
      <span class="k">剩余</span>
      <span class="v" class:overdue-text={sla?.state === 'overdue'} class:due-soon-text={sla?.state === 'due_soon'}>{stateText}</span>
    </div>
  </div>

  <div class="status-row">
    <label for="status">处置状态</label>
    <select id="status" value={status} onchange={(e) => onstatus(e.currentTarget.value)}>
      {#each statuses as s (s.value)}
        <option value={s.value}>{s.label}</option>
      {/each}
    </select>
  </div>
</div>

<style>
  .sla-panel { display: flex; flex-direction: column; gap: 8px; }
  .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
  .grid > div {
    display: flex; flex-direction: column; gap: 1px;
    background: var(--bg-sunken); border: 1px solid var(--border);
    border-radius: var(--radius-sm); padding: 5px 8px;
  }
  .k { font-size: 10.5px; color: var(--text-faint); }
  .v { font-size: 13px; font-weight: 600; }
  .status-row { display: flex; align-items: center; gap: 8px; }
  .status-row label { font-size: 11.5px; color: var(--text-dim); }
  .status-row select { flex: 1; max-width: 180px; }
</style>
