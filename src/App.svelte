<script>
  import VulnTable from './components/VulnTable.svelte';
  import FilterBar from './components/FilterBar.svelte';
  import SummaryStrip from './components/SummaryStrip.svelte';
  import VulnDetail from './components/VulnDetail.svelte';
  import PolicyPanel from './components/PolicyPanel.svelte';
  import DataDialog from './components/DataDialog.svelte';

  import { loadState, saveState, download, timestampedName, clearState } from './lib/storage.js';
  import { coalescePolicy, DEFAULT_POLICY } from './lib/policy.js';
  import { enrich, summarise, emptyVuln, validateVuln } from './lib/model.js';
  import { sortVulns } from './lib/priority.js';
  import { applyFilters, emptyFilters, severityCounts } from './lib/view.js';
  import { exportCsv, exportJson, exportTriageList } from './lib/io.js';
  import { sampleVulns } from './lib/sample.js';
  import { parseVector, buildVector } from './lib/cvss/parser.js';

  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------
  const loaded = loadState();
  let vulns = $state(loaded.vulns ?? sampleVulns());
  let policy = $state(coalescePolicy(loaded.policy ?? DEFAULT_POLICY));
  let filters = $state(emptyFilters());
  let sort = $state('priority');
  let selectedId = $state(null);
  let editing = $state(null); // draft record while creating/editing
  let dialog = $state(null); // 'import' | 'export' | 'policy' | null
  let exportFormat = $state('json');
  let toast = $state(null);
  let persistWarning = $state(loaded.persisted === false ? '本地存储不可用，更改只保留在当前页面。' : '');

  const now = new Date();

  // ---------------------------------------------------------------------------
  // Derived
  // ---------------------------------------------------------------------------
  let enriched = $derived(enrichAll(vulns));
  let filtered = $derived(applyFilters(enriched, filters));
  let ordered = $derived(sortVulns(filtered, sort));
  let summary = $derived(summarise(enriched, { now }));
  let counts = $derived(severityCounts(enriched));
  let selected = $derived(enriched.find((v) => v.id === selectedId) ?? null);

  function enrichAll(list) {
    return list.map((v) => enrich(v, { weights: policy.weights, slaDays: policy.slaDays, now }));
  }

  // ---------------------------------------------------------------------------
  // Persistence
  // ---------------------------------------------------------------------------
  function persist(nextVulns = vulns, nextPolicy = policy) {
    const result = saveState({ vulns: nextVulns, policy: nextPolicy });
    if (!result.ok) persistWarning = result.reason;
  }

  function notify(message, tone = 'ok') {
    toast = { message, tone };
    setTimeout(() => {
      if (toast?.message === message) toast = null;
    }, 3200);
  }

  // ---------------------------------------------------------------------------
  // Mutations
  // ---------------------------------------------------------------------------
  function replaceVuln(id, patch, { save = true } = {}) {
    vulns = vulns.map((v) => (v.id === id ? { ...v, ...patch, updatedAt: new Date().toISOString() } : v));
    if (save) persist();
  }

  function addRecord(raw) {
    const validated = validateVuln(raw);
    if (!validated.ok) return { ok: false, errors: validated.errors };
    vulns = [validated.value, ...vulns];
    persist();
    return { ok: true, record: validated.value };
  }

  function deleteVuln(id) {
    const target = enriched.find((v) => v.id === id);
    if (!target) return;
    if (!confirm(`删除「${target.title || target.cve || '该漏洞'}」？此操作不可撤销。`)) return;
    vulns = vulns.filter((v) => v.id !== id);
    if (selectedId === id) selectedId = null;
    if (editing?.id === id) editing = null;
    persist();
    notify('已删除。', 'ok');
  }

  // ---------------------------------------------------------------------------
  // Editing
  // ---------------------------------------------------------------------------
  function startCreate() {
    const draft = emptyVuln();
    editing = { mode: 'new', draft };
  }

  function startEdit(id) {
    const v = vulns.find((x) => x.id === id);
    if (!v) return;
    selectedId = id;
    editing = { mode: 'edit', draft: { ...v } };
  }

  function saveDraft() {
    if (!editing) return;
    const raw = editing.draft;
    const validated = validateVuln(raw);
    if (!validated.ok) {
      notify(validated.errors[0].message, 'bad');
      return;
    }
    if (editing.mode === 'new') {
      vulns = [validated.value, ...vulns];
      selectedId = validated.value.id;
      notify('已创建。', 'ok');
    } else {
      vulns = vulns.map((v) =>
        v.id === validated.value.id
          ? { ...validated.value, updatedAt: new Date().toISOString() }
          : v,
      );
      selectedId = validated.value.id;
      notify('已保存。', 'ok');
    }
    persist();
    editing = null;
  }

  function discardDraft() {
    editing = null;
  }

  // ---------------------------------------------------------------------------
  // Import / export
  // ---------------------------------------------------------------------------
  let exportText = $derived.by(() => {
    if (dialog !== 'export') return '';
    if (exportFormat === 'json') return exportJson(vulns, policy);
    if (exportFormat === 'csv') return exportCsv(vulns);
    return exportTriageList(enriched);
  });

  function openExport() {
    dialog = 'export';
  }

  function downloadExport() {
    const ext = exportFormat === 'json' ? 'json' : 'csv';
    const mime = exportFormat === 'json' ? 'application/json' : 'text/csv';
    download(timestampedName('vuln-priority-desk', ext), exportText, mime);
    notify('已开始下载。', 'ok');
  }

  async function copyExport() {
    try {
      await navigator.clipboard.writeText(exportText);
      notify('已复制到剪贴板。', 'ok');
    } catch {
      notify('复制失败，请手动选择文本复制。', 'bad');
    }
  }

  function handleImport(records, { filename } = {}) {
    // Merge: same id replaced, everything else appended. Vector-list imports get
    // readable placeholder titles so they are not anonymous rows.
    const byId = new Map(vulns.map((v) => [v.id, v]));
    let added = 0;
    let updated = 0;
    for (const record of records) {
      const normalised = {
        ...record,
        title: record.title || (record.cve ? record.cve : `导入自 ${filename || '向量清单'}`),
      };
      if (byId.has(normalised.id)) {
        byId.set(normalised.id, { ...normalised, updatedAt: new Date().toISOString() });
        updated += 1;
      } else {
        byId.set(normalised.id, normalised);
        added += 1;
      }
    }
    vulns = [...byId.values()];
    persist();
    dialog = null;
    notify(`导入完成：新增 ${added} 条，更新 ${updated} 条。`, 'ok');
  }

  function resetPolicy() {
    policy = coalescePolicy(DEFAULT_POLICY);
    persist(vulns, policy);
    notify('已恢复默认策略。', 'ok');
  }

  function updatePolicy(next) {
    policy = coalescePolicy(next);
    persist(vulns, policy);
  }

  // ---------------------------------------------------------------------------
  // Keyboard
  // ---------------------------------------------------------------------------
  function handleKeydown(event) {
    if (dialog || editing) {
      if (event.key === 'Escape') {
        if (editing) editing = null;
        else dialog = null;
      }
      return;
    }
    if (event.key === 'n' && !event.metaKey && !event.ctrlKey && !isTyping(event.target)) {
      event.preventDefault();
      startCreate();
    }
    if (event.key === 'Escape') selectedId = null;
  }

  function isTyping(target) {
    const tag = target?.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target?.isContentEditable;
  }
</script>

<svelte:window onkeydown={handleKeydown} />

<div class="shell">
  <header class="topbar">
    <div class="brand">
      <span class="logo">CVSS 4.0</span>
      <h1>漏洞优先级排序台</h1>
    </div>
    <div class="top-actions">
      <button onclick={() => (dialog = 'policy')}>策略</button>
      <button onclick={() => (dialog = 'import')}>导入</button>
      <button onclick={openExport}>导出</button>
      <button class="primary" onclick={startCreate}>+ 新增漏洞</button>
    </div>
  </header>

  {#if persistWarning}
    <div class="banner">{persistWarning}</div>
  {/if}

  <main class="layout">
    <section class="queue" aria-label="漏洞队列">
      <div class="queue-head">
        <SummaryStrip {summary} {counts} />
      </div>
      <FilterBar
        {filters}
        onChange={(next) => (filters = next)}
        total={enriched.length}
        shown={filtered.length}
        severityCounts={counts}
      />
      <div class="queue-table">
        <VulnTable
          rows={ordered}
          {sort}
          {selectedId}
          onsort={(s) => (sort = s)}
          onselect={(id) => (selectedId = id)}
          onopen={(id) => startEdit(id)}
        />
      </div>
    </section>

    <aside class="side" class:open={Boolean(editing || selected)} aria-label="详情与策略">
      <button class="side-close" onclick={() => { if (editing) discardDraft(); else selectedId = null; }} aria-label="关闭详情面板">✕</button>
      {#if editing}
        <VulnDetail
          vuln={editing.draft}
          {policy}
          mode={editing.mode}
          oncancel={discardDraft}
          onsavemetrics={(vector, opts) => {
            editing.draft = { ...editing.draft, vector };
            if (opts?.commit) saveDraft();
          }}
          onmeta={(patch) => (editing.draft = { ...editing.draft, ...patch })}
          onrequestdelete={() => {
            const id = editing.draft.id;
            deleteVuln(id);
          }}
        />
      {:else if selected}
        <div class="panel-stack">
          <header class="side-head">
            <div>
              <span class="eyebrow">{selected.cve || '未登记 CVE'}</span>
              <h2>{selected.title || '（未命名漏洞）'}</h2>
            </div>
            <button class="primary" onclick={() => startEdit(selected.id)}>编辑</button>
          </header>
          <div class="readout card">
            <p class="vector mono" title={selected.vector}>{selected.vector}</p>
            <div class="readout-grid">
              <div><span class="k">CVSS</span><span class="v">{selected.cvss.ok ? selected.cvss.score.toFixed(1) : '无效'}</span></div>
              <div><span class="k">风险分</span><span class="v">{selected.risk.score}</span></div>
              <div><span class="k">优先级</span><span class="v">{selected.priority.id}</span></div>
              <div><span class="k">SLA</span><span class="v" class:overdue-text={selected.sla.overdue}>{selected.sla.dueDateText || '—'}</span></div>
            </div>
            {#if !selected.cvss.ok}
              <ul class="readout-errors">
                {#each selected.cvss.errors.slice(0, 4) as e}
                  <li><code>{e.code}</code> {e.message}</li>
                {/each}
              </ul>
            {/if}
            {#if selected.notes}<p class="notes">{selected.notes}</p>{/if}
          </div>
        </div>
      {:else}
        <div class="empty-side">
          <h2>从左侧选择一条漏洞</h2>
          <p>查看评分构成、风险来源与 SLA，或按 <kbd>N</kbd> 新建一条记录。</p>
          <p class="hint">评分按 FIRST CVSS v4.0 规范的宏向量 + 插值规则计算，基础 / 威胁 / 环境 / 补充四组指标全部支持。</p>
        </div>
      {/if}
    </aside>
  </main>

  {#if dialog === 'policy'}
    <div class="drawer-overlay" role="presentation" onclick={(e) => e.target === e.currentTarget && (dialog = null)}>
      <div class="drawer card" role="dialog" aria-modal="true" aria-label="排序策略">
        <header>
          <h2>排序与 SLA 策略</h2>
          <button class="ghost" onclick={() => (dialog = null)} aria-label="关闭">✕</button>
        </header>
        <PolicyPanel {policy} onchange={updatePolicy} onreset={resetPolicy} />
      </div>
    </div>
  {/if}

  {#if dialog === 'import' || dialog === 'export'}
    <DataDialog
      mode={dialog}
      {exportText}
      {exportFormat}
      onformat={(f) => (exportFormat = f)}
      ondownload={downloadExport}
      onimport={handleImport}
      oncopy={copyExport}
      onclose={() => (dialog = null)}
    />
  {/if}

  {#if toast}
    <div class="toast {toast.tone}" role="status">{toast.message}</div>
  {/if}
</div>

<style>
  .shell { height: 100%; display: flex; flex-direction: column; }
  .topbar {
    display: flex; justify-content: space-between; align-items: center;
    padding: 8px 14px; border-bottom: 1px solid var(--border-strong);
    background: var(--bg-raised); flex-shrink: 0;
  }
  .brand { display: flex; align-items: baseline; gap: 10px; }
  .logo {
    font-family: var(--mono); font-size: 10px; letter-spacing: 0.6px;
    color: var(--accent); border: 1px solid var(--accent-dim); background: #16233a;
    border-radius: 4px; padding: 1px 6px;
  }
  h1 { margin: 0; font-size: 15px; font-weight: 650; letter-spacing: -0.2px; }
  .top-actions { display: flex; gap: 6px; }
  .banner {
    padding: 4px 14px; font-size: 11.5px; background: var(--tone-medium-bg);
    color: var(--sev-medium); border-bottom: 1px solid #55460f;
  }
  .layout { flex: 1; display: grid; grid-template-columns: minmax(0, 1fr) 430px; min-height: 0; }
  .queue { display: flex; flex-direction: column; min-width: 0; min-height: 0; border-right: 1px solid var(--border-strong); }
  .queue-head { padding: 9px 12px; border-bottom: 1px solid var(--border); }
  .queue-table { flex: 1; min-height: 0; overflow: hidden; }
  .side { min-height: 0; overflow: auto; background: var(--bg); }
  .side-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 10px; padding: 14px 16px 0; }
  .side-head > div { min-width: 0; }
  .side-head h2 { margin: 2px 0 0; font-size: 15.5px; font-weight: 650; line-height: 1.35; }
  .eyebrow {
    display: block; font-size: 10.5px; color: var(--text-faint);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .panel-stack { display: flex; flex-direction: column; gap: 11px; padding-bottom: 16px; }
  .readout { margin: 0 16px; padding: 10px 11px; display: flex; flex-direction: column; gap: 8px; }
  .vector { margin: 0; font-size: 10.5px; color: var(--text-dim); word-break: break-all; line-height: 1.45; }
  .readout-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 7px; }
  .readout-grid > div { display: flex; flex-direction: column; background: var(--bg-sunken); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 4px 7px; }
  .k { font-size: 10px; color: var(--text-faint); }
  .v { font-family: var(--mono); font-size: 14px; font-weight: 600; }
  .readout-errors { margin: 0; padding-left: 16px; font-size: 11px; color: #ffc9c4; }
  .readout-errors code { font-family: var(--mono); font-size: 10px; }
  .notes { margin: 0; font-size: 11.5px; color: var(--text-dim); border-top: 1px dashed var(--border); padding-top: 7px; }
  .empty-side { padding: 28px 20px; display: flex; flex-direction: column; gap: 8px; }
  .empty-side h2 { margin: 0; font-size: 14px; }
  .empty-side p { margin: 0; font-size: 12px; color: var(--text-dim); line-height: 1.6; }
  .empty-side .hint { color: var(--text-faint); font-size: 11px; }
  kbd { font-family: var(--mono); font-size: 10.5px; background: var(--bg-sunken); border: 1px solid var(--border-strong); border-radius: 3px; padding: 0 4px; }
  .drawer-overlay { position: fixed; inset: 0; background: rgba(5, 8, 12, 0.6); z-index: 40; display: flex; justify-content: flex-end; }
  .drawer { width: min(380px, 100%); height: 100%; border-radius: 0; border-right: none; display: flex; flex-direction: column; }
  .drawer header { display: flex; justify-content: space-between; align-items: center; padding: 11px 13px; border-bottom: 1px solid var(--border); }
  .drawer h2 { margin: 0; font-size: 13.5px; }
  .drawer :global(.policy) { padding: 12px 13px; }
  .toast {
    position: fixed; bottom: 18px; left: 50%; transform: translateX(-50%);
    padding: 7px 14px; border-radius: var(--radius); font-size: 12px; z-index: 60;
    background: var(--bg-raised); border: 1px solid var(--border-strong); box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  }
  .toast.ok { border-color: #1d4327; color: #b7e4c4; }
  .toast.bad { border-color: #5c2020; color: #ffc9c4; }

  .side-close { display: none; }

  /* Narrow screens: the detail/edit panel becomes an overlay drawer instead of a
     second column, so the queue keeps the full width and editing still works. */
  @media (max-width: 1080px) {
    .layout { grid-template-columns: minmax(0, 1fr); }
    .side {
      position: fixed; top: 0; right: 0; bottom: 0; width: min(460px, 100%);
      background: var(--bg); border-left: 1px solid var(--border-strong);
      z-index: 30; box-shadow: -12px 0 32px rgba(0, 0, 0, 0.45);
      transform: translateX(100%); transition: transform 0.18s ease;
      visibility: hidden;
    }
    .side.open { transform: translateX(0); visibility: visible; }
    .side-close {
      display: block; position: absolute; top: 9px; right: 9px; z-index: 2;
      padding: 1px 6px; font-size: 12px;
    }
    .side-head { padding-right: 44px; }
  }
</style>
