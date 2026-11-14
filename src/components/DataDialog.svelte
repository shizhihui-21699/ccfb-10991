<script>
  import { importData } from '../lib/io.js';

  // Import/export dialog. Import is all-or-nothing and every rejected row is listed
  // with its row number and the offending metric, so nothing is silently dropped.
  let {
    mode = 'import', // 'import' | 'export'
    exportText = '',
    exportFormat = 'json',
    onformat = () => {},
    ondownload = () => {},
    onclose = () => {},
    onimport = () => {},
    oncopy = () => {},
  } = $props();

  let pasted = $state('');
  let filename = $state('');
  let report = $state(null);
  let busy = $state(false);

  async function handleFile(event) {
    const file = event.currentTarget.files?.[0];
    if (!file) return;
    filename = file.name;
    if (file.size > 8 * 1024 * 1024) {
      report = { ok: false, errors: [{ row: 0, field: '_', message: '文件超过 8 MB，请拆分后导入。' }] };
      return;
    }
    pasted = await file.text();
    preview();
  }

  function preview() {
    if (!pasted.trim()) {
      report = null;
      return;
    }
    report = importData(pasted, { filename });
  }

  function confirmImport() {
    if (!report?.ok) return;
    busy = true;
    onimport(report.records, { filename });
    busy = false;
  }

  const MAX_ERRORS_SHOWN = 40;
</script>

<div class="overlay" role="presentation" onclick={(e) => e.target === e.currentTarget && onclose()}>
  <div class="dialog card" role="dialog" aria-modal="true" aria-label={mode === 'import' ? '导入漏洞数据' : '导出漏洞数据'}>
    <header>
      <h2>{mode === 'import' ? '导入' : '导出'}</h2>
      <button class="ghost close" onclick={onclose} aria-label="关闭">✕</button>
    </header>

    {#if mode === 'import'}
      <div class="body">
        <p class="lead">支持 JSON（本工具导出格式）、CSV（中文或英文表头）、以及每行一条 <code class="mono">CVSS:4.0/...</code> 的向量清单。</p>

        <div class="file-row">
          <label class="file-button">
            选择文件
            <input type="file" accept=".json,.csv,.txt,text/plain,application/json,text/csv" onchange={handleFile} />
          </label>
          {#if filename}<span class="filename mono">{filename}</span>{/if}
        </div>

        <label class="paste-label" for="paste">或粘贴内容</label>
        <textarea
          id="paste"
          class="mono"
          rows="7"
          placeholder={'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N\nCVSS:4.0/... - 9.3'}
          bind:value={pasted}
          oninput={preview}
        ></textarea>

        {#if report}
          {#if report.ok}
            <div class="report ok">
              <strong>校验通过</strong>：{report.records.length} 条记录可导入（格式：{report.detected}）。
              {#if report.records.length}
                <ul class="preview-list">
                  {#each report.records.slice(0, 5) as r}
                    <li>
                      <span class="mono">{r.cve || r.vector.slice(0, 48) + '…'}</span>
                      {#if r.title}<span class="dim">{r.title}</span>{/if}
                    </li>
                  {/each}
                  {#if report.records.length > 5}<li class="dim">… 其余 {report.records.length - 5} 条</li>{/if}
                </ul>
              {/if}
            </div>
          {:else}
            <div class="report bad">
              <strong>发现 {report.errors.length} 个问题，未导入任何记录</strong>
              <ul class="error-list">
                {#each report.errors.slice(0, MAX_ERRORS_SHOWN) as err}
                  <li>
                    <span class="row-badge">第 {err.row} 行</span>
                    {#if err.cve}<span class="mono dim">{err.cve}</span>{/if}
                    <span class="field-badge mono">{err.field}</span>
                    <span>{err.message}</span>
                    {#if err.detail?.hint}<span class="dim">{err.detail.hint}</span>{/if}
                  </li>
                {/each}
                {#if report.errors.length > MAX_ERRORS_SHOWN}
                  <li class="dim">… 还有 {report.errors.length - MAX_ERRORS_SHOWN} 个问题未显示</li>
                {/if}
              </ul>
            </div>
          {/if}
        {/if}
      </div>

      <footer>
        <span class="hint">导入会与现有记录合并，不会覆盖。</span>
        <div class="actions">
          <button onclick={onclose}>取消</button>
          <button class="primary" disabled={!report?.ok || busy} onclick={confirmImport}>
            导入{report?.ok ? ` ${report.records.length} 条` : ''}
          </button>
        </div>
      </footer>
    {:else}
      <div class="body">
        <div class="format-tabs">
          <button class:active={exportFormat === 'json'} onclick={() => onformat('json')}>JSON（可回导）</button>
          <button class:active={exportFormat === 'csv'} onclick={() => onformat('csv')}>CSV（表格）</button>
          <button class:active={exportFormat === 'triage'} onclick={() => onformat('triage')}>排期清单（含优先级/SLA）</button>
        </div>
        <textarea class="mono" rows="12" readonly value={exportText}></textarea>
      </div>
      <footer>
        <span class="hint">{exportText.split('\n').length - 1} 行</span>
        <div class="actions">
          <button onclick={oncopy}>复制</button>
          <button class="primary" onclick={ondownload}>下载文件</button>
        </div>
      </footer>
    {/if}
  </div>
</div>

<style>
  .overlay {
    position: fixed; inset: 0; background: rgba(5, 8, 12, 0.72);
    display: flex; align-items: center; justify-content: center; z-index: 50; padding: 20px;
  }
  .dialog {
    width: min(760px, 100%); max-height: 86vh; display: flex; flex-direction: column;
    background: var(--bg-raised); box-shadow: 0 18px 48px rgba(0, 0, 0, 0.55);
  }
  header { display: flex; justify-content: space-between; align-items: center; padding: 11px 14px; border-bottom: 1px solid var(--border); }
  h2 { margin: 0; font-size: 14px; }
  .close { font-size: 13px; padding: 0 6px; }
  .body { padding: 12px 14px; overflow: auto; display: flex; flex-direction: column; gap: 9px; }
  .lead { margin: 0; font-size: 12px; color: var(--text-dim); }
  code { background: var(--bg-sunken); padding: 0 4px; border-radius: 3px; font-size: 11.5px; }
  .file-row { display: flex; gap: 9px; align-items: center; }
  .file-button {
    display: inline-flex; align-items: center; padding: 4px 11px; cursor: pointer;
    background: var(--bg-sunken); border: 1px solid var(--border-strong); border-radius: var(--radius-sm);
    font-size: 12px;
  }
  .file-button:hover { border-color: var(--accent); }
  .file-button input { display: none; }
  .filename { font-size: 11.5px; color: var(--text-dim); }
  .paste-label { font-size: 11px; color: var(--text-faint); margin-bottom: -5px; }
  textarea { width: 100%; resize: vertical; font-size: 11.5px; line-height: 1.45; }
  .report { border-radius: var(--radius-sm); padding: 8px 10px; font-size: 11.5px; }
  .report.ok { background: #12281a; border: 1px solid #1d4327; color: #b7e4c4; }
  .report.bad { background: var(--tone-critical-bg); border: 1px solid #5c2020; color: #ffc9c4; }
  .preview-list, .error-list { margin: 5px 0 0; padding-left: 0; list-style: none; display: flex; flex-direction: column; gap: 3px; }
  .error-list li { display: flex; flex-wrap: wrap; gap: 5px; align-items: baseline; }
  .row-badge { font-family: var(--mono); font-size: 10px; background: #6b1d1d; color: #ffd9d6; padding: 0 4px; border-radius: 3px; }
  .field-badge { font-size: 10px; background: #3a2323; color: #ffb3ac; padding: 0 4px; border-radius: 3px; }
  .dim { color: var(--text-faint); }
  footer { display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; border-top: 1px solid var(--border); gap: 10px; }
  .hint { font-size: 11px; color: var(--text-faint); }
  .actions { display: flex; gap: 7px; }
  .format-tabs { display: flex; gap: 5px; }
  .format-tabs button { font-size: 11.5px; }
  .format-tabs button.active { border-color: var(--accent); color: var(--accent); background: var(--accent-dim); }
</style>
