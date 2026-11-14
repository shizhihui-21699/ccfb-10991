<script>
  import { parseVector } from '../lib/cvss/parser.js';

  let {
    value = '',
    onchange = () => {},
    placeholder = 'CVSS:4.0/AV:N/AC:L/...',
    id = '',
  } = $props();

  let touched = $state(false);
  let focused = $state(false);

  // Live diagnostics: parse as the user types, but only surface problems once the
  // field has been touched or blurred, so an empty box is not immediately red.
  let parsed = $derived(parseVector(value));
  let showErrors = $derived(touched && !parsed.ok);
  let errors = $derived(parsed.ok ? [] : parsed.errors);

  function commit(next) {
    onchange(next);
  }

  function handleInput(event) {
    commit(event.currentTarget.value);
  }

  function handleBlur() {
    focused = false;
    touched = true;
    const next = value.trim();
    if (parsed.ok && next !== value) commit(parsed.canonical);
  }
</script>

<div class="vector-field">
  <input
    {id}
    class="mono"
    class:invalid={showErrors}
    class:valid={touched && parsed.ok}
    type="text"
    spellcheck="false"
    autocapitalize="off"
    autocomplete="off"
    {placeholder}
    value={value}
    oninput={handleInput}
    onblur={handleBlur}
    onfocus={() => (focused = true)}
    aria-invalid={showErrors}
    aria-describedby={showErrors ? `${id}-errors` : undefined}
  />

  {#if focused && parsed.ok && parsed.warnings?.length}
    <ul class="warnings">
      {#each parsed.warnings as warning}
        <li>{warning}</li>
      {/each}
    </ul>
  {/if}

  {#if showErrors}
    <ul class="errors" id="{id}-errors">
      {#each errors.slice(0, 6) as error}
        <li>
          <span class="code">{error.code}</span>
          <span class="msg">{error.message}</span>
          {#if error.hint}<span class="hint">{error.hint}</span>{/if}
          {#if error.expectedValues}
            <span class="allowed">允许值：<code>{error.expectedValues.join(' / ')}</code></span>
          {/if}
        </li>
      {/each}
      {#if errors.length > 6}
        <li class="more">还有 {errors.length - 6} 个问题…</li>
      {/if}
    </ul>
  {:else if errors.length > 0 && value}
    <p class="muted">继续输入，提交时将校验向量格式。</p>
  {/if}
</div>

<style>
  .vector-field { display: flex; flex-direction: column; gap: 4px; }
  input {
    width: 100%;
    padding: 7px 9px;
    font-size: 12.5px;
    letter-spacing: 0.1px;
  }
  input.valid { border-color: #2b5137; }
  .errors, .warnings {
    margin: 2px 0 0;
    padding: 6px 9px;
    list-style: none;
    border-radius: var(--radius-sm);
    font-size: 12px;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .errors { background: var(--tone-critical-bg); border: 1px solid #5c2020; }
  .warnings { background: var(--tone-medium-bg); border: 1px solid #55460f; color: var(--sev-medium); }
  .errors li { display: flex; flex-wrap: wrap; gap: 6px; align-items: baseline; }
  .code {
    font-family: var(--mono);
    font-size: 10px;
    padding: 0 4px;
    border-radius: 3px;
    background: #6b1d1d;
    color: #ffd9d6;
    letter-spacing: 0.2px;
  }
  .msg { color: #ffc9c4; }
  .hint { color: #ffd9a8; }
  .allowed { color: var(--text-dim); font-size: 11.5px; }
  .allowed code { font-family: var(--mono); color: var(--text); }
  .more { color: var(--text-dim); font-size: 11.5px; }
  .muted { margin: 0; font-size: 11.5px; color: var(--text-faint); }
</style>
