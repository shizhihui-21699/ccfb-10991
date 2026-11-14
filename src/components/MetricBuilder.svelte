<script>
  import { METRIC_GROUPS, METRICS } from '../lib/cvss/metrics.js';
  import { effectiveMetric } from '../lib/cvss/score.js';

  let { metrics = {}, onchange = () => {}, disabled = false } = $props();

  const group = (id) => METRIC_GROUPS.find((g) => g.id === id);

  function set(key, value) {
    onchange({ ...metrics, [key]: value });
  }

  function resetGroup(keys) {
    const next = { ...metrics };
    for (const key of keys) next[key] = METRICS[key].values[0].value;
    onchange(next);
  }

  // A modified metric only matters when the vector carries it; the UI marks the
  // effective value so the analyst sees what the score actually uses.
  function isModified(key) {
    return key.startsWith('M') && metrics[key] !== 'X' && metrics[key] !== undefined;
  }
</script>

<div class="builder">
  {#each METRIC_GROUPS as g (g.id)}
    {#if g.subgroups}
      <section class="group">
        <header>
          <h4>{g.title}<span class="en">{g.en}</span></h4>
          <p>{g.hint}</p>
        </header>
        {#each g.subgroups as sub (sub.id)}
          <div class="subgroup">
            <div class="sub-header">
              <h5>{sub.title}</h5>
              <button class="ghost tiny" onclick={() => resetGroup(sub.metrics)} {disabled}>重置</button>
            </div>
            {#each sub.metrics as key (key)}
              <div class="metric-row">
                <label for="m-{key}">
                  <span class="name">{METRICS[key].name}</span>
                  <span class="key mono">{key}</span>
                </label>
                <select
                  id="m-{key}"
                  value={metrics[key] ?? METRICS[key].values[0].value}
                  onchange={(e) => set(key, e.currentTarget.value)}
                  {disabled}
                >
                  {#each METRICS[key].values as v (v.value)}
                    <option value={v.value}>{v.label}（{v.value}）</option>
                  {/each}
                </select>
              </div>
            {/each}
          </div>
        {/each}
      </section>
    {:else}
      <section class="group">
        <header>
          <h4>{g.title}<span class="en">{g.en}</span></h4>
          <div class="head-right">
            <p>{g.hint}</p>
            <button class="ghost tiny" onclick={() => resetGroup(g.metrics)} {disabled}>重置</button>
          </div>
        </header>
        <div class="metrics-grid">
          {#each g.metrics as key (key)}
            <div class="metric-row">
              <label for="m-{key}">
                <span class="name">{METRICS[key].name}</span>
                <span class="key mono">{key}</span>
                {#if key in ['VC', 'VI', 'VA', 'SC', 'SI', 'SA']}
                  <span class="effective" title="当前生效值">生效 {effectiveMetric(metrics, key)}</span>
                {/if}
              </label>
              <select
                id="m-{key}"
                value={metrics[key] ?? METRICS[key].values[0].value}
                onchange={(e) => set(key, e.currentTarget.value)}
                {disabled}
              >
                {#each METRICS[key].values as v (v.value)}
                  <option value={v.value}>{v.label}（{v.value}）</option>
                {/each}
              </select>
            </div>
          {/each}
        </div>
      </section>
    {/if}
  {/each}
</div>

<style>
  .builder { display: flex; flex-direction: column; gap: 14px; }
  .group {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--bg-sunken);
    padding: 10px 12px;
  }
  header { display: flex; justify-content: space-between; gap: 10px; margin-bottom: 8px; align-items: flex-start; }
  h4 { margin: 0; font-size: 13px; display: flex; gap: 7px; align-items: baseline; }
  h4 .en { font-size: 10.5px; color: var(--text-faint); font-weight: 500; letter-spacing: 0.4px; text-transform: uppercase; }
  header p { margin: 1px 0 0; font-size: 11px; color: var(--text-faint); }
  .head-right { display: flex; align-items: flex-start; gap: 8px; }
  .subgroup + .subgroup { margin-top: 10px; padding-top: 8px; border-top: 1px dashed var(--border); }
  .sub-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
  h5 { margin: 0; font-size: 11.5px; color: var(--text-dim); font-weight: 600; letter-spacing: 0.3px; }
  .metrics-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(255px, 1fr)); gap: 5px 14px; }
  .metric-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 1px 0; }
  label { display: flex; align-items: baseline; gap: 5px; min-width: 0; flex: 1; }
  .name { font-size: 12px; color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .key { font-size: 10px; color: var(--text-faint); }
  .effective { font-size: 10px; color: var(--accent); margin-left: auto; }
  select { min-width: 118px; max-width: 140px; font-size: 11.5px; padding: 2px 5px; }
  button.tiny { font-size: 11px; padding: 1px 6px; }
</style>
