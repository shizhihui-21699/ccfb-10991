<script>
  import { SEVERITY_LABELS } from '../lib/cvss/metrics.js';

  let { severity = 'None', score = null, size = 'normal', showScore = true } = $props();

  let label = $derived(SEVERITY_LABELS[severity] ?? severity);
  let text = $derived(showScore && score !== null ? `${label} ${Number(score).toFixed(1)}` : label);
</script>

<span class="badge {severity} {size}" title="CVSS 严重度：{severity}">{text}</span>

<style>
  .badge.small { font-size: 10.5px; padding: 0 5px; }
  .badge.large { font-size: 13px; padding: 2px 10px; }
</style>
