// Client-side view/filter logic, kept out of components so it can be tested.

export const DEFAULT_FILTERS = {
  text: '',
  severities: [],
  slaState: 'any',
  status: 'any',
  minAsset: 1,
  epssOnly: false,
};

export function emptyFilters() {
  return { ...DEFAULT_FILTERS, severities: [] };
}

export function hasActiveFilters(filters) {
  const f = filters ?? {};
  return Boolean(
    f.text ||
      (f.severities && f.severities.length) ||
      (f.slaState && f.slaState !== 'any') ||
      (f.status && f.status !== 'any') ||
      (f.minAsset && f.minAsset > 1) ||
      f.epssOnly,
  );
}

export function countActiveFilters(filters) {
  const f = filters ?? {};
  return (
    (f.text ? 1 : 0) +
    (f.severities?.length ? 1 : 0) +
    (f.slaState && f.slaState !== 'any' ? 1 : 0) +
    (f.status && f.status !== 'any' ? 1 : 0) +
    (f.minAsset && f.minAsset > 1 ? 1 : 0) +
    (f.epssOnly ? 1 : 0)
  );
}

export function applyFilters(rows, filters = {}) {
  const f = { ...DEFAULT_FILTERS, ...filters };
  const text = String(f.text ?? '').trim().toLowerCase();
  const severities = new Set(f.severities ?? []);

  return rows.filter((row) => {
    if (text) {
      const haystack = [row.title, row.cve, row.assetName, row.owner, row.notes, row.vector]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      if (!haystack.includes(text)) return false;
    }
    if (severities.size && !severities.has(row.cvss.ok ? row.cvss.severity : 'None')) return false;
    if (f.slaState === 'overdue' && !row.sla.overdue) return false;
    if (f.slaState === 'due_soon' && !row.sla.dueSoon) return false;
    if (f.slaState === 'not_overdue' && row.sla.overdue) return false;
    if (f.status === 'active' && !['open', 'in_progress'].includes(row.status)) return false;
    if (f.status !== 'any' && f.status !== 'active' && row.status !== f.status) return false;
    if (Number(f.minAsset) > 1 && Number(row.assetImportance) < Number(f.minAsset)) return false;
    if (f.epssOnly && (row.epss === null || row.epss === undefined)) return false;
    return true;
  });
}

export function severityCounts(rows) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, None: 0 };
  for (const row of rows) {
    if (!row.cvss.ok) continue;
    counts[row.cvss.severity] += 1;
  }
  return counts;
}
