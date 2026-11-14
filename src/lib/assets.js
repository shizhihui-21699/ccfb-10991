// Localised asset labels plus a helper for the detail panel.

export const SAMPLE_ASSETS_ZH = [];

export function assetSummary(name, importance) {
  return name ? `${name}（重要性 ${importance}）` : `未指定资产（重要性 ${importance}）`;
}
