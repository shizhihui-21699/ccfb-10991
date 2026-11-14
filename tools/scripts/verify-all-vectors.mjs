// Exhaustive verification against the complete official vector sets.
// Requires tools/data/official/* (fetch with tools/scripts/fetch-official-vectors.mjs).
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scoreVector } from '../../src/lib/cvss/score.js';

const here = dirname(fileURLToPath(import.meta.url));
const dataDir = join(here, '..', 'data', 'official');
const FILES = [
  'vectors_base4',
  'vectors_modified4',
  'vectors_random4',
  'vectors_simple4',
  'vectors_threat4',
  'vectors_security4',
  'vectors_supplemental4',
];

let grandTotal = 0;
let grandBad = 0;

for (const file of FILES) {
  let text;
  try {
    text = readFileSync(join(dataDir, file), 'utf8');
  } catch {
    console.log(`${file}: missing (run fetch-official-vectors.mjs)`);
    continue;
  }
  let total = 0;
  let bad = 0;
  const samples = [];
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    const idx = line.indexOf(' - ');
    const vector = line.slice(0, idx).trim();
    const expected = Number(line.slice(idx + 3).trim().replace(/[(),]/g, ''));
    total += 1;
    const result = scoreVector(vector);
    if (!result.ok) {
      bad += 1;
      if (samples.length < 3) samples.push({ vector, errors: result.errors });
    } else if (Math.abs(result.score - expected) > 1e-9) {
      bad += 1;
      if (samples.length < 3) samples.push({ vector, expected, actual: result.score });
    }
  }
  grandTotal += total;
  grandBad += bad;
  console.log(`${bad === 0 ? 'PASS' : 'FAIL'} ${file}: ${total} vectors, ${bad} mismatches`);
  for (const s of samples) console.log('   ', JSON.stringify(s));
}

console.log(`\n${grandBad === 0 ? 'ALL PASS' : 'FAILURES'}: ${grandTotal - grandBad}/${grandTotal} vectors match the official scores.`);
process.exitCode = grandBad === 0 ? 0 : 1;
