// Downloads the official CVSS v4.0 test-vector files used for the exhaustive
// verification run (579,918 vectors). They are large (~74 MB) and are therefore
// NOT committed; the committed tests/fixtures/official-vectors.json sample is
// generated from them by tools/scripts/make-fixtures.mjs.
//
//   node tools/scripts/fetch-official-vectors.mjs        # download
//   node tools/scripts/make-fixtures.mjs                 # regenerate the sample
//   node tools/scripts/verify-all-vectors.mjs            # exhaustive check
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, '..', 'data', 'official');
const BASE = 'https://raw.githubusercontent.com/RedHatProductSecurity/cvss/master/tests';
const FILES = [
  'vectors_base4',
  'vectors_modified4',
  'vectors_random4',
  'vectors_simple4',
  'vectors_threat4',
  'vectors_security4',
  'vectors_supplemental4',
];

mkdirSync(outDir, { recursive: true });

for (const file of FILES) {
  const target = join(outDir, file);
  if (existsSync(target)) {
    console.log(`skip   ${file} (already present)`);
    continue;
  }
  const res = await fetch(`${BASE}/${file}`);
  if (!res.ok) {
    console.error(`FAILED ${file}: HTTP ${res.status}`);
    process.exitCode = 1;
    continue;
  }
  const text = await res.text();
  writeFileSync(target, text);
  console.log(`fetched ${file} (${(text.length / 1024 / 1024).toFixed(1)} MB)`);
}
