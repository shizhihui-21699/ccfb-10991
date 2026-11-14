// End-to-end smoke test in a real browser (Chrome via playwright-core).
// Optional: install with `npm i -D playwright-core` and run against `npm run preview`.
//
//   npx vite build && npx vite preview --port 4173 &
//   node tools/scripts/ui-smoke.mjs
const BASE = process.env.SMOKE_URL ?? 'http://localhost:4173/';
const CHROME = process.env.CHROME_PATH ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

let chromium;
try {
  ({ chromium } = await import('playwright-core'));
} catch {
  console.error('playwright-core not installed. Run: npm i -D playwright-core');
  process.exit(2);
}

const checks = [];
const check = (name, ok, detail = '') => {
  checks.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);
};

const browser = await chromium.launch({ executablePath: CHROME, headless: true });
const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
const pageErrors = [];
page.on('pageerror', (e) => pageErrors.push(e.message));
await page.goto(BASE, { waitUntil: 'networkidle' });

const rows = page.locator('tbody tr');
check('sample queue renders', (await rows.count()) >= 5, `${await rows.count()} rows`);

// select -> read-only detail
await rows.first().click();
await page.waitForTimeout(250);
check('click selects a row and shows detail', (await page.locator('.side-head h2').count()) === 1);

// edit -> invalid vector -> per-item diagnostics
await page.getByRole('button', { name: '编辑' }).click();
await page.waitForTimeout(200);
await page.locator('#f-vector').fill('CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
await page.locator('#f-vector').blur();
await page.waitForTimeout(250);
const errText = (await page.locator('.errors li').allTextContents()).join(' ');
check('invalid vector names the offending metric', errText.includes('AV') && errText.includes('Z'), errText.slice(0, 80));
await page.getByRole('button', { name: '保存' }).click();
await page.waitForTimeout(200);
check('save is blocked while the vector is invalid', (await page.locator('.save-error').count()) === 1);

// valid vector -> preview score
await page.locator('#f-vector').fill('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
await page.locator('#f-vector').blur();
await page.waitForTimeout(250);
check('base score previews as 9.3', (await page.locator('.score-cell .num').first().textContent())?.trim() === '9.3');

// builder keeps vector in sync
await page.getByRole('button', { name: '按指标逐项选择' }).click();
await page.locator('#m-E').selectOption('U');
await page.waitForTimeout(250);
const baseScore = (await page.locator('.score-cell .num').nth(0).textContent())?.trim();
const threatScore = (await page.locator('.score-cell .num').nth(1).textContent())?.trim();
check('E:U lowers the threat score below the base score', Number(threatScore) < Number(baseScore), `base ${baseScore} -> threat ${threatScore}`);
await page.locator('#m-E').selectOption('X');
await page.waitForTimeout(200);
check('E:X (unset) makes the threat score equal the base score', (await page.locator('.score-cell .num').nth(1).textContent())?.trim() === baseScore);

// policy -> live SLA recompute
await page.getByRole('button', { name: '取消' }).click();
await page.getByRole('button', { name: '策略' }).click();
await page.locator('#sla-Critical').fill('1');
await page.locator('#sla-Critical').blur();
await page.waitForTimeout(300);
check('tightening the Critical SLA marks rows overdue', Number(await page.locator('.stat.bad .value').textContent()) > 0);
await page.keyboard.press('Escape');

// filters
await page.locator('select[aria-label="按 SLA 状态筛选"]').selectOption('overdue');
await page.waitForTimeout(200);
check('overdue filter narrows the queue', (await rows.count()) > 0 && (await rows.count()) < 6, `${await rows.count()} rows`);

// import rejects bad rows with row numbers
await page.getByRole('button', { name: '导入' }).click();
await page.locator('#paste').fill(
  'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N - 9.3\nCVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N\n',
);
await page.waitForTimeout(350);
const importErrors = (await page.locator('.error-list li').allTextContents()).join(' ');
check('import reports the failing row and metric', importErrors.includes('第 2 行') && importErrors.includes('AV'), importErrors.slice(0, 80));
await page.keyboard.press('Escape');

check('no uncaught page errors', pageErrors.length === 0, pageErrors.join('; '));

await browser.close();
const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
