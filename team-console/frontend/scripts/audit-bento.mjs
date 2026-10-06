// Static source/token audit only. No browser, DOM rendering, screenshots or UI tests.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import postcss from 'postcss';
import { uiColors as c } from '../src/uiTheme.ts';

const css = fs.readFileSync(new URL('../src/styles.css', import.meta.url), 'utf8');
const ast = postcss.parse(css);
const violations = [];
ast.walkDecls(d => {
  if (['gap', 'row-gap', 'column-gap'].includes(d.prop) && /(?:^|\s)(?:4|8|40|48)px(?:\s|$)/.test(d.value)) violations.push(`${d.prop}:${d.value}`);
  if (d.prop.includes('border-radius') && /(?:^|\s)(?:0|2px|4px)(?:\s|$)/.test(d.value)) violations.push(`${d.prop}:${d.value}`);
  if (d.prop === 'grid-auto-flow' && d.value.includes('dense')) violations.push('dense changes reading order');
  if (d.prop === 'order') violations.push('visual order differs from DOM');
  if (d.prop === 'font-family' && /\b(Inter|Roboto|Geist)\b/i.test(d.value)) violations.push('legacy/excluded font');
  if (d.value.includes('gradient(')) violations.push('unexpected gradient');
});
assert.deepEqual(violations, [], 'Bento token violations');
assert.match(css, /grid-template-columns:\s*repeat\(4, minmax\(0, 1fr\)\)/);
assert.match(css, /@media \(min-width: 768px\)/);
assert.match(css, /@media \(min-width: 1200px\)/);
assert.match(css, /\.overview-primary\s*\{\s*grid-row: span 2/);
assert.match(css, /@media \(hover: hover\) and \(pointer: fine\) and \(prefers-reduced-motion: no-preference\)/);
assert.match(css, /translateY\(-4px\) scale\(1\.01\)/);
assert.match(css, /\.tile-icon\s*\{[^}]*transition:/);
assert.match(css, /@media \(prefers-reduced-motion: reduce\)\s*\{[\s\S]*transform: none !important/);
assert.match(css, /:focus-visible\s*\{[^}]*outline: 2px solid/);
assert.doesNotMatch(css, /workspace-layout|console-sider\b|radial-gradient/);

function luminance(color) {
  const rgb = color.replace('#', '').match(/../g).map(n => parseInt(n, 16) / 255).map(n => n <= .04045 ? n / 12.92 : ((n + .055) / 1.055) ** 2.4);
  return rgb[0] * .2126 + rgb[1] * .7152 + rgb[2] * .0722;
}
function contrast(a, b) { const x = luminance(a), y = luminance(b); return (Math.max(x, y) + .05) / (Math.min(x, y) + .05); }
const pairs = [
  ['body', c.ink, c.canvas], ['surface', c.ink, c.surface], ['secondary', c.secondary, c.surface],
  ['secondary canvas', c.secondary, c.canvas], ['hero', '#ffffff', c.ink], ['hero accent', c.accent, c.ink],
  ['accent primary', c.ink, c.accent], ['accent secondary', c.accentInk, c.accent], ['selection', c.accentInk, c.accentSoft],
  ['link', c.accentInk, c.surface], ['placeholder', '#71717a', '#ffffff'],
  ['success', c.success, c.successSurface], ['warning', c.warning, c.warningSurface], ['error', c.danger, c.dangerSurface],
  ['info', c.info, c.infoSurface], ['primary button', '#ffffff', c.ink], ['accent button hover', c.ink, '#bef264'],
  ['floating button hover', '#ffffff', '#27272a'], ['expanded task secondary', c.secondary, c.accentSoft],
];
const ratios = pairs.map(([role, fg, bg]) => ({ role, ratio: +contrast(fg, bg).toFixed(2) }));
for (const { role, ratio } of ratios) assert.ok(ratio >= 4.5, `${role}: ${ratio}:1`);
const app = fs.readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
assert.doesNotMatch(app, /toggleVariant|team-console-ui|classic|workspace-layout/);
assert.match(app, /aria-current=/);
assert.match(app, /href="#main-content"/);
// Lean list surfaces: retain actions/confirmation, not explanatory card walls.
for (const name of ['Accounts', 'Batches']) {
  const source = fs.readFileSync(new URL(`../src/pages/${name}.tsx`, import.meta.url), 'utf8');
  assert.match(source, /<ListHeading/);
  assert.doesNotMatch(source, /<Bento(?:Lead|Stat)/);
  assert.match(source, /无法撤销/);
}
const jobs = fs.readFileSync(new URL('../src/pages/Jobs.tsx', import.meta.url), 'utf8');
assert.match(jobs, /className="task-filters"/);
assert.match(jobs, /<AuthorizationTaskModal/);
assert.doesNotMatch(app, /你的工作空间管理台|page-heading/);
const floating = fs.readFileSync(new URL('../src/TaskProgressFloat.tsx', import.meta.url), 'utf8');
assert.match(app, /<TaskProgressFloat/);
assert.equal((app.match(/useJobs\(\)/g) || []).length, 1, 'one shared progress subscription');
assert.doesNotMatch(floating, /\b(?:fetch|useJobs|watchJobs|setInterval|useResource)\s*\(/, 'floating panel must not start a second transport');
assert.match(floating, /aria-label="全局任务进度"/);
assert.match(floating, /aria-label="收起任务进度"/);
assert.match(css, /\.task-float\s*\{[^}]*position:\s*fixed/);
assert.match(css, /\.task-float-scroll\s*\{[^}]*overflow:\s*auto/);
assert.match(css, /\.task-float-panel\s*\{[^}]*max-height:/);
assert.doesNotMatch(floating, /<Modal\b|<AuthorizationTaskModal\b/, 'expanded tasks must remain inline');
assert.match(floating, /aria-expanded=\{open\}/);
assert.match(floating, /aria-controls=\{detailId\}/);
assert.match(floating, /hidden=\{!open\}/);
assert.match(floating, /open && \(row\.authorization_batch/);
assert.match(floating, /TaskAuthorizationExpansion key=\{key\}/);
assert.match(css, /\.float-summary-grid\s*\{[^}]*grid-template-columns: minmax\(0, 1fr\)/);
assert.match(css, /\.float-summary-primary\s*\{[^}]*grid-column: span 2; grid-row: span 2/);
assert.match(css, /\.float-task-toggle:focus-visible\s*\{[^}]*outline: 2px solid/);
assert.match(css, /prefers-reduced-motion: reduce[\s\S]*\.float-task-toggle:hover[\s\S]*transform: none !important/);
const expansion = fs.readFileSync(new URL('../src/TaskAuthorizationExpansion.tsx', import.meta.url), 'utf8');
assert.match(expansion, /useAuthorizationDetail/);
assert.doesNotMatch(expansion, /<Modal\b|\b(?:fetch|useJobs|watchJobs|setInterval)\s*\(/);
const billing = fs.readFileSync(new URL('../src/WorkspaceBilling.tsx', import.meta.url), 'utf8');
const team = fs.readFileSync(new URL('../src/pages/Team.tsx', import.meta.url), 'utf8');
assert.match(team, /<WorkspaceBilling key=\{parent\.id \+ ':' \+ workspace\.id\}/);
assert.match(billing, /查询账单/);
assert.match(billing, /BILLING_TIME_LABEL/);
assert.match(billing, /encodeURIComponent\(workspace\.id\)/);
assert.match(billing, /dateTime=\{view\.renewal\.iso\}/);
assert.doesNotMatch(billing, /\b(?:setInterval|setTimeout|Date\.parse)\s*\(/, 'no automatic billing polling or local-zone parsing');
assert.match(css, /\.billing-details dl\s*\{[^}]*minmax\(0, 1fr\)/);
const parentBilling = fs.readFileSync(new URL('../src/ParentBilling.tsx', import.meta.url), 'utf8');
assert.match(team, /<ParentBilling parent=\{item\}/);
assert.match(team, /parent-mobile-select[^\n]*<ParentBilling parent=\{parent\}/);
assert.match(team, /onRefresh=\{\(\) => \{ data\.reload\(\); onParentsChanged\(\); \}\}/);
assert.match(parentBilling, /dateTime=\{view\.time\.iso\}/);
assert.match(parentBilling, /北京时间/);
assert.doesNotMatch(parentBilling, /\b(?:fetch|post|useResource|setInterval)\s*\(/, 'parent billing is cache-only');
assert.match(css, /\.parent-billing-value\s*\{[^}]*flex-wrap: wrap/);
assert.match(css, /\.selected-list-item \.parent-billing-value\s*\{ color: var\(--accent-ink\)/);
console.log(JSON.stringify({ checks: 'static tokens, responsive declarations, motion, focus, no legacy theme', contrast: ratios, minimumTextContrast: Math.min(...ratios.map(r => r.ratio)), renderedUI: false }, null, 2));
