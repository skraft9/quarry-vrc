// Render coverage for the dashboard's inline-SVG sparkline builder and the money-tile meter,
// lifted straight out of static/app.js and exercised headless. Both are pure - spark() returns an
// SVG string and meterPct() is arithmetic - so no DOM or browser is needed.
//
//     node tests/test_render.js
//
// Exits non-zero if anything fails.
const fs = require('fs');
const path = require('path');

// Resolve relative to this file so the checkout can live anywhere.
const src = fs.readFileSync(path.join(__dirname, '..', 'static', 'app.js'), 'utf8');

// Lift a `function NAME(...) { ... }` whole by brace-matching, so the test runs the REAL shipped
// source rather than a copy that could drift from it.
function grab(name) {
  const start = src.indexOf('function ' + name + '(');
  if (start < 0) throw new Error('not found in app.js: ' + name);
  let j = src.indexOf('{', start), depth = 0;
  for (; j < src.length; j++) {
    if (src[j] === '{') depth++;
    else if (src[j] === '}') { depth--; if (depth === 0) { j++; break; } }
  }
  return src.slice(start, j);
}

// spark() closes over a module-level counter (unique gradient ids); declare it so the lifted
// source runs standalone.
const sandbox = 'var sparkSeq = 0;\n'
  + grab('spark') + '\n'
  + grab('meterPct') + '\n'
  + 'return { spark: spark, meterPct: meterPct };';
const api = (new Function(sandbox))();
const spark = api.spark;
const meterPct = api.meterPct;

let pass = 0, fail = 0;
function t(name, cond, got) {
  if (cond) { pass++; console.log('  PASS  ' + name); }
  else { fail++; console.log('  FAIL  ' + name + (got !== undefined ? '  <- ' + JSON.stringify(got) : '')); }
}
function almost(a, b) { return Math.abs(a - b) < 1e-6; }

// Pull the [x,y] vertices out of the stroke path (the one with fill="none").
function linePoints(svg) {
  const m = svg.match(/<path d="([^"]+)" fill="none"/);
  if (!m) return [];
  const nums = m[1].match(/-?\d+(?:\.\d+)?/g).map(Number);
  const pts = [];
  for (let i = 0; i + 1 < nums.length; i += 2) pts.push([nums[i], nums[i + 1]]);
  return pts;
}

console.log('-- spark(): structure --');
{
  const svg = spark([70, 74, 78, 83, 90, 95, 101, 108, 112, 118, 123, 128]);
  t('returns an <svg class="spark"> string', /^<svg class="spark"/.test(svg) && /<\/svg>$/.test(svg), svg.slice(0, 40));
  t('viewBox is 0 0 180 34', svg.indexOf('viewBox="0 0 180 34"') >= 0);
  t('has exactly two <path (area + line)', (svg.match(/<path /g) || []).length === 2);
  t('has one end-point <circle', (svg.match(/<circle /g) || []).length === 1);
  t('fill and stroke are theme tokens', svg.indexOf('var(--accent)') >= 0 && svg.indexOf('var(--accent-2)') >= 0);
  t('no external URL / http / xlink', svg.indexOf('http') < 0 && svg.indexOf('xlink') < 0);
  t('marked aria-hidden (decorative)', svg.indexOf('aria-hidden="true"') >= 0);
}

console.log('\n-- spark(): geometry --');
{
  const svg = spark([70, 74, 78, 83, 90, 95, 101, 108, 112, 118, 123, 128]);
  const pts = linePoints(svg);
  t('twelve vertices for a twelve-point series', pts.length === 12, pts.length);
  t('first vertex sits at x=0', almost(pts[0][0], 0), pts[0]);
  t('last vertex sits at x=180 (full width)', almost(pts[pts.length - 1][0], 180), pts[pts.length - 1]);
  t('end-point circle is anchored at x=180', svg.indexOf('cx="180.0"') >= 0);
  // A rising series draws UP the screen: SVG y grows downward, so the last y is above (smaller than) the first.
  t('a rising series slopes upward (last y < first y)', pts[pts.length - 1][1] < pts[0][1], [pts[0][1], pts[pts.length - 1][1]]);
  t('every vertex is on-canvas (0..34 in y)', pts.every(function (p) { return p[1] >= 0 && p[1] <= 34; }), pts);
}

console.log('\n-- spark(): unique gradient ids --');
{
  const a = spark([1, 2, 3]);
  const b = spark([1, 2, 3]);
  const idA = (a.match(/id="(qspark\d+)"/) || [])[1];
  const idB = (b.match(/id="(qspark\d+)"/) || [])[1];
  t('each call mints its own gradient id', idA && idB && idA !== idB, [idA, idB]);
  t('the fill references that call\'s own gradient', a.indexOf('fill="url(#' + idA + ')"') >= 0);
}

console.log('\n-- spark(): degenerate input --');
{
  const empty = spark([]);
  t('empty series still renders a valid svg', /^<svg class="spark"/.test(empty) && empty.indexOf('NaN') < 0, empty);
  const one = spark([5]);
  t('single-point series does not throw / no NaN', one.indexOf('NaN') < 0 && (one.match(/<path /g) || []).length === 2);
  const flat = spark([7, 7, 7, 7]);
  t('flat series produces finite coordinates (no NaN)', flat.indexOf('NaN') < 0);
  const flatPts = linePoints(flat);
  t('flat series is a level line', flatPts.every(function (p) { return almost(p[1], flatPts[0][1]); }), flatPts);
}

console.log('\n-- meterPct(): real ratios + clamp --');
{
  t('14 of 128 reports ~= 10.94%', almost(meterPct(14, 128), 14 / 128 * 100), meterPct(14, 128));
  t('92 of 100 = 92%', almost(meterPct(92, 100), 92));
  t('half = 50%', almost(meterPct(50, 100), 50));
  t('over-full clamps to 100', meterPct(200, 100) === 100);
  t('negative numerator clamps to 0', meterPct(-5, 10) === 0);
  t('zero denominator is 0, not Infinity', meterPct(5, 0) === 0);
  t('negative denominator is 0', meterPct(1, -2) === 0);
  t('zero over zero is 0', meterPct(0, 0) === 0);
  t('missing numerator (undefined) is 0', meterPct(undefined, 100) === 0);
  t('missing denominator (undefined) is 0', meterPct(5, undefined) === 0);
  t('result never exceeds 100 across a sweep',
    [[0, 5], [1, 5], [5, 5], [9, 5], [128, 14]].every(function (p) {
      const v = meterPct(p[0], p[1]); return v >= 0 && v <= 100;
    }));
}

console.log('\n' + pass + '/' + (pass + fail) + ' passed');
process.exit(fail ? 1 : 0);
