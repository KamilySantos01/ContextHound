#!/usr/bin/env node
'use strict';

/**
 * ContextHound Benchmark — measures false-positive and detection rates.
 *
 * Usage:
 *   npm run benchmark          (builds first, then runs)
 *   node scripts/benchmark.js  (requires dist/ to already exist)
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ── Paths ─────────────────────────────────────────────────────────────────────
const ROOT = path.resolve(__dirname, '..');
const DIST_CLI = path.join(ROOT, 'dist', 'cli.js');
const BENCHMARKS = path.join(ROOT, 'benchmarks');
const LABELS_PATH = path.join(BENCHMARKS, 'labels.json');

// ── ANSI colours ──────────────────────────────────────────────────────────────
const G = '\x1b[32m';   // green
const R = '\x1b[31m';   // red
const Y = '\x1b[33m';   // yellow
const C = '\x1b[36m';   // cyan
const B = '\x1b[1m';    // bold
const D = '\x1b[2m';    // dim
const X = '\x1b[0m';    // reset

// ── Guards ────────────────────────────────────────────────────────────────────
if (!fs.existsSync(DIST_CLI)) {
  console.error(`${R}dist/cli.js not found. Run: npm run build${X}`);
  process.exit(1);
}
if (!fs.existsSync(LABELS_PATH)) {
  console.error(`${R}benchmarks/labels.json not found.${X}`);
  process.exit(1);
}

// ── Run hound on a directory, return parsed ScanResult ────────────────────────
function runHound(dir) {
  const tmpBase = path.join(os.tmpdir(), `hound-bench-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  const tmpFile = `${tmpBase}.json`;

  try {
    execSync(
      `node "${DIST_CLI}" scan --dir "${dir}" --format json --out "${tmpBase}" --no-cache --threshold 0`,
      { cwd: ROOT, stdio: 'pipe' },
    );
  } catch (e) {
    // exit codes 2 (threshold breach) and 3 (failOn) produce valid JSON output
    if (e.status === 1) {
      try { fs.unlinkSync(tmpFile); } catch {}
      const stderr = e.stderr?.toString().trim() ?? '(no stderr)';
      throw new Error(`hound exited with error:\n${stderr.slice(0, 400)}`);
    }
  }

  let raw;
  try {
    raw = fs.readFileSync(tmpFile, 'utf8');
  } catch {
    throw new Error(`JSON output file not written by hound. Expected: ${tmpFile}`);
  } finally {
    try { fs.unlinkSync(tmpFile); } catch {}
  }

  return JSON.parse(raw);
}

// ── Findings lookup: basename → ruleId[] ─────────────────────────────────────
function buildFindingsMap(scanResult) {
  const map = {};
  for (const f of scanResult.allFindings ?? []) {
    const base = path.basename(f.file.replace(/\\/g, '/'));
    (map[base] ??= []).push(f.id);
  }
  return map;
}

// ── Main ──────────────────────────────────────────────────────────────────────
function main() {
  const labels = JSON.parse(fs.readFileSync(LABELS_PATH, 'utf8'));

  console.log(`\n${B}${C}ContextHound Benchmark${X}  ${D}v${labels.version ?? 1}${X}`);
  console.log('═'.repeat(60));
  console.log(`${D}CLI:        ${DIST_CLI}${X}`);
  console.log(`${D}Benchmarks: ${BENCHMARKS}${X}\n`);

  // ─── SAFE fixtures ────────────────────────────────────────────────────────
  let safeResult;
  try {
    safeResult = runHound(path.join(BENCHMARKS, 'safe'));
  } catch (e) {
    console.error(`${R}Failed scanning safe/: ${e.message}${X}`);
    process.exit(1);
  }

  const safeMap = buildFindingsMap(safeResult);

  console.log(`${B}SAFE FIXTURES${X}  ${D}(expect 0 findings per file)${X}`);
  console.log('─'.repeat(60));

  let safeClean = 0;
  let safeFpFiles = 0;
  const allFpRules = [];

  for (const fixture of labels.safe) {
    const findings = safeMap[fixture.file] ?? [];
    const pass = findings.length === 0;
    const marker = pass ? `${G}✓${X}` : `${R}✗${X}`;
    const detail = pass
      ? `${D}0 findings${X}`
      : `${R}${findings.length} FP: [${findings.join(', ')}]${X}`;
    console.log(`  ${marker}  ${fixture.file.padEnd(28)}  ${detail}`);

    if (pass) {
      safeClean++;
    } else {
      safeFpFiles++;
      allFpRules.push(...findings);
    }
  }

  const totalSafe = labels.safe.length;
  const fpRate = totalSafe > 0 ? ((safeFpFiles / totalSafe) * 100).toFixed(1) : '0.0';
  console.log(`\n  ${B}Safe:${X} ${safeClean}/${totalSafe} clean  │  File-level FP rate: ${B}${fpRate}%${X}\n`);

  // ─── UNSAFE fixtures ──────────────────────────────────────────────────────
  let unsafeResult;
  try {
    unsafeResult = runHound(path.join(BENCHMARKS, 'unsafe'));
  } catch (e) {
    console.error(`${R}Failed scanning unsafe/: ${e.message}${X}`);
    process.exit(1);
  }

  const unsafeMap = buildFindingsMap(unsafeResult);

  console.log(`${B}UNSAFE FIXTURES${X}  ${D}(expect specific rules to fire)${X}`);
  console.log('─'.repeat(60));

  let detectedCount = 0;
  let expectedTotal = 0;
  const allFnRules = [];
  const allExtraRules = [];

  for (const fixture of labels.unsafe) {
    const actual = new Set(unsafeMap[fixture.file] ?? []);
    const expected = fixture.expectFindings ?? [];
    expectedTotal += expected.length;

    const missed = expected.filter((r) => !actual.has(r));
    const extra = [...actual].filter((r) => !expected.includes(r));
    const allFound = missed.length === 0;

    detectedCount += expected.length - missed.length;

    const marker = allFound ? `${G}✓${X}` : `${R}✗${X}`;
    let detail = expected.map((r) => (actual.has(r) ? `${G}${r} ✓${X}` : `${R}${r} ✗${X}`)).join(', ');
    if (extra.length > 0) {
      detail += `  ${Y}+[${extra.join(', ')}]${X}`;
    }
    console.log(`  ${marker}  ${fixture.file.padEnd(28)}  ${detail}`);

    allFnRules.push(...missed);
    allExtraRules.push(...extra);
  }

  const totalUnsafe = labels.unsafe.length;
  const detRate = expectedTotal > 0 ? ((detectedCount / expectedTotal) * 100).toFixed(1) : '0.0';
  console.log(`\n  ${B}Unsafe:${X} ${detectedCount}/${expectedTotal} expected rules fired  │  Detection rate: ${B}${detRate}%${X}\n`);

  // ─── Summary ──────────────────────────────────────────────────────────────
  console.log('═'.repeat(60));
  console.log(`${B}SUMMARY${X}`);
  console.log(`  File-level FP rate:   ${B}${fpRate}%${X}  (${safeFpFiles} FP file(s) / ${totalSafe} safe files)`);
  console.log(`  Detection rate:       ${B}${detRate}%${X}  (${detectedCount}/${expectedTotal} expected findings triggered)`);

  if (allFpRules.length > 0) {
    console.log(`  False positive rules: ${R}${allFpRules.join(', ')}${X}`);
  }
  if (allFnRules.length > 0) {
    console.log(`  False negative rules: ${R}${allFnRules.join(', ')}${X}`);
  }
  if (allExtraRules.length > 0) {
    console.log(`  Extra rules fired:    ${Y}${allExtraRules.join(', ')}${X}  (additional findings in unsafe fixtures)`);
  }
  console.log('═'.repeat(60) + '\n');

  // Exit 1 if any FPs or FNs (useful for CI quality gates)
  if (safeFpFiles > 0 || allFnRules.length > 0) {
    process.exit(1);
  }
}

main();
