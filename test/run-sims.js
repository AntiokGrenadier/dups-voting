// test/run-sims.js — drives both round1 and round2 with pass/fail tracking
'use strict';

const H = require('./harness');
const round1 = require('./round1');
const round2 = require('./round2');
const round3 = require('./round3');

let passed = 0, failed = 0;
const failures = [];

async function sim(num, name, fn) {
  const label = `#${String(num).padStart(3, '0')} ${name}`;
  try {
    await fn();
    passed++;
    console.log(`  PASS  ${label}`);
  } catch (e) {
    failed++;
    failures.push({ num, name, err: e.message });
    console.log(`  FAIL  ${label}`);
    console.log(`        ${e.message}`);
  }
}

(async function main() {
  process.on('unhandledRejection', (e) => {
    console.error('[unhandledRejection]', e && e.stack || e);
  });

  console.log('\n=== DUPS voting — red-team simulations ===');

  // Pure-logic and contract tests run first — no npm install needed, fast,
  // and catch a class of bugs (signature errors, stale IDs) before we even
  // spawn the server.
  console.log('\nUnit tests (pure logic):');
  try { require('child_process').execSync('node test/unit-pure.js', { stdio: 'inherit' }); }
  catch (e) { failed++; failures.push({ num: 0, name: 'unit-pure', err: 'one or more unit-pure tests failed' }); }

  console.log('\nContract tests (HTML/JS contract):');
  try { require('child_process').execSync('node test/unit-contracts.js', { stdio: 'inherit' }); }
  catch (e) { failed++; failures.push({ num: 0, name: 'unit-contracts', err: 'one or more contract tests failed' }); }

  console.log('\nBehavior tests (endpoint logic with stubs):');
  try { require('child_process').execSync('node test/unit-behavior.js', { stdio: 'inherit' }); }
  catch (e) { failed++; failures.push({ num: 0, name: 'unit-behavior', err: 'one or more behavior tests failed' }); }

  console.log('\nRound 1 (originals, updated to v4):');
  await H.startServer();
  try {
    await round1(sim);
    console.log('\nRound 2 (v3 attack surface, updated for v4):');
    await round2(sim);
    console.log('\nRound 3 (v4 public-internet attack surface):');
    await round3(sim);
  } finally {
    H.stopServer();
  }

  const total = passed + failed;
  console.log('\n=== Summary ===');
  console.log(`  Total:  ${total}`);
  console.log(`  Passed: ${passed}`);
  console.log(`  Failed: ${failed}`);
  if (failures.length) {
    console.log('\nFailures:');
    for (const f of failures) console.log(`  #${f.num} ${f.name}\n    ${f.err}`);
  }
  process.exit(failed ? 1 : 0);
})().catch((e) => {
  console.error('FATAL', e);
  H.stopServer();
  process.exit(2);
});
