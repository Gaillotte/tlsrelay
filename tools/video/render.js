// Video of the demonstration (tools/video/make-video.sh): builds a timeline from
// the recorded run of tools/demo.sh (script -T) and the editor screenshots,
// plays it in player.html (xterm.js) and records the page with Playwright.
// Usage: node render.js <typescript> <timing> <screenshot dir> <xterm package dir> <output .webm>
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const [typescriptFile, timingFile, shotsDir, xtermDir, outFile] = process.argv.slice(2);
if (!outFile) {
  console.error('usage: node render.js <typescript> <timing> <screenshot dir> <xterm package dir> <output .webm>');
  process.exit(2);
}

// Chapters of tools/demo.sh, in order: card shown before each step, caption kept during it.
const chapters = {
  1: ['Versions', 'tlsrelay and the OpenSSL library it runs on.'],
  2: ['PKI built by the mini-CA', 'Root, Servers CA and Clients CA; each instance creates its own key, the CA signs its request.'],
  3: ['Starting the instances', 'An echo destination, the server relay and the client relay, each with its administration channel.'],
  4: ['Three ports, three modes', '50 concurrent channels on the plain, TLS 1.3 and mutual TLS ports; every byte checked by SHA-256.'],
  5: ['TLS seen from outside', 'openssl s_client: TLS 1.3 with ALPN tlsrelay/1, TLS 1.2 refused, client certificate required on mTLS.'],
  6: ['Whitelist reloaded while running', 'The client is removed from the server\'s whitelist, refused, then restored.'],
  7: ['Transparent renegotiation', 'A 40 s stream while sessions are renegotiated every 15 s: new TLS connection, no cut, no loss.'],
  8: ['Network cuts', 'Every connection is reset every 3 s; the session resumes with its token and nothing is lost.'],
  9: ['Hot PKI rotation', 'The server gets a new key and certificate; open channels drain on the old generation.'],
  10: ['Revocation', 'The client\'s certificate is revoked and the CRL deployed: its channels are closed, it is refused.'],
  11: ['Administration and metrics', 'Open channels, Prometheus metrics, and no secret in the logs.'],
  12: ['The editor checks configurations', 'tlsrelay-admin validates with the service\'s own rules, even on a machine without a display.'],
  13: ['Graceful stop and audit', 'Instances drain and stop; the CA\'s hash-chained audit log is intact.'],
};
const shots = [
  ['01-configuration', 'Configuration of an instance: one form, per mode.'],
  ['02-errors', 'Every value is checked by the service\'s own loader: the faulty fields are framed and listed.'],
  ['03-whitelist', 'The server\'s whitelist: address, ports and certificate subject of each peer.'],
  ['04-diff', 'Nothing is written without review: line diff of every file, original kept as .bak.'],
  ['05-export', 'Deployment package for Linux or Windows: configuration, whitelist, PKI kit, CRL, script.'],
  ['06-pki-inventory', 'The mini-CA of the demonstration: issued, superseded and revoked certificates.'],
  ['07-pki-audit', 'Every CA operation in a hash-chained audit log; tampering is detected.'],
  ['08-sign', 'Signing a request: subject and requested extensions are shown before the CA signs.'],
  ['09-revoke', 'Revocation with its reason; the CRLs are published at once.'],
  ['10-root-change', 'Root change wizard: the trust files and commands for the three steps.'],
];

// Recorded output: the first line of the typescript is the header written by script.
const raw = fs.readFileSync(typescriptFile);
let offset = raw.indexOf(0x0a) + 1;
const timeline = [];
const out = (data, wait) => timeline.push({ kind: 'out', data, wait });

timeline.push({ kind: 'card', kicker: 'Demonstration', title: 'tlsrelay',
  text: 'A TCP relay that carries applications over plaintext, TLS 1.3 or mutual TLS, with transparent renegotiation, ' +
        'hot certificate rotation, revocation and a graphical editor. Recorded from a real run on one Linux machine.',
  pre: 'application ──► client relay ══ plain | TLS 1.3 | mTLS ══► server relay ──► destination', ms: 6500 });
timeline.push({ kind: 'caption', chapter: 'tlsrelay', text: 'Real binaries, real network connections on 127.0.0.1' });

const banner = /\x1b\[1m━━ (\d+)\. /g;
for (const line of fs.readFileSync(timingFile, 'utf8').trim().split('\n')) {
  const [seconds, bytes] = line.split(' ');
  let chunk = raw.subarray(offset, offset + Number(bytes)).toString('utf8');
  offset += Number(bytes);
  const delay = Number(seconds);
  let wait = Math.min(delay * 1000, 900);
  if (delay > 3) {
    timeline.push({ kind: 'later', text: `⏱ ${Math.round(delay)} s later`, ms: 1300 });
    wait = 300;
  }
  // Each step of the demonstration starts with its banner: chapter card, then a clean screen.
  let last = 0;
  for (const m of chunk.matchAll(banner)) {
    if (m.index > last) { out(chunk.slice(last, m.index), wait); wait = 0; }
    const n = Number(m[1]);
    const [title, text] = chapters[n] || [`Step ${n}`, ''];
    timeline.push({ kind: 'pause', ms: 1800 });
    timeline.push({ kind: 'card', kicker: `Step ${n} of 13`, title, text, ms: 3800 });
    timeline.push({ kind: 'clear' });
    timeline.push({ kind: 'caption', chapter: `${n}. ${title}`, text });
    last = m.index;
  }
  if (last < chunk.length) out(chunk.slice(last).replace(/Script done on .*/s, ''), wait);
}
timeline.push({ kind: 'pause', ms: 3500 });

timeline.push({ kind: 'card', kicker: 'The editor', title: 'tlsrelay-admin',
  text: 'Configurations, whitelists and the mini-CA, for administrators who prefer a window. ' +
        'The same files and rules as the command line.', ms: 4500 });
for (const [name, text] of shots) {
  const file = path.join(shotsDir, `${name}.png`);
  if (!fs.existsSync(file)) continue;
  timeline.push({ kind: 'caption', chapter: 'Editor', text });
  timeline.push({ kind: 'shot', src: 'file://' + path.resolve(file), ms: 5200 });
}

const result = raw.toString('utf8').match(/Result: (\d+) check\(s\) passed, (\d+) failed/);
timeline.push({ kind: 'card', kicker: 'Result', title: result ? `${result[1]} checks passed, ${result[2]} failed` : 'Demonstration complete',
  text: 'Everything shown runs in CI on every push, on Linux and Windows. ' +
        'Reproduce it with tools/demo.sh; this video is produced by tools/video/make-video.sh.',
  pre: 'docs/SPEC.md · docs/DESIGN.md · docs/TESTS.md · docs/EDITOR.md', ms: 6500 });

// Page: xterm.js and the timeline inlined.
const template = fs.readFileSync(path.join(__dirname, 'player.html'), 'utf8');
// Replacement functions: the recorded output contains "$" sequences that a replacement string would interpret.
const xterm = path.resolve(xtermDir);
const page = template
  .replace('XTERM_CSS', () => 'file://' + path.join(xterm, 'css', 'xterm.css'))
  .replace('XTERM_JS', () => 'file://' + path.join(xterm, 'lib', 'xterm.js'))
  .replace('TIMELINE_JSON', () => JSON.stringify(timeline).replace(/<\//g, '<\\/'));
const pageFile = path.join(path.dirname(path.resolve(outFile)), 'player.generated.html');
fs.writeFileSync(pageFile, page);

(async () => {
  const videoDir = path.join(path.dirname(path.resolve(outFile)), 'raw-video');
  fs.rmSync(videoDir, { recursive: true, force: true });
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1280, height: 720 },
    recordVideo: { dir: videoDir, size: { width: 1280, height: 720 } } });
  const tab = await context.newPage();
  let failure = null;
  tab.on('pageerror', e => { failure = e; });
  tab.on('requestfailed', r => { failure = new Error('cannot load ' + r.url()); });
  await tab.goto('file://' + pageFile);
  await tab.waitForTimeout(1000);
  if (failure) throw failure;
  await tab.waitForFunction(() => window.done === true, null, { timeout: 30 * 60 * 1000, polling: 500 });
  await tab.waitForTimeout(800);
  const video = tab.video();
  await context.close();
  await browser.close();
  fs.renameSync(await video.path(), outFile);
  console.log('recorded', outFile);
})().catch(e => { console.error(e); process.exit(1); });
