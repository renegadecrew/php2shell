import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { BANNER, csvCell, runCli } from '../src/cli.js';
import {
  classifyPhp,
  createAppServer,
  inspectPhpInfoFix,
  isPublicAddress,
  lookup,
  normalizeDomain,
  parseCrt,
  probeHost,
  requestCachedJson,
  requestHostPinned
} from '../src/server.js';

function lookupDependencies(hostCount, probeHostFn, overrides = {}) {
  return {
    requestJson: async (_url, provider) => provider === 'crt.name'
      ? Array.from({ length: hostCount }, (_, index) => ({ sub: `host-${index}.example.com` }))
      : [],
    probeHost: probeHostFn,
    randomSample: (items, limit) => items.slice(0, limit),
    ...overrides
  };
}

async function listenLocal(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server.address().port;
}

test('crt.name JSON rows use sub and retain first-seen dates', () => {
  const records = parseCrt([
    { sub: 'portal.example.mx', first_seen: '2026-01-02T03:04:05Z' },
    { name_value: 'legacy.example.mx', date: '2025-03-04' },
    { name_value: 'old.example.mx', not_before: '2024-06-07T08:09:10Z' }
  ]);

  assert.deepEqual(records, [
    { hostname: 'portal.example.mx', firstSeen: '2026-01-02T03:04:05Z' },
    { hostname: 'legacy.example.mx', firstSeen: '2025-03-04' },
    { hostname: 'old.example.mx', firstSeen: '2024-06-07T08:09:10Z' }
  ]);
});

test('domain input accepts registrable Mexican domains and public suffixes', () => {
  assert.deepEqual(normalizeDomain('midominio.mx'), { domain: 'midominio.mx', scopeType: 'registrable' });
  assert.deepEqual(normalizeDomain('midominio.com.mx'), { domain: 'midominio.com.mx', scopeType: 'registrable' });
  assert.deepEqual(normalizeDomain('gob.mx'), { domain: 'gob.mx', scopeType: 'publicSuffix' });
  assert.deepEqual(normalizeDomain('.mx'), { domain: 'mx', scopeType: 'publicSuffix' });
});

test('PHP version disclosure is compared to the published fixed patch', () => {
  const vulnerable = classifyPhp({ 'x-powered-by': 'PHP/8.2.34' });
  const fixed = classifyPhp({ 'x-powered-by': 'PHP/8.2.35' });
  const oldBranch = classifyPhp({ 'x-powered-by': 'PHP/8.1.33' });
  const vendorPkg = classifyPhp({ 'x-powered-by': 'PHP/8.2.28-1~deb12u2' });

  assert.equal(vulnerable.affectedCandidate, true);
  assert.equal(vulnerable.version, '8.2.34');
  assert.equal(fixed.affectedCandidate, false);
  assert.match(fixed.assessment, /At\/above/);
  assert.equal(oldBranch.affectedCandidate, true);
  assert.match(oldBranch.assessment, /vendor backport unknown/);
  assert.equal(vendorPkg.version, '8.2.28');
  assert.equal(vendorPkg.vendorSuffix, '-1~deb12u2');
  assert.match(vendorPkg.assessment, /vendor suffix present/);
});

test('phpinfo HTML heading exposes an exact version while normal prose does not false-positive', () => {
  const result = classifyPhp({}, '<html><h1 class="p">PHP Version 8.3.35</h1><table><tr>');
  assert.equal(result.version, '8.3.35');
  assert.equal(result.versionSource, 'PHP response');
  assert.equal(result.affectedCandidate, true);

  const cellResult = classifyPhp({}, '<table><tr><td class="e">PHP Version</td><td class="v">8.4.27</td></tr></table>');
  assert.equal(cellResult.version, '8.4.27');
  assert.equal(cellResult.affectedCandidate, false);

  const proseResult = classifyPhp({}, '<article><p>Requires PHP Version 8.1.0 or newer to install this plugin.</p></article>');
  assert.equal(proseResult.version, null);
  assert.equal(proseResult.assessment, 'Version not disclosed');
});

test('a hidden version is unknown rather than reported as PHP patched or affected', () => {
  assert.deepEqual(classifyPhp({ server: 'nginx' }), {
    version: null,
    versionSource: null,
    assessment: 'Version not disclosed'
  });
});

test('inspectPhpInfoFix distinguishes present, absent, truncated, and non-phpinfo bodies', () => {
  assert.equal(inspectPhpInfoFix('<h1 class="p">PHP Version 8.2.34</h1><tr><td>memory_hard_limit_percent</td><td>0</td></tr>', false), 'present');
  assert.equal(inspectPhpInfoFix('<h1 class="p">PHP Version 8.2.34</h1><h2><a name="module_Core">Core</a></h2>', false), 'absent');
  assert.equal(inspectPhpInfoFix('<h1 class="p">PHP Version 8.2.34</h1><h2><a name="module_Core">Core</a></h2>', true), null);
  assert.equal(inspectPhpInfoFix('<html><body>Hello world</body></html>', false), null);
});

test('the pinned HTTP probe preserves 200, 302 Location, and 403 and extracts exposed PHP headers', async (t) => {
  const fixture = createServer((request, response) => {
    response.setHeader('x-powered-by', 'PHP/8.2.34');
    if (request.url === '/redirect') {
      response.statusCode = 302;
      response.setHeader('location', 'https://www.example.com/');
      return response.end();
    }
    response.statusCode = request.url === '/forbidden' ? 403 : 200;
    response.end('fixture response');
  });
  const port = await listenLocal(fixture);
  t.after(() => new Promise((resolve) => fixture.close(resolve)));

  const ok = await requestHostPinned('http:', 'localhost', '127.0.0.1', 4, '/', 8192, port);
  const forbidden = await requestHostPinned('http:', 'localhost', '127.0.0.1', 4, '/forbidden', 8192, port);
  const redirect = await requestHostPinned('http:', 'localhost', '127.0.0.1', 4, '/redirect', 8192, port);

  assert.equal(ok.status, 200);
  assert.equal(classifyPhp(ok.headers, ok.body).version, '8.2.34');
  assert.equal(classifyPhp(ok.headers, ok.body).affectedCandidate, true);
  assert.equal(forbidden.status, 403);
  assert.equal(redirect.status, 302);
  assert.equal(redirect.location, 'https://www.example.com/');
});

test('CT source responses are cached and concurrent identical lookups share one request', async (t) => {
  let requests = 0;
  const fixture = createServer((_request, response) => {
    requests += 1;
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify([{ hostname: 'a.example.test' }]));
  });
  const port = await listenLocal(fixture);
  t.after(() => new Promise((resolve) => fixture.close(resolve)));

  const url = new URL(`http://127.0.0.1:${port}/names`);
  const [first, second] = await Promise.all([
    requestCachedJson(url, 'fixture'),
    requestCachedJson(url, 'fixture')
  ]);

  assert.deepEqual(first, [{ hostname: 'a.example.test' }]);
  assert.deepEqual(second, first);
  assert.equal(requests, 1);
});

test('active lookup caps default scan at 90 unique hosts when no candidates are found', async () => {
  const probeFn = async () => ({
    status: 200,
    protocol: 'https',
    phpVersion: null,
    phpPresent: false,
    affectedCandidate: false,
    assessment: 'Version not disclosed'
  });
  const report = await lookup(
    { domain: 'example.com', scopeType: 'registrable' },
    true,
    () => {},
    lookupDependencies(130, probeFn)
  );

  const checkedHostnames = report.checks.map(({ hostname }) => hostname);
  assert.equal(report.stats.discoveredHostnames, 131);
  assert.equal(report.stats.checkedHosts, 90);
  assert.equal(report.stats.batches, 3);
  assert.equal(new Set(checkedHostnames).size, 90);
  assert.equal(report.findings.length, 0);
  assert.equal(report.stats.http200Count, 90);
  assert.equal(report.stats.noResponseCount, 0);
});

test('active lookup continues past 90 hosts and stops on the first batch containing a candidate', async () => {
  const probeFn = async (hostname) => hostname === 'host-95.example.com'
    ? { status: 200, protocol: 'https', phpVersion: '8.2.34', phpPresent: true, affectedCandidate: true, assessment: 'Below fixed release (candidate)' }
    : { status: 200, protocol: 'https', phpVersion: null, phpPresent: false, affectedCandidate: false, assessment: 'Version not disclosed' };
  const report = await lookup(
    { domain: 'example.com', scopeType: 'registrable' },
    true,
    () => {},
    lookupDependencies(130, probeFn, { maxBatches: 4 })
  );

  assert.equal(report.stats.discoveredHostnames, 131);
  assert.equal(report.stats.checkedHosts, 120);
  assert.equal(report.stats.batches, 4);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].hostname, 'host-95.example.com');
  assert.equal(new Set(report.checks.map(({ hostname }) => hostname)).size, 120);
});

test('active lookup returns only version-confirmed candidates with HTTP evidence', async () => {
  const probeFn = async (hostname) => hostname === 'example.com'
    ? { status: 403, protocol: 'https', phpVersion: '8.2.34', phpPresent: true, affectedCandidate: true, assessment: 'Below fixed release (candidate)' }
    : { status: 200, protocol: 'https', phpVersion: '8.2.35', phpPresent: true, affectedCandidate: false, assessment: 'At/above fixed release' };
  const report = await lookup(
    { domain: 'example.com', scopeType: 'registrable' },
    true,
    () => {},
    lookupDependencies(40, probeFn)
  );

  assert.equal(report.stats.checkedHosts, 30);
  assert.equal(report.stats.http403Count, 1);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].hostname, 'example.com');
  assert.equal(report.findings[0].check.status, 403);
  assert.equal(report.findings[0].check.phpVersion, '8.2.34');
  assert.equal(report.checks.length, 30);
});

test('lookup retains firstSeen from crt.name when Shodan CTL also reports the host', async () => {
  const report = await lookup(
    { domain: 'example.com', scopeType: 'registrable' },
    false,
    () => {},
    {
      requestJson: async (_url, provider) => {
        if (provider === 'Shodan CTL') return ['app.example.com'];
        return [{ sub: 'app.example.com', first_seen: '2026-02-01T00:00:00Z' }];
      }
    }
  );

  const appRecord = report.findings.find(({ hostname }) => hostname === 'app.example.com');
  assert.ok(appRecord);
  assert.equal(appRecord.firstSeen, '2026-02-01T00:00:00Z');
  assert.deepEqual(appRecord.sources, ['Shodan CTL', 'crt.name']);
});

test('phpinfo fix marker on root updates targetAssessment and patchedCount stats', async () => {
  const rootBody = '<h1 class="p">PHP Version 8.2.34</h1><h2><a name="module_Core">Core</a></h2><tr><td>memory_hard_limit_percent</td><td>0</td></tr>';
  const requestedPaths = [];
  const check = await probeHost('example.com', {
    deep: true,
    dnsLookupFn: async () => [{ address: '93.184.216.34', family: 4 }],
    requestFn: async (protocol, _host, _ip, _family, reqPath) => {
      requestedPaths.push(`${protocol}${reqPath}`);
      return { status: 200, headers: {}, location: null, protocol: 'https', body: rootBody, truncated: false };
    }
  });

  assert.deepEqual(requestedPaths, ['https:/']);
  assert.equal(check.php2ShellFix, 'present');
  assert.equal(check.php2ShellFixPath, '/');
  assert.equal(check.affectedCandidate, false);

  const report = await lookup(
    { domain: 'example.com', scopeType: 'registrable' },
    true,
    () => {},
    lookupDependencies(0, async () => check)
  );
  assert.equal(report.targetAssessment.verdict, 'confirmed_patched');
  assert.equal(report.targetAssessment.endpoint, '/');
  assert.equal(report.stats.patchedCount, 1);
  assert.equal(report.stats.unknownCount, 0);
});

test('probeHost falls back across multiple DNS addresses and skips phpinfo paths for non-target hosts', async () => {
  const attempts = [];
  const check = await probeHost('sub.example.com', {
    deep: false,
    dnsLookupFn: async () => [
      { address: '2001:4860:4860::8888', family: 6 },
      { address: '93.184.216.34', family: 4 }
    ],
    requestFn: async (protocol, _host, ip, _family, reqPath) => {
      attempts.push(`${protocol}//${ip}${reqPath}`);
      if (ip.includes(':')) throw new Error('Network unreachable');
      return {
        status: reqPath === '/' ? 200 : 404,
        headers: reqPath === '/' ? { server: 'nginx' } : {},
        location: null,
        protocol: protocol.slice(0, -1),
        body: 'ok',
        truncated: false
      };
    }
  });

  assert.equal(check.status, 200);
  assert.equal(check.protocol, 'https');
  assert.equal(attempts.length, 4); // https+http on IPv6 fail, https / on IPv4 succeeds, plus 1 random .php probe
  assert.ok(!attempts.some((entry) => entry.endsWith('/phpinfo.php') || entry.endsWith('/info.php')));
});

test('probe address validation rejects private and special-use IPv4 and IPv6 ranges', () => {
  for (const address of ['10.0.0.1', '172.16.0.1', '192.168.0.1', '192.0.2.4', '198.51.100.4', '203.0.113.4', '127.0.0.1']) {
    assert.equal(isPublicAddress(address), false, `${address} must not be probed`);
  }
  assert.equal(isPublicAddress('8.8.8.8'), true);
  assert.equal(isPublicAddress('2001:4860:4860::8888'), true);
  assert.equal(isPublicAddress('::ffff:8.8.8.8'), true);
  for (const v6 of ['::1', 'fe80::1', 'fc00::1', '2001:db8::1', '2001:0db8::1', '2001::1', '2002::1', '2::1', '30::1', '3ffe::1', '::ffff:127.0.0.1', '::ffff:7f00:1']) {
    assert.equal(isPublicAddress(v6), false, `${v6} must not be probed`);
  }
});

test('HTTP server validates loopback headers, JSON payloads, progress IDs, and lookup responses', async (t) => {
  const server = createAppServer({
    lookupFn: async (scope, activeCheck, onProgress) => {
      onProgress({ phase: 'complete', checked: 1, batches: 1, candidates: 0, total: 1 });
      return { domain: scope.domain, scopeType: scope.scopeType, activeCheck, findings: [], checks: [], stats: {}, errors: [], cves: [] };
    }
  });
  const port = await listenLocal(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const health = await fetch(`http://127.0.0.1:${port}/api/health`);
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { ok: true });

  const badOrigin = await fetch(`http://127.0.0.1:${port}/api/health`, {
    headers: { origin: 'https://evil.example' }
  });
  assert.equal(badOrigin.status, 403);

  const nullBody = await fetch(`http://127.0.0.1:${port}/api/lookup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: 'null'
  });
  assert.equal(nullBody.status, 400);

  const oversizedBody = await fetch(`http://127.0.0.1:${port}/api/lookup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ domain: 'a'.repeat(3000) })
  });
  assert.equal(oversizedBody.status, 413);

  const scanId = '11111111-2222-4333-8444-555555555555';
  const okLookup = await fetch(`http://127.0.0.1:${port}/api/lookup`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ domain: 'example.com', activeCheck: false, scanId })
  });
  assert.equal(okLookup.status, 200);
  const payload = await okLookup.json();
  assert.equal(payload.domain, 'example.com');
  assert.equal(payload.activeCheck, false);

  const progress = await fetch(`http://127.0.0.1:${port}/api/progress?id=${scanId}`);
  assert.equal(progress.status, 200);
  assert.equal((await progress.json()).phase, 'complete');

  const badProgress = await fetch(`http://127.0.0.1:${port}/api/progress?id=short`);
  assert.equal(badProgress.status, 400);
});

test('normalizeDomain rejects non-ICANN TLDs such as .mex and localhost', () => {
  assert.throws(() => normalizeDomain('gob.mex'), /recognized TLD/);
  assert.throws(() => normalizeDomain('localhost'), /recognized TLD/);
});

test('probeHost records tlsError when HTTPS fails and falls back to HTTP', async () => {
  const check = await probeHost('example.com', {
    deep: false,
    dnsLookupFn: async () => [{ address: '93.184.216.34', family: 4 }],
    requestFn: async (protocol) => {
      if (protocol === 'https:') throw new Error('self-signed certificate');
      return {
        status: 200,
        headers: { 'x-powered-by': 'PHP/8.2.35' },
        location: null,
        protocol: 'http',
        body: 'ok',
        truncated: false
      };
    }
  });

  assert.equal(check.protocol, 'http');
  assert.equal(check.tlsError, 'self-signed certificate');
  assert.equal(check.evidence[0].tlsError, 'self-signed certificate');
  assert.equal(check.phpVersion, '8.2.35');
});

test('lookup supports stopOnCandidate=false and maxBatches to collect candidates across multiple batches', async () => {
  const probeFn = async (hostname) => (hostname === 'host-1.example.com' || hostname === 'host-35.example.com')
    ? { status: 200, protocol: 'https', phpVersion: '8.2.34', phpPresent: true, affectedCandidate: true, assessment: 'Below fixed release (candidate)' }
    : { status: 200, protocol: 'https', phpVersion: null, phpPresent: false, affectedCandidate: false, assessment: 'Version not disclosed' };

  const report = await lookup(
    { domain: 'example.com', scopeType: 'registrable' },
    true,
    () => {},
    lookupDependencies(70, probeFn, { stopOnCandidate: false, maxBatches: 2 })
  );

  assert.equal(report.stats.batches, 2);
  assert.equal(report.stats.checkedHosts, 60);
  assert.deepEqual(report.findings.map(({ hostname }) => hostname), ['host-1.example.com', 'host-35.example.com']);
});

test('async /api/scans streams SSE events and retains partial results when cancelled', async (t) => {
  const server = createAppServer({
    lookupFn: async (scope, activeCheck, onProgress, deps, signal) => {
      onProgress({ phase: 'enumerating', domain: scope.domain, scopeType: scope.scopeType });
      const partial = {
        domain: scope.domain,
        scopeType: scope.scopeType,
        queriedAt: new Date().toISOString(),
        mode: 'passive+http',
        summary: 'Partial',
        partial: true,
        cancelled: false,
        activeCheck,
        stats: { discoveredHostnames: 2, checkedHosts: 1, batches: 1 },
        findings: [],
        checks: [{ hostname: scope.domain, sources: ['Queried domain'], check: { status: 200, protocol: 'https', evidence: [] } }],
        errors: [],
        cves: []
      };
      deps.onBatch?.(partial);
      await new Promise((resolve) => {
        if (signal?.aborted) return resolve();
        signal?.addEventListener('abort', resolve, { once: true });
      });
      return { ...partial, cancelled: true };
    }
  });
  const port = await listenLocal(server);
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const startRes = await fetch(`http://127.0.0.1:${port}/api/scans`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ domain: 'example.com', activeCheck: true })
  });
  assert.equal(startRes.status, 202);
  const { scanId } = await startRes.json();

  const eventsRes = await fetch(`http://127.0.0.1:${port}/api/scans/${scanId}/events`);
  assert.equal(eventsRes.status, 200);
  const reader = eventsRes.body.getReader();
  const decoder = new TextDecoder();
  let streamText = '';

  while (!streamText.includes('event: batch')) {
    const { value, done } = await reader.read();
    if (done) break;
    streamText += decoder.decode(value, { stream: true });
  }
  assert.match(streamText, /event: batch/);

  const cancelRes = await fetch(`http://127.0.0.1:${port}/api/scans/${scanId}/cancel`, { method: 'POST' });
  assert.equal(cancelRes.status, 200);

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    streamText += decoder.decode(value, { stream: true });
  }
  assert.match(streamText, /event: cancelled/);
  assert.match(streamText, /"cancelled":true/);
});

test('CLI prints blood-red banner to stderr, omits it for --help/--version, and neutralizes CSV formulas', async () => {
  const makeBuffer = (isTTY = false) => {
    let data = '';
    return { isTTY, write(chunk) { data += String(chunk); }, text() { return data; } };
  };

  const helpOut = makeBuffer();
  const helpErr = makeBuffer(true);
  assert.equal(await runCli(['--help'], { stdout: helpOut, stderr: helpErr }), 0);
  assert.match(helpOut.text(), /Usage: php2shell/);
  assert.equal(helpErr.text(), '');

  const verOut = makeBuffer();
  const verErr = makeBuffer(true);
  assert.equal(await runCli(['--version'], { stdout: verOut, stderr: verErr }), 0);
  assert.match(verOut.text(), /^php2shell \d+\.\d+\.\d+/);
  assert.equal(verErr.text(), '');

  const dir = mkdtempSync(path.join(tmpdir(), 'php2shell-cli-'));
  try {
    const inputPath = path.join(dir, 'domains.txt');
    writeFileSync(inputPath, '# comment\nexample.com\n\nexample.com\n', 'utf8');

    const out = makeBuffer();
    const err = makeBuffer(true);
    const code = await runCli(['--input', inputPath, '--format', 'csv', '--color'], {
      stdout: out,
      stderr: err,
      lookupFn: async (scope) => ({
        domain: scope.domain,
        scopeType: scope.scopeType,
        activeCheck: true,
        summary: 'Found 1; checked 1 in 1 batch.',
        findings: [],
        checks: [{
          hostname: 'example.com',
          sources: ['Queried domain'],
          firstSeen: null,
          check: {
            status: 200,
            protocol: 'https',
            phpPresent: false,
            phpVersion: null,
            assessment: '=CMD()',
            evidence: [{ protocol: 'https', status: 200, path: '/' }]
          }
        }]
      })
    });
    assert.equal(code, 0);
    assert.ok(err.text().includes(BANNER.trim()));
    assert.ok(err.text().includes('\x1b[1;31m'));
    assert.match(out.text(), /"'=CMD\(\)"/);
    assert.equal(csvCell('=1+1'), `"'=1+1"`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
