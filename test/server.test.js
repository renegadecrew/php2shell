import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { classifyPhp, isPublicAddress, lookup, normalizeDomain, parseCrt, requestCachedJson, requestHostPinned } from '../src/server.js';

function lookupDependencies(hostCount, probeHost) {
  return {
    requestJson: async (_url, provider) => provider === 'crt.name'
      ? Array.from({ length: hostCount }, (_, index) => ({ sub: `host-${index}.example.com` }))
      : [],
    probeHost,
    randomSample: (items, limit) => items.slice(0, limit)
  };
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

  assert.equal(vulnerable.affectedCandidate, true);
  assert.equal(vulnerable.version, '8.2.34');
  assert.equal(fixed.affectedCandidate, false);
  assert.match(fixed.assessment, /At\/above/);
  assert.equal(oldBranch.affectedCandidate, true);
  assert.match(oldBranch.assessment, /vendor backport unknown/);
});

test('phpinfo HTML heading exposes an exact version to the classifier', () => {
  const result = classifyPhp({}, '<html><h1 class="p">PHP Version 8.3.35</h1><table><tr>');
  assert.equal(result.version, '8.3.35');
  assert.equal(result.versionSource, 'PHP response');
  assert.equal(result.affectedCandidate, true);
});

test('a hidden version is unknown rather than reported as PHP patched or affected', () => {
  assert.deepEqual(classifyPhp({ server: 'nginx' }), {
    version: null,
    versionSource: null,
    assessment: 'Version not disclosed'
  });
});

test('the pinned HTTP probe preserves 200 and 403 and extracts exposed PHP headers', async (t) => {
  const fixture = createServer((request, response) => {
    response.setHeader('x-powered-by', 'PHP/8.2.34');
    response.statusCode = request.url === '/forbidden' ? 403 : 200;
    response.end('fixture response');
  });
  await new Promise((resolve, reject) => {
    fixture.once('error', reject);
    fixture.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise((resolve) => fixture.close(resolve)));

  const port = fixture.address().port;
  const ok = await requestHostPinned('http:', 'localhost', '127.0.0.1', 4, '/', 8192, port);
  const forbidden = await requestHostPinned('http:', 'localhost', '127.0.0.1', 4, '/forbidden', 8192, port);

  assert.equal(ok.status, 200);
  assert.equal(classifyPhp(ok.headers, ok.body).version, '8.2.34');
  assert.equal(classifyPhp(ok.headers, ok.body).affectedCandidate, true);
  assert.equal(forbidden.status, 403);
});

test('CT source responses are cached and concurrent identical lookups share one request', async (t) => {
  let requests = 0;
  const fixture = createServer((_request, response) => {
    requests += 1;
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify([{ hostname: 'a.example.test' }]));
  });
  await new Promise((resolve, reject) => {
    fixture.once('error', reject);
    fixture.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise((resolve) => fixture.close(resolve)));

  const url = new URL(`http://127.0.0.1:${fixture.address().port}/names`);
  const [first, second] = await Promise.all([
    requestCachedJson(url, 'fixture'),
    requestCachedJson(url, 'fixture')
  ]);

  assert.deepEqual(first, [{ hostname: 'a.example.test' }]);
  assert.deepEqual(second, first);
  assert.equal(requests, 1);
});

test('active lookup retries random batches without repeats and stops at 90 hosts', async () => {
  const probeHost = async () => ({
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
    lookupDependencies(94, probeHost)
  );

  const checkedHostnames = report.checks.map(({ hostname }) => hostname);
  assert.equal(report.stats.discoveredHostnames, 95);
  assert.equal(report.stats.checkedHosts, 90);
  assert.equal(report.stats.batches, 3);
  assert.equal(new Set(checkedHostnames).size, 90);
  assert.equal(report.findings.length, 0);
  assert.equal(report.stats.http200Count, 90);
  assert.equal(report.stats.noResponseCount, 0);
});

test('active lookup returns only version-confirmed candidates with HTTP evidence', async () => {
  const probeHost = async (hostname) => hostname === 'example.com'
    ? { status: 403, protocol: 'https', phpVersion: '8.2.34', phpPresent: true, affectedCandidate: true, assessment: 'Below fixed release (candidate)' }
    : { status: 200, protocol: 'https', phpVersion: '8.2.35', phpPresent: true, affectedCandidate: false, assessment: 'At/above fixed release' };
  const report = await lookup(
    { domain: 'example.com', scopeType: 'registrable' },
    true,
    () => {},
    lookupDependencies(40, probeHost)
  );

  assert.equal(report.stats.checkedHosts, 30);
  assert.equal(report.stats.http403Count, 1);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].hostname, 'example.com');
  assert.equal(report.findings[0].check.status, 403);
  assert.equal(report.findings[0].check.phpVersion, '8.2.34');
  assert.equal(report.checks.length, 30);
});

test('probe address validation rejects private and special-use address ranges', () => {
  for (const address of ['10.0.0.1', '172.16.0.1', '192.168.0.1', '192.0.2.4', '198.51.100.4', '203.0.113.4', '127.0.0.1']) {
    assert.equal(isPublicAddress(address), false, `${address} must not be probed`);
  }
  assert.equal(isPublicAddress('8.8.8.8'), true);
  assert.equal(isPublicAddress('2001:4860:4860::8888'), true);
  assert.equal(isPublicAddress('2001:db8::1'), false);
  assert.equal(isPublicAddress('2001::1'), false);
  assert.equal(isPublicAddress('2002::1'), false);
});
