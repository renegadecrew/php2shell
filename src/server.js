import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { URL } from 'node:url';
import { lookup as dnsLookup } from 'node:dns/promises';
import https from 'node:https';
import { isIP } from 'node:net';
import { parse as parseDomain } from 'tldts';
import { randomBytes, randomInt } from 'node:crypto';

const here = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.resolve(here, '../public');
const publicAssets = new Map([
  ['/styles.css', { file: 'styles.css', type: 'text/css; charset=utf-8' }],
  ['/app.js', { file: 'app.js', type: 'text/javascript; charset=utf-8' }],
  ['/php2shell-banner.svg', { file: 'php2shell-banner.svg', type: 'image/svg+xml; charset=utf-8' }]
]);
const port = Number(process.env.PORT || 3000);
const maxBodyBytes = 2048;
const requestWindowMs = 60_000;
const requestLimit = 20;
const sampleBatchSize = 30;
const maxSampleBatches = 3;
const clientRequests = new Map();
const sourceCache = new Map();
const sourceCacheTtlMs = 30 * 60_000;
const sourceCacheMaxEntries = 64;
const scanProgress = new Map();
const progressTtlMs = 10 * 60_000;
const progressCleanup = setInterval(() => {
  const now = Date.now();
  for (const [scanId, state] of scanProgress) {
    if (now - Date.parse(state.updatedAt) > progressTtlMs) scanProgress.delete(scanId);
  }
}, 60_000);
progressCleanup.unref?.();

const CVES = [
  {
    id: 'CVE-2026-109618',
    label: 'RCE via out-of-memory corruption',
    url: 'https://www.cve.org/CVERecord?id=CVE-2026-109618'
  },
  {
    id: 'CVE-2026-109619',
    label: 'RCE via stale global state',
    url: 'https://www.cve.org/CVERecord?id=CVE-2026-109619'
  }
];

function normalizeDomain(value) {
  if (typeof value !== 'string' || value.length > 253) throw new Error('Enter a registrable domain or public suffix.');
  const raw = value.trim().toLowerCase().replace(/^\./, '').replace(/\.$/, '');
  if (!raw || raw.includes('://') || raw.includes('/') || raw.includes('@') || raw.includes(':')) {
    throw new Error('Enter a hostname only; omit scheme, path, and port.');
  }
  let ascii;
  try {
    ascii = new URL(`http://${raw}`).hostname;
  } catch {
    throw new Error('Invalid domain or suffix. Examples: example.com, site.com.mx, .mx.');
  }
  const parsed = parseDomain(ascii);
  if (parsed.domain) return { domain: parsed.domain, scopeType: 'registrable' };
  if (parsed.publicSuffix === ascii) return { domain: ascii, scopeType: 'publicSuffix' };
  throw new Error('Enter a valid domain or public suffix.');
}

function withinRateLimit(ip) {
  const now = Date.now();
  const items = (clientRequests.get(ip) || []).filter((time) => now - time < requestWindowMs);
  if (items.length >= requestLimit) return false;
  items.push(now);
  clientRequests.set(ip, items);
  return true;
}

async function requestJson(url, provider, timeoutMs = 12_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { accept: 'application/json,text/plain;q=0.9', 'user-agent': 'php2shell-passive-audit/1.0' }
    });
    if (!response.ok) throw new Error(`${provider} returned HTTP ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

async function requestCachedJson(url, provider, timeoutMs = 12_000) {
  const key = url.toString();
  const cached = sourceCache.get(key);
  if (cached && cached.expiresAt > Date.now()) {
    sourceCache.delete(key);
    sourceCache.set(key, cached);
    return cached.promise;
  }
  if (cached) sourceCache.delete(key);

  const entry = { expiresAt: Number.POSITIVE_INFINITY, promise: null };
  entry.promise = requestJson(url, provider, timeoutMs)
    .then((payload) => {
      entry.expiresAt = Date.now() + sourceCacheTtlMs;
      return payload;
    })
    .catch((error) => {
      if (sourceCache.get(key) === entry) sourceCache.delete(key);
      throw error;
    });
  sourceCache.set(key, entry);
  while (sourceCache.size > sourceCacheMaxEntries) sourceCache.delete(sourceCache.keys().next().value);
  return entry.promise;
}

function parseCrt(payload) {
  if (!Array.isArray(payload)) return [];
  return payload.flatMap((row) => {
    if (typeof row === 'string') return row.split(/[\r\n,]+/);
    if (!row || typeof row !== 'object') return [];
    // crt.name's documented /v1/search JSON uses `sub`; crt.sh and other
    // CT-compatible feeds commonly use `name_value` or `name` instead.
    const name = row.sub || row.subdomain || row.name || row.hostname || row.domain || row.name_value;
    return name ? String(name).split(/[\r\n]+/).map((hostname) => ({
      hostname,
      firstSeen: row.first_seen || row.firstSeen || row.entry_timestamp || row.not_before || row.notBefore || row.date || null
    })) : [];
  });
}

function parseShodan(payload) {
  if (Array.isArray(payload)) return payload.map((entry) => typeof entry === 'string' ? entry : entry?.hostname || entry?.domain).filter(Boolean);
  if (Array.isArray(payload?.hostnames)) return payload.hostnames.map((entry) => typeof entry === 'string' ? entry : entry?.hostname || entry?.domain).filter(Boolean);
  return [];
}

function cleanHost(value, apex) {
  const hostname = String(value).trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
  if (!hostname || hostname.length > 253 || hostname.includes('*')) return null;
  const labels = hostname.split('.');
  if (labels.some((part) => !part || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part))) return null;
  if (hostname !== apex && !hostname.endsWith(`.${apex}`)) return null;
  return hostname;
}

function randomSample(items, limit = 30) {
  const shuffled = [...items];
  for (let index = shuffled.length - 1; index > 0; index -= 1) {
    const swapIndex = randomInt(index + 1);
    [shuffled[index], shuffled[swapIndex]] = [shuffled[swapIndex], shuffled[index]];
  }
  return shuffled.slice(0, limit);
}

function isPublicAddress(address) {
  if (isIP(address) === 4) {
    const octets = address.split('.').map(Number);
    const value = octets.reduce((sum, octet) => (sum * 256) + octet, 0) >>> 0;
    const inRange = (network, prefix) => {
      const base = network.split('.').map(Number).reduce((sum, octet) => (sum * 256) + octet, 0) >>> 0;
      const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
      return ((value & mask) >>> 0) === ((base & mask) >>> 0);
    };
    const nonPublicRanges = [
      ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
      ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
      ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
      ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
    ];
    return !nonPublicRanges.some(([network, prefix]) => inRange(network, prefix));
  }
  if (isIP(address) !== 6) return false;
  const normalized = address.toLowerCase();
  if (normalized.startsWith('::ffff:')) return isPublicAddress(normalized.slice(7));
  // Public IPv6 unicast allocations are in 2000::/3. Exclude documentation space.
  const secondHextet = normalized.split(':')[1] || '0';
  const secondHextetValue = Number.parseInt(secondHextet || '0', 16);
  return /^[23]/.test(normalized) &&
    !normalized.startsWith('2001:db8:') &&
    !(normalized.startsWith('2001:') && secondHextetValue <= 0x01ff) &&
    !normalized.startsWith('2002:');
}

function requestHostPinned(protocol, hostname, ip, family, requestPath = '/', maxBodyBytes = 8192, port = protocol === 'https:' ? 443 : 80) {
  return new Promise((resolve, reject) => {
    const transport = protocol === 'https:' ? https : http;
    let settled = false;
    let body = Buffer.alloc(0);
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve({ ...result, body: body.toString('utf8') });
    };
    const request = transport.request({
      hostname,
      ...(protocol === 'https:' ? { servername: hostname } : {}),
      port,
      method: 'GET',
      path: requestPath,
      timeout: 4000,
      headers: {
        'user-agent': 'php2shell-blue-team-inventory/1.0',
        accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5',
        connection: 'close'
      },
      lookup: (_host, options, callback) => {
        if (options?.all) callback(null, [{ address: ip, family }]);
        else callback(null, ip, family);
      }
    }, (response) => {
      const base = { status: response.statusCode || null, headers: response.headers, protocol: protocol.slice(0, -1) };
      response.on('data', (chunk) => {
        if (body.length < maxBodyBytes) {
          body = Buffer.concat([body, chunk.subarray(0, maxBodyBytes - body.length)]);
        }
        if (body.length >= maxBodyBytes) {
          finish({ ...base, truncated: true });
          // Stop even if the server keeps streaming after the local byte cap.
          response.destroy();
        }
      });
      response.on('end', () => finish(base));
      response.on('error', () => finish(base));
    });
    request.on('timeout', () => request.destroy(new Error('Request timeout (4s).')));
    request.on('error', (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
    request.end();
  });
}

function classifyPhp(headers, body = '') {
  const exposed = `${headers['x-powered-by'] || ''} ${headers.server || ''}`;
  const headerMatch = exposed.match(/\bPHP(?:\s*\/\s*|\s+)(\d+\.\d+\.\d+)(?:\b|[-+])/i);
  const infoMatch = body.match(/PHP\s+Version(?:(?:\s|<[^>]*>)){0,24}(\d+\.\d+\.\d+)/i);
  const zendMatch = body.match(/Zend Engine\s+v?4\.(\d+)\.(\d+)/i);
  const version = headerMatch?.[1] || infoMatch?.[1] || (zendMatch ? `8.${zendMatch[1]}.${zendMatch[2]}` : null);
  if (!version) return { version: null, versionSource: null, assessment: 'Version not disclosed' };
  const versionSource = headerMatch ? 'HTTP header' : infoMatch ? 'PHP response' : 'Zend Engine';
  if (version.split('.').length < 3) return { version, affectedCandidate: false, assessment: 'Partial version; patch unknown' };
  const parts = version.split('.').map(Number);
  const fixed = { '8.2': '8.2.35', '8.3': '8.3.36', '8.4': '8.4.27', '8.5': '8.5.12' };
  const branch = `${parts[0]}.${parts[1]}`;
  if (fixed[branch]) {
    const [fixedMajor, fixedMinor, fixedPatch] = fixed[branch].split('.').map(Number);
    const isOlder = parts[0] < fixedMajor || (parts[0] === fixedMajor && parts[1] < fixedMinor) ||
      (parts[0] === fixedMajor && parts[1] === fixedMinor && parts[2] < fixedPatch);
    return {
      version,
      versionSource,
      affectedCandidate: isOlder,
      assessment: isOlder ? 'Below fixed release (candidate)' : 'At/above fixed release'
    };
  }
  if (parts[0] < 8 || (parts[0] === 8 && parts[1] <= 1)) {
    return { version, versionSource, affectedCandidate: true, assessment: 'Legacy branch; vendor backport unknown' };
  }
  return { version, versionSource, affectedCandidate: false, assessment: 'Verify vendor package status' };
}

function inspectPhpInfoFix(body, truncated = false) {
  const looksLikePhpInfo = /phpinfo\s*\(\)|PHP Version|module_Core/i.test(body);
  if (!looksLikePhpInfo) return null;
  if (/memory_hard_limit_percent/i.test(body)) return 'present';
  const hasCoreTable = /module_Core|>\s*Core\s*</i.test(body);
  return hasCoreTable && !truncated ? 'absent' : null;
}

async function probeHost(hostname, { deep = false } = {}) {
  try {
    const addresses = await dnsLookup(hostname, { all: true, verbatim: true });
    if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address))) {
      return { status: null, error: 'DNS failure or non-public address.', phpVersion: null, assessment: 'Not checked', evidence: [] };
    }
    let response;
    let protocol;
    try {
      protocol = 'https:';
      response = await requestHostPinned(protocol, hostname, addresses[0].address, addresses[0].family);
    } catch {
      protocol = 'http:';
      response = await requestHostPinned(protocol, hostname, addresses[0].address, addresses[0].family);
    }
    let php = classifyPhp(response.headers, response.body);
    let phpPresence = Boolean(php.version || /PHPSESSID/i.test(response.headers['set-cookie'] || '') || /\bPHP\s+(?:Fatal error|Warning|Notice|Deprecated):/i.test(response.body));
    const evidence = [];
    const makeEvidence = (path, result, detected, present) => ({
      path,
      status: result.status,
      protocol: result.protocol,
      phpPresent: present,
      phpVersion: detected.version || null,
      versionSource: detected.versionSource || null,
      php2ShellFix: inspectPhpInfoFix(result.body || '', result.truncated)
    });
    const rootEvidence = makeEvidence('/', response, php, phpPresence);
    evidence.push(rootEvidence);
    let phpEvidence = phpPresence ? rootEvidence : null;
    let versionEvidence = php.version ? rootEvidence : null;

    // A static homepage can hide PHP behind PHP-FPM. The exact domain also gets
    // two bounded phpinfo checks for the PHP2Shell fix marker.
    const phpProbePaths = deep
      ? ['/phpinfo.php', '/info.php', `/${randomBytes(8).toString('hex')}.php`]
      : [`/${randomBytes(8).toString('hex')}.php`, '/phpinfo.php', '/info.php'];
    for (const probePath of phpProbePaths) {
      if (!deep && php.version) break;
      try {
        const isPhpInfoPath = probePath === '/phpinfo.php' || probePath === '/info.php';
        const probe = await requestHostPinned(protocol, hostname, addresses[0].address, addresses[0].family, probePath, isPhpInfoPath ? 262144 : 8192);
        const probePhp = classifyPhp(probe.headers, probe.body);
        const probePresent = Boolean(probePhp.version || /PHPSESSID/i.test(probe.headers['set-cookie'] || '') || /\bPHP\s+(?:Fatal error|Warning|Notice|Deprecated):/i.test(probe.body));
        const probeEvidence = makeEvidence(probePath, probe, probePhp, probePresent);
        evidence.push(probeEvidence);
        if (probePhp.version) {
          php = probePhp;
          versionEvidence = probeEvidence;
        }
        if (probeEvidence.php2ShellFix) {
          php.php2ShellFix = probeEvidence.php2ShellFix;
          php.php2ShellFixPath = probePath;
          if (probeEvidence.php2ShellFix === 'present') {
            php.affectedCandidate = false;
            php.assessment = 'PHP2Shell fix marker found in phpinfo';
          } else if (php.affectedCandidate === true) {
            php.assessment = 'Affected version; fix marker absent in complete phpinfo';
          }
        }
        if (probePresent && !phpEvidence) phpEvidence = probeEvidence;
        phpPresence ||= probePresent;
        if (deep && probeEvidence.php2ShellFix) break;
      } catch {
        // Keep the root HTTP result even if a secondary fingerprint request fails.
      }
    }
    return {
      status: response.status,
      protocol: response.protocol,
      phpVersion: php.version,
      phpVersionSource: php.versionSource || null,
      phpPresent: phpPresence,
      affectedCandidate: php.affectedCandidate,
      assessment: php.assessment,
      php2ShellFix: php.php2ShellFix || null,
      php2ShellFixPath: php.php2ShellFixPath || null,
      endpoint: versionEvidence?.path || phpEvidence?.path || '/',
      versionEvidence: versionEvidence ? {
        path: versionEvidence.path,
        protocol: versionEvidence.protocol,
        status: versionEvidence.status,
        source: versionEvidence.versionSource
      } : null,
      evidence
    };
  } catch (error) {
    return { status: null, error: error.message || 'No HTTPS response.', phpVersion: null, assessment: 'Not checked', evidence: [] };
  }
}

async function probeHosts(selected, onHostComplete = () => {}, probe = probeHost, targetHostname = null) {
  const results = new Map();
  let cursor = 0;
  let completed = 0;
  async function worker() {
    while (cursor < selected.length) {
      const item = selected[cursor++];
      const hostname = typeof item === 'string' ? item : item.hostname;
      results.set(hostname, await probe(hostname, { deep: hostname === targetHostname }));
      completed += 1;
      onHostComplete(completed, selected.length);
    }
  }
  await Promise.all(Array.from({ length: Math.min(8, selected.length) }, worker));
  return { results, checked: selected.length };
}

async function lookup(scope, activeCheck = true, onProgress = () => {}, dependencies = {}) {
  const fetchSource = dependencies.requestJson || requestCachedJson;
  const probe = dependencies.probeHost || probeHost;
  const sample = dependencies.randomSample || randomSample;
  const { domain: apex, scopeType } = scope;
  onProgress({ phase: 'enumerating', domain: apex, scopeType });
  const sourceQueries = [];
  if (scopeType === 'publicSuffix') {
    const suffixUrl = new URL('https://crt.sh/');
    suffixUrl.searchParams.set('q', `%.${apex}`);
    suffixUrl.searchParams.set('output', 'json');
    const shodanUrl = new URL(`https://ctl.shodan.io/api/v1/domain/${encodeURIComponent(apex)}/hostnames`);
    sourceQueries.push(
      { name: 'Shodan CTL', url: shodanUrl, parse: parseShodan, timeoutMs: 45_000 },
      { name: 'crt.sh (suffix query)', url: suffixUrl, parse: parseCrt, timeoutMs: 55_000 }
    );
  } else {
    const crtUrl = new URL('https://crt.name/v1/search');
    crtUrl.searchParams.set('apex', apex);
    crtUrl.searchParams.set('format', 'json');
    crtUrl.searchParams.set('dates', '1');
    const shodanUrl = new URL(`https://ctl.shodan.io/api/v1/domain/${encodeURIComponent(apex)}/hostnames`);
    sourceQueries.push(
      { name: 'Shodan CTL', url: shodanUrl, parse: parseShodan },
      { name: 'crt.name', url: crtUrl, parse: parseCrt }
    );
  }
  const providers = await Promise.allSettled(sourceQueries.map(({ url, name, timeoutMs }) => fetchSource(url, name, timeoutMs)));

  const records = new Map();
  providers.forEach((result, index) => {
    if (result.status !== 'fulfilled') return;
    const source = sourceQueries[index];
    for (const row of source.parse(result.value)) {
      const item = typeof row === 'string' ? { hostname: row, firstSeen: null } : row;
      const hostname = cleanHost(item.hostname, apex);
      if (!hostname || (scopeType === 'publicSuffix' && hostname === apex)) continue;
      const current = records.get(hostname) || { hostname, firstSeen: item.firstSeen || null, sources: [] };
      if (!current.sources.includes(source.name)) current.sources.push(source.name);
      records.set(hostname, current);
    }
  });

  // Always check the exact registrable domain entered, even if CT providers fail
  // or do not include the apex in their hostname lists.
  if (scopeType === 'registrable') {
    const root = records.get(apex) || { hostname: apex, firstSeen: null, sources: [] };
    if (!root.sources.includes('Queried domain')) root.sources.push('Queried domain');
    records.set(apex, root);
  }

  const errors = providers.flatMap((result, index) => result.status === 'rejected'
    ? [{ source: sourceQueries[index].name, message: result.reason?.message || 'Source request failed.' }]
    : []);

  const shouldProbe = activeCheck;
  const discovered = [...records.values()];
  onProgress({ phase: 'discovered', discovered: discovered.length, scopeType });
  let allFindings = shouldProbe
    ? []
    : scopeType === 'publicSuffix' ? sample(discovered, sampleBatchSize) : discovered;
  let probeResults = new Map();
  let checkedHosts = 0;
  let batchCount = 0;
  let candidates = [];

  if (shouldProbe) {
    const remainingCtl = discovered.filter(({ sources }) => sources.includes('Shodan CTL'));
    const remainingOther = discovered.filter(({ sources }) => !sources.includes('Shodan CTL'));
    const pullSample = (pool, limit) => {
      const selected = sample(pool, limit);
      const selectedNames = new Set(selected.map(({ hostname }) => hostname));
      for (let index = pool.length - 1; index >= 0; index -= 1) {
        if (selectedNames.has(pool[index].hostname)) pool.splice(index, 1);
      }
      return selected;
    };
    while ((remainingCtl.length || remainingOther.length) && batchCount < maxSampleBatches) {
      const batch = [];
      if (scopeType === 'registrable' && batchCount === 0) {
        const root = [...remainingCtl, ...remainingOther].find(({ hostname }) => hostname === apex);
        if (root) {
          batch.push(root);
          for (const pool of [remainingCtl, remainingOther]) {
            const index = pool.findIndex(({ hostname }) => hostname === apex);
            if (index >= 0) pool.splice(index, 1);
          }
        }
      }
      batch.push(...pullSample(remainingCtl, sampleBatchSize - batch.length));
      if (batch.length < sampleBatchSize) {
        batch.push(...pullSample(remainingOther, sampleBatchSize - batch.length));
      }
      if (!batch.length) break;
      batchCount += 1;
      onProgress({ phase: 'checking', batch: batchCount, batches: maxSampleBatches, checked: checkedHosts, total: Math.min(discovered.length, sampleBatchSize * maxSampleBatches) });
      const result = await probeHosts(batch, (completedInBatch, batchTotal) => {
        onProgress({
          phase: 'checking',
          batch: batchCount,
          batches: maxSampleBatches,
          checked: checkedHosts + completedInBatch,
          total: Math.min(discovered.length, sampleBatchSize * maxSampleBatches),
          batchCompleted: completedInBatch,
          batchTotal
        });
      }, probe, scopeType === 'registrable' ? apex : null);
      checkedHosts += result.checked;
      for (const [hostname, check] of result.results) probeResults.set(hostname, check);

      candidates = batch
        .filter(({ hostname }) => result.results.get(hostname)?.affectedCandidate === true && result.results.get(hostname)?.phpVersion)
        .map((finding) => ({ ...finding, check: result.results.get(finding.hostname) }));
      if (candidates.length) break;
    }
    allFindings = [...probeResults.entries()].map(([hostname, check]) => ({
      ...discovered.find((item) => item.hostname === hostname),
      check
    }));
  }
  allFindings.sort((a, b) => a.hostname.localeCompare(b.hostname));
  const stats = {
    discoveredHostnames: records.size,
    checkedHosts,
    sampledHostnames: shouldProbe ? checkedHosts : allFindings.length,
    batches: batchCount,
    candidateCount: candidates.length,
    patchedCount: allFindings.filter((finding) => finding.check?.assessment === 'At/above fixed release').length,
    unknownCount: shouldProbe ? allFindings.filter((finding) => Number.isInteger(finding.check?.status) && !finding.check?.affectedCandidate && finding.check?.assessment !== 'At/above fixed release').length : 0,
    noResponseCount: shouldProbe ? allFindings.filter((finding) => !Number.isInteger(finding.check?.status)).length : 0,
    phpDetectedCount: shouldProbe ? allFindings.filter((finding) => finding.check?.phpPresent).length : 0,
    versionDetectedCount: shouldProbe ? allFindings.filter((finding) => finding.check?.phpVersion).length : 0,
    httpResponses: allFindings.filter((finding) => Number.isInteger(finding.check?.status)).length,
    http200Count: allFindings.filter((finding) => finding.check?.status === 200).length,
    http403Count: allFindings.filter((finding) => finding.check?.status === 403).length,
    otherHttpCount: allFindings.filter((finding) => Number.isInteger(finding.check?.status) && finding.check.status !== 200 && finding.check.status !== 403).length
  };
  const targetCheck = scopeType === 'registrable' ? probeResults.get(apex) : null;
  const targetAssessment = scopeType !== 'registrable' ? null : !shouldProbe
    ? { hostname: apex, verdict: 'not_checked', label: 'Not checked', message: 'Active HTTP checks are disabled.' }
    : !targetCheck || !Number.isInteger(targetCheck.status)
      ? {
        hostname: apex,
        verdict: 'unreachable',
        label: 'No HTTP response',
        httpStatus: targetCheck?.status ?? null,
        phpVersion: targetCheck?.phpVersion ?? null,
        message: targetCheck?.error || 'The exact domain could not be reached.'
      }
      : targetCheck.php2ShellFix === 'present'
        ? {
          hostname: apex,
          verdict: 'confirmed_patched',
          label: 'PHP2Shell patch detected',
          httpStatus: targetCheck.status,
          phpVersion: targetCheck.phpVersion,
          versionSource: targetCheck.phpVersionSource,
          assessment: targetCheck.assessment,
          endpoint: targetCheck.php2ShellFixPath,
          evidence: 'memory_hard_limit_percent is present in exposed phpinfo output'
        }
        : targetCheck.php2ShellFix === 'absent' && targetCheck.affectedCandidate === true
          ? {
            hostname: apex,
            verdict: 'confirmed_vulnerable',
            label: 'Unpatched PHP2Shell marker detected',
            httpStatus: targetCheck.status,
            phpVersion: targetCheck.phpVersion,
            versionSource: targetCheck.phpVersionSource,
            assessment: targetCheck.assessment,
            endpoint: targetCheck.php2ShellFixPath,
            evidence: 'A complete exposed PHP Core table lacks memory_hard_limit_percent'
          }
          : targetCheck.affectedCandidate === true && targetCheck.phpVersion
        ? {
          hostname: apex,
          verdict: 'potentially_affected',
          label: 'Potentially affected',
          httpStatus: targetCheck.status,
          phpVersion: targetCheck.phpVersion,
          versionSource: targetCheck.phpVersionSource,
          assessment: targetCheck.assessment,
          endpoint: targetCheck.endpoint
        }
        : targetCheck.assessment === 'At/above fixed release'
          ? {
            hostname: apex,
            verdict: 'fixed_release',
            label: 'At/above fixed release',
            httpStatus: targetCheck.status,
            phpVersion: targetCheck.phpVersion,
            versionSource: targetCheck.phpVersionSource,
            assessment: targetCheck.assessment,
            endpoint: targetCheck.endpoint
          }
          : {
            hostname: apex,
            verdict: 'unknown',
            label: targetCheck.phpVersion ? 'Version needs verification' : 'PHP version not disclosed',
            httpStatus: targetCheck.status,
            phpVersion: targetCheck.phpVersion,
            versionSource: targetCheck.phpVersionSource,
            assessment: targetCheck.assessment,
            endpoint: targetCheck.endpoint
          };
  onProgress({ phase: 'complete', checked: checkedHosts, batches: batchCount, candidates: candidates.length, total: Math.min(discovered.length, sampleBatchSize * maxSampleBatches) });

  return {
    domain: apex,
    scopeType,
    queriedAt: new Date().toISOString(),
    mode: shouldProbe ? 'passive+http' : 'passive',
    summary: shouldProbe
      ? `Found ${stats.discoveredHostnames}; checked ${stats.checkedHosts} in ${batchCount}/${maxSampleBatches} batches. Candidates require a disclosed version below the fixed release.${errors.length ? ' A CT source failed.' : ''}`
      : scopeType === 'publicSuffix'
        ? `Passive discovery under ${apex}: ${stats.discoveredHostnames} hosts; sample ${stats.sampledHostnames}. No hosts were probed.${errors.length ? ' A CT source failed.' : ''}`
        : `Passive discovery: ${stats.discoveredHostnames} hosts. No hosts were contacted.${errors.length ? ' Partial results; a CT source failed.' : ''}`,
    activeCheck: Boolean(shouldProbe),
    sampleLimit: sampleBatchSize,
    maxSampleBatches,
    stats,
    targetAssessment,
    sources: scopeType === 'publicSuffix'
      ? { shodanCtl: 'https://ctl.shodan.io/', crtSh: 'https://crt.sh/' }
      : { crtName: 'https://crt.name/', shodanCtl: 'https://ctl.shodan.io/' },
    cves: CVES,
    findings: shouldProbe ? candidates : allFindings,
    checks: shouldProbe ? allFindings : [],
    errors
  };
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBodyBytes) throw new Error('Request body too large.');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  res.end(JSON.stringify(data));
}

function isLoopbackHostHeader(value) {
  if (typeof value !== 'string' || !value) return false;
  try {
    const hostname = new URL(`http://${value}`).hostname.toLowerCase();
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
  } catch {
    return false;
  }
}

function isLocalApiRequest(req) {
  const host = req.headers.host;
  if (!isLoopbackHostHeader(host)) return false;
  const origin = req.headers.origin;
  if (!origin) return true; // Local CLI clients do not normally send Origin.
  try {
    const parsedOrigin = new URL(origin);
    return (parsedOrigin.protocol === 'http:' || parsedOrigin.protocol === 'https:') &&
      parsedOrigin.host.toLowerCase() === host.toLowerCase();
  } catch {
    return false;
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname.startsWith('/api/') && !isLocalApiRequest(req)) {
    return sendJson(res, 403, { error: 'API access is limited to same-origin loopback requests.' });
  }
  if (req.method === 'GET' && url.pathname === '/api/health') return sendJson(res, 200, { ok: true });
  if (req.method === 'GET' && url.pathname === '/api/progress') {
    const scanId = url.searchParams.get('id') || '';
    if (!/^[a-z0-9-]{20,64}$/i.test(scanId)) return sendJson(res, 400, { error: 'Invalid scan ID.' });
    const progress = scanProgress.get(scanId);
    return progress ? sendJson(res, 200, progress) : sendJson(res, 404, { error: 'Scan not found.' });
  }
  if (req.method === 'GET' && url.pathname === '/favicon.ico') {
    res.writeHead(204, { 'cache-control': 'public, max-age=86400' });
    return res.end();
  }

  if (req.method === 'POST' && url.pathname === '/api/lookup') {
    const ip = req.socket.remoteAddress || 'unknown';
    if (!withinRateLimit(ip)) return sendJson(res, 429, { error: 'Rate limit: 20 requests per minute.' });
    try {
      const body = await readBody(req);
      const scope = normalizeDomain(body.domain);
      const scanId = typeof body.scanId === 'string' && /^[a-z0-9-]{20,64}$/i.test(body.scanId) ? body.scanId : null;
      const reportProgress = (state) => {
        if (!scanId) return;
        scanProgress.set(scanId, { ...state, updatedAt: new Date().toISOString() });
      };
      reportProgress({ phase: 'starting', checked: 0, total: 0, batch: 0, batches: maxSampleBatches });
      try {
        const data = await lookup(scope, body.activeCheck !== false, reportProgress);
        return sendJson(res, 200, data);
      } catch (error) {
        reportProgress({ phase: 'failed', error: error.message || 'Lookup failed.' });
        throw error;
      }
    } catch (error) {
      const status = error.statusCode || (error.message?.includes('Request body too large') ? 413
        : error instanceof SyntaxError || /domain|hostname|suffix/i.test(error.message || '') ? 400 : 502);
      return sendJson(res, status, { error: error.message || 'Lookup failed.', details: error.details || undefined });
    }
  }

  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
    try {
      const html = await readFile(path.join(publicDir, 'index.html'));
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
        'content-security-policy': "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'"
      });
      return res.end(html);
    } catch {
      return sendJson(res, 500, { error: 'Failed to load UI.' });
    }
  }

  if (req.method === 'GET' && publicAssets.has(url.pathname)) {
    const asset = publicAssets.get(url.pathname);
    try {
      const content = await readFile(path.join(publicDir, asset.file));
      res.writeHead(200, {
        'content-type': asset.type,
        'cache-control': 'no-cache',
        'x-content-type-options': 'nosniff'
      });
      return res.end(content);
    } catch {
      return sendJson(res, 500, { error: 'Failed to load UI asset.' });
    }
  }
  return sendJson(res, 404, { error: 'No encontrado.' });
});

const isMainModule = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMainModule) {
  server.listen(port, '127.0.0.1', () => {
    console.log(`php2shell blue-team audit listening at http://127.0.0.1:${port}`);
  });
}

export { classifyPhp, isPublicAddress, lookup, normalizeDomain, parseCrt, requestCachedJson, requestHostPinned };
