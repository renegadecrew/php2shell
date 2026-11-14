import { randomBytes } from 'node:crypto';
import { lookup as dnsLookup } from 'node:dns/promises';
import { CVES, classifyPhp, hasPhpSignal, inspectPhpInfoFix } from './classifier.js';
import { cleanHost, parseCrt, parseShodan, randomSample } from './discovery.js';
import { abortError, isPublicAddress, requestCachedJson, requestHostPinned } from './network.js';

const SAMPLE_BATCH_SIZE = 30;
const MAX_SAMPLE_BATCHES = 3;
const MAX_PROBE_ADDRESSES = 2;

function applyPhpInfoFixAssessment(php, fixStatus) {
  if (fixStatus === 'present') {
    php.affectedCandidate = false;
    php.assessment = 'PHP2Shell fix marker found in phpinfo';
  } else if (fixStatus === 'absent' && php.affectedCandidate === true) {
    php.assessment = 'Affected version; fix marker absent in complete phpinfo';
  }
}

function makeEvidence(requestPath, result, detected, present, tlsError = null) {
  return {
    path: requestPath,
    status: result.status,
    protocol: result.protocol,
    ...(result.location ? { location: result.location } : {}),
    ...(tlsError ? { tlsError } : {}),
    phpPresent: present,
    phpVersion: detected.version || null,
    versionSource: detected.versionSource || null,
    php2ShellFix: inspectPhpInfoFix(result.body || '', result.truncated)
  };
}

async function fetchRootWithFallback(hostname, addresses, requestFn, signal) {
  let lastError;
  const candidates = addresses.slice(0, MAX_PROBE_ADDRESSES);
  for (let index = 0; index < candidates.length; index += 1) {
    const entry = candidates[index];
    if (signal?.aborted) throw abortError('Scan aborted.');
    let timedOut = false;
    let tlsError = null;
    try {
      const response = await requestFn('https:', hostname, entry.address, entry.family, '/', 8192, 443, signal);
      return { response, protocol: 'https:', targetAddress: entry, tlsError: null };
    } catch (httpsError) {
      if (signal?.aborted || httpsError?.name === 'AbortError') throw httpsError;
      tlsError = httpsError?.message || 'HTTPS failed';
      timedOut ||= /timeout/i.test(tlsError);
      lastError = httpsError;
    }
    try {
      const response = await requestFn('http:', hostname, entry.address, entry.family, '/', 8192, 80, signal);
      return { response, protocol: 'http:', targetAddress: entry, tlsError };
    } catch (httpError) {
      if (signal?.aborted || httpError?.name === 'AbortError') throw httpError;
      timedOut ||= /timeout/i.test(httpError?.message || '');
      lastError = httpError;
    }
    // Only retry another IP when the failure wasn't a full HTTP timeout on the same family.
    const next = candidates[index + 1];
    if (timedOut && next && next.family === entry.family) break;
  }
  throw lastError || new Error('No HTTP response.');
}

async function probeHost(hostname, { deep = false, signal = undefined, dnsLookupFn = dnsLookup, requestFn = requestHostPinned } = {}) {
  try {
    if (signal?.aborted) throw abortError('Scan aborted.');
    const addresses = await dnsLookupFn(hostname, { all: true, verbatim: true });
    if (!addresses.length || addresses.some(({ address }) => !isPublicAddress(address))) {
      return { status: null, error: 'DNS failure or non-public address.', phpVersion: null, assessment: 'Not checked', evidence: [] };
    }

    const { response, protocol, targetAddress, tlsError } = await fetchRootWithFallback(hostname, addresses, requestFn, signal);

    let php = classifyPhp(response.headers, response.body);
    let phpPresence = hasPhpSignal(response.headers, response.body, php);
    const evidence = [];
    const rootEvidence = makeEvidence('/', response, php, phpPresence, tlsError);
    evidence.push(rootEvidence);
    let phpEvidence = phpPresence ? rootEvidence : null;
    let versionEvidence = php.version ? rootEvidence : null;

    if (rootEvidence.php2ShellFix) {
      php.php2ShellFix = rootEvidence.php2ShellFix;
      php.php2ShellFixPath = '/';
      applyPhpInfoFixAssessment(php, rootEvidence.php2ShellFix);
    }

    // Exact registrable domains check /phpinfo.php and /info.php for the PHP2Shell fix marker;
    // other hosts only run a random non-existent .php probe when '/' disclosed no PHP version.
    const phpProbePaths = deep
      ? (php.php2ShellFix ? [] : ['/phpinfo.php', '/info.php', `/${randomBytes(8).toString('hex')}.php`])
      : (php.version ? [] : [`/${randomBytes(8).toString('hex')}.php`]);

    for (const probePath of phpProbePaths) {
      if (signal?.aborted) throw abortError('Scan aborted.');
      if (!deep && php.version) break;
      try {
        const isPhpInfoPath = probePath === '/phpinfo.php' || probePath === '/info.php';
        const defaultPort = protocol === 'https:' ? 443 : 80;
        const probe = await requestFn(
          protocol,
          hostname,
          targetAddress.address,
          targetAddress.family,
          probePath,
          isPhpInfoPath ? 262144 : 8192,
          defaultPort,
          signal
        );
        const probePhp = classifyPhp(probe.headers, probe.body);
        const probePresent = hasPhpSignal(probe.headers, probe.body, probePhp);
        const probeEvidence = makeEvidence(probePath, probe, probePhp, probePresent);
        evidence.push(probeEvidence);
        if (probePhp.version) {
          php = probePhp;
          versionEvidence = probeEvidence;
        }
        if (probeEvidence.php2ShellFix) {
          php.php2ShellFix = probeEvidence.php2ShellFix;
          php.php2ShellFixPath = probePath;
          applyPhpInfoFixAssessment(php, probeEvidence.php2ShellFix);
        }
        if (probePresent && !phpEvidence) phpEvidence = probeEvidence;
        phpPresence ||= probePresent;
        if (deep && probeEvidence.php2ShellFix) break;
      } catch (probeError) {
        if (signal?.aborted || probeError?.name === 'AbortError') throw probeError;
        // Keep the root HTTP result even if a secondary fingerprint request fails.
      }
    }

    return {
      status: response.status,
      protocol: response.protocol,
      ...(response.location ? { location: response.location } : {}),
      ...(tlsError ? { tlsError } : {}),
      phpVersion: php.version,
      phpVersionSource: php.versionSource || null,
      ...(php.vendorSuffix ? { vendorSuffix: php.vendorSuffix } : {}),
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
    if (error?.name === 'AbortError') throw error;
    return { status: null, error: error.message || 'No HTTPS response.', phpVersion: null, assessment: 'Not checked', evidence: [] };
  }
}

async function probeHosts(selected, onHostComplete = () => {}, probe = probeHost, targetHostname = null, signal = undefined) {
  const results = new Map();
  let cursor = 0;
  let completed = 0;
  async function worker() {
    while (cursor < selected.length) {
      if (signal?.aborted) throw abortError('Scan aborted.');
      const item = selected[cursor++];
      const hostname = typeof item === 'string' ? item : item.hostname;
      const check = await probe(hostname, { deep: hostname === targetHostname, signal });
      results.set(hostname, check);
      completed += 1;
      onHostComplete(completed, selected.length);
    }
  }
  try {
    await Promise.all(Array.from({ length: Math.min(8, selected.length) }, worker));
    return { results, checked: results.size, aborted: false };
  } catch (error) {
    if (error?.name === 'AbortError') {
      return { results, checked: results.size, aborted: true };
    }
    throw error;
  }
}

function buildTargetAssessment(scopeType, apex, shouldProbe, targetCheck) {
  if (scopeType !== 'registrable') return null;
  if (!shouldProbe) {
    return { hostname: apex, verdict: 'not_checked', label: 'Not checked', message: 'Active HTTP checks are disabled.' };
  }
  if (!targetCheck || !Number.isInteger(targetCheck.status)) {
    return {
      hostname: apex,
      verdict: 'unreachable',
      label: 'No HTTP response',
      httpStatus: targetCheck?.status ?? null,
      phpVersion: targetCheck?.phpVersion ?? null,
      message: targetCheck?.error || 'The exact domain could not be reached.'
    };
  }
  if (targetCheck.php2ShellFix === 'present') {
    return {
      hostname: apex,
      verdict: 'confirmed_patched',
      label: 'PHP2Shell patch detected',
      httpStatus: targetCheck.status,
      phpVersion: targetCheck.phpVersion,
      versionSource: targetCheck.phpVersionSource,
      assessment: targetCheck.assessment,
      endpoint: targetCheck.php2ShellFixPath,
      evidence: 'memory_hard_limit_percent is present in exposed phpinfo output'
    };
  }
  if (targetCheck.php2ShellFix === 'absent' && targetCheck.affectedCandidate === true) {
    return {
      hostname: apex,
      verdict: 'confirmed_vulnerable',
      label: 'Unpatched PHP2Shell marker detected',
      httpStatus: targetCheck.status,
      phpVersion: targetCheck.phpVersion,
      versionSource: targetCheck.phpVersionSource,
      assessment: targetCheck.assessment,
      endpoint: targetCheck.php2ShellFixPath,
      evidence: 'A complete exposed PHP Core table lacks memory_hard_limit_percent'
    };
  }
  if (targetCheck.affectedCandidate === true && targetCheck.phpVersion) {
    return {
      hostname: apex,
      verdict: 'potentially_affected',
      label: 'Potentially affected',
      httpStatus: targetCheck.status,
      phpVersion: targetCheck.phpVersion,
      versionSource: targetCheck.phpVersionSource,
      assessment: targetCheck.assessment,
      endpoint: targetCheck.endpoint
    };
  }
  if (targetCheck.assessment === 'At/above fixed release') {
    return {
      hostname: apex,
      verdict: 'fixed_release',
      label: 'At/above fixed release',
      httpStatus: targetCheck.status,
      phpVersion: targetCheck.phpVersion,
      versionSource: targetCheck.phpVersionSource,
      assessment: targetCheck.assessment,
      endpoint: targetCheck.endpoint
    };
  }
  return {
    hostname: apex,
    verdict: 'unknown',
    label: targetCheck.phpVersion ? 'Version needs verification' : 'PHP version not disclosed',
    httpStatus: targetCheck.status,
    phpVersion: targetCheck.phpVersion,
    versionSource: targetCheck.phpVersionSource,
    assessment: targetCheck.assessment,
    endpoint: targetCheck.endpoint
  };
}

function buildSourceQueries(apex, scopeType) {
  if (scopeType === 'publicSuffix') {
    const suffixUrl = new URL('https://crt.sh/');
    suffixUrl.searchParams.set('q', `%.${apex}`);
    suffixUrl.searchParams.set('output', 'json');
    const shodanUrl = new URL(`https://ctl.shodan.io/api/v1/domain/${encodeURIComponent(apex)}/hostnames`);
    return [
      { name: 'Shodan CTL', url: shodanUrl, parse: parseShodan, timeoutMs: 45_000 },
      { name: 'crt.sh (suffix query)', url: suffixUrl, parse: parseCrt, timeoutMs: 35_000 }
    ];
  }
  const crtUrl = new URL('https://crt.name/v1/search');
  crtUrl.searchParams.set('apex', apex);
  crtUrl.searchParams.set('format', 'json');
  crtUrl.searchParams.set('dates', '1');
  const shodanUrl = new URL(`https://ctl.shodan.io/api/v1/domain/${encodeURIComponent(apex)}/hostnames`);
  return [
    { name: 'Shodan CTL', url: shodanUrl, parse: parseShodan },
    { name: 'crt.name', url: crtUrl, parse: parseCrt }
  ];
}

function buildReport({
  apex,
  scopeType,
  shouldProbe,
  discoveredCount,
  checkedHosts,
  batchCount,
  allFindings,
  candidates,
  targetCheck,
  errors,
  partial = false,
  cancelled = false
}) {
  const sortedFindings = [...allFindings].sort((a, b) => a.hostname.localeCompare(b.hostname));
  const sortedCandidates = [...candidates].sort((a, b) => a.hostname.localeCompare(b.hostname));
  const isPatchedFinding = (finding) =>
    finding.check?.assessment === 'At/above fixed release' || finding.check?.php2ShellFix === 'present';
  const stats = {
    discoveredHostnames: discoveredCount,
    checkedHosts,
    sampledHostnames: shouldProbe ? checkedHosts : sortedFindings.length,
    batches: batchCount,
    candidateCount: sortedCandidates.length,
    patchedCount: shouldProbe ? sortedFindings.filter(isPatchedFinding).length : 0,
    unknownCount: shouldProbe
      ? sortedFindings.filter((finding) => Number.isInteger(finding.check?.status) && !finding.check?.affectedCandidate && !isPatchedFinding(finding)).length
      : 0,
    noResponseCount: shouldProbe ? sortedFindings.filter((finding) => !Number.isInteger(finding.check?.status)).length : 0,
    phpDetectedCount: shouldProbe ? sortedFindings.filter((finding) => finding.check?.phpPresent).length : 0,
    versionDetectedCount: shouldProbe ? sortedFindings.filter((finding) => finding.check?.phpVersion).length : 0,
    httpResponses: sortedFindings.filter((finding) => Number.isInteger(finding.check?.status)).length,
    http200Count: sortedFindings.filter((finding) => finding.check?.status === 200).length,
    http403Count: sortedFindings.filter((finding) => finding.check?.status === 403).length,
    otherHttpCount: sortedFindings.filter((finding) => Number.isInteger(finding.check?.status) && finding.check.status !== 200 && finding.check.status !== 403).length
  };
  const targetAssessment = buildTargetAssessment(scopeType, apex, shouldProbe, targetCheck);
  const batchWord = `batch${batchCount === 1 ? '' : 'es'}`;
  const errorNote = errors.length ? ' A CT source failed.' : '';
  let summary;
  if (shouldProbe) {
    const prefix = cancelled
      ? `Cancelled after checking ${stats.checkedHosts} of ${stats.discoveredHostnames} in ${batchCount} ${batchWord}`
      : `Found ${stats.discoveredHostnames}; checked ${stats.checkedHosts} in ${batchCount} ${batchWord}`;
    summary = `${prefix}. Candidates require a disclosed version below the fixed release.${errorNote}`;
  } else if (scopeType === 'publicSuffix') {
    summary = `Passive discovery under ${apex}: ${stats.discoveredHostnames} hosts; sample ${stats.sampledHostnames}. No hosts were probed.${errorNote}`;
  } else {
    summary = `Passive discovery: ${stats.discoveredHostnames} hosts. No hosts were contacted.${errors.length ? ' Partial results; a CT source failed.' : ''}`;
  }

  return {
    domain: apex,
    scopeType,
    queriedAt: new Date().toISOString(),
    mode: shouldProbe ? 'passive+http' : 'passive',
    summary,
    partial,
    cancelled,
    activeCheck: Boolean(shouldProbe),
    sampleLimit: SAMPLE_BATCH_SIZE,
    maxSampleBatches: MAX_SAMPLE_BATCHES,
    stats,
    targetAssessment,
    sources: scopeType === 'publicSuffix'
      ? { shodanCtl: 'https://ctl.shodan.io/', crtSh: 'https://crt.sh/' }
      : { crtName: 'https://crt.name/', shodanCtl: 'https://ctl.shodan.io/' },
    cves: CVES,
    findings: shouldProbe ? sortedCandidates : sortedFindings,
    checks: shouldProbe ? sortedFindings : [],
    errors
  };
}

async function lookup(scope, activeCheck = true, onProgress = () => {}, dependencies = {}, signal = undefined) {
  if (signal?.aborted) throw abortError('Scan aborted.');
  const fetchSource = dependencies.requestJson || requestCachedJson;
  const probe = dependencies.probeHost || probeHost;
  const sample = dependencies.randomSample || randomSample;
  const onBatch = dependencies.onBatch || null;
  const stopOnCandidate = dependencies.stopOnCandidate !== false;
  const maxBatches = Number.isInteger(dependencies.maxBatches) && dependencies.maxBatches > 0 ? dependencies.maxBatches : null;
  const returnPartialOnAbort = Boolean(dependencies.returnPartialOnAbort);
  const { domain: apex, scopeType } = scope;

  onProgress({ phase: 'enumerating', domain: apex, scopeType });
  const sourceQueries = buildSourceQueries(apex, scopeType);
  const providers = await Promise.allSettled(
    sourceQueries.map(({ url, name, timeoutMs }) => fetchSource(url, name, timeoutMs, signal))
  );
  if (signal?.aborted) throw abortError('Scan aborted.');

  const records = new Map();
  providers.forEach((result, index) => {
    if (result.status !== 'fulfilled') return;
    const source = sourceQueries[index];
    for (const row of source.parse(result.value)) {
      const item = typeof row === 'string' ? { hostname: row, firstSeen: null } : row;
      const hostname = cleanHost(item.hostname, apex);
      if (!hostname || (scopeType === 'publicSuffix' && hostname === apex)) continue;
      const current = records.get(hostname) || { hostname, firstSeen: null, sources: [] };
      if (!current.firstSeen && item.firstSeen) current.firstSeen = item.firstSeen;
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
  const discoveredByName = new Map(discovered.map((item) => [item.hostname, item]));
  onProgress({ phase: 'discovered', discovered: discovered.length, scopeType });
  let allFindings = shouldProbe
    ? []
    : scopeType === 'publicSuffix' ? sample(discovered, SAMPLE_BATCH_SIZE) : discovered;
  const probeResults = new Map();
  let checkedHosts = 0;
  let batchCount = 0;
  let candidates = [];
  let wasCancelled = false;

  const snapshot = (partial, cancelled) => {
    const findings = shouldProbe
      ? [...probeResults.entries()].map(([hostname, check]) => ({ ...discoveredByName.get(hostname), check }))
      : allFindings;
    const matched = shouldProbe
      ? findings.filter((item) => item.check?.affectedCandidate === true && item.check?.phpVersion)
      : findings;
    return buildReport({
      apex,
      scopeType,
      shouldProbe,
      discoveredCount: records.size,
      checkedHosts,
      batchCount,
      allFindings: findings,
      candidates: matched,
      targetCheck: scopeType === 'registrable' ? probeResults.get(apex) : null,
      errors,
      partial,
      cancelled
    });
  };

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
    const totalBatches = maxBatches
      ? Math.min(maxBatches, Math.max(1, Math.ceil(discovered.length / SAMPLE_BATCH_SIZE)))
      : Math.max(1, Math.ceil(discovered.length / SAMPLE_BATCH_SIZE));
    const totalRounds = Math.max(1, Math.ceil(totalBatches / MAX_SAMPLE_BATCHES));

    while ((remainingCtl.length || remainingOther.length) && (!maxBatches || batchCount < maxBatches)) {
      if (signal?.aborted) {
        if (returnPartialOnAbort) { wasCancelled = true; break; }
        throw abortError('Scan aborted.');
      }
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
      batch.push(...pullSample(remainingCtl, SAMPLE_BATCH_SIZE - batch.length));
      if (batch.length < SAMPLE_BATCH_SIZE) {
        batch.push(...pullSample(remainingOther, SAMPLE_BATCH_SIZE - batch.length));
      }
      if (!batch.length) break;
      batchCount += 1;
      const currentRound = Math.ceil(batchCount / MAX_SAMPLE_BATCHES);
      onProgress({
        phase: 'checking',
        batch: batchCount,
        batches: totalBatches,
        round: currentRound,
        rounds: totalRounds,
        checked: checkedHosts,
        total: discovered.length
      });
      const result = await probeHosts(batch, (completedInBatch, batchTotal) => {
        onProgress({
          phase: 'checking',
          batch: batchCount,
          batches: totalBatches,
          round: currentRound,
          rounds: totalRounds,
          checked: checkedHosts + completedInBatch,
          total: discovered.length,
          batchCompleted: completedInBatch,
          batchTotal
        });
      }, probe, scopeType === 'registrable' ? apex : null, signal);
      checkedHosts += result.checked;
      for (const [hostname, check] of result.results) probeResults.set(hostname, check);

      if (result.aborted) {
        if (returnPartialOnAbort) { wasCancelled = true; break; }
        throw abortError('Scan aborted.');
      }

      const partialReport = snapshot(true, false);
      candidates = partialReport.findings;
      if (onBatch) onBatch(partialReport);
      if (stopOnCandidate && candidates.length) break;
    }
    allFindings = [...probeResults.entries()].map(([hostname, check]) => ({
      ...discoveredByName.get(hostname),
      check
    }));
  }

  const finalReport = snapshot(wasCancelled, wasCancelled);
  onProgress({
    phase: wasCancelled ? 'cancelled' : 'complete',
    checked: checkedHosts,
    batches: batchCount,
    candidates: finalReport.findings.length,
    total: discovered.length
  });
  return finalReport;
}

export { MAX_SAMPLE_BATCHES, SAMPLE_BATCH_SIZE, buildTargetAssessment, lookup, probeHost, probeHosts };
