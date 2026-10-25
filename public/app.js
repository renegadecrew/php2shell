const form = document.querySelector('#lookup-form');
const input = document.querySelector('#domain');
const button = document.querySelector('#submit');
const notice = document.querySelector('#notice');
const results = document.querySelector('#results');
const progressPanel = document.querySelector('#scan-progress');
const progressLabel = document.querySelector('#progress-label');
const progressCount = document.querySelector('#progress-count');
const progressBar = document.querySelector('#progress-bar');
let currentData = null;

function escapeText(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

function showNotice(message, error = false) {
  notice.hidden = false;
  notice.classList.toggle('error', error);
  notice.textContent = message;
}

async function refreshProgress(scanId) {
  try {
    const response = await fetch(`/api/progress?id=${encodeURIComponent(scanId)}`, { cache: 'no-store' });
    if (!response.ok) return;
    const state = await response.json();
    const checked = state.checked || 0;
    const total = state.total || 0;
    progressBar.max = Math.max(total, 1);
    progressBar.value = Math.min(checked, progressBar.max);
    progressCount.textContent = total ? `${checked}/${total}` : '';
    if (state.phase === 'enumerating') progressLabel.textContent = 'Querying CT sources…';
    else if (state.phase === 'discovered') progressLabel.textContent = `${state.discovered} hosts found; preparing probes…`;
    else if (state.phase === 'checking') progressLabel.textContent = `Batch ${state.batch}/${state.batches} · ${state.batchCompleted || 0}/${state.batchTotal || 0}`;
    else if (state.phase === 'complete') progressLabel.textContent = `Complete · ${state.checked || 0} hosts checked`;
    else if (state.phase === 'failed') progressLabel.textContent = 'Scan failed.';
  } catch {
    // Progress is informational; the lookup request remains authoritative.
  }
}

function downloadReport(name, mimeType, content) {
  const blob = new Blob([content], { type: mimeType });
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = objectUrl;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
}

function csvCell(value) {
  let text = String(value ?? '');
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function exportCsv(data) {
  const entries = data.checks?.length ? data.checks : data.findings;
  const header = ['hostname', 'http_status', 'protocol', 'php_detected', 'php_version', 'version_source', 'assessment', 'http_evidence', 'version_evidence', 'sources', 'first_seen'];
  const lines = [header.map(csvCell).join(',')];
  for (const item of entries) {
    const check = item.check || {};
    lines.push([
      item.hostname,
      check.status ?? check.error,
      check.protocol,
      check.phpPresent,
      check.phpVersion,
      check.phpVersionSource,
      check.assessment,
      (check.evidence || []).map((entry) => `${String(entry.protocol || '').toUpperCase()} ${entry.status ?? 'No response'} GET ${entry.path}`).join('; '),
      check.versionEvidence ? `${String(check.versionEvidence.protocol || '').toUpperCase()} ${check.versionEvidence.status ?? 'No response'} GET ${check.versionEvidence.path} · ${check.versionEvidence.source || ''}` : '',
      (item.sources || []).join('; '),
      item.firstSeen
    ].map(csvCell).join(','));
  }
  const safeDomain = String(data.domain).replace(/[^a-z0-9.-]/gi, '_');
  downloadReport(`php2shell-${safeDomain}.csv`, 'text/csv;charset=utf-8', `\uFEFF${lines.join('\r\n')}`);
}

document.querySelector('#download-json').addEventListener('click', () => {
  if (!currentData) return;
  const safeDomain = String(currentData.domain).replace(/[^a-z0-9.-]/gi, '_');
  downloadReport(`php2shell-${safeDomain}.json`, 'application/json;charset=utf-8', JSON.stringify(currentData, null, 2));
});

document.querySelector('#download-csv').addEventListener('click', () => {
  if (currentData) exportCsv(currentData);
});

function render(data) {
  currentData = data;
  const suffixSearch = data.scopeType === 'publicSuffix';
  const activeScan = data.activeCheck === true;
  document.querySelector('#result-eyebrow').textContent = suffixSearch && !activeScan ? 'DISCOVERED HOSTS' : 'AFFECTED CANDIDATES';
  document.querySelector('#result-domain').textContent = data.domain;
  document.querySelector('#result-count').textContent = suffixSearch && !activeScan
    ? `SAMPLE ${data.findings.length}/${data.stats.discoveredHostnames}`
    : `${data.findings.length} CANDIDATE${data.findings.length === 1 ? '' : 'S'}`;
  document.querySelector('#result-summary').textContent = data.summary;
  const stats = data.stats || {};
  document.querySelector('#stats').textContent = suffixSearch && !activeScan
    ? `Found: ${stats.discoveredHostnames ?? 0} · Sample: ${stats.sampledHostnames ?? 0} · HTTP probes: 0`
    : `Found: ${stats.discoveredHostnames ?? 0} · Checked: ${stats.checkedHosts ?? 0} (${stats.batches ?? 0}/3) · 200: ${stats.http200Count ?? 0} · 403: ${stats.http403Count ?? 0} · Other: ${stats.otherHttpCount ?? 0} · No response: ${stats.noResponseCount ?? 0} · PHP: ${stats.phpDetectedCount ?? 0} · Versions: ${stats.versionDetectedCount ?? 0} · Fixed: ${stats.patchedCount ?? 0} · Unknown: ${stats.unknownCount ?? 0}`;
  const body = document.querySelector('#rows');
  body.replaceChildren();
  for (const finding of data.findings) {
    const row = document.createElement('tr');
    const check = finding.check;
    const status = check ? (check.status ? String(check.status) : escapeText(check.error || 'No response')) : '<span class="passive">NOT CHECKED</span>';
    const versionEvidence = check?.versionEvidence;
    const versionDetails = versionEvidence
      ? ` · GET ${versionEvidence.path} · ${versionEvidence.source || 'PHP version'}`
      : check?.phpVersionSource ? ` · ${check.phpVersionSource}` : '';
    const php = check ? `${escapeText(check.phpVersion || '—')}<small>${escapeText(check.assessment || '')}${escapeText(versionDetails)}</small>` : '—';
    const protocol = check?.protocol === 'http' ? 'http' : 'https';
    row.innerHTML = `<td><a class="host-link" href="${protocol}://${escapeText(finding.hostname)}/" target="_blank" rel="noopener noreferrer">${escapeText(finding.hostname)} ↗</a></td><td>${finding.sources.map((source) => `<span class="source-tag">${escapeText(source)}</span>`).join('')}</td><td>${escapeText(finding.firstSeen || '—')}</td><td>${status}</td><td>${php}</td>`;
    body.append(row);
  }
  document.querySelector('#empty').hidden = data.findings.length > 0;
  document.querySelector('#empty').textContent = activeScan
    ? (stats.checkedHosts === 0 && data.errors.length
      ? 'Discovery returned no hosts; no probes ran.'
      : `No disclosed affected versions in ${stats.checkedHosts ?? 0} checked hosts. See probe evidence for HTTP results.`)
    : suffixSearch
    ? (data.errors.length ? 'CT source unavailable; no hosts returned.' : 'No hosts returned for this suffix.')
    : 'No disclosed affected versions. Review per-host probe evidence.';
  const checksPanel = document.querySelector('#checks-panel');
  checksPanel.hidden = !activeScan || data.checks.length === 0;
  // When there are no affected candidates, expose the evidence by default so
  // an empty candidate list cannot look like the hosts were never checked.
  checksPanel.open = activeScan && data.findings.length === 0 && data.checks.length > 0;
  document.querySelector('#checks-summary').textContent = checksPanel.open
    ? `No candidates · ${data.checks.length} host results`
    : `Probe evidence (${data.checks.length}) · expand for host results`;
  const checksBody = document.querySelector('#checks-rows');
  checksBody.replaceChildren();
  for (const item of data.checks) {
    const check = item.check || {};
    const row = document.createElement('tr');
    const status = Number.isInteger(check.status) ? `${String(check.protocol || 'http').toUpperCase()} ${check.status}` : check.error || 'No response';
    const php = check.phpVersion || (check.phpPresent ? 'PHP detected; version hidden' : 'No PHP signal');
    const protocol = check.protocol === 'http' ? 'http' : 'https';
    const httpEvidence = (check.evidence || []).map((entry) => `${String(entry.protocol || '').toUpperCase()} ${entry.status ?? '—'} · GET ${entry.path}`).join(' · ');
    const phpEvidence = check.versionEvidence || (check.evidence || []).find((entry) => entry.phpPresent);
    const phpDetails = phpEvidence
      ? `GET ${phpEvidence.path}${phpEvidence.versionSource || phpEvidence.source ? ` · ${phpEvidence.versionSource || phpEvidence.source}` : ' · PHP signal'}`
      : 'No PHP version evidence';
    row.innerHTML = `<td><a class="host-link" href="${protocol}://${escapeText(item.hostname)}/" target="_blank" rel="noopener noreferrer">${escapeText(item.hostname)} ↗</a></td><td>${escapeText(status)}<small class="evidence-paths">${escapeText(httpEvidence || 'No HTTP response evidence')}</small></td><td>${escapeText(php)}<small class="evidence-paths">${escapeText(phpDetails)}</small></td><td>${escapeText(check.assessment || 'Not checked')}</td>`;
    checksBody.append(row);
  }
  const errorBox = document.querySelector('#source-errors');
  errorBox.hidden = data.errors.length === 0;
  errorBox.textContent = data.errors.map((item) => `${item.source}: ${item.message}`).join(' · ');
  const cves = document.querySelector('#cves');
  cves.replaceChildren();
  for (const cve of data.cves) {
    const link = document.createElement('a');
    link.className = 'cve-card';
    link.href = cve.url;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.innerHTML = `<strong>${escapeText(cve.id)} ↗</strong><span>${escapeText(cve.label)}</span>`;
    cves.append(link);
  }
  document.querySelector('#queried-at').textContent = `${new Date(data.queriedAt).toLocaleString('en-GB')} · ${activeScan ? 'BOUNDED HTTP FINGERPRINT' : 'PASSIVE DISCOVERY'}`;
  results.hidden = false;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  results.hidden = true;
  notice.hidden = true;
  progressPanel.hidden = false;
  progressLabel.textContent = 'Starting scan…';
  progressCount.textContent = '';
  progressBar.max = 90;
  progressBar.value = 0;
  button.disabled = true;
  button.querySelector('span:first-child').textContent = 'Scanning…';
  const scanId = crypto.randomUUID();
  const progressTimer = setInterval(() => refreshProgress(scanId), 600);
  try {
    const response = await fetch('/api/lookup', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ domain: input.value, activeCheck: true, scanId })
    });
    const data = await response.json();
    if (!response.ok) {
      const details = (data.details || []).map((item) => `${item.source}: ${item.message}`);
      throw new Error([data.error || 'Request failed.', ...details].join(' · '));
    }
    render(data);
    if (data.errors.length === 2) showNotice('Both CT sources failed. The entered domain was still checked; source errors are shown.');
    else if (data.errors.length) showNotice('One CT source failed; partial results are shown.');
  } catch (error) {
    showNotice(error.message || 'Connection error.', true);
  } finally {
    clearInterval(progressTimer);
    progressPanel.hidden = true;
    button.disabled = false;
      button.querySelector('span:first-child').textContent = 'Scan';
  }
});
