const form = document.querySelector('#lookup-form');
const input = document.querySelector('#domain');
const activeCheckInput = document.querySelector('#active-check');
const stopOnCandidateInput = document.querySelector('#stop-on-candidate');
const allBatchesInput = document.querySelector('#all-batches');
const button = document.querySelector('#submit');
const cancelButton = document.querySelector('#cancel-scan');
const notice = document.querySelector('#notice');
const results = document.querySelector('#results');
const progressPanel = document.querySelector('#scan-progress');
const progressLabel = document.querySelector('#progress-label');
const progressCount = document.querySelector('#progress-count');
const progressBar = document.querySelector('#progress-bar');
const footerSources = document.querySelector('#footer-sources');
const checksFilterInput = document.querySelector('#checks-filter');
const filterPills = [...document.querySelectorAll('.filter-pill')];

let currentData = null;
let activeScanId = null;
let activeEventSource = null;
let activeFilterMode = 'all';

function escapeText(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

function showNotice(message, error = false) {
  notice.hidden = false;
  notice.classList.toggle('error', error);
  notice.textContent = message;
}

function updateProgressUi(state) {
  const checked = state.checked || 0;
  const total = state.total || 0;
  progressBar.max = Math.max(total, 1);
  progressBar.value = Math.min(checked, progressBar.max);
  progressCount.textContent = total ? `${checked}/${total}` : '';
  if (state.phase === 'enumerating') progressLabel.textContent = 'Querying CT sources…';
  else if (state.phase === 'discovered') progressLabel.textContent = `${state.discovered} hosts found; preparing probes…`;
  else if (state.phase === 'checking') progressLabel.textContent = `Round ${state.round || 1}/${state.rounds || 1} · Batch ${state.batch}/${state.batches} · ${state.batchCompleted || 0}/${state.batchTotal || 0}`;
  else if (state.phase === 'complete') progressLabel.textContent = `Complete · ${state.checked || 0} hosts checked`;
  else if (state.phase === 'cancelled') progressLabel.textContent = `Cancelled · ${state.checked || 0} hosts checked`;
  else if (state.phase === 'failed') progressLabel.textContent = 'Scan failed.';
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
  const header = ['hostname', 'http_status', 'protocol', 'tls_error', 'php_detected', 'php_version', 'version_source', 'assessment', 'php2shell_fix_marker', 'http_evidence', 'version_evidence', 'sources', 'first_seen'];
  const lines = [header.map(csvCell).join(',')];
  for (const item of entries) {
    const check = item.check || {};
    lines.push([
      item.hostname,
      check.status ?? check.error,
      check.protocol,
      check.tlsError || '',
      check.phpPresent,
      check.phpVersion,
      check.phpVersionSource,
      check.assessment,
      check.php2ShellFix,
      (check.evidence || []).map((entry) => `${String(entry.protocol || '').toUpperCase()} ${entry.status ?? 'No response'} GET ${entry.path}${entry.location ? ` -> ${entry.location}` : ''}`).join('; '),
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

if (activeCheckInput && stopOnCandidateInput) {
  activeCheckInput.addEventListener('change', () => {
    stopOnCandidateInput.disabled = !activeCheckInput.checked;
    if (allBatchesInput) allBatchesInput.disabled = !activeCheckInput.checked;
  });
}

if (cancelButton) {
  cancelButton.addEventListener('click', async () => {
    if (!activeScanId) return;
    cancelButton.disabled = true;
    try {
      await fetch(`/api/scans/${encodeURIComponent(activeScanId)}/cancel`, { method: 'POST' });
    } catch {
      // Ignore transient cancel request errors; SSE close handles UI cleanup.
    }
  });
}

function matchesCheckFilter(item) {
  const check = item.check || {};
  if (activeFilterMode === 'candidates' && !(check.affectedCandidate === true && check.phpVersion)) return false;
  if (activeFilterMode === 'php' && !check.phpPresent) return false;
  if (activeFilterMode === '200' && check.status !== 200) return false;
  if (activeFilterMode === '403' && check.status !== 403) return false;
  if (activeFilterMode === 'errors' && Number.isInteger(check.status)) return false;

  const query = (checksFilterInput?.value || '').trim().toLowerCase();
  if (!query) return true;
  const haystack = [
    item.hostname,
    check.status,
    check.error,
    check.tlsError,
    check.phpVersion,
    check.assessment
  ].filter(Boolean).join(' ').toLowerCase();
  return haystack.includes(query);
}

function renderChecksRows(data) {
  const checksBody = document.querySelector('#checks-rows');
  checksBody.replaceChildren();
  const filtered = (data.checks || []).filter(matchesCheckFilter);
  for (const item of filtered) {
    const check = item.check || {};
    const row = document.createElement('tr');
    const status = Number.isInteger(check.status) ? `${String(check.protocol || 'http').toUpperCase()} ${check.status}` : check.error || 'No response';
    const php = check.phpVersion || (check.phpPresent ? 'PHP detected; version hidden' : 'No PHP signal');
    const protocol = check.protocol === 'http' ? 'http' : 'https';
    const httpEvidence = (check.evidence || [])
      .map((entry) => `${String(entry.protocol || '').toUpperCase()} ${entry.status ?? '—'} · GET ${entry.path}${entry.location ? ` → ${entry.location}` : ''}${entry.tlsError ? ` (HTTPS fallback: ${entry.tlsError})` : ''}`)
      .join(' · ');
    const phpEvidence = check.versionEvidence || (check.evidence || []).find((entry) => entry.phpPresent);
    const fixTag = check.php2ShellFix === 'present'
      ? ' · Fix marker present'
      : check.php2ShellFix === 'absent' ? ' · Fix marker absent' : '';
    const phpDetails = phpEvidence
      ? `GET ${phpEvidence.path}${phpEvidence.versionSource || phpEvidence.source ? ` · ${phpEvidence.versionSource || phpEvidence.source}` : ' · PHP signal'}${fixTag}`
      : `No PHP version evidence${fixTag}`;
    row.innerHTML = `<td><a class="host-link" href="${protocol}://${escapeText(item.hostname)}/" target="_blank" rel="noopener noreferrer">${escapeText(item.hostname)} ↗</a></td><td>${escapeText(status)}<small class="evidence-paths">${escapeText(httpEvidence || 'No HTTP response evidence')}</small></td><td>${escapeText(php)}<small class="evidence-paths">${escapeText(phpDetails)}</small></td><td>${escapeText(check.assessment || 'Not checked')}</td>`;
    checksBody.append(row);
  }
  if (!filtered.length) {
    const emptyRow = document.createElement('tr');
    emptyRow.innerHTML = '<td colspan="4" class="empty">No probe evidence rows match the current filter.</td>';
    checksBody.append(emptyRow);
  }
}

if (checksFilterInput) {
  checksFilterInput.addEventListener('input', () => {
    if (currentData) renderChecksRows(currentData);
  });
}

for (const pill of filterPills) {
  pill.addEventListener('click', () => {
    activeFilterMode = pill.dataset.filter || 'all';
    for (const other of filterPills) other.classList.toggle('is-active', other === pill);
    if (currentData) renderChecksRows(currentData);
  });
}

function render(data, { streaming = false } = {}) {
  currentData = data;
  const suffixSearch = data.scopeType === 'publicSuffix';
  const activeScan = data.activeCheck === true;
  if (footerSources) footerSources.textContent = suffixSearch ? 'Shodan CTL + crt.sh' : 'Shodan CTL + crt.name';
  document.querySelector('#result-eyebrow').textContent = !activeScan ? 'DISCOVERED HOSTS' : 'AFFECTED CANDIDATES';
  document.querySelector('#result-domain').textContent = data.domain;
  document.querySelector('#result-count').textContent = !activeScan
    ? (suffixSearch ? `SAMPLE ${data.findings.length}/${data.stats.discoveredHostnames}` : `${data.findings.length} HOST${data.findings.length === 1 ? '' : 'S'}`)
    : `${data.findings.length} CANDIDATE${data.findings.length === 1 ? '' : 'S'}`;
  document.querySelector('#result-summary').textContent = data.summary;
  const targetPanel = document.querySelector('#target-assessment');
  const target = data.targetAssessment;
  targetPanel.hidden = !target;
  if (target) {
    document.querySelector('#target-host').textContent = target.hostname;
    const verdict = document.querySelector('#target-verdict');
    verdict.textContent = target.label;
    verdict.dataset.state = target.verdict;
    document.querySelector('#target-http').textContent = Number.isInteger(target.httpStatus) ? String(target.httpStatus) : '—';
    document.querySelector('#target-php').textContent = target.phpVersion || 'Not disclosed';
    const targetDetails = [];
    if (target.versionSource) targetDetails.push(target.versionSource);
    if (target.evidence) targetDetails.push(target.evidence);
    if (target.endpoint) targetDetails.push(`GET ${target.endpoint}`);
    document.querySelector('#target-source').textContent = targetDetails.join(' · ');
    document.querySelector('#target-note').textContent = target.verdict === 'confirmed_vulnerable'
      ? 'A full exposed phpinfo Core table lacks the PHP2Shell fix marker and the reported version is affected. Remove public phpinfo and patch the runtime.'
      : target.verdict === 'confirmed_patched'
        ? 'The PHP2Shell fix marker is present in exposed phpinfo output, including possible vendor backports. Verify the runtime serving the application.'
        : target.verdict === 'potentially_affected'
          ? 'The disclosed version is below the fixed release. Verify the installed package and vendor backports.'
          : target.verdict === 'fixed_release'
            ? 'The disclosed version is at or above the fixed release; confirm the installed package on the host.'
            : target.verdict === 'unknown'
              ? 'The response does not provide enough version evidence to determine exposure.'
              : target.message || 'No direct version assessment is available.';
  }
  const stats = data.stats || {};
  document.querySelector('#stats').textContent = !activeScan
    ? `Found: ${stats.discoveredHostnames ?? 0} · Sample: ${stats.sampledHostnames ?? 0} · HTTP probes: 0`
    : `Found: ${stats.discoveredHostnames ?? 0} · Checked: ${stats.checkedHosts ?? 0} (${stats.batches ?? 0} batch${stats.batches === 1 ? '' : 'es'}) · 200: ${stats.http200Count ?? 0} · 403: ${stats.http403Count ?? 0} · Other: ${stats.otherHttpCount ?? 0} · No response: ${stats.noResponseCount ?? 0} · PHP: ${stats.phpDetectedCount ?? 0} · Versions: ${stats.versionDetectedCount ?? 0} · Fixed: ${stats.patchedCount ?? 0} · Unknown: ${stats.unknownCount ?? 0}`;
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
      : streaming
        ? `No affected candidates yet in ${stats.checkedHosts ?? 0} checked hosts; continuing…`
        : `No disclosed affected versions in ${stats.checkedHosts ?? 0} checked hosts. See probe evidence for HTTP results.`)
    : suffixSearch
      ? (data.errors.length ? 'CT source unavailable; no hosts returned.' : 'No hosts returned for this suffix.')
      : 'No hosts discovered.';
  const checksPanel = document.querySelector('#checks-panel');
  checksPanel.hidden = !activeScan || data.checks.length === 0;
  if (!streaming && activeScan && data.findings.length === 0 && data.checks.length > 0) {
    checksPanel.open = true;
  }
  document.querySelector('#checks-summary').textContent = checksPanel.open
    ? `${data.findings.length ? `${data.findings.length} candidate${data.findings.length === 1 ? '' : 's'}` : 'No candidates'} · ${data.checks.length} host results`
    : `Probe evidence (${data.checks.length}) · expand for host results`;
  renderChecksRows(data);

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
  document.querySelector('#queried-at').textContent = `${new Date(data.queriedAt).toLocaleString('en-GB')} · ${activeScan ? 'BOUNDED HTTP FINGERPRINT' : 'PASSIVE DISCOVERY'}${data.cancelled ? ' · CANCELLED (PARTIAL)' : ''}`;
  results.hidden = false;
}

function finishScanUi() {
  if (activeEventSource) {
    activeEventSource.close();
    activeEventSource = null;
  }
  activeScanId = null;
  progressPanel.hidden = true;
  button.disabled = false;
  button.querySelector('span:first-child').textContent = 'Scan';
  if (cancelButton) cancelButton.disabled = false;
}

function showSourceNotices(data) {
  if (data.errors?.length === 2) showNotice('Both CT sources failed. The entered domain was still checked; source errors are shown.');
  else if (data.errors?.length) showNotice('One CT source failed; partial results are shown.');
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (activeEventSource) activeEventSource.close();
  const activeCheck = activeCheckInput ? activeCheckInput.checked : true;
  const stopOnCandidate = stopOnCandidateInput ? stopOnCandidateInput.checked : true;

  results.hidden = true;
  notice.hidden = true;
  progressPanel.hidden = false;
  progressLabel.textContent = activeCheck ? 'Starting scan…' : 'Querying CT sources…';
  progressCount.textContent = '';
  progressBar.max = 90;
  progressBar.value = 0;
  button.disabled = true;
  button.querySelector('span:first-child').textContent = 'Scanning…';
  if (cancelButton) cancelButton.disabled = false;

  try {
    const startResponse = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        domain: input.value,
        activeCheck,
        stopOnCandidate,
        maxBatches: allBatchesInput?.checked ? null : 3
      })
    });
    const startData = await startResponse.json();
    if (!startResponse.ok) {
      throw new Error(startData.error || 'Request failed.');
    }

    activeScanId = startData.scanId;
    const events = new EventSource(`/api/scans/${encodeURIComponent(activeScanId)}/events`);
    activeEventSource = events;

    events.addEventListener('progress', (ev) => {
      updateProgressUi(JSON.parse(ev.data));
    });
    events.addEventListener('batch', (ev) => {
      render(JSON.parse(ev.data), { streaming: true });
    });
    events.addEventListener('complete', (ev) => {
      const data = JSON.parse(ev.data);
      render(data, { streaming: false });
      showSourceNotices(data);
      finishScanUi();
    });
    events.addEventListener('cancelled', (ev) => {
      const data = JSON.parse(ev.data);
      if (data?.checks) {
        render(data, { streaming: false });
        showNotice(`Scan cancelled after ${data.stats?.checkedHosts ?? 0} hosts; partial results are shown below.`);
      } else {
        showNotice('Scan cancelled.');
      }
      finishScanUi();
    });
    events.addEventListener('scan-error', (ev) => {
      const payload = JSON.parse(ev.data);
      showNotice(payload.error || 'Scan failed.', true);
      finishScanUi();
    });
    events.onerror = async () => {
      if (!activeScanId) return;
      try {
        const res = await fetch(`/api/scans/${encodeURIComponent(activeScanId)}`);
        if (res.ok) {
          const snapshot = await res.json();
          if (snapshot.status === 'running') return; // Allow EventSource automatic reconnect.
          if (snapshot.report) render(snapshot.report, { streaming: false });
          if (snapshot.status === 'failed') showNotice(snapshot.error || 'Scan failed.', true);
        }
      } catch {
        showNotice('Connection error.', true);
      }
      finishScanUi();
    };
  } catch (error) {
    showNotice(error.message || 'Connection error.', true);
    finishScanUi();
  }
});
