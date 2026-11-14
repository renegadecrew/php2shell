#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { normalizeDomain } from './discovery.js';
import { lookup } from './probe.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const VERSION = pkg.version || '1.0.0';

const BANNER = String.raw`
 ██▀███   ██░ ██  ██▀███    ██████    ██████  ██░ ██ ▓█████  ██▓     ██▓    
▓██ ▒ ██▒▓██░ ██▒▓██ ▒ ██▒ ▒██▒  ██▒ ▒██    ▒ ▓██░ ██▒▓█   ▀ ▓██▒    ▓██▒    
▓██ ░▄█ ▒▒██▀▀██░▓██ ░▄█ ▒  ░▒  ██▒  ░ ▓██▄   ▒██▀▀██░▒███   ▒██░    ▒██░    
▒██▀▀█▄  ░▓█ ░██ ▒██▀▀█▄      ▄██▀     ▒   ██▒░▓█ ░██ ▒▓█  ▄ ▒██░    ▒██░    
░██▓ ▒██▒░▓█▒░██▓░██▓ ▒██▒  ▄██▀     ▒██████▒▒░▓█▒░██▓░▒████▒░██████▒░██████▒
░ ▒▓ ░▒▓░ ▒ ░░▒░▒░ ▒▓ ░▒▓░ ██▓▒▄▄▄   ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░░ ▒░ ░░ ▒░▓  ░░ ▒░▓  ░
  ░▒ ░ ▒░ ▒ ░▒░ ░  ░▒ ░ ▒░ ▒██████▒  ░ ░▒  ░ ░ ▒ ░▒░ ░ ░ ░  ░░ ░ ▒  ░░ ░ ▒  ░
  ░░   ░  ░  ░░ ░  ░░   ░  ░ ▒░  ░   ░  ░  ░   ░  ░░ ░   ░     ░ ░     ░ ░   
   ░      ░  ░  ░   ░        ░             ░   ░  ░  ░   ░  ░    ░  ░    ░  ░
`;

function colorEnabled(stream = process.stderr, { noColor = false, forceColor = false } = {}) {
  if (noColor || process.env.NO_COLOR !== undefined) return false;
  if (forceColor) return true;
  return Boolean(stream && stream.isTTY);
}

function printBanner({ noColor = false, forceColor = false, stderr = process.stderr } = {}) {
  const useColor = colorEnabled(stderr, { noColor, forceColor });
  if (useColor) stderr.write(`\x1b[1;31m${BANNER}\x1b[0m\n`);
  else stderr.write(`${BANNER}\n`);
}

function usageText() {
  return [
    'Usage: php2shell [options] [domain]',
    '',
    'Options:',
    '  -i, --input <file>       Read target domains/suffixes from file (one per line)',
    '  -o, --output <file>      Write formatted report to file instead of stdout',
    '  -f, --format <fmt>       Output format: txt | json | csv (default: txt)',
    '  -p, --passive            Passive CT discovery only (no HTTP probes)',
    '      --all-batches        Continue across all batches instead of stopping on first candidate',
    '      --max-batches <n>    Maximum number of 30-host batches per domain',
    '      --no-color           Disable ANSI color in stderr banner and summary',
    '      --color              Force ANSI color when NO_COLOR is unset',
    '  -v, --version            Show version and exit',
    '  -h, --help               Show this help message and exit'
  ].join('\n');
}

function parseArgs(argv) {
  const options = {
    domains: [],
    inputFile: null,
    outputFile: null,
    format: 'txt',
    passive: false,
    stopOnCandidate: true,
    maxBatches: null,
    noColor: false,
    forceColor: false,
    help: false,
    version: false
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '-h' || arg === '--help') options.help = true;
    else if (arg === '-v' || arg === '--version') options.version = true;
    else if (arg === '-p' || arg === '--passive') options.passive = true;
    else if (arg === '--all-batches') options.stopOnCandidate = false;
    else if (arg === '--no-color') options.noColor = true;
    else if (arg === '--color') options.forceColor = true;
    else if (arg === '-i' || arg === '--input') {
      options.inputFile = argv[++index];
      if (!options.inputFile) throw new Error('Missing file path after --input.');
    } else if (arg === '-o' || arg === '--output') {
      options.outputFile = argv[++index];
      if (!options.outputFile) throw new Error('Missing file path after --output.');
    } else if (arg === '-f' || arg === '--format') {
      const fmt = (argv[++index] || '').toLowerCase();
      if (!['txt', 'json', 'csv'].includes(fmt)) throw new Error('Format must be txt, json, or csv.');
      options.format = fmt;
    } else if (arg === '--max-batches') {
      const val = Number(argv[++index]);
      if (!Number.isInteger(val) || val < 1 || val > 500) throw new Error('--max-batches must be an integer between 1 and 500.');
      options.maxBatches = val;
    } else if (arg.startsWith('-')) {
      throw new Error(`Unknown option: ${arg}`);
    } else {
      options.domains.push(arg);
    }
  }
  return options;
}

function readDomainsFile(filePath) {
  const raw = readFileSync(filePath, 'utf8');
  const seen = new Set();
  const domains = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    if (!seen.has(trimmed)) {
      seen.add(trimmed);
      domains.push(trimmed);
    }
  }
  return domains;
}

function csvCell(value) {
  let text = String(value ?? '');
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function formatCsvReports(reports) {
  const header = ['domain', 'hostname', 'http_status', 'protocol', 'tls_error', 'php_detected', 'php_version', 'version_source', 'assessment', 'php2shell_fix_marker', 'http_evidence', 'version_evidence', 'sources', 'first_seen'];
  const lines = [header.map(csvCell).join(',')];
  for (const report of reports) {
    const entries = report.checks?.length ? report.checks : report.findings;
    for (const item of entries) {
      const check = item.check || {};
      lines.push([
        report.domain,
        item.hostname,
        check.status ?? check.error ?? '',
        check.protocol ?? '',
        check.tlsError ?? '',
        check.phpPresent ?? false,
        check.phpVersion ?? '',
        check.phpVersionSource ?? '',
        check.assessment ?? '',
        check.php2ShellFix ?? '',
        (check.evidence || []).map((entry) => `${String(entry.protocol || '').toUpperCase()} ${entry.status ?? 'No response'} GET ${entry.path}${entry.location ? ` -> ${entry.location}` : ''}`).join('; '),
        check.versionEvidence ? `${String(check.versionEvidence.protocol || '').toUpperCase()} ${check.versionEvidence.status ?? 'No response'} GET ${check.versionEvidence.path} · ${check.versionEvidence.source || ''}` : '',
        (item.sources || []).join('; '),
        item.firstSeen ?? ''
      ].map(csvCell).join(','));
    }
  }
  return `${lines.join('\n')}\n`;
}

function formatTxtReports(reports) {
  const lines = [];
  for (const report of reports) {
    if (report.activeCheck) {
      const rows = report.checks || [];
      for (const item of rows) {
        const check = item.check || {};
        const status = Number.isInteger(check.status) ? `${String(check.protocol || 'http').toUpperCase()}:${check.status}` : (check.error || 'NO_RESPONSE');
        const php = check.phpVersion || (check.phpPresent ? 'PHP_HIDDEN' : '-');
        const flag = check.affectedCandidate && check.phpVersion ? 'CANDIDATE' : (check.php2ShellFix === 'present' ? 'PATCHED' : 'INFO');
        lines.push(`${report.domain}\t${item.hostname}\t${flag}\t${status}\t${php}\t${check.assessment || '-'}`);
      }
    } else {
      for (const item of report.findings || []) {
        lines.push(`${report.domain}\t${item.hostname}`);
      }
    }
  }
  return lines.length ? `${lines.join('\n')}\n` : '';
}

async function runCli(argv = process.argv.slice(2), { lookupFn = lookup, stdout = process.stdout, stderr = process.stderr } = {}) {
  const options = parseArgs(argv);
  if (options.help) {
    stdout.write(`${usageText()}\n`);
    return 0;
  }
  if (options.version) {
    stdout.write(`php2shell ${VERSION}\n`);
    return 0;
  }

  const targets = [...options.domains];
  if (options.inputFile) targets.push(...readDomainsFile(options.inputFile));
  const uniqueTargets = [...new Set(targets)];
  if (!uniqueTargets.length) {
    stderr.write(`${usageText()}\n`);
    return 2;
  }

  printBanner({ noColor: options.noColor, forceColor: options.forceColor, stderr });
  const useColor = colorEnabled(stderr, { noColor: options.noColor, forceColor: options.forceColor });
  const reports = [];

  for (const rawDomain of uniqueTargets) {
    const scope = normalizeDomain(rawDomain);
    stderr.write(`[+] Scanning ${scope.domain} (${options.passive ? 'passive' : 'active'})...\n`);
    const report = await lookupFn(
      scope,
      !options.passive,
      (state) => {
        if (state.phase === 'discovered') {
          stderr.write(`    discovered ${state.discovered} host(s)\n`);
        } else if (state.phase === 'checking' && state.batchCompleted === undefined) {
          stderr.write(`    batch ${state.batch}/${state.batches}...\n`);
        }
      },
      { stopOnCandidate: options.stopOnCandidate, maxBatches: options.maxBatches }
    );
    reports.push(report);
    const candCount = report.findings?.length || 0;
    const summaryLine = `    ${report.summary}`;
    if (useColor && candCount > 0 && report.activeCheck) {
      stderr.write(`\x1b[1;31m${summaryLine}\x1b[0m\n`);
    } else {
      stderr.write(`${summaryLine}\n`);
    }
  }

  let output;
  if (options.format === 'json') {
    output = `${JSON.stringify(reports.length === 1 ? reports[0] : reports, null, 2)}\n`;
  } else if (options.format === 'csv') {
    output = formatCsvReports(reports);
  } else {
    output = formatTxtReports(reports);
  }

  if (options.outputFile) {
    writeFileSync(options.outputFile, output, 'utf8');
    stderr.write(`[+] Wrote ${options.format.toUpperCase()} output to ${options.outputFile}\n`);
  } else {
    stdout.write(output);
  }
  return 0;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  runCli().then(
    (code) => { process.exitCode = code; },
    (error) => {
      process.stderr.write(`Error: ${error.message}\n`);
      process.exitCode = 1;
    }
  );
}

export { BANNER, colorEnabled, csvCell, formatCsvReports, formatTxtReports, parseArgs, printBanner, readDomainsFile, runCli };
