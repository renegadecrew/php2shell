import { randomInt } from 'node:crypto';
import { parse as parseDomain } from 'tldts';

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
  if (!parsed.isIcann) {
    throw new Error('Enter a valid domain or public suffix with a recognized TLD (e.g. example.com, gob.mx).');
  }
  if (parsed.domain) return { domain: parsed.domain, scopeType: 'registrable' };
  if (parsed.publicSuffix === ascii) return { domain: ascii, scopeType: 'publicSuffix' };
  throw new Error('Enter a valid domain or public suffix.');
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
  if (labels.some((part) => !part || part.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part))) return null;
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

export { cleanHost, normalizeDomain, parseCrt, parseShodan, randomSample };
