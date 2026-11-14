import http from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';

const SOURCE_CACHE_TTL_MS = 30 * 60_000;
const SOURCE_CACHE_MAX_ENTRIES = 64;
const sourceCache = new Map();

const NON_PUBLIC_IPV4_RANGES = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4]
];

function ipv4ToUint32(address) {
  return address.split('.').map(Number).reduce((sum, octet) => (sum * 256) + octet, 0) >>> 0;
}

function parseIpv6Hextets(address) {
  let working = address.toLowerCase();
  let embeddedHextets = null;
  if (working.includes('.')) {
    const lastColon = working.lastIndexOf(':');
    const ipv4Tail = working.slice(lastColon + 1);
    if (isIP(ipv4Tail) !== 4) return null;
    const octets = ipv4Tail.split('.').map(Number);
    embeddedHextets = [(octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]];
    working = working.slice(0, lastColon);
  }

  const doubleColonParts = working.split('::');
  if (doubleColonParts.length > 2) return null;

  const parseGroup = (part) => (part ? part.split(':').map((hex) => Number.parseInt(hex, 16)) : []);
  const targetLength = embeddedHextets ? 6 : 8;

  let hextets;
  if (doubleColonParts.length === 2) {
    const left = parseGroup(doubleColonParts[0]);
    const right = parseGroup(doubleColonParts[1]);
    const missing = targetLength - left.length - right.length;
    if (missing < 0) return null;
    hextets = [...left, ...new Array(missing).fill(0), ...right];
  } else {
    hextets = parseGroup(working);
    if (hextets.length !== targetLength) return null;
  }

  if (embeddedHextets) hextets.push(...embeddedHextets);
  return hextets.length === 8 && hextets.every((value) => Number.isInteger(value) && value >= 0 && value <= 0xffff)
    ? hextets
    : null;
}

function isPublicAddress(address) {
  const family = isIP(address);
  if (family === 4) {
    const value = ipv4ToUint32(address);
    return !NON_PUBLIC_IPV4_RANGES.some(([network, prefix]) => {
      const base = ipv4ToUint32(network);
      const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
      return ((value & mask) >>> 0) === ((base & mask) >>> 0);
    });
  }
  if (family !== 6) return false;

  const normalized = address.toLowerCase();
  if (normalized.startsWith('::ffff:')) {
    const tail = normalized.slice(7);
    if (isIP(tail) === 4) return isPublicAddress(tail);
  }

  const hextets = parseIpv6Hextets(normalized);
  if (!hextets) return false;
  const [h0, h1] = hextets;

  // Public IPv6 unicast allocations are strictly within 2000::/3 (0x2000..0x3fff).
  if ((h0 & 0xe000) !== 0x2000) return false;
  // Exclude 2001::/23 (Teredo, ORCHID, Benchmarking, etc.), 2001:db8::/32 (documentation), 2002::/16 (6to4), and 3ffe::/16 (6bone).
  if (h0 === 0x2001 && (h1 <= 0x01ff || h1 === 0x0db8)) return false;
  if (h0 === 0x2002 || h0 === 0x3ffe) return false;
  return true;
}

function abortError(message = 'Operation aborted.') {
  const error = new Error(message);
  error.name = 'AbortError';
  return error;
}

function requestHostPinned(
  protocol,
  hostname,
  ip,
  family,
  requestPath = '/',
  maxBodyBytes = 8192,
  port = protocol === 'https:' ? 443 : 80,
  signal = undefined
) {
  if (signal?.aborted) return Promise.reject(abortError('Request aborted.'));
  return new Promise((resolve, reject) => {
    const transport = protocol === 'https:' ? https : http;
    let settled = false;
    const chunks = [];
    let totalBytes = 0;

    const cleanup = () => {
      if (signal) signal.removeEventListener('abort', onAbort);
    };

    const finish = (result) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve({ ...result, body: Buffer.concat(chunks, totalBytes).toString('utf8') });
    };

    const fail = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
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
      const base = {
        status: response.statusCode || null,
        headers: response.headers,
        location: typeof response.headers.location === 'string' ? response.headers.location : null,
        protocol: protocol.slice(0, -1)
      };
      response.on('data', (chunk) => {
        if (totalBytes < maxBodyBytes) {
          const slice = chunk.subarray(0, maxBodyBytes - totalBytes);
          chunks.push(slice);
          totalBytes += slice.length;
        }
        if (totalBytes >= maxBodyBytes) {
          finish({ ...base, truncated: true });
          // Stop even if the server keeps streaming after the local byte cap.
          response.destroy();
        }
      });
      response.on('end', () => finish(base));
      response.on('error', () => finish(base));
    });

    const onAbort = () => {
      const err = abortError('Request aborted.');
      request.destroy(err);
      fail(err);
    };

    if (signal) signal.addEventListener('abort', onAbort, { once: true });
    request.on('timeout', () => request.destroy(new Error('Request timeout (4s).')));
    request.on('error', fail);
    request.end();
  });
}

async function requestJson(url, provider, timeoutMs = 12_000, signal = undefined) {
  if (signal?.aborted) throw abortError('Request aborted.');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const onAbort = () => controller.abort();
  if (signal) signal.addEventListener('abort', onAbort, { once: true });
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { accept: 'application/json,text/plain;q=0.9', 'user-agent': 'php2shell-passive-audit/1.0' }
    });
    if (!response.ok) throw new Error(`${provider} returned HTTP ${response.status}`);
    const text = await response.text();
    try {
      return JSON.parse(text);
    } catch {
      throw new Error(`${provider} returned non-JSON response (HTTP ${response.status})`);
    }
  } finally {
    clearTimeout(timer);
    if (signal) signal.removeEventListener('abort', onAbort);
  }
}

async function requestCachedJson(url, provider, timeoutMs = 12_000, signal = undefined) {
  if (signal?.aborted) throw abortError('Request aborted.');
  const key = url.toString();
  const cached = sourceCache.get(key);
  let promise;
  if (cached && cached.expiresAt > Date.now()) {
    sourceCache.delete(key);
    sourceCache.set(key, cached);
    promise = cached.promise;
  } else {
    if (cached) sourceCache.delete(key);
    const entry = { expiresAt: Number.POSITIVE_INFINITY, promise: null };
    entry.promise = requestJson(url, provider, timeoutMs)
      .then((payload) => {
        entry.expiresAt = Date.now() + SOURCE_CACHE_TTL_MS;
        return payload;
      })
      .catch((error) => {
        if (sourceCache.get(key) === entry) sourceCache.delete(key);
        throw error;
      });
    sourceCache.set(key, entry);
    while (sourceCache.size > SOURCE_CACHE_MAX_ENTRIES) sourceCache.delete(sourceCache.keys().next().value);
    promise = entry.promise;
  }

  if (!signal) return promise;
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(abortError('Request aborted.'));
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      }
    );
  });
}

export { abortError, isPublicAddress, requestCachedJson, requestHostPinned, requestJson };
