import { randomUUID } from 'node:crypto';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { URL } from 'node:url';
import { classifyPhp, inspectPhpInfoFix } from './classifier.js';
import { normalizeDomain, parseCrt } from './discovery.js';
import { isPublicAddress, requestCachedJson, requestHostPinned } from './network.js';
import { MAX_SAMPLE_BATCHES, lookup, probeHost } from './probe.js';

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
const progressTtlMs = 10 * 60_000;
const scanIdPattern = /^[a-z0-9-]{20,64}$/i;

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

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBodyBytes) throw new Error('Request body too large.');
    chunks.push(chunk);
  }
  const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    const error = new Error('Request body must be a JSON object.');
    error.statusCode = 400;
    throw error;
  }
  return parsed;
}

function sendJson(res, status, data) {
  if (res.writableEnded) return;
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  res.end(JSON.stringify(data));
}

function writeSseEvent(res, eventName, payload) {
  if (res.writableEnded) return;
  res.write(`event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`);
}

function parseMaxBatches(value) {
  if (value === undefined || value === null || value === '') return null;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 500) {
    const error = new Error('maxBatches must be an integer between 1 and 500.');
    error.statusCode = 400;
    throw error;
  }
  return parsed;
}

function createAppServer({ lookupFn = lookup } = {}) {
  const clientRequests = new Map();
  const scanProgress = new Map();
  const scans = new Map();

  const cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [scanId, state] of scanProgress) {
      if (now - Date.parse(state.updatedAt) > progressTtlMs) scanProgress.delete(scanId);
    }
    for (const [scanId, scan] of scans) {
      if (scan.status !== 'running' && now - scan.updatedAt > progressTtlMs) scans.delete(scanId);
    }
    for (const [ip, timestamps] of clientRequests) {
      const fresh = timestamps.filter((time) => now - time < requestWindowMs);
      if (fresh.length) clientRequests.set(ip, fresh);
      else clientRequests.delete(ip);
    }
  }, 60_000);
  cleanupTimer.unref?.();

  const withinRateLimit = (ip) => {
    const now = Date.now();
    const items = (clientRequests.get(ip) || []).filter((time) => now - time < requestWindowMs);
    if (items.length >= requestLimit) return false;
    items.push(now);
    clientRequests.set(ip, items);
    return true;
  };

  const broadcastScan = (scan, eventName, payload) => {
    for (const listener of scan.listeners) {
      writeSseEvent(listener, eventName, payload);
    }
  };

  const closeScanListeners = (scan) => {
    for (const listener of scan.listeners) {
      if (!listener.writableEnded) listener.end();
    }
    scan.listeners.clear();
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname.startsWith('/api/') && !isLocalApiRequest(req)) {
      return sendJson(res, 403, { error: 'API access is limited to same-origin loopback requests.' });
    }
    if (req.method === 'GET' && url.pathname === '/api/health') return sendJson(res, 200, { ok: true });
    if (req.method === 'GET' && url.pathname === '/api/progress') {
      const scanId = url.searchParams.get('id') || '';
      if (!scanIdPattern.test(scanId)) return sendJson(res, 400, { error: 'Invalid scan ID.' });
      const progress = scanProgress.get(scanId);
      return progress ? sendJson(res, 200, progress) : sendJson(res, 404, { error: 'Scan not found.' });
    }
    if (req.method === 'GET' && url.pathname === '/favicon.ico') {
      res.writeHead(204, { 'cache-control': 'public, max-age=86400' });
      return res.end();
    }

    if (req.method === 'POST' && url.pathname === '/api/scans') {
      const ip = req.socket.remoteAddress || 'unknown';
      if (!withinRateLimit(ip)) return sendJson(res, 429, { error: 'Rate limit: 20 requests per minute.' });
      try {
        const body = await readBody(req);
        const scope = normalizeDomain(body.domain);
        const activeCheck = body.activeCheck !== false;
        const stopOnCandidate = body.stopOnCandidate !== false;
        const maxBatches = parseMaxBatches(body.maxBatches);
        const scanId = randomUUID();
        const controller = new AbortController();
        const scan = {
          id: scanId,
          status: 'running',
          progress: { phase: 'starting', checked: 0, total: 0, batch: 0, batches: MAX_SAMPLE_BATCHES },
          report: null,
          error: null,
          controller,
          listeners: new Set(),
          updatedAt: Date.now()
        };
        scans.set(scanId, scan);
        sendJson(res, 202, { scanId });

        const onProgress = (state) => {
          scan.progress = { ...state, updatedAt: new Date().toISOString() };
          scan.updatedAt = Date.now();
          scanProgress.set(scanId, scan.progress);
          broadcastScan(scan, 'progress', scan.progress);
        };
        const onBatch = (partialReport) => {
          scan.report = partialReport;
          scan.updatedAt = Date.now();
          broadcastScan(scan, 'batch', partialReport);
        };

        Promise.resolve()
          .then(() => lookupFn(
            scope,
            activeCheck,
            onProgress,
            { onBatch, stopOnCandidate, maxBatches, returnPartialOnAbort: true },
            controller.signal
          ))
          .then((report) => {
            scan.report = report;
            scan.updatedAt = Date.now();
            if (report?.cancelled || controller.signal.aborted) {
              scan.status = 'cancelled';
              broadcastScan(scan, 'cancelled', report);
            } else {
              scan.status = 'complete';
              broadcastScan(scan, 'complete', report);
            }
            closeScanListeners(scan);
          })
          .catch((error) => {
            scan.updatedAt = Date.now();
            if (error?.name === 'AbortError' || controller.signal.aborted) {
              scan.status = 'cancelled';
              broadcastScan(scan, 'cancelled', scan.report || { cancelled: true, domain: scope.domain });
            } else {
              scan.status = 'failed';
              scan.error = error?.message || 'Lookup failed.';
              broadcastScan(scan, 'scan-error', { error: scan.error });
            }
            closeScanListeners(scan);
          });
        return;
      } catch (error) {
        const status = error.statusCode || (error.message?.includes('Request body too large') ? 413
          : error instanceof SyntaxError || /domain|hostname|suffix|TLD|JSON|maxBatches/i.test(error.message || '') ? 400 : 502);
        return sendJson(res, status, { error: error.message || 'Lookup failed.' });
      }
    }

    const scanRouteMatch = url.pathname.match(/^\/api\/scans\/([^/]+)(?:\/(events|cancel))?$/);
    if (scanRouteMatch) {
      const [, scanId, action] = scanRouteMatch;
      if (!scanIdPattern.test(scanId)) return sendJson(res, 400, { error: 'Invalid scan ID.' });
      const scan = scans.get(scanId);
      if (!scan) return sendJson(res, 404, { error: 'Scan not found.' });

      if (req.method === 'GET' && !action) {
        return sendJson(res, 200, {
          id: scan.id,
          status: scan.status,
          progress: scan.progress,
          report: scan.report,
          error: scan.error
        });
      }
      if (req.method === 'POST' && action === 'cancel') {
        if (scan.status === 'running') scan.controller.abort();
        return sendJson(res, 200, { ok: true, status: scan.status });
      }
      if (req.method === 'GET' && action === 'events') {
        res.writeHead(200, {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-store',
          connection: 'keep-alive',
          'x-content-type-options': 'nosniff'
        });
        if (scan.progress) writeSseEvent(res, 'progress', scan.progress);
        if (scan.status === 'complete') {
          writeSseEvent(res, 'complete', scan.report);
          return res.end();
        }
        if (scan.status === 'cancelled') {
          writeSseEvent(res, 'cancelled', scan.report || { cancelled: true });
          return res.end();
        }
        if (scan.status === 'failed') {
          writeSseEvent(res, 'scan-error', { error: scan.error || 'Lookup failed.' });
          return res.end();
        }
        if (scan.report) writeSseEvent(res, 'batch', scan.report);
        scan.listeners.add(res);
        const keepalive = setInterval(() => {
          if (!res.writableEnded) res.write(': keepalive\n\n');
        }, 15_000);
        keepalive.unref?.();
        req.on('close', () => {
          clearInterval(keepalive);
          scan.listeners.delete(res);
        });
        return;
      }
    }

    if (req.method === 'POST' && url.pathname === '/api/lookup') {
      const ip = req.socket.remoteAddress || 'unknown';
      if (!withinRateLimit(ip)) return sendJson(res, 429, { error: 'Rate limit: 20 requests per minute.' });
      const controller = new AbortController();
      const onDisconnect = () => {
        if (!res.writableEnded) controller.abort();
      };
      res.on('close', onDisconnect);
      try {
        const body = await readBody(req);
        const scope = normalizeDomain(body.domain);
        const stopOnCandidate = body.stopOnCandidate !== false;
        const maxBatches = parseMaxBatches(body.maxBatches);
        const scanId = typeof body.scanId === 'string' && scanIdPattern.test(body.scanId) ? body.scanId : null;
        const reportProgress = (state) => {
          if (!scanId) return;
          scanProgress.set(scanId, { ...state, updatedAt: new Date().toISOString() });
        };
        reportProgress({ phase: 'starting', checked: 0, total: 0, batch: 0, batches: MAX_SAMPLE_BATCHES });
        try {
          const data = await lookupFn(
            scope,
            body.activeCheck !== false,
            reportProgress,
            { stopOnCandidate, maxBatches },
            controller.signal
          );
          return sendJson(res, 200, data);
        } catch (error) {
          if (error?.name === 'AbortError' || controller.signal.aborted) {
            reportProgress({ phase: 'cancelled', error: 'Scan cancelled by client.' });
            return;
          }
          reportProgress({ phase: 'failed', error: error.message || 'Lookup failed.' });
          throw error;
        }
      } catch (error) {
        if (controller.signal.aborted) return;
        const status = error.statusCode || (error.message?.includes('Request body too large') ? 413
          : error instanceof SyntaxError || /domain|hostname|suffix|TLD|JSON|maxBatches/i.test(error.message || '') ? 400 : 502);
        return sendJson(res, status, { error: error.message || 'Lookup failed.', details: error.details || undefined });
      } finally {
        res.off('close', onDisconnect);
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
    return sendJson(res, 404, { error: 'Not found.' });
  });

  server.requestTimeout = 0;
  server.headersTimeout = 60_000;
  server.on('close', () => clearInterval(cleanupTimer));
  return server;
}

const isMainModule = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMainModule) {
  const server = createAppServer();
  server.listen(port, '127.0.0.1', () => {
    console.log(`php2shell blue-team audit listening at http://127.0.0.1:${port}`);
  });
}

export {
  classifyPhp,
  createAppServer,
  inspectPhpInfoFix,
  isLocalApiRequest,
  isPublicAddress,
  lookup,
  normalizeDomain,
  parseCrt,
  probeHost,
  requestCachedJson,
  requestHostPinned
};
