// Each public hostname can reach only its fixed loopback VPC service.
const MAX_BODY = 64 * 1024;
const MAX_HEADERS = 16 * 1024;
const MINER_HOST = 'studio-miner.sam-sn78.workers.dev';
const COMPETITION_HOST = 'api.umi.vision';
const ROUTES = new Map([
  [`${MINER_HOST}\n/healthz`, {
    method: 'GET', binding: 'MINER_ORIGIN', origin: 'http://127.0.0.1:8787', timeoutMs: 180_000,
  }],
  [`${MINER_HOST}\n/v1/translate`, {
    method: 'POST', binding: 'MINER_ORIGIN', origin: 'http://127.0.0.1:8787', timeoutMs: 180_000,
  }],
  [`${COMPETITION_HOST}\n/v1/competition/assignments/query`, {
    method: 'POST', binding: 'ASSIGNMENT_ORIGIN', origin: 'http://127.0.0.1:8129', timeoutMs: 30_000,
  }],
]);
const HOP_HEADERS = [
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
];

class BodyLimitError extends Error {}

/** @param {number} status @param {string} code */
function failure(status, code) {
  return Response.json({ ok: false, error: code }, {
    status, headers: { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' },
  });
}

/** @param {Headers} input */
function cleanHeaders(input) {
  const headers = new Headers(input);
  const connection = headers.get('connection');
  for (const token of connection?.split(',') ?? []) headers.delete(token.trim());
  for (const name of HOP_HEADERS) headers.delete(name);
  return headers;
}

/**
 * Bodies in this protocol are bounded JSON envelopes, not video uploads.
 * Preserve their exact bytes because the miner authenticates the body digest.
 * @param {ReadableStream<Uint8Array> | null} stream
 * @param {AbortSignal} signal
 */
async function readBody(stream, signal) {
  if (!stream) return new Uint8Array();
  const reader = stream.getReader();
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener('abort', cancel, { once: true });
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      signal.throwIfAborted();
      const { done, value } = await reader.read();
      signal.throwIfAborted();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BODY) throw new BodyLimitError();
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return bytes;
  } catch (error) {
    cancel();
    throw error;
  } finally {
    signal.removeEventListener('abort', cancel);
    reader.releaseLock();
  }
}

/** @satisfies {ExportedHandler<Env>} */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.protocol !== 'https:') return failure(400, 'https_required');
    if (url.search || url.hash) return failure(400, 'query_not_supported');
    const route = ROUTES.get(`${url.hostname}\n${url.pathname}`);
    if (!route) return failure(404, 'not_found');
    if (request.method !== route.method) return failure(405, 'method_not_allowed');
    if (request.headers.has('upgrade')) return failure(400, 'upgrade_not_supported');
    let headerBytes = 0;
    for (const [name, value] of request.headers) headerBytes += new TextEncoder().encode(name + value).length + 4;
    if (headerBytes > MAX_HEADERS) return failure(431, 'headers_too_large');
    const encoding = request.headers.get('content-encoding');
    if (encoding && encoding !== 'identity') return failure(415, 'content_encoding_not_supported');
    const length = request.headers.get('content-length');
    if (length !== null && (!/^(0|[1-9][0-9]*)$/.test(length) || Number(length) > MAX_BODY)) {
      return failure(413, 'body_too_large');
    }

    const controller = new AbortController();
    const abort = () => controller.abort(new Error('client_disconnected'));
    request.signal.addEventListener('abort', abort, { once: true });
    if (request.signal.aborted) abort();
    const timer = setTimeout(() => controller.abort(new Error('deadline_exceeded')), route.timeoutMs);
    let stage = 'request';
    try {
      const body = await readBody(request.body, controller.signal);
      const headers = cleanHeaders(request.headers);
      for (const name of ['host', 'content-length', 'cookie', 'forwarded', 'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for']) headers.delete(name);
      headers.set('accept-encoding', 'identity');
      stage = 'origin';
      const binding = route.binding === 'MINER_ORIGIN'
        ? env.MINER_ORIGIN : env.ASSIGNMENT_ORIGIN;
      if (!binding || typeof binding.fetch !== 'function') throw new Error('missing_origin_binding');
      const upstream = await binding.fetch(new Request(`${route.origin}${url.pathname}`, {
        method: request.method, headers,
        body: route.method === 'POST' ? body : undefined,
        signal: controller.signal, redirect: 'manual',
      }));
      if (upstream.status >= 300 && upstream.status < 400) {
        await upstream.body?.cancel();
        return failure(502, 'origin_redirect_rejected');
      }
      stage = 'response';
      const responseBody = await readBody(upstream.body, controller.signal);
      const responseHeaders = cleanHeaders(upstream.headers);
      for (const name of ['content-length', 'content-encoding', 'set-cookie', 'server']) responseHeaders.delete(name);
      responseHeaders.set('cache-control', 'no-store');
      responseHeaders.set('cdn-cache-control', 'no-store');
      responseHeaders.set('x-content-type-options', 'nosniff');
      return new Response([204, 205, 304].includes(upstream.status) ? null : responseBody, {
        status: upstream.status, headers: responseHeaders,
      });
    } catch (error) {
      if (controller.signal.aborted) return failure(504, 'request_deadline_or_disconnect');
      if (error instanceof BodyLimitError) return failure(stage === 'request' ? 413 : 502, 'body_too_large');
      console.error(JSON.stringify({ event: 'studio_proxy_failure', stage, route: url.pathname }));
      return failure(503, 'origin_unavailable');
    } finally {
      clearTimeout(timer);
      request.signal.removeEventListener('abort', abort);
    }
  },
};
