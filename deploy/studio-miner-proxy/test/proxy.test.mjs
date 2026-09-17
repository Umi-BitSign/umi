import assert from 'node:assert/strict';
import test from 'node:test';
import worker from '../src/index.mjs';

const minerOrigin = 'https://studio-miner.sam-sn78.workers.dev';
const competitionOrigin = 'https://api.umi.vision';
function run(path, options = {}, fetch = async () => new Response('ok'), origin = minerOrigin) {
  return worker.fetch(new Request(origin + path, options), {
    MINER_ORIGIN: { fetch }, ASSIGNMENT_ORIGIN: { fetch },
  });
}

test('unknown paths and methods never reach the private service', async () => {
  const denied = async () => assert.fail('private service called');
  for (const path of ['/', '/metrics', '/docs', '/openapi.json', '/wallets', '/v1/translate/extra', '/healthz%2f..']) {
    assert.equal((await run(path, {}, denied)).status, 404);
  }
  assert.equal((await run('/healthz', { method: 'POST' }, denied)).status, 405);
  assert.equal((await run('/v1/translate', {}, denied)).status, 405);
  assert.equal((await run('/healthz?url=http://other-host', {}, denied)).status, 400);
  assert.equal((await run('/v1/competition/assignments/query', { method: 'POST' }, denied)).status, 404);
  assert.equal((await run('/healthz', {}, denied, competitionOrigin)).status, 404);
});

test('forwards only the exact assignment query route to its separate origin', async () => {
  const body = '{"signed":"query"}\n';
  const response = await run('/v1/competition/assignments/query', {
    method: 'POST', body, headers: { 'content-type': 'application/json' },
  }, async request => {
    assert.equal(request.url, 'http://127.0.0.1:8129/v1/competition/assignments/query');
    assert.equal(await request.text(), body);
    return Response.json({ schema: 'umi-assignment-feed-response/1', assignments: [] });
  }, competitionOrigin);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    schema: 'umi-assignment-feed-response/1', assignments: [],
  });
  const denied = async () => assert.fail('private service called');
  assert.equal((await run('/v1/competition/assignments/query/more', { method: 'POST' }, denied, competitionOrigin)).status, 404);
  assert.equal((await run('/v1/competition/assignments/query', {}, denied, competitionOrigin)).status, 405);
});

test('forwards exact request/response bytes and authentication headers to a fixed target', async () => {
  const body = '{ "unchanged": "héllo", "signed": true }\n';
  const response = await run('/v1/translate', { method: 'POST', body, headers: {
    'x-umi-body-sha256': 'example-digest', 'btauth-signature': 'example-signature',
    'content-type': 'application/json', cookie: 'private', 'x-forwarded-host': 'attacker',
  } }, async request => {
    assert.equal(request.url, 'http://127.0.0.1:8787/v1/translate');
    assert.equal(await request.text(), body);
    assert.equal(request.headers.get('btauth-signature'), 'example-signature');
    assert.equal(request.headers.get('x-umi-body-sha256'), 'example-digest');
    assert.equal(request.headers.get('cookie'), null);
    assert.equal(request.headers.get('x-forwarded-host'), null);
    assert.equal(request.redirect, 'manual');
    return new Response(body, { headers: { 'x-umi-signature': 'response-signature', 'cache-control': 'public', 'set-cookie': 'bad' } });
  });
  assert.equal(await response.text(), body);
  assert.equal(response.headers.get('x-umi-signature'), 'response-signature');
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('set-cookie'), null);
});

test('blocks oversized bodies with or without content-length', async () => {
  const denied = async () => assert.fail('private service called');
  for (const headers of [{}, { 'content-length': '65537' }, { 'content-length': '01' }]) {
    assert.equal((await run('/v1/translate', { method: 'POST', body: 'x'.repeat(65537), headers }, denied)).status, 413);
  }
  const exact = await run('/v1/translate', { method: 'POST', body: 'x'.repeat(65536) }, async req => {
    assert.equal((await req.arrayBuffer()).byteLength, 65536);
    return new Response('ok');
  });
  assert.equal(exact.status, 200);
});

test('rejects oversized headers and encoded bodies', async () => {
  const denied = async () => assert.fail('private service called');
  assert.equal((await run('/healthz', { headers: { extra: 'x'.repeat(16385) } }, denied)).status, 431);
  assert.equal((await run('/v1/translate', { method: 'POST', headers: { 'content-encoding': 'gzip' } }, denied)).status, 415);
});

test('preserves backend unavailability and authorization failures', async () => {
  for (const code of [401, 403, 429, 503]) {
    const response = await run('/v1/translate', { method: 'POST' }, async () => new Response('rejected', { status: code }));
    assert.equal(response.status, code);
    assert.equal(await response.text(), 'rejected');
  }
});

test('rejects redirects and oversized upstream responses', async () => {
  assert.equal((await run('/healthz', {}, async () => Response.redirect('http://other-internal-host/'))).status, 502);
  assert.equal((await run('/healthz', {}, async () => new Response('x'.repeat(65537)))).status, 502);
});

test('reports disconnected backend without leaking exception details', async () => {
  const response = await run('/healthz', {}, async () => { throw new Error('PRIVATE DATA'); });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { ok: false, error: 'origin_unavailable' });
});

test('client abort cancels body read before forwarding', async () => {
  const controller = new AbortController();
  let cancelled = false;
  const body = new ReadableStream({ cancel() { cancelled = true; } });
  const pending = run('/v1/translate', { method: 'POST', body, duplex: 'half', signal: controller.signal },
    async () => assert.fail('private service called'));
  controller.abort();
  assert.equal((await pending).status, 504);
  assert.equal(cancelled, true);
});
