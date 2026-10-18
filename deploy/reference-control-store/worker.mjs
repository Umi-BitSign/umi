/** Authenticated, bounded R2 control operations. Never signs or deletes objects. */
const CHANNELS = {
  a3ca19a108fe7d1a8e53a2db76f480ebe237b7942595f23135d6e11889ed40c0: "linux-amd64",
  "85ea6ef2c7e4f24d9d0eefa367425119b509e8604ce1675443efcbacc7bb4461": "linux-arm64",
};
const CHANNEL = /^validator-supervisor\/channels\/([0-9a-f]{64})\/(linux-amd64|linux-arm64)\/after\/(0\/initial|[1-9][0-9]{0,15}\/[0-9a-f]{64})\.json$/;
const APPROVAL = /^validator-supervisor\/translation-reference-policies\/[0-9a-f]{64}\.json$/;
const HEX = /^[0-9a-f]{64}$/;
const ETAG = /^"[0-9a-f]{32}"$/;
const encoder = new TextEncoder();
const hex = (bytes) => Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");

function response(status, body = null, headers = {}) {
  return new Response(body, { status, headers: {
    "Cache-Control": "no-store, no-cache, must-revalidate, no-transform",
    "X-Content-Type-Options": "nosniff", ...headers,
  } });
}

async function authorized(request, secret) {
  if (typeof secret !== "string" || !HEX.test(secret)) return false;
  const token = request.headers.get("Authorization")?.match(/^Bearer ([0-9a-f]{64})$/)?.[1];
  if (!token) return false;
  const [left, right] = await Promise.all([token, secret].map(async (value) =>
    new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)))));
  let difference = 0;
  for (let i = 0; i < 32; i++) difference |= left[i] ^ right[i];
  return difference === 0;
}

async function bounded(request, maximum) {
  const length = request.headers.get("Content-Length");
  if (!length || !/^[1-9][0-9]*$/.test(length) || Number(length) > maximum) return null;
  if (request.headers.has("Content-Encoding") || !request.body) return null;
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximum || size > Number(length)) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  if (size !== Number(length)) return null;
  const raw = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { raw.set(chunk, offset); offset += chunk.length; }
  return raw;
}

export default {
  async fetch(request, env) {
    if (!(await authorized(request, env.PUBLICATION_TOKEN))) return response(401);
    const url = new URL(request.url);
    if (url.search || url.pathname.includes("%")) return response(400);
    const key = url.pathname.slice(1);
    const channel = CHANNEL.exec(key);
    const approval = APPROVAL.test(key);
    if ((!channel || CHANNELS[channel[1]] !== channel[2]) && !approval) return response(403);
    if (channel) {
      const sequence = Number(channel[3].split("/")[0]);
      if (!Number.isSafeInteger(sequence)) return response(400);
    }
    const maximum = approval ? 16 * 1024 : 1024 * 1024;
    if (request.method === "GET" || request.method === "HEAD") {
      const object = request.method === "GET" ? await env.CONTROL.get(key) : await env.CONTROL.head(key);
      if (!object) return response(404);
      if (object.size < 1 || object.size > maximum) return response(422);
      const headers = {
        ETag: object.httpEtag, "Content-Length": String(object.size),
        "Content-Type": "application/json",
      };
      if (object.customMetadata?.sha256) headers["x-amz-meta-sha256"] = object.customMetadata.sha256;
      return response(200, request.method === "GET" ? object.body : null, headers);
    }
    if (request.method !== "PUT") return response(405);
    const match = request.headers.get("If-Match");
    const absent = request.headers.get("If-None-Match");
    if (approval ? match !== null || absent !== "*" :
        !((match !== null && ETAG.test(match) && absent === null) || (match === null && absent === "*"))) {
      return response(428);
    }
    const raw = await bounded(request, maximum);
    if (raw === null) return response(413);
    const digest = hex(await crypto.subtle.digest("SHA-256", raw));
    const declared = request.headers.get("x-amz-meta-sha256");
    if (approval && declared !== digest) return response(422);
    const conditions = new Headers(match ? { "If-Match": match } : { "If-None-Match": "*" });
    // R2 evaluates these conditions atomically. A failed condition returns null.
    const stored = await env.CONTROL.put(key, raw, {
      onlyIf: conditions, sha256: digest,
      customMetadata: approval ? { sha256: digest } : {},
      httpMetadata: {
        contentType: "application/json",
        cacheControl: approval ? "public, max-age=31536000, immutable" :
          "no-store, no-cache, must-revalidate, no-transform",
      },
    });
    if (stored === null) return response(412);
    return response(200, null, { ETag: stored.httpEtag });
  },
};
