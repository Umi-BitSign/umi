/** Authenticated, uncached metadata reads from the existing private bucket. */
export const HEAD_BATCH_PATH = "/v1/internal/r2/heads";
export const MAX_HEAD_KEYS = 32;
const MAX_BODY_BYTES = 64 * 1024;
const encoder = new TextEncoder();

export type MetadataBindings = {
  ARTIFACTS: R2Bucket;
  METADATA_ENDPOINT?: string;
  METADATA_BUCKET?: string;
  /** Maps native S3 access IDs to purpose-derived HMAC keys, never S3 secrets. */
  METADATA_KEYS_JSON?: string;
};

type RequestBody = {
  schema: "umi-r2-head-batch/1";
  nonce: string;
  issued_at_unix_ms: number;
  endpoint: string;
  bucket: string;
  keys: string[];
};

function reply(status: number, body?: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    },
  });
}

async function boundedBody(request: Request): Promise<Uint8Array<ArrayBuffer> | null> {
  const declared = request.headers.get("Content-Length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_BODY_BYTES)) return null;
  if (request.body === null) return null;
  const reader = request.body.getReader();
  const parts: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.byteLength;
      if (bytes > MAX_BODY_BYTES) {
        await reader.cancel();
        return null;
      }
      parts.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  const raw = new Uint8Array(bytes);
  let offset = 0;
  for (const part of parts) { raw.set(part, offset); offset += part.byteLength; }
  return raw;
}

function fromHex(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(value.match(/../g) ?? [], (part) => Number.parseInt(part, 16));
}

function validBody(value: unknown, env: MetadataBindings): value is RequestBody {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const body = value as Record<string, unknown>;
  return Object.keys(body).sort().join(",") === "bucket,endpoint,issued_at_unix_ms,keys,nonce,schema"
    && body.schema === "umi-r2-head-batch/1"
    && typeof body.nonce === "string" && /^[0-9a-f]{32}$/.test(body.nonce)
    && typeof body.issued_at_unix_ms === "number" && Number.isSafeInteger(body.issued_at_unix_ms)
    && Math.abs(Date.now() - body.issued_at_unix_ms) <= 120_000
    && body.endpoint === env.METADATA_ENDPOINT && body.bucket === env.METADATA_BUCKET
    && Array.isArray(body.keys) && body.keys.length > 0 && body.keys.length <= MAX_HEAD_KEYS
    && body.keys.every((key): key is string => typeof key === "string" && key.length > 0
      && encoder.encode(key).byteLength <= 1024 && !/[\u0000-\u001f\u007f]/.test(key))
    && new Set(body.keys).size === body.keys.length;
}

export async function serveMetadata(request: Request, env: MetadataBindings): Promise<Response> {
  if (request.method !== "POST" || !env.METADATA_ENDPOINT || !env.METADATA_BUCKET
      || !env.METADATA_KEYS_JSON) return reply(404);
  const auth = /^UMI-R2-Metadata\/1 ([A-Za-z0-9]{16,128}):([0-9a-f]{64})$/.exec(
    request.headers.get("Authorization") ?? "",
  );
  if (!auth) return reply(401);
  let secret: unknown;
  try {
    const keys: unknown = JSON.parse(env.METADATA_KEYS_JSON);
    if (keys === null || typeof keys !== "object" || Array.isArray(keys)) return reply(503);
    secret = (keys as Record<string, unknown>)[auth[1]!];
  } catch { return reply(503); }
  if (typeof secret !== "string" || !/^[0-9a-f]{64}$/.test(secret)) return reply(401);
  if (request.headers.get("Content-Type")?.split(";", 1)[0]?.trim() !== "application/json") return reply(415);
  const raw = await boundedBody(request);
  if (raw === null) return reply(413);
  const signed = new Uint8Array(encoder.encode(`POST\n${HEAD_BATCH_PATH}\n`).length + raw.length);
  signed.set(encoder.encode(`POST\n${HEAD_BATCH_PATH}\n`));
  signed.set(raw, signed.length - raw.length);
  const key = await crypto.subtle.importKey("raw", fromHex(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  if (!await crypto.subtle.verify("HMAC", key, fromHex(auth[2]!), signed)) return reply(401);
  let body: unknown;
  try { body = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(raw)); }
  catch { return reply(400); }
  if (!validBody(body, env)) return reply(400);

  const objects: ({ key: string; status: 404 | 503 } | { key: string; status: 200; size_bytes: number; etag: string })[] = [];
  // Six outstanding operations also fit Workers' connection allowance. The
  // request's 32-head ceiling fits the free plan's subrequest allowance.
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(6, body.keys.length) }, async () => {
    while (next < body.keys.length) {
      const index = next++;
      const objectKey = body.keys[index]!;
      try {
        const object = await env.ARTIFACTS.head(objectKey);
        objects[index] = object === null ? { key: objectKey, status: 404 }
          : { key: objectKey, status: 200, size_bytes: object.size, etag: object.etag };
      } catch { objects[index] = { key: objectKey, status: 503 }; }
    }
  }));
  return reply(200, {
    schema: "umi-r2-head-batch-response/1", nonce: body.nonce,
    endpoint: body.endpoint, bucket: body.bucket, objects,
  });
}
