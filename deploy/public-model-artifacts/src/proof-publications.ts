/** Bounded conditional writes of original objects; no packed representation. */
export const PUBLISH_BATCH_PATH = "/v1/internal/r2/proof-publications";
export const MAX_PUBLISH_OBJECTS = 8;
const MAX_BODY_BYTES = 64 * 1024;
const MAX_OBJECT_BYTES = 4096;
const encoder = new TextEncoder();

export type ProofPublicationBindings = {
  PROOF_EVIDENCE?: R2Bucket;
  PROOF_ENDPOINT?: string;
  PROOF_BUCKET?: string;
  /** Access ID -> { key: purpose-derived HMAC hex, prefixes: exact writable prefixes }. */
  PROOF_PUBLICATION_KEYS_JSON?: string;
};
type Item = { key: string; sha256: string; md5: string; content_b64: string };
type Body = { schema: "umi-r2-proof-publication-batch/1"; nonce: string; issued_at_unix_ms: number; endpoint: string; bucket: string; objects: Item[] };
type Result = { key: string; status: 409 | 503 } | { key: string; status: 200; size_bytes: number; etag: string; sha256: string };

function reply(status: number, body?: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" },
  });
}
function fromHex(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(value.match(/../g) ?? [], (part) => Number.parseInt(part, 16));
}
function keys(value: Record<string, unknown>, expected: string): boolean {
  return Object.keys(value).sort().join(",") === expected;
}
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
async function boundedBody(request: Request): Promise<Uint8Array<ArrayBuffer> | null> {
  const declared = request.headers.get("Content-Length");
  if (declared !== null && (!/^\d+$/.test(declared) || Number(declared) > MAX_BODY_BYTES)) return null;
  if (request.body === null) return null;
  const reader = request.body.getReader();
  const raw = new Uint8Array(MAX_BODY_BYTES);
  let size = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      if (size + part.value.byteLength > MAX_BODY_BYTES) { await reader.cancel(); return null; }
      raw.set(part.value, size); size += part.value.byteLength;
    }
  } finally { reader.releaseLock(); }
  return raw.slice(0, size);
}
function validBody(value: unknown, env: ProofPublicationBindings, prefixes: string[]): value is Body {
  if (!record(value) || !keys(value, "bucket,endpoint,issued_at_unix_ms,nonce,objects,schema")) return false;
  return value.schema === "umi-r2-proof-publication-batch/1"
    && typeof value.nonce === "string" && /^[0-9a-f]{32}$/.test(value.nonce)
    && typeof value.issued_at_unix_ms === "number" && Number.isSafeInteger(value.issued_at_unix_ms)
    && Math.abs(Date.now() - value.issued_at_unix_ms) <= 120_000
    && value.endpoint === env.PROOF_ENDPOINT && value.bucket === env.PROOF_BUCKET
    && Array.isArray(value.objects) && value.objects.length > 0 && value.objects.length <= MAX_PUBLISH_OBJECTS
    && value.objects.every((item: unknown): item is Item => record(item)
      && keys(item, "content_b64,key,md5,sha256")
      && typeof item.sha256 === "string" && /^[0-9a-f]{64}$/.test(item.sha256)
      && typeof item.md5 === "string" && /^[0-9a-f]{32}$/.test(item.md5)
      && typeof item.key === "string" && prefixes.some((prefix) => item.key === `${prefix}/objects/${item.sha256}`)
      && typeof item.content_b64 === "string" && item.content_b64.length > 0 && item.content_b64.length <= 5464
      && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(item.content_b64))
    && new Set(value.objects.map((item: Item) => item.key)).size === value.objects.length;
}
function exact(object: R2Object, item: Item, size: number): boolean {
  return object.size === size && object.etag === item.md5 && object.customMetadata?.sha256 === item.sha256;
}

export async function serveProofPublications(request: Request, env: ProofPublicationBindings): Promise<Response> {
  if (request.method !== "POST" || !env.PROOF_EVIDENCE || !env.PROOF_ENDPOINT || !env.PROOF_BUCKET || !env.PROOF_PUBLICATION_KEYS_JSON) return reply(404);
  const auth = /^UMI-R2-Proof-Publication\/1 ([A-Za-z0-9]{16,128}):([0-9a-f]{64})$/.exec(request.headers.get("Authorization") ?? "");
  if (!auth) return reply(401);
  let credential: unknown;
  try {
    const configured: unknown = JSON.parse(env.PROOF_PUBLICATION_KEYS_JSON);
    if (!record(configured)) return reply(503);
    credential = configured[auth[1]!];
  } catch { return reply(503); }
  if (!record(credential) || !keys(credential, "key,prefixes") || typeof credential.key !== "string" || !/^[0-9a-f]{64}$/.test(credential.key)
    || !Array.isArray(credential.prefixes) || credential.prefixes.length === 0 || credential.prefixes.length > 16
    || !credential.prefixes.every((prefix): prefix is string => typeof prefix === "string" && /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,95}$/.test(prefix))) return reply(401);
  if (request.headers.get("Content-Type")?.split(";", 1)[0]?.trim() !== "application/json") return reply(415);
  const raw = await boundedBody(request);
  if (raw === null) return reply(413);
  const prefix = encoder.encode(`POST\n${PUBLISH_BATCH_PATH}\n`);
  const signed = new Uint8Array(prefix.length + raw.length); signed.set(prefix); signed.set(raw, prefix.length);
  const key = await crypto.subtle.importKey("raw", fromHex(credential.key), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  if (!await crypto.subtle.verify("HMAC", key, fromHex(auth[2]!), signed)) return reply(401);
  let body: unknown;
  try { body = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(raw)); } catch { return reply(400); }
  if (!validBody(body, env, credential.prefixes)) return reply(400);
  const parsed = body;
  // Authenticate every supplied content identity once before making any writes.
  const payloads: Uint8Array<ArrayBuffer>[] = [];
  for (const item of parsed.objects) {
    let decoded: string;
    try { decoded = atob(item.content_b64); } catch { return reply(400); }
    if (decoded.length === 0 || decoded.length > MAX_OBJECT_BYTES || btoa(decoded) !== item.content_b64) return reply(400);
    const bytes = Uint8Array.from(decoded, (c) => c.charCodeAt(0));
    const hash = await crypto.subtle.digest("SHA-256", bytes);
    if (Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, "0")).join("") !== item.sha256) return reply(400);
    payloads.push(bytes);
  }
  const objects: Result[] = [];
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(6, parsed.objects.length) }, async () => {
    while (next < parsed.objects.length) {
      const index = next++;
      const item = parsed.objects[index]!;
      const bytes = payloads[index]!;
      try {
        let object = await env.PROOF_EVIDENCE!.put(item.key, bytes, {
          onlyIf: { etagDoesNotMatch: "*" }, md5: fromHex(item.md5),
          customMetadata: { sha256: item.sha256 },
        });
        // A conditional conflict or lost prior acknowledgement is reusable only
        // with exact original size, MD5/ETag and SHA metadata. Never overwrite.
        if (object === null) object = await env.PROOF_EVIDENCE!.head(item.key);
        objects[index] = object !== null && exact(object, item, bytes.length)
          ? { key: item.key, status: 200, size_bytes: object.size, etag: object.etag, sha256: item.sha256 }
          : { key: item.key, status: 409 };
      } catch { objects[index] = { key: item.key, status: 503 }; }
    }
  }));
  return reply(200, { schema: "umi-r2-proof-publication-batch-response/1", nonce: parsed.nonce, endpoint: parsed.endpoint, bucket: parsed.bucket, objects });
}
