const MAX_BYTES = 16 * 1024 * 1024;
const MAX_WINDOW_SECONDS = 7 * 24 * 60 * 60;
const PATH = /^\/v1\/clips\/([1-9][0-9]{9})\/([1-9][0-9]{9})\/([0-9a-f]{64})\/([0-9a-f]{64})\.mp4$/;
const HEADERS = {
  "Cache-Control": "no-store, private",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Robots-Tag": "noindex, nofollow, noarchive",
};

type Bindings = Env & { UPLOAD_TOKEN: string };

function absent(status = 404): Response {
  return new Response(null, { status, headers: HEADERS });
}

function checksumHex(checksum: ArrayBuffer | undefined): string | undefined {
  if (!checksum) return undefined;
  return Array.from(new Uint8Array(checksum), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function authorized(request: Request, secret: string): Promise<boolean> {
  if (!/^[0-9a-f]{64}$/.test(secret)) return false;
  const value = request.headers.get("Authorization");
  if (!value?.startsWith("Bearer ")) return false;
  const candidate = value.slice("Bearer ".length);
  if (!/^[0-9a-f]{64}$/.test(candidate)) return false;
  const encoder = new TextEncoder();
  const [expected, received] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(secret)),
    crypto.subtle.digest("SHA-256", encoder.encode(candidate)),
  ]);
  const left = new Uint8Array(expected);
  const right = new Uint8Array(received);
  let difference = 0;
  for (let i = 0; i < left.length; i += 1) difference |= left[i]! ^ right[i]!;
  return difference === 0;
}

async function upload(request: Request, env: Bindings, match: RegExpExecArray): Promise<Response> {
  if (!(await authorized(request, env.UPLOAD_TOKEN))) return absent();
  const notBefore = Number(match[1]);
  const expires = Number(match[2]);
  const now = Math.floor(Date.now() / 1000);
  if (expires <= notBefore || expires - notBefore > MAX_WINDOW_SECONDS || now < notBefore || now >= expires) {
    return absent();
  }
  const length = Number(request.headers.get("Content-Length"));
  if (!Number.isSafeInteger(length) || length <= 0 || length > MAX_BYTES) return absent();
  if (request.headers.get("Content-Type") !== "video/mp4") return absent();
  const body = await request.arrayBuffer();
  if (body.byteLength !== length) return absent();
  const bytes = new Uint8Array(body);
  if (bytes.length < 8 || String.fromCharCode(...bytes.subarray(4, 8)) !== "ftyp") return absent();
  const digest = await crypto.subtle.digest("SHA-256", body);
  if (checksumHex(digest) !== match[4]) return absent();

  const key = new URL(request.url).pathname.slice(1);
  const created = await env.CLIPS.put(key, body, {
    onlyIf: new Headers({ "If-None-Match": "*" }),
    sha256: digest,
    httpMetadata: { contentType: "video/mp4", cacheControl: "no-store, private" },
  });
  if (created) return new Response(null, { status: 201, headers: HEADERS });
  const existing = await env.CLIPS.head(key);
  if (existing?.size === length && checksumHex(existing.checksums.sha256) === match[4]) {
    return new Response(null, { status: 200, headers: HEADERS });
  }
  return absent(409);
}

export default {
  async fetch(request: Request, env: Bindings): Promise<Response> {
    const url = new URL(request.url);
    if (url.protocol !== "https:" || url.search) return absent();
    const match = PATH.exec(url.pathname);
    if (!match) return absent();
    if (request.method === "PUT") {
      try {
        return await upload(request, env, match);
      } catch {
        console.error(JSON.stringify({ event: "clip_storage_unavailable" }));
        return absent(503);
      }
    }
    if (!["GET", "HEAD"].includes(request.method)) return absent();
    const notBefore = Number(match[1]);
    const expires = Number(match[2]);
    const now = Math.floor(Date.now() / 1000);
    if (expires <= notBefore || expires - notBefore > MAX_WINDOW_SECONDS || now < notBefore || now >= expires) {
      return absent();
    }

    // The complete capability and time window are part of the exact R2 key.
    // Changing any segment selects an absent object, not an extended grant.
    const key = url.pathname.slice(1);
    try {
      let object: R2Object | null;
      let body: ReadableStream | null = null;
      if (request.method === "HEAD") {
        object = await env.CLIPS.head(key);
      } else {
        const fetched = await env.CLIPS.get(key);
        object = fetched;
        body = fetched?.body ?? null;
      }
      if (!object) return absent();
      const digest = checksumHex(object.checksums.sha256);
      if (object.size <= 0 || object.size > MAX_BYTES || digest !== match[4]) {
        if (body) await body.cancel();
        return absent();
      }
      return new Response(body, {
        headers: {
          ...HEADERS,
          "Content-Type": "video/mp4",
          "Content-Length": String(object.size),
        },
      });
    } catch {
      // Do not log URL capabilities, object keys, or storage exception text.
      console.error(JSON.stringify({ event: "clip_storage_unavailable" }));
      return absent(503);
    }
  },
} satisfies ExportedHandler<Bindings>;
