const MAX_BYTES = 16 * 1024 * 1024;
const MAX_WINDOW_SECONDS = 86400;
const PATH = /^\/v1\/clips\/([1-9][0-9]{9})\/([1-9][0-9]{9})\/([0-9a-f]{64})\/([0-9a-f]{64})\.mp4$/;
const HEADERS = {
  "Cache-Control": "no-store, private",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Robots-Tag": "noindex, nofollow, noarchive",
};

function absent(status = 404): Response {
  return new Response(null, { status, headers: HEADERS });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.protocol !== "https:" || url.search || !["GET", "HEAD"].includes(request.method)) {
      return absent();
    }
    const match = PATH.exec(url.pathname);
    if (!match) return absent();
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
      const checksum = object.checksums.sha256;
      const digest = checksum && Array.from(new Uint8Array(checksum), (byte) => byte.toString(16).padStart(2, "0")).join("");
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
} satisfies ExportedHandler<Env>;
