import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { serve } from "../src/index";
import { HEAD_BATCH_PATH, serveMetadata, type MetadataBindings } from "../src/r2-heads";

const encoder = new TextEncoder();
const endpoint = "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com";
const bucket = "umi-model-artifacts";
const access = "A".repeat(20);
const secret = "53".repeat(32);
const bindings = (): MetadataBindings => ({
  ARTIFACTS: env.ARTIFACTS,
  METADATA_ENDPOINT: endpoint,
  METADATA_BUCKET: bucket,
  METADATA_KEYS_JSON: JSON.stringify({ [access]: secret }),
});
const body = (changes: Record<string, unknown> = {}) => ({
  schema: "umi-r2-head-batch/1", nonce: "12".repeat(16), issued_at_unix_ms: Date.now(),
  endpoint, bucket, keys: ["private/probe"], ...changes,
});

async function signed(value: unknown): Promise<Request> {
  const raw = JSON.stringify(value);
  const key = await crypto.subtle.importKey("raw", encoder.encode("S".repeat(32)),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(`POST\n${HEAD_BATCH_PATH}\n${raw}`));
  const hex = Array.from(new Uint8Array(signature), (part) => part.toString(16).padStart(2, "0")).join("");
  return new Request(`https://artifacts.example${HEAD_BATCH_PATH}`, {
    method: "POST", headers: { "Content-Type": "application/json", Authorization: `UMI-R2-Metadata/1 ${access}:${hex}` },
    body: raw,
  });
}

describe("private R2 metadata transport", () => {
  it("returns exact current metadata in request order without exposing bytes", async () => {
    await env.ARTIFACTS.put("private/probe", "never return the payload");
    const stored = await env.ARTIFACTS.head("private/probe");
    const request = body({ keys: ["private/absent", "private/probe"] });
    const response = await serve(await signed(request), bindings() as Env & MetadataBindings);
    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(await response.json()).toEqual({
      schema: "umi-r2-head-batch-response/1", nonce: request.nonce, endpoint, bucket,
      objects: [{ key: "private/absent", status: 404 },
        { key: "private/probe", status: 200, size_bytes: stored!.size, etag: stored!.etag }],
    });
  });

  it("does not expose private metadata without credentials or allow a signed body to change", async () => {
    const unsigned = new Request(`https://artifacts.example${HEAD_BATCH_PATH}`, { method: "POST", body: "{}" });
    expect((await serveMetadata(unsigned, bindings())).status).toBe(401);
    const original = await signed(body());
    const tampered = new Request(original, { body: JSON.stringify(body({ keys: ["private/other"] })) });
    expect((await serveMetadata(tampered, bindings())).status).toBe(401);
    const foreign = bindings();
    foreign.METADATA_KEYS_JSON = JSON.stringify({ ["B".repeat(20)]: secret });
    expect((await serveMetadata(await signed(body()), foreign)).status).toBe(401);
  });

  it.each([
    { bucket: "other" }, { endpoint: "https://other.example" }, { nonce: "bad" },
    { issued_at_unix_ms: Date.now() - 180_000 }, { extra: true }, { keys: [] },
    { keys: ["same", "same"] }, { keys: ["a\u0000b"] }, { keys: ["x".repeat(1025)] },
    { keys: Array.from({ length: 33 }, (_, index) => String(index)) },
  ])("rejects invalid namespace, clock or work bounds before reading R2: %j", async (changes) => {
    let reads = 0;
    const configured = bindings();
    configured.ARTIFACTS = { head: async () => { reads++; return null; } } as unknown as R2Bucket;
    expect((await serveMetadata(await signed(body(changes)), configured)).status).toBe(400);
    expect(reads).toBe(0);
  });

  it("keeps six concurrent heads, exact ordering, and individual failures in a full batch", async () => {
    let active = 0;
    let maximum = 0;
    const configured = bindings();
    configured.ARTIFACTS = { head: async (key: string) => {
      maximum = Math.max(maximum, ++active);
      try {
        await new Promise((resolve) => setTimeout(resolve, key === "0" ? 10 : 1));
        if (key === "3") throw new Error("private provider diagnostic");
        return null;
      } finally { active--; }
    } } as unknown as R2Bucket;
    const keys = Array.from({ length: 32 }, (_, index) => String(index));
    const response = await serveMetadata(await signed(body({ keys })), configured);
    const result = await response.json<{ objects: { key: string; status: number }[] }>();
    expect(maximum).toBe(6);
    expect(active).toBe(0);
    expect(result.objects).toEqual(keys.map((key) => ({ key, status: key === "3" ? 503 : 404 })));
  });

  it("disables an unconfigured route and rejects query, insecure and read requests", async () => {
    const configured = bindings();
    delete configured.METADATA_KEYS_JSON;
    expect((await serveMetadata(await signed(body()), configured)).status).toBe(404);
    for (const url of [`http://artifacts.example${HEAD_BATCH_PATH}`, `https://artifacts.example${HEAD_BATCH_PATH}?list=1`]) {
      expect((await serve(new Request(url), bindings() as Env & MetadataBindings)).status).toBe(404);
    }
    expect((await serveMetadata(new Request(`https://artifacts.example${HEAD_BATCH_PATH}`), bindings())).status).toBe(404);
  });

  it("refuses oversized streamed bodies even without a trustworthy content length", async () => {
    const original = await signed(body());
    const request = new Request(original, { body: "x".repeat(65537) });
    expect((await serveMetadata(request, bindings())).status).toBe(413);
  });
});
