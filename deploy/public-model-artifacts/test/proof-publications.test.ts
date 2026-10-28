import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { serve } from "../src/index";
import { PUBLISH_BATCH_PATH, serveProofPublications, type ProofPublicationBindings } from "../src/proof-publications";

const encoder = new TextEncoder();
const endpoint = "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com";
const bucket = "umi-cohort-evidence";
const access = "A".repeat(20);
const secret = "53".repeat(32);
const md5s = ["cfcd208495d565ef66e7dff9f98764da", "c4ca4238a0b923820dcc509a6f75849b", "c81e728d9d4c2f636f067f89cc14862c", "eccbc87e4b5ce2fe28308fd9f2a7baf3", "a87ff679a2f3e71d9181a67b7542122c", "e4da3b7fbbce2345d7772b0674a318d5", "1679091c5a880faf6fb5e6087eb1b2dc", "8f14e45fceea167a5a36dedd4bea2543"];
const bindings = (): ProofPublicationBindings => ({
  PROOF_EVIDENCE: env.PROOF_EVIDENCE, PROOF_ENDPOINT: endpoint, PROOF_BUCKET: bucket,
  PROOF_PUBLICATION_KEYS_JSON: JSON.stringify({ [access]: { key: secret, prefixes: ["proofs"] } }),
});
async function item(number: number) {
  const raw = String(number);
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(raw));
  const sha256 = Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, "0")).join("");
  return { key: `proofs/objects/${sha256}`, sha256, md5: md5s[number]!, content_b64: btoa(raw) };
}
async function body(count = 1) {
  return { schema: "umi-r2-proof-publication-batch/1", nonce: "12".repeat(16), issued_at_unix_ms: Date.now(), endpoint, bucket, objects: await Promise.all(Array.from({ length: count }, (_, i) => item(i))) };
}
async function signed(value: unknown) {
  const raw = JSON.stringify(value);
  const key = await crypto.subtle.importKey("raw", encoder.encode("S".repeat(32)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(`POST\n${PUBLISH_BATCH_PATH}\n${raw}`));
  const hex = Array.from(new Uint8Array(signature), (b) => b.toString(16).padStart(2, "0")).join("");
  return new Request(`https://artifacts.example${PUBLISH_BATCH_PATH}`, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `UMI-R2-Proof-Publication/1 ${access}:${hex}` }, body: raw });
}

describe("private conditional proof publications", () => {
  it("stores exact original keys and bytes, recovers unchanged repeats, and never overwrites", async () => {
    const request = await body(2);
    for (const object of request.objects) await env.PROOF_EVIDENCE.delete(object.key);
    const configured = { ...env, ...bindings() } as Env & ProofPublicationBindings;
    const first = await serve(await signed(request), configured);
    expect(first.status).toBe(200);
    expect(first.headers.get("Cache-Control")).toBe("no-store");
    const result = await first.json<{ objects: { status: number; etag: string }[] }>();
    expect(result.objects.map((o) => o.status)).toEqual([200, 200]);
    expect(result.objects.map((o) => o.etag)).toEqual(md5s.slice(0, 2));
    expect(await (await env.PROOF_EVIDENCE.get(request.objects[0]!.key))!.text()).toBe("0");
    const repeated = await serveProofPublications(await signed(request), configured);
    expect((await repeated.json<{ objects: { status: number }[] }>()).objects.map((o) => o.status)).toEqual([200, 200]);
    await env.PROOF_EVIDENCE.delete(request.objects[0]!.key);
    await env.PROOF_EVIDENCE.put(request.objects[0]!.key, "conflicting original", { customMetadata: { sha256: request.objects[0]!.sha256 } });
    const conflict = await serveProofPublications(await signed(request), configured);
    expect((await conflict.json<{ objects: { status: number }[] }>()).objects.map((o) => o.status)).toEqual([409, 200]);
    expect(await (await env.PROOF_EVIDENCE.get(request.objects[0]!.key))!.text()).toBe("conflicting original");
  });

  it("bounds backend concurrency, returns partial success in request order, and redacts failure", async () => {
    const request = await body(8);
    let active = 0, peak = 0;
    const configured = bindings();
    configured.PROOF_EVIDENCE = { put: async (key: string, _raw: Uint8Array, options: R2PutOptions) => {
      peak = Math.max(peak, ++active);
      try {
        expect(options.onlyIf).toEqual({ etagDoesNotMatch: "*" });
        await new Promise((resolve) => setTimeout(resolve, 1));
        const index = request.objects.findIndex((o) => o.key === key);
        if (index === 3) throw new Error("private upstream details");
        return { size: 1, etag: md5s[index], customMetadata: { sha256: request.objects[index]!.sha256 } };
      } finally { active--; }
    } } as unknown as R2Bucket;
    const response = await serveProofPublications(await signed(request), configured);
    const raw = await response.text();
    expect(raw).not.toContain("private upstream details");
    expect(JSON.parse(raw).objects.map((o: { status: number }) => o.status)).toEqual([200, 200, 200, 503, 200, 200, 200, 200]);
    expect(peak).toBe(6); expect(active).toBe(0);
  });

  it.each(["prefix", "frame", "digest", "duplicate", "count", "expired", "bucket", "endpoint", "size", "base64", "extra"])("rejects %s before any writes", async (change) => {
    const request = await body();
    const first = request.objects[0]!;
    if (change === "prefix") first.key = first.key.replace("proofs/", "other/");
    if (change === "frame") first.key = first.key.replace("/objects/", "/frames/history/");
    if (change === "digest") { first.sha256 = "f".repeat(64); first.key = `proofs/objects/${first.sha256}`; }
    if (change === "duplicate") request.objects.push(first);
    if (change === "count") request.objects = Array.from({ length: 9 }, () => first);
    if (change === "expired") request.issued_at_unix_ms -= 180000;
    if (change === "bucket") request.bucket = "foreign";
    if (change === "endpoint") request.endpoint = "https://foreign.example";
    if (change === "size") first.content_b64 = btoa("x".repeat(4097));
    if (change === "base64") first.content_b64 = "invalid";
    if (change === "extra") Object.assign(request, { extra: true });
    let calls = 0;
    const configured = bindings(); configured.PROOF_EVIDENCE = { put: async () => { calls++; return null; } } as unknown as R2Bucket;
    expect((await serveProofPublications(await signed(request), configured)).status).toBe(400);
    expect(calls).toBe(0);
  });

  it("requires separately selected write authority and bounded authenticated bodies", async () => {
    const value = await body();
    const request = await signed(value);
    expect((await serveProofPublications(new Request(request, { body: "{}" }), bindings())).status).toBe(401);
    expect((await serveProofPublications(new Request(request, { body: "x".repeat(65537) }), bindings())).status).toBe(413);
    const disabled = bindings(); delete disabled.PROOF_PUBLICATION_KEYS_JSON;
    expect((await serveProofPublications(await signed(value), disabled)).status).toBe(404);
    const foreign = bindings(); foreign.PROOF_PUBLICATION_KEYS_JSON = JSON.stringify({ ["B".repeat(20)]: { key: secret, prefixes: ["proofs"] } });
    expect((await serveProofPublications(await signed(value), foreign)).status).toBe(401);
    const wrongPurpose = await signed(value);
    wrongPurpose.headers.set("Authorization", wrongPurpose.headers.get("Authorization")!.replace("UMI-R2-Proof-Publication/1", "UMI-R2-Metadata/1"));
    expect((await serveProofPublications(wrongPurpose, bindings())).status).toBe(401);
  });
});
