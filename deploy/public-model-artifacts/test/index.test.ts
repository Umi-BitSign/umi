import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { serve, type Catalog } from "../src/index";

const encoder = new TextEncoder();
const model = encoder.encode("model-comparator");
const runtime = encoder.encode("runtime-comparator");
const modelSha = "11".repeat(32);
const runtimeSha = "22".repeat(32);
const modelArchiveSha = "33".repeat(32);
const runtimeArchiveSha = "44".repeat(32);
const decode = async (response: Response) => new TextDecoder().decode(await response.arrayBuffer());

const catalog: Catalog = [
  {
    path: `/v1/models/${modelSha}/umi-model-bundle.tar`,
    key: `public/v1/models/${modelSha}/umi-model-bundle.tar`,
    kind: "model",
    identitySha256: modelSha,
    archiveSha256: modelArchiveSha,
    bytes: model.length,
    mediaType: "application/x-tar",
    filename: `umi-model-bundle-${modelSha}.tar`,
  },
  {
    path: `/v1/runtimes/${runtimeSha}/offline-cpu-runtime.oci.tar`,
    key: `public/v1/runtimes/${runtimeSha}/offline-cpu-runtime.oci.tar`,
    kind: "runtime",
    identitySha256: runtimeSha,
    archiveSha256: runtimeArchiveSha,
    bytes: runtime.length,
    mediaType: "application/x-tar",
    filename: `offline-cpu-runtime-${runtimeSha}.oci.tar`,
  },
];

type Bindings = Env & { ARTIFACTS: R2Bucket };
const invoke = (path: string, init?: RequestInit) => serve(
  new Request(`https://artifacts.example${path}`, init),
  env as Bindings,
  catalog,
);

beforeEach(async () => {
  for (const artifact of catalog) await env.ARTIFACTS.delete(artifact.key);
  await env.ARTIFACTS.put(catalog[0]!.key, model, {
    customMetadata: { sha256: modelArchiveSha, identity: modelSha, kind: "model" },
  });
  await env.ARTIFACTS.put(catalog[1]!.key, runtime, {
    customMetadata: { sha256: runtimeArchiveSha, identity: runtimeSha, kind: "runtime" },
  });
});

describe("public model artifacts", () => {
  it("publishes a bounded discovery index without listing the bucket", async () => {
    await env.ARTIFACTS.put("private/model.tar", "private");
    const response = await invoke("/v1/index.json");
    expect(response.status).toBe(200);
    const body = await response.json<{ artifacts: Array<{ url: string }> }>();
    expect(body.artifacts).toHaveLength(2);
    expect(body.artifacts.map((entry) => entry.url)).toEqual(catalog.map((entry) => `https://artifacts.example${entry.path}`));
    expect(JSON.stringify(body)).not.toContain("private/model.tar");
  });

  it("streams the complete immutable artifact", async () => {
    const response = await invoke(catalog[0]!.path);
    expect(response.status).toBe(200);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(model);
    expect(response.headers.get("ETag")).toBe(`"${modelArchiveSha}"`);
    expect(response.headers.get("Content-Length")).toBe(String(model.length));
    expect(response.headers.get("Accept-Ranges")).toBe("bytes");
  });

  it("supports a single bounded byte range", async () => {
    const response = await invoke(catalog[1]!.path, { headers: { Range: "bytes=2-8" } });
    expect(response.status).toBe(206);
    expect(await decode(response)).toBe("ntime-c");
    expect(response.headers.get("Content-Range")).toBe(`bytes 2-8/${runtime.length}`);
    expect(response.headers.get("Content-Length")).toBe("7");
  });

  it("supports suffix and open-ended ranges", async () => {
    const suffix = await invoke(catalog[0]!.path, { headers: { Range: "bytes=-5" } });
    expect(await decode(suffix)).toBe("rator");
    const open = await invoke(catalog[0]!.path, { headers: { Range: "bytes=6-" } });
    expect(await decode(open)).toBe("comparator");
  });

  it.each(["bytes=", "bytes=99-100", "bytes=4-3", "bytes=0-1,3-4", "items=0-1"])(
    "rejects invalid range %s",
    async (range) => {
      const response = await invoke(catalog[0]!.path, { headers: { Range: range } });
      expect(response.status).toBe(416);
      expect(response.headers.get("Content-Range")).toBe(`bytes */${model.length}`);
    },
  );

  it("supports HEAD and conditional requests", async () => {
    const head = await invoke(catalog[0]!.path, { method: "HEAD" });
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
    const cached = await invoke(catalog[0]!.path, { headers: { "If-None-Match": `"${modelArchiveSha}"` } });
    expect(cached.status).toBe(304);
    const changed = await invoke(catalog[0]!.path, { headers: { "If-Match": `"${runtimeArchiveSha}"` } });
    expect(changed.status).toBe(412);
  });

  it("checks object existence and metadata before conditional responses", async () => {
    await env.ARTIFACTS.delete(catalog[0]!.key);
    const missing = await invoke(catalog[0]!.path, {
      headers: { "If-None-Match": `"${modelArchiveSha}"` },
    });
    expect(missing.status).toBe(404);

    await env.ARTIFACTS.put(catalog[0]!.key, model, {
      customMetadata: { sha256: runtimeArchiveSha, identity: modelSha, kind: "model" },
    });
    const mismatched = await invoke(catalog[0]!.path, {
      headers: { "If-None-Match": `"${modelArchiveSha}"` },
    });
    expect(mismatched.status).toBe(404);
  });

  it("refuses objects whose bound metadata differs", async () => {
    await env.ARTIFACTS.put(catalog[0]!.key, model, {
      customMetadata: { sha256: runtimeArchiveSha, identity: modelSha, kind: "model" },
    });
    expect((await invoke(catalog[0]!.path)).status).toBe(404);
  });

  it.each(["/", "/v1/models.json", "/private/model.tar", `${catalog[0]!.path}?download=1`])(
    "does not expose %s",
    async (path) => expect((await invoke(path)).status).toBe(404),
  );

  it.each(["POST", "PUT", "DELETE", "OPTIONS"])("rejects %s", async (method) => {
    expect((await invoke(catalog[0]!.path, { method })).status).toBe(404);
  });
});
