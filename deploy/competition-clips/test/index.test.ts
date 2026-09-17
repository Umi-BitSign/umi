import { env } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import worker from "../src/index";

const bytes = new TextEncoder().encode("0000ftypexposed synthetic clip, not a private holdout");
const digestBuffer = await crypto.subtle.digest("SHA-256", bytes);
const digest = Array.from(new Uint8Array(digestBuffer), (byte) => byte.toString(16).padStart(2, "0")).join("");
const now = Math.floor(Date.now() / 1000);
const token = "ab".repeat(32);
const uploadToken = "cd".repeat(32);
const path = `/v1/clips/${now - 60}/${now + 3600}/${token}/${digest}.mp4`;
const capabilityPath = (marker: string) => `/v1/clips/${now - 60}/${now + 3600}/${marker.repeat(64)}/${digest}.mp4`;
const request = (pathname = path, method = "GET") => new Request(`https://clips.example${pathname}`, { method });

type TestBindings = Env & { UPLOAD_TOKEN: string };

function bindings(secret = uploadToken): TestBindings {
  return new Proxy(env, {
    get(target, property, receiver) {
      return property === "UPLOAD_TOKEN" ? secret : Reflect.get(target, property, receiver);
    },
  }) as TestBindings;
}

function invoke(input: Request, secret = uploadToken) {
  return worker.fetch(input, bindings(secret));
}

function uploadRequest(body: Uint8Array = bytes, pathname = path, secret = uploadToken) {
  return new Request(`https://clips.example${pathname}`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${secret}`,
      "Content-Length": String(body.length),
      "Content-Type": "video/mp4",
    },
    body,
  });
}

async function upload(pathname = path, body: Uint8Array = bytes, checksum = true) {
  await env.CLIPS.put(pathname.slice(1), body, checksum ? { sha256: digestBuffer } : {});
}

describe("private clip delivery", () => {
  it("streams only the selected object with the verified checksum and no cache", async () => {
    await upload();
    const response = await invoke(request());
    expect(response.status).toBe(200);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
    expect(response.headers.get("Content-Length")).toBe(String(bytes.length));
    expect(response.headers.get("Cache-Control")).toBe("no-store, private");
    expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
  });

  it("supports HEAD without a body", async () => {
    await upload();
    const response = await invoke(request(path, "HEAD"));
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("");
  });

  it.each(["POST", "DELETE", "PATCH", "OPTIONS"])("rejects %s", async (method) => {
    await upload();
    expect((await invoke(request(path, method))).status).toBe(404);
  });

  it.each(["/", "/v1/clips", "/labels.json", "/candidate/model.zip", `${path}?download=1`, `${path}/extra`, path.replace(token, "cd".repeat(32)), path.replace(digest, "ef".repeat(32))])("rejects unavailable or malformed path %s", async (pathname) => {
    await upload();
    expect((await invoke(request(pathname))).status).toBe(404);
  });

  it("cannot change the original time window", async () => {
    await upload();
    expect((await invoke(request(path.replace(String(now + 3600), String(now + 7200))))).status).toBe(404);
  });

  it("serves a capability covering a multi-day evaluation window", async () => {
    const pathname = `/v1/clips/${now - 60}/${now + 4 * 24 * 60 * 60}/${token}/${digest}.mp4`;
    await upload(pathname);
    expect((await invoke(request(pathname))).status).toBe(200);
  });

  it.each([[now - 100, now - 1], [now + 60, now + 3600], [now - 60, now + 7 * 24 * 60 * 60], [now + 60, now - 60]])("rejects expired, premature or invalid windows %s %s", async (start, end) => {
    const pathname = `/v1/clips/${start}/${end}/${token}/${digest}.mp4`;
    await upload(pathname);
    expect((await invoke(request(pathname))).status).toBe(404);
  });

  it("rejects objects without a stored SHA256", async () => {
    await upload(path, bytes, false);
    expect((await invoke(request())).status).toBe(404);
  });

  it("rejects a digest that disagrees with the stored checksum", async () => {
    const pathname = path.replace(digest, "ef".repeat(32));
    await upload(pathname);
    expect((await invoke(request(pathname))).status).toBe(404);
  });

  it("never lists other stored objects", async () => {
    await env.CLIPS.put("private/labels.json", "DO NOT SERVE");
    expect((await invoke(request("/private/labels.json"))).status).toBe(404);
    expect((await invoke(request("/?list-type=2"))).status).toBe(404);
  });

  it("preserves immutable objects under conditional creation", async () => {
    await upload();
    const result = await env.CLIPS.put(path.slice(1), "replacement", { onlyIf: new Headers({ "If-None-Match": "*" }) });
    expect(result).toBeNull();
    const response = await invoke(request());
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
  });

  it("stops serving at the exact expiry boundary", async () => {
    await upload();
    const clock = vi.spyOn(Date, "now").mockReturnValue((now + 3600) * 1000);
    try { expect((await invoke(request())).status).toBe(404); }
    finally { clock.mockRestore(); }
  });

  it("rejects cleartext transport", async () => {
    await upload();
    expect((await invoke(new Request(`http://clips.example${path}`))).status).toBe(404);
  });

  it.each([0, 16 * 1024 * 1024 + 1])("rejects a %s-byte object", async (size) => {
    const body = new Uint8Array(size);
    const sha = await crypto.subtle.digest("SHA-256", body);
    const hex = Array.from(new Uint8Array(sha), (byte) => byte.toString(16).padStart(2, "0")).join("");
    const pathname = path.replace(digest, hex);
    await env.CLIPS.put(pathname.slice(1), body, { sha256: sha });
    expect((await invoke(request(pathname))).status).toBe(404);
  });

  it("accepts an authenticated immutable upload and an identical retry", async () => {
    const pathname = capabilityPath("1");
    const created = await invoke(uploadRequest(bytes, pathname));
    expect(created.status).toBe(201);
    expect((await invoke(request(pathname))).status).toBe(200);
    const retry = await invoke(uploadRequest(bytes, pathname));
    expect(retry.status).toBe(200);
  });

  it("hides the upload route without the exact token", async () => {
    const pathname = capabilityPath("2");
    const missing = uploadRequest(bytes, pathname);
    missing.headers.delete("Authorization");
    expect((await invoke(missing)).status).toBe(404);
    expect((await invoke(uploadRequest(bytes, pathname, "ef".repeat(32)))).status).toBe(404);
    expect(await env.CLIPS.head(pathname.slice(1))).toBeNull();
  });

  it("rejects an upload whose bytes disagree with the path digest", async () => {
    const pathname = capabilityPath("3");
    const changed = new Uint8Array(bytes);
    changed[changed.length - 1] = changed[changed.length - 1]! ^ 1;
    expect((await invoke(uploadRequest(changed, pathname))).status).toBe(404);
    expect(await env.CLIPS.head(pathname.slice(1))).toBeNull();
  });

  it("does not overwrite a conflicting object", async () => {
    const pathname = capabilityPath("4");
    const changed = new Uint8Array(bytes);
    changed[changed.length - 1] = changed[changed.length - 1]! ^ 1;
    const changedDigest = await crypto.subtle.digest("SHA-256", changed);
    await env.CLIPS.put(pathname.slice(1), changed, { sha256: changedDigest });
    expect((await invoke(uploadRequest(bytes, pathname))).status).toBe(409);
    const stored = await env.CLIPS.get(pathname.slice(1));
    expect(new Uint8Array(await stored!.arrayBuffer())).toEqual(changed);
  });
});
