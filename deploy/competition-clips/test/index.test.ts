import { env } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";
import worker from "../src/index";

const bytes = new TextEncoder().encode("exposed synthetic clip, not a private holdout");
const digestBuffer = await crypto.subtle.digest("SHA-256", bytes);
const digest = Array.from(new Uint8Array(digestBuffer), (byte) => byte.toString(16).padStart(2, "0")).join("");
const now = Math.floor(Date.now() / 1000);
const token = "ab".repeat(32);
const path = `/v1/clips/${now - 60}/${now + 3600}/${token}/${digest}.mp4`;
const request = (pathname = path, method = "GET") => new Request(`https://clips.example${pathname}`, { method });

async function upload(pathname = path, body: Uint8Array = bytes, checksum = true) {
  await env.CLIPS.put(pathname.slice(1), body, checksum ? { sha256: digestBuffer } : {});
}

describe("private clip delivery", () => {
  it("streams only the selected object with the verified checksum and no cache", async () => {
    await upload();
    const response = await worker.fetch(request(), env);
    expect(response.status).toBe(200);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
    expect(response.headers.get("Content-Length")).toBe(String(bytes.length));
    expect(response.headers.get("Cache-Control")).toBe("no-store, private");
    expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
  });

  it("supports HEAD without a body", async () => {
    await upload();
    const response = await worker.fetch(request(path, "HEAD"), env);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("");
  });

  it.each(["POST", "PUT", "DELETE", "PATCH", "OPTIONS"])("rejects %s", async (method) => {
    await upload();
    expect((await worker.fetch(request(path, method), env)).status).toBe(404);
  });

  it.each(["/", "/v1/clips", "/labels.json", "/candidate/model.zip", `${path}?download=1`, `${path}/extra`, path.replace(token, "cd".repeat(32)), path.replace(digest, "ef".repeat(32))])("rejects unavailable or malformed path %s", async (pathname) => {
    await upload();
    expect((await worker.fetch(request(pathname), env)).status).toBe(404);
  });

  it("cannot change the original time window", async () => {
    await upload();
    expect((await worker.fetch(request(path.replace(String(now + 3600), String(now + 7200))), env)).status).toBe(404);
  });

  it.each([[now - 100, now - 1], [now + 60, now + 3600], [now - 60, now + 86400], [now + 60, now - 60]])("rejects expired, premature or invalid windows %s %s", async (start, end) => {
    const pathname = `/v1/clips/${start}/${end}/${token}/${digest}.mp4`;
    await upload(pathname);
    expect((await worker.fetch(request(pathname), env)).status).toBe(404);
  });

  it("rejects objects without a stored SHA256", async () => {
    await upload(path, bytes, false);
    expect((await worker.fetch(request(), env)).status).toBe(404);
  });

  it("rejects a digest that disagrees with the stored checksum", async () => {
    const pathname = path.replace(digest, "ef".repeat(32));
    await upload(pathname);
    expect((await worker.fetch(request(pathname), env)).status).toBe(404);
  });

  it("never lists other stored objects", async () => {
    await env.CLIPS.put("private/labels.json", "DO NOT SERVE");
    expect((await worker.fetch(request("/private/labels.json"), env)).status).toBe(404);
    expect((await worker.fetch(request("/?list-type=2"), env)).status).toBe(404);
  });

  it("preserves immutable objects under conditional creation", async () => {
    await upload();
    const result = await env.CLIPS.put(path.slice(1), "replacement", { onlyIf: new Headers({ "If-None-Match": "*" }) });
    expect(result).toBeNull();
    const response = await worker.fetch(request(), env);
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(bytes);
  });

  it("stops serving at the exact expiry boundary", async () => {
    await upload();
    const clock = vi.spyOn(Date, "now").mockReturnValue((now + 3600) * 1000);
    try { expect((await worker.fetch(request(), env)).status).toBe(404); }
    finally { clock.mockRestore(); }
  });

  it("rejects cleartext transport", async () => {
    await upload();
    expect((await worker.fetch(new Request(`http://clips.example${path}`), env)).status).toBe(404);
  });

  it.each([0, 16 * 1024 * 1024 + 1])("rejects a %s-byte object", async (size) => {
    const body = new Uint8Array(size);
    const sha = await crypto.subtle.digest("SHA-256", body);
    const hex = Array.from(new Uint8Array(sha), (byte) => byte.toString(16).padStart(2, "0")).join("");
    const pathname = path.replace(digest, hex);
    await env.CLIPS.put(pathname.slice(1), body, { sha256: sha });
    expect((await worker.fetch(request(pathname), env)).status).toBe(404);
  });
});
