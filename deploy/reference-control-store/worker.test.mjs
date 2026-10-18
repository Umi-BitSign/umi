import { createHash } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "./worker.mjs";

const token = "a".repeat(64);
const origin = "https://control.example/";
const prefix = "validator-supervisor/channels/a3ca19a108fe7d1a8e53a2db76f480ebe237b7942595f23135d6e11889ed40c0/linux-amd64/after/";
const approval = "validator-supervisor/translation-reference-policies/" + "b".repeat(64) + ".json";
const sha = (body) => createHash("sha256").update(body).digest("hex");

function fixture() {
  const objects = new Map(), calls = [];
  const env = {
    PUBLICATION_TOKEN: token,
    CONTROL: {
      async get(key) {
        calls.push(["get", key]);
        const value = objects.get(key);
        return value ? { ...value, body: value.raw } : null;
      },
      async head(key) { calls.push(["head", key]); return objects.get(key) ?? null; },
      async put(key, raw, options) {
        calls.push(["put", key]);
        const current = objects.get(key);
        const condition = options.onlyIf;
        if ((condition.get("If-None-Match") === "*" && current) ||
            (condition.has("If-Match") && condition.get("If-Match") !== current?.httpEtag)) return null;
        assert.equal(options.sha256, sha(raw));
        const value = { raw, size: raw.length, customMetadata: options.customMetadata,
          httpEtag: '"' + createHash("md5").update(raw).digest("hex") + '"' };
        objects.set(key, value);
        return value;
      },
    },
  };
  async function call(method, key, body = null, extra = {}) {
    const raw = body === null ? undefined : Buffer.from(body);
    const headers = { Authorization: "Bearer " + token, ...extra };
    if (raw !== undefined && !("Content-Length" in headers)) headers["Content-Length"] = String(raw.length);
    return worker.fetch(new Request(origin + key, { method, headers, body: raw }), env);
  }
  return { env, objects, calls, call };
}

test("conditional create/update refuses stale writers and repeated creates", async () => {
  const f = fixture(), key = prefix + "0/initial.json";
  assert.equal((await f.call("GET", key)).status, 404);
  assert.equal((await f.call("PUT", key, "first", { "If-None-Match": "*" })).status, 200);
  const old = (await f.call("GET", key)).headers.get("ETag");
  assert.equal((await f.call("PUT", key, "second", { "If-Match": old })).status, 200);
  assert.equal((await f.call("PUT", key, "stale", { "If-Match": old })).status, 412);
  assert.equal((await f.call("PUT", key, "replacement", { "If-None-Match": "*" })).status, 412);
  assert.equal(await (await f.call("GET", key)).text(), "second");
});

test("immutable approval requires body checksum and conditional create", async () => {
  const f = fixture(), raw = '{"signed":"synthetic qualification"}';
  const headers = { "If-None-Match": "*", "x-amz-meta-sha256": sha(raw) };
  assert.equal((await f.call("PUT", approval, raw, headers)).status, 200);
  assert.equal((await f.call("HEAD", approval)).headers.get("x-amz-meta-sha256"), sha(raw));
  assert.equal((await f.call("PUT", approval, raw, headers)).status, 412);
  assert.equal((await f.call("PUT", approval, "changed", headers)).status, 422);
  const etag = (await f.call("HEAD", approval)).headers.get("ETag");
  assert.equal((await f.call("PUT", approval, raw, { "If-Match": etag })).status, 428);
});

test("authorization, route and platform refusals occur before R2 access", async () => {
  const f = fixture();
  assert.equal((await f.call("GET", prefix + "0/initial.json", null, { Authorization: "Bearer " + "c".repeat(64) })).status, 401);
  for (const key of ["wallets/key", "validator-supervisor/releases/ab/release.bundle",
    prefix.replace("linux-amd64", "linux-arm64") + "0/initial.json",
    prefix + "00/initial.json", prefix + "0/initial.json?x=1", prefix + "0/%69nitial.json"]) {
    assert.ok([400, 403].includes((await f.call("GET", key)).status));
  }
  assert.equal(f.calls.length, 0);
});

test("no unconditional write, delete or overflow may reach R2", async () => {
  const f = fixture(), key = prefix + "0/initial.json";
  assert.equal((await f.call("PUT", key, "value")).status, 428);
  assert.equal((await f.call("DELETE", key)).status, 405);
  assert.equal((await f.call("PUT", key, "value", { "If-Match": '"' + "a".repeat(32) + '"', "If-None-Match": "*" })).status, 428);
  assert.equal((await f.call("PUT", key, "value", { "If-None-Match": "*", "Content-Length": String(2**22) })).status, 413);
  assert.equal((await f.call("PUT", approval, "value", { "If-None-Match": "*", "Content-Length": String(2**16) })).status, 413);
  assert.equal(f.calls.length, 0);
});

test("response is bounded and carries exact original bytes and metadata", async () => {
  const f = fixture(), key = prefix + "0/initial.json";
  await f.call("PUT", key, "payload", { "If-None-Match": "*" });
  const head = await f.call("HEAD", key);
  assert.equal(head.headers.get("Content-Length"), "7");
  assert.equal(await head.text(), "");
  assert.ok(head.headers.get("Cache-Control").includes("no-store"));
  f.objects.get(key).size = 2**22;
  assert.equal((await f.call("GET", key)).status, 422);
});
