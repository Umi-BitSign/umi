// Administrative upload only. Never import this module into the public Worker.
import assert from "node:assert/strict";
import { constants } from "node:fs";
import { open, lstat } from "node:fs/promises";
import { createHash, randomBytes } from "node:crypto";
import { dirname, isAbsolute } from "node:path";

const REQUEST_TIMEOUT_MS = 120_000;

async function privateRead(path, maximum) {
  assert(isAbsolute(path));
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    assert(stat.isFile() && stat.size > 0 && stat.size <= maximum);
    assert.equal(stat.uid, process.getuid());
    assert.equal(stat.mode & 0o077, 0);
    const body = await handle.readFile();
    assert.equal(body.length, stat.size);
    return body;
  } finally { await handle.close(); }
}

async function main() {
  const [input, output, originText, tokenPath] = process.argv.slice(2);
  assert.equal(process.argv.length, 6);
  assert(isAbsolute(input) && isAbsolute(output) && isAbsolute(tokenPath));
  const uploadToken = (await privateRead(tokenPath, 256)).toString("utf8").trim();
  assert(/^[0-9a-f]{64}$/.test(uploadToken));
  const origin = new URL(originText);
  assert(origin.protocol === "https:" && origin.href === `${origin.origin}/`);
  assert(!origin.username && !origin.password && !origin.port);
  const parent = await lstat(dirname(output));
  assert(parent.isDirectory() && parent.uid === process.getuid() && (parent.mode & 0o077) === 0);
  const inputBytes = await privateRead(input, 128 * 1024);
  const manifest = JSON.parse(inputBytes);
  assert.deepEqual(Object.keys(manifest).sort(), ["expires_unix", "not_before_unix", "schema", "videos"]);
  assert.equal(manifest.schema, "umi-selected-clip-upload/1");
  const { not_before_unix: start, expires_unix: end } = manifest;
  assert(Number.isSafeInteger(start) && Number.isSafeInteger(end));
  assert(start >= 1e9 && end < 1e10 && end > start && end - start <= 7 * 24 * 60 * 60);
  assert(end > Math.floor(Date.now() / 1000));
  assert(Array.isArray(manifest.videos) && manifest.videos.length >= 1 && manifest.videos.length <= 64);
  const seen = new Set();
  const prepared = [];
  for (const video of manifest.videos) {
    assert.deepEqual(Object.keys(video).sort(), ["path", "sha256"]);
    assert(/^[0-9a-f]{64}$/.test(video.sha256) && !seen.has(video.sha256));
    seen.add(video.sha256);
    const body = await privateRead(video.path, 16 * 1024 * 1024);
    assert.equal(createHash("sha256").update(body).digest("hex"), video.sha256);
    assert.equal(body.subarray(4, 8).toString("ascii"), "ftyp");
    // Keep only a verified path, not up to 64 videos in memory.
    prepared.push({ path: video.path, sha256: video.sha256, bytes: body.length });
  }
  const inputSha = createHash("sha256").update(inputBytes).digest("hex");
  let receipt;
  try { receipt = JSON.parse(await privateRead(output, 128 * 1024)); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
  if (!receipt) {
    receipt = {
      schema: "umi-selected-clip-delivery/1", input_sha256: inputSha,
      not_before_unix: start, expires_unix: end,
      videos: prepared.map(({ sha256, bytes }) => ({
        sha256, bytes,
        url: `${origin.origin}/v1/clips/${start}/${end}/${randomBytes(32).toString("hex")}/${sha256}.mp4`,
      })),
    };
    // Retain capabilities before uploading; a retry never mints a new window.
    const file = await open(output, "wx", 0o600);
    try { await file.writeFile(JSON.stringify(receipt)); await file.sync(); }
    finally { await file.close(); }
  }
  assert.equal(receipt.schema, "umi-selected-clip-delivery/1");
  assert.equal(receipt.input_sha256, inputSha);
  assert.equal(receipt.not_before_unix, start);
  assert.equal(receipt.expires_unix, end);
  assert.equal(receipt.videos.length, prepared.length);
  for (const [i, video] of prepared.entries()) {
    const item = receipt.videos[i];
    assert(item.sha256 === video.sha256 && item.bytes === video.bytes);
    const url = new URL(item.url);
    assert.equal(url.origin, origin.origin);
    assert.equal(item.url, `${origin.origin}${url.pathname}`);
    assert(new RegExp(`^/v1/clips/${start}/${end}/[0-9a-f]{64}/${video.sha256}[.]mp4$`).test(url.pathname));
  }
  for (const [i, video] of prepared.entries()) {
    const body = await privateRead(video.path, 16 * 1024 * 1024);
    assert.equal(body.length, video.bytes);
    assert.equal(createHash("sha256").update(body).digest("hex"), video.sha256);
    const url = receipt.videos[i].url;
    const uploaded = await fetch(url, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${uploadToken}`,
        "Content-Type": "video/mp4",
        "Content-Length": String(body.length),
      },
      body,
      redirect: "error",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    assert([200, 201].includes(uploaded.status));
    await uploaded.body?.cancel();

    const stored = await fetch(url, {
      headers: { Accept: "video/mp4" },
      redirect: "error",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    assert.equal(stored.status, 200);
    assert.equal(Number(stored.headers.get("Content-Length")), video.bytes);
    assert(stored.body);
    const hash = createHash("sha256");
    let total = 0;
    for await (const chunk of stored.body) {
      total += chunk.length;
      assert(total <= video.bytes);
      hash.update(chunk);
    }
    assert(total === video.bytes && hash.digest("hex") === video.sha256);
  }
  console.log(JSON.stringify({ status: "selected_clips_uploaded_and_verified", count: prepared.length }));
}

main().catch(() => {
  console.error(JSON.stringify({ status: "blocked", reason_code: "selected_clip_upload_failed" }));
  process.exitCode = 1;
});
