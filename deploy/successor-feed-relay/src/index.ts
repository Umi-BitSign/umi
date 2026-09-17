/** Copy one retained v4 directive per tick. No signing or public upload route. */
import canonicalize from "canonicalize";
const MiB = 1024 * 1024;
const HEX = /^[0-9a-f]{64}$/;
const CURSOR = /^(3|4)\/([1-9][0-9]{0,15})\/([0-9a-f]{64})$/;
const PAGE = "umi-validator-supervisor-directive-page/4";
const encoder = new TextEncoder();
const payloadLimits = {
  "cutoff-certificate.json": 512 * MiB,
  "evidence.json": 512 * MiB,
  "policy.json": 2 * MiB,
  "release-identity.json": 65536,
  "replay-limits.json": 65536,
  "roster.json": 512 * MiB,
  "settlement-certificate.json": 512 * MiB,
  "settlement.json": 512 * MiB,
} as const;
type RecordValue = Record<string, unknown>;
type Cursor = { version: number; sequence: number; hash: string };
type Signed = { raw: RecordValue; directive: RecordValue; cursor: Cursor };
type Config = {
  prefix: string;
  source: string;
  initial: Cursor;
  binding: string;
};

function requireValue(condition: unknown): asserts condition {
  if (!condition) throw new Error("successor_relay_validation_failed");
}
function record(value: unknown): RecordValue {
  requireValue(
    value !== null && typeof value === "object" && !Array.isArray(value),
  );
  return value as RecordValue;
}
function integer(value: unknown, maximum = Number.MAX_SAFE_INTEGER): number {
  requireValue(
    typeof value === "number" &&
      Number.isSafeInteger(value) &&
      value > 0 &&
      value <= maximum,
  );
  return value;
}
function hash(value: unknown): string {
  requireValue(typeof value === "string" && HEX.test(value));
  return value;
}
function cursor(value: string): Cursor {
  const match = CURSOR.exec(value);
  requireValue(match);
  return {
    version: Number(match[1]),
    sequence: integer(Number(match[2])),
    hash: hash(match[3]),
  };
}
function cursorText(value: Cursor): string {
  return `${value.version}/${value.sequence}/${value.hash}`;
}
function sameCursor(left: Cursor, right: Cursor): boolean {
  return cursorText(left) === cursorText(right);
}
function hex(value: ArrayBuffer): string {
  return Array.from(new Uint8Array(value), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}
async function sha(value: Uint8Array): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", new Uint8Array(value)));
}
function canonical(value: unknown): Uint8Array<ArrayBuffer> {
  const text = canonicalize(value);
  requireValue(typeof text === "string");
  return new Uint8Array(encoder.encode(text));
}
function parse(body: Uint8Array): unknown {
  const text = new TextDecoder("utf-8", {
    fatal: true,
    ignoreBOM: true,
  }).decode(body);
  const value: unknown = JSON.parse(text);
  requireValue(canonicalize(value) === text); // Reject duplicate keys and noncanonical bytes.
  return value;
}

async function configuration(env: Env): Promise<Config> {
  const origin = new URL(env.SOURCE_ORIGIN);
  requireValue(
    origin.protocol === "https:" &&
      origin.origin === env.SOURCE_ORIGIN &&
      !origin.username &&
      !origin.password,
  );
  requireValue(
    env.PLATFORM === "linux-amd64" || env.PLATFORM === "linux-arm64",
  );
  const prefix = `validator-supervisor/channels/${hash(env.CHANNEL_ID)}/${env.PLATFORM}/successor/`;
  const initial = cursor(env.INITIAL_CURSOR);
  requireValue(initial.version === 3);
  const source = `${origin.origin}/${prefix}`;
  const binding = await sha(
    encoder.encode(JSON.stringify([source, prefix, cursorText(initial)])),
  );
  return { prefix, source, initial, binding };
}

async function response(config: Config, route: string): Promise<Response> {
  // All routes are constructed below from parsed hashes and fixed filenames.
  const result = await fetch(config.source + route, {
    redirect: "manual",
    signal: AbortSignal.timeout(60_000),
    headers: { Accept: "application/json", "Accept-Encoding": "identity" },
  });
  if (result.status !== 200 || result.headers.has("Content-Encoding")) {
    await result.body?.cancel();
    throw new Error("successor_relay_source_unavailable");
  }
  return result;
}

async function bounded(
  body: ReadableStream<Uint8Array> | null,
  maximum: number,
): Promise<Uint8Array<ArrayBuffer>> {
  requireValue(body);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      requireValue(size <= maximum);
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}
async function document(
  config: Config,
  route: string,
  maximum = MiB,
): Promise<Uint8Array<ArrayBuffer>> {
  const result = await response(config, route);
  return bounded(result.body, maximum);
}

function signed(value: unknown, env: Env): Signed {
  const raw = record(value),
    directive = record(raw.directive);
  requireValue(raw.schema === "umi-validator-supervisor-signed-directive/4");
  requireValue(
    directive.schema === "umi-validator-supervisor-directive/4" &&
      directive.channel_id === env.CHANNEL_ID,
  );
  requireValue(
    directive.mode === "hold" ||
      directive.mode === "competition_replay" ||
      directive.mode === "competition_weights",
  );
  requireValue(
    Array.isArray(raw.signatures) &&
      raw.signatures.length > 0 &&
      raw.signatures.length <= 64,
  );
  return {
    raw,
    directive,
    cursor: {
      version: 4,
      sequence: integer(directive.sequence),
      hash: hash(raw.directive_sha256),
    },
  };
}
async function page(
  body: Uint8Array,
  after: Cursor,
  env: Env,
): Promise<{ items: Signed[]; head: Signed }> {
  const value = record(parse(body));
  requireValue(
    value.schema === PAGE &&
      value.after_version === after.version &&
      value.after_sequence === after.sequence &&
      value.after_directive_sha256 === after.hash,
  );
  requireValue(
    Array.isArray(value.directives) &&
      value.directives.length <= 16 &&
      typeof value.more === "boolean",
  );
  const items = value.directives.map((item) => signed(item, env));
  const head = signed(value.head, env);
  let previous = after;
  for (const item of items) {
    requireValue((await sha(canonical(item.directive))) === item.cursor.hash);
    requireValue(
      item.cursor.sequence === previous.sequence + 1 &&
        item.directive.predecessor_version === previous.version &&
        item.directive.previous_directive_sha256 === previous.hash,
    );
    previous = item.cursor;
  }
  requireValue(sameCursor(head.cursor, previous));
  if (!items.length) {
    requireValue(after.version === 4 && value.more === false);
    requireValue((await sha(canonical(head.directive))) === head.cursor.hash);
  } else
    requireValue(
      JSON.stringify(items[items.length - 1]?.raw) === JSON.stringify(head.raw),
    );
  return { items, head };
}

function relayPage(
  after: Cursor,
  item: Signed,
  empty: boolean,
): Uint8Array<ArrayBuffer> {
  // Pagination envelopes are unsigned protocol data. Signed objects remain
  // canonical and unchanged. The empty tail is installed before its inbound link.
  return canonical({
    schema: PAGE,
    after_version: after.version,
    after_sequence: after.sequence,
    after_directive_sha256: after.hash,
    directives: empty ? [] : [item.raw],
    more: !empty,
    head: item.raw,
  });
}

function verifiedObject(
  object: R2Object | null,
  size: number,
  digest: string,
): void {
  requireValue(
    object &&
      object.size === size &&
      object.checksums.sha256 &&
      hex(object.checksums.sha256) === digest,
  );
}
async function putBytes(
  env: Env,
  key: string,
  body: Uint8Array<ArrayBuffer>,
): Promise<void> {
  const digest = await sha(body);
  const existing = await env.FEED.head(key);
  if (!existing) {
    await env.FEED.put(key, body, {
      sha256: digest,
      onlyIf: new Headers({ "If-None-Match": "*" }),
      httpMetadata: {
        contentType: "application/json",
        cacheControl: "public, max-age=31536000, immutable",
      },
    });
  }
  verifiedObject(await env.FEED.head(key), body.byteLength, digest);
}
async function copyFile(
  env: Env,
  config: Config,
  route: string,
  size: number,
  digest: string,
): Promise<void> {
  const key = config.prefix + route;
  const existing = await env.FEED.head(key);
  if (existing) {
    verifiedObject(existing, size, digest);
    return;
  }
  const upstream = await response(config, route);
  if (
    upstream.headers.get("Content-Length") !== String(size) ||
    !upstream.body
  ) {
    await upstream.body?.cancel();
    throw new Error("successor_relay_length_mismatch");
  }
  // FixedLengthStream bounds bytes even when an upstream lies about its length.
  // R2 verifies SHA-256 before making the conditional create visible.
  const stream = new FixedLengthStream(size);
  const stop = new AbortController();
  const pipe = upstream.body.pipeTo(stream.writable, { signal: stop.signal });
  const put = env.FEED.put(key, stream.readable, {
    sha256: digest,
    onlyIf: new Headers({ "If-None-Match": "*" }),
    httpMetadata: {
      contentType: "application/json",
      cacheControl: "public, max-age=31536000, immutable",
    },
  }).then(
    (value) => {
      if (!value) stop.abort();
      return value;
    },
    (error: unknown) => {
      stop.abort();
      throw error;
    },
  );
  const results = await Promise.allSettled([pipe, put]);
  if (results[1]?.status === "rejected")
    throw new Error("successor_relay_upload_failed");
  verifiedObject(await env.FEED.head(key), size, digest);
}

async function dependencies(
  env: Env,
  config: Config,
  item: Signed,
): Promise<void> {
  const directive = item.directive;
  if (directive.mode === "hold") return;
  const target = record(directive.replay_package),
    limits = record(target.limits);
  const root = `packages/${hash(target.package_sha256)}/`;
  const body = await document(
    config,
    root + "manifest.json",
    integer(limits.maximum_manifest_bytes, 256 * 1024),
  );
  requireValue((await sha(body)) === hash(target.manifest_sha256));
  const domain = encoder.encode("umi-competition-replay-package-v1\0");
  const packageBytes = new Uint8Array(domain.length + body.length);
  packageBytes.set(domain);
  packageBytes.set(body, domain.length);
  requireValue((await sha(packageBytes)) === target.package_sha256);
  const manifest = record(parse(body));
  requireValue(
    manifest.schema === "umi-competition-replay-package-manifest/1" &&
      manifest.profile === "competition_publication_replay_no_weight/1",
  );
  requireValue(Array.isArray(manifest.files) && manifest.files.length === 8);
  const files = manifest.files.map(record);
  let total = body.length;
  for (const [index, name] of Object.keys(payloadLimits).entries()) {
    const file = files[index];
    requireValue(file && file.name === name);
    const maximum = payloadLimits[name as keyof typeof payloadLimits];
    const limitName =
      "maximum_" + name.slice(0, -5).replaceAll("-", "_") + "_bytes";
    const size = integer(file.size_bytes, integer(limits[limitName], maximum));
    total += size;
    requireValue(total <= integer(limits.maximum_aggregate_bytes, 2048 * MiB));
    hash(file.sha256);
  }
  for (const file of files)
    await copyFile(
      env,
      config,
      root + String(file.name),
      integer(file.size_bytes),
      hash(file.sha256),
    );
  await putBytes(env, config.prefix + root + "manifest.json", body);
  if (directive.mode === "competition_weights") {
    const auth = record(directive.chain_authorization);
    await copyFile(
      env,
      config,
      `authorizations/${hash(auth.signed_authorization_sha256)}.json`,
      integer(auth.authorization_size_bytes, 4 * MiB),
      hash(auth.signed_authorization_sha256),
    );
  }
  const route = `directives/${item.cursor.hash}/execution.json`;
  await putBytes(env, config.prefix + route, await document(config, route));
}

async function publishPage(
  env: Env,
  key: string,
  body: Uint8Array<ArrayBuffer>,
  head: Cursor,
): Promise<void> {
  const existing = await env.FEED.head(key),
    digest = await sha(body);
  if (existing) {
    const previous = cursor(String(existing.customMetadata?.head));
    if (previous.sequence > head.sequence) return;
    if (previous.sequence === head.sequence) {
      requireValue(sameCursor(previous, head));
      verifiedObject(existing, body.length, digest);
      return;
    }
  }
  const updated = await env.FEED.put(key, body, {
    sha256: digest,
    onlyIf: new Headers(
      existing ? { "If-Match": existing.httpEtag } : { "If-None-Match": "*" },
    ),
    customMetadata: { head: cursorText(head) },
    httpMetadata: { contentType: "application/json", cacheControl: "no-store" },
  });
  requireValue(updated); // A concurrent tick retries from its durable checkpoint.
}

export async function tick(env: Env): Promise<string> {
  if (env.ENABLED !== "true") return "disabled";
  const config = await configuration(env);
  const checkpointKey = config.prefix + "relay/checkpoint.json";
  const checkpoint = await env.FEED.get(checkpointKey);
  let after = config.initial;
  if (checkpoint) {
    requireValue(checkpoint.size <= 4096);
    const stored = record(parse(await bounded(checkpoint.body, 4096)));
    requireValue(
      stored.schema === "umi-successor-r2-checkpoint/1" &&
        stored.binding === config.binding &&
        typeof stored.cursor === "string",
    );
    after = cursor(stored.cursor);
    requireValue(
      after.version === 4 && after.sequence > config.initial.sequence,
    );
  }
  const route = `after/${cursorText(after)}.json`;
  const upstream = await document(config, route);
  const current = await page(upstream, after, env),
    first = current.items[0];
  if (!first) {
    await publishPage(env, config.prefix + route, upstream, after);
    return "caught_up";
  }
  // The immutable per-directive page is copied byte-for-byte. Cursor pages
  // link forward to an explicit empty tail so initial history does not stop early.
  const exactRoute = `directives/${first.cursor.hash}/page.json`;
  const exact = await document(config, exactRoute);
  const checked = await page(exact, after, env);
  requireValue(
    checked.items.length === 1 &&
      JSON.stringify(checked.head.raw) === JSON.stringify(first.raw),
  );
  await dependencies(env, config, first);
  await putBytes(env, config.prefix + exactRoute, exact);
  await publishPage(
    env,
    config.prefix + `after/${cursorText(first.cursor)}.json`,
    relayPage(first.cursor, first, true),
    first.cursor,
  );
  await publishPage(
    env,
    config.prefix + route,
    relayPage(after, first, false),
    first.cursor,
  );
  const bytes = canonical({
    schema: "umi-successor-r2-checkpoint/1",
    binding: config.binding,
    cursor: cursorText(first.cursor),
  });
  const updated = await env.FEED.put(checkpointKey, bytes, {
    sha256: await sha(bytes),
    onlyIf: new Headers(
      checkpoint
        ? { "If-Match": checkpoint.httpEtag }
        : { "If-None-Match": "*" },
    ),
    httpMetadata: { contentType: "application/json", cacheControl: "no-store" },
  });
  requireValue(updated);
  return "advanced";
}

export default {
  async fetch(): Promise<Response> {
    return new Response(null, { status: 404 });
  },
  async scheduled(_event: ScheduledController, env: Env): Promise<void> {
    try {
      console.log(
        JSON.stringify({
          event: "successor_feed_relay",
          status: await tick(env),
        }),
      );
    } catch {
      console.error(
        JSON.stringify({ event: "successor_feed_relay", status: "failed" }),
      );
      throw new Error("successor_feed_relay_failed");
    }
  },
} satisfies ExportedHandler<Env>;
