import { env } from "cloudflare:test";
import canonicalize from "canonicalize";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker, { tick } from "../src/index";

// Synthetic protocol-shaped transport data, not production authority signatures.
// The Python feed and each validator independently verify real signatures.
const encoder = new TextEncoder();
const bytes = (value: unknown) =>
  new Uint8Array(encoder.encode(canonicalize(value)));
const sha = async (value: Uint8Array) =>
  Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new Uint8Array(value)),
    ),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
const initial = "3/19/" + "ab".repeat(32);
const channel = "cd".repeat(32);
const config: Env = {
  ...env,
  ENABLED: "true",
  SOURCE_ORIGIN: "https://source.example",
  CHANNEL_ID: channel,
  PLATFORM: "linux-amd64",
  INITIAL_CURSOR: initial,
};
const prefix = `validator-supervisor/channels/${channel}/linux-amd64/successor/`;
const base = `https://source.example/${prefix}`;
const payloadNames = [
  "cutoff-certificate.json",
  "evidence.json",
  "policy.json",
  "release-identity.json",
  "replay-limits.json",
  "roster.json",
  "settlement-certificate.json",
  "settlement.json",
];
const limits = Object.fromEntries(
  payloadNames.map((name) => [
    "maximum_" + name.slice(0, -5).replaceAll("-", "_") + "_bytes",
    65536,
  ]),
);

async function fixture(mode = "competition_weights") {
  const payloads = payloadNames.map((name) => ({
    name,
    bytes: bytes({ name, exposed_fixture: true }),
  }));
  const manifest = bytes({
    schema: "umi-competition-replay-package-manifest/1",
    profile: "competition_publication_replay_no_weight/1",
    files: await Promise.all(
      payloads.map(async (file) => ({
        name: file.name,
        size_bytes: file.bytes.length,
        sha256: await sha(file.bytes),
      })),
    ),
  });
  const domain = encoder.encode("umi-competition-replay-package-v1\0");
  const joined = new Uint8Array(domain.length + manifest.length);
  joined.set(domain);
  joined.set(manifest, domain.length);
  const packageHash = await sha(joined),
    manifestHash = await sha(manifest);
  const auth = bytes({
    schema: "synthetic-authorization",
    signature: "fixture-only",
  });
  const authHash = await sha(auth);
  const directive = {
    schema: "umi-validator-supervisor-directive/4",
    channel_id: channel,
    sequence: 20,
    predecessor_version: 3,
    previous_directive_sha256: "ab".repeat(32),
    mode,
    replay_package: {
      package_sha256: packageHash,
      manifest_sha256: manifestHash,
      limits: {
        ...limits,
        maximum_manifest_bytes: 65536,
        maximum_aggregate_bytes: 1024 * 1024,
      },
    },
    chain_authorization: {
      signed_authorization_sha256: authHash,
      authorization_size_bytes: auth.length,
    },
  };
  const signed = {
    schema: "umi-validator-supervisor-signed-directive/4",
    directive,
    directive_sha256: await sha(bytes(directive)),
    signatures: [{ signature: "fixture-only" }],
  };
  const page = {
    schema: "umi-validator-supervisor-directive-page/4",
    after_version: 3,
    after_sequence: 19,
    after_directive_sha256: "ab".repeat(32),
    directives: [signed],
    more: false,
    head: signed,
  };
  const exactRoute = `directives/${signed.directive_sha256}/page.json`;
  const afterRoute = `after/${initial}.json`;
  const nextCursor = `4/20/${signed.directive_sha256}`;
  const objects = new Map<string, Uint8Array>([
    [afterRoute, bytes(page)],
    [exactRoute, bytes(page)],
    [`packages/${packageHash}/manifest.json`, manifest],
    [`authorizations/${authHash}.json`, auth],
    [
      `directives/${signed.directive_sha256}/execution.json`,
      bytes({ execution: "fixture" }),
    ],
    [
      `after/${nextCursor}.json`,
      bytes({
        ...page,
        after_version: 4,
        after_sequence: 20,
        after_directive_sha256: signed.directive_sha256,
        directives: [],
      }),
    ],
    ...payloads.map((file): [string, Uint8Array] => [
      `packages/${packageHash}/${file.name}`,
      file.bytes,
    ]),
  ]);
  return {
    objects,
    page,
    signed,
    exactRoute,
    afterRoute,
    nextCursor,
    packageHash,
    payloads,
  };
}

function source(
  objects: Map<string, Uint8Array>,
  override?: (route: string, value: Uint8Array) => Response | undefined,
) {
  const requests: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init: RequestInit) => {
      expect(url.startsWith(base)).toBe(true);
      expect(init.redirect).toBe("manual");
      expect(init.signal).toBeDefined();
      const route = url.slice(base.length);
      requests.push(route);
      const value = objects.get(route);
      if (!value) return new Response(null, { status: 404 });
      return (
        override?.(route, value) ??
        new Response(new Uint8Array(value), {
          headers: {
            "Content-Type": "application/json",
            "Content-Length": String(value.length),
          },
        })
      );
    }),
  );
  return requests;
}

async function append(f: Awaited<ReturnType<typeof fixture>>) {
  const next = structuredClone(f.signed);
  next.directive.sequence++;
  next.directive.predecessor_version = 4;
  next.directive.previous_directive_sha256 = f.signed.directive_sha256;
  next.directive_sha256 = await sha(bytes(next.directive));
  const nextPage = {
    ...f.page,
    after_version: 4,
    after_sequence: 20,
    after_directive_sha256: f.signed.directive_sha256,
    directives: [next],
    head: next,
  };
  f.objects.set(`after/${f.nextCursor}.json`, bytes(nextPage));
  f.objects.set(
    `directives/${next.directive_sha256}/page.json`,
    bytes(nextPage),
  );
  f.objects.set(
    `directives/${next.directive_sha256}/execution.json`,
    bytes({ execution: "fixture" }),
  );
  const end = `4/21/${next.directive_sha256}`;
  f.objects.set(
    `after/${end}.json`,
    bytes({
      ...nextPage,
      after_sequence: 21,
      after_directive_sha256: next.directive_sha256,
      directives: [],
    }),
  );
  return { next, nextPage, end };
}

beforeEach(async () => {
  // The current plugin keeps local R2 storage between tests. No remote binding.
  const objects = await env.FEED.list({ limit: 128 });
  expect(objects.truncated).toBe(false);
  if (objects.objects.length)
    await env.FEED.delete(objects.objects.map((item) => item.key));
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("successor R2 relay", () => {
  it("defaults to disabled and has no public upload or trigger route", async () => {
    expect(await tick(env)).toBe("disabled");
    expect((await worker.fetch()).status).toBe(404);
    expect((await env.FEED.list()).objects).toHaveLength(0);
  });

  it("copies all referenced bytes before publishing a cursor and survives restart", async () => {
    const f = await fixture();
    source(f.objects);
    const originalPut = env.FEED.put.bind(env.FEED);
    const writes: string[] = [];
    vi.spyOn(env.FEED, "put").mockImplementation(
      async (...args: Parameters<typeof env.FEED.put>) => {
        writes.push(args[0]);
        return originalPut(...args);
      },
    );
    expect(await tick(config)).toBe("advanced");
    const cursorIndex = writes.indexOf(prefix + f.afterRoute);
    expect(cursorIndex).toBe(13);
    expect(writes.at(-1)).toBe(prefix + "relay/checkpoint.json");
    for (const [route, expected] of f.objects) {
      const stored = await env.FEED.get(prefix + route);
      expect(stored).not.toBeNull();
      expect(new Uint8Array(await stored!.arrayBuffer())).toEqual(
        route === f.afterRoute ? bytes({ ...f.page, more: true }) : expected,
      );
    }
    expect(await tick({ ...config })).toBe("caught_up");
    expect(await tick({ ...config })).toBe("caught_up");
    expect(
      (await env.FEED.head(prefix + `after/${f.nextCursor}.json`))?.httpMetadata
        ?.cacheControl,
    ).toBe("no-store");
  });

  it("recovers interrupted dependency copying without a cursor or duplicate objects", async () => {
    const f = await fixture(),
      missing = `packages/${f.packageHash}/policy.json`;
    const retained = f.objects.get(missing)!;
    f.objects.delete(missing);
    source(f.objects);
    await expect(tick(config)).rejects.toThrow();
    expect(await env.FEED.head(prefix + f.afterRoute)).toBeNull();
    expect(await env.FEED.head(prefix + "relay/checkpoint.json")).toBeNull();
    const old = await env.FEED.head(
      prefix + `packages/${f.packageHash}/evidence.json`,
    );
    expect(old).not.toBeNull();
    f.objects.set(missing, retained);
    const requests = source(f.objects);
    expect(await tick(config)).toBe("advanced");
    expect(requests).not.toContain(`packages/${f.packageHash}/evidence.json`);
    expect((await env.FEED.head(old!.key))?.version).toBe(old?.version);
  });

  it("recovers a lost checkpoint write after cursor publication", async () => {
    const f = await fixture();
    source(f.objects);
    const originalPut = env.FEED.put.bind(env.FEED);
    const spy = vi
      .spyOn(env.FEED, "put")
      .mockImplementation(async (...args: Parameters<typeof env.FEED.put>) => {
        if (args[0].endsWith("relay/checkpoint.json"))
          throw new Error("interrupted");
        return originalPut(...args);
      });
    await expect(tick(config)).rejects.toThrow();
    expect(await env.FEED.head(prefix + f.afterRoute)).not.toBeNull();
    expect(await env.FEED.head(prefix + "relay/checkpoint.json")).toBeNull();
    spy.mockRestore();
    expect(await tick(config)).toBe("advanced");
  });

  it("handles overlapping ticks without replacing immutable bytes", async () => {
    const f = await fixture();
    source(f.objects);
    const results = await Promise.allSettled([tick(config), tick(config)]);
    expect(results.some((result) => result.status === "fulfilled")).toBe(true);
    expect(await tick(config)).toBe("caught_up");
    const copied = await env.FEED.get(prefix + f.exactRoute);
    expect(new Uint8Array(await copied!.arrayBuffer())).toEqual(
      f.objects.get(f.exactRoute),
    );
  });

  it("copies a multi-item source page one unchanged hop per tick", async () => {
    const f = await fixture(),
      next = await append(f);
    f.objects.set(
      f.afterRoute,
      bytes({ ...f.page, directives: [f.signed, next.next], head: next.next }),
    );
    source(f.objects);
    expect(await tick(config)).toBe("advanced");
    expect(
      await env.FEED.head(
        prefix + `directives/${next.next.directive_sha256}/page.json`,
      ),
    ).toBeNull();
    expect(
      new Uint8Array(
        await (await env.FEED.get(prefix + f.afterRoute))!.arrayBuffer(),
      ),
    ).toEqual(bytes({ ...f.page, more: true }));
    expect(await tick(config)).toBe("advanced");
    expect(await tick(config)).toBe("caught_up");
    expect(
      await (await env.FEED.get(prefix + `after/${f.nextCursor}.json`))!.json(),
    ).toEqual({ ...next.nextPage, more: true });
  });

  it("does not let a delayed empty-head response overwrite a newer cursor page", async () => {
    const f = await fixture();
    source(f.objects);
    await tick(config);
    const oldEmpty = f.objects.get(`after/${f.nextCursor}.json`)!;
    let resume: (() => void) | undefined;
    const paused = new Promise<void>((resolve) => {
      resume = resolve;
    });
    let arrived: (() => void) | undefined;
    const arrival = new Promise<void>((resolve) => {
      arrived = resolve;
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        arrived!();
        await paused;
        return new Response(new Uint8Array(oldEmpty));
      }),
    );
    const delayed = tick(config);
    await arrival;
    const next = await append(f);
    source(f.objects);
    expect(await tick(config)).toBe("advanced");
    resume!();
    expect(await delayed).toBe("caught_up");
    expect(
      await (await env.FEED.get(prefix + `after/${f.nextCursor}.json`))!.json(),
    ).toEqual({ ...next.nextPage, more: true });
    expect(await tick(config)).toBe("caught_up");
  });

  it("does not move the checkpoint backwards when an older tick finishes late", async () => {
    const f = await fixture();
    source(f.objects);
    const originalPut = env.FEED.put.bind(env.FEED);
    let resume: (() => void) | undefined;
    const paused = new Promise<void>((resolve) => {
      resume = resolve;
    });
    let arrived: (() => void) | undefined;
    const arrival = new Promise<void>((resolve) => {
      arrived = resolve;
    });
    let blockOnce = true;
    const spy = vi
      .spyOn(env.FEED, "put")
      .mockImplementation(async (...args: Parameters<typeof env.FEED.put>) => {
        if (args[0].endsWith("checkpoint.json") && blockOnce) {
          blockOnce = false;
          arrived!();
          await paused;
        }
        return originalPut(...args);
      });
    const delayed = tick(config).then(
      () => "unexpected",
      () => "conflict",
    );
    await arrival;
    expect(await tick(config)).toBe("advanced");
    await append(f);
    expect(await tick(config)).toBe("advanced");
    resume!();
    expect(await delayed).toBe("conflict");
    spy.mockRestore();
    expect(await tick(config)).toBe("caught_up");
  });

  it.each(["hold", "competition_replay"])(
    "copies %s without a chain authorization",
    async (mode) => {
      const f = await fixture(mode);
      const requests = source(f.objects);
      expect(await tick(config)).toBe("advanced");
      expect(
        requests.some((route) => route.startsWith("authorizations/")),
      ).toBe(false);
      if (mode === "hold")
        expect(
          requests.some(
            (route) =>
              route.startsWith("packages/") || route.endsWith("execution.json"),
          ),
        ).toBe(false);
    },
  );

  it.each([301, 302, 307, 404, 500, 503])(
    "does not publish after HTTP %s",
    async (status) => {
      const f = await fixture();
      source(
        f.objects,
        () =>
          new Response(null, {
            status,
            headers: { Location: "https://other.example/private" },
          }),
      );
      await expect(tick(config)).rejects.toThrow();
      expect((await env.FEED.list()).objects).toHaveLength(0);
    },
  );

  it.each([
    "truncated",
    "oversized",
    "wrong-sha",
    "wrong-length",
    "compressed",
  ])("rejects %s payload before cursor publication", async (failure) => {
    const f = await fixture();
    source(f.objects, (route, value) => {
      if (!route.endsWith("evidence.json")) return;
      let body = value;
      if (failure === "truncated") body = value.slice(0, -1);
      if (failure === "oversized") body = new Uint8Array(value.length + 1);
      if (failure === "wrong-sha") body = new Uint8Array(value.length);
      const headers: Record<string, string> = {
        "Content-Length": String(
          value.length + (failure === "wrong-length" ? 1 : 0),
        ),
      };
      if (failure === "compressed") headers["Content-Encoding"] = "gzip";
      return new Response(new Uint8Array(body), { headers });
    });
    await expect(tick(config)).rejects.toThrow();
    expect(await env.FEED.head(prefix + f.afterRoute)).toBeNull();
    expect(
      await env.FEED.head(prefix + `packages/${f.packageHash}/evidence.json`),
    ).toBeNull();
  });

  it("rejects an existing wrong object instead of replacing it", async () => {
    const f = await fixture();
    source(f.objects);
    const key = prefix + `packages/${f.packageHash}/evidence.json`;
    await env.FEED.put(key, "wrong bytes");
    await expect(tick(config)).rejects.toThrow();
    expect(await (await env.FEED.get(key))!.text()).toBe("wrong bytes");
    expect(await env.FEED.head(prefix + f.afterRoute)).toBeNull();
  });

  it.each(["chain", "channel", "sequence", "one-hop", "manifest"])(
    "rejects %s disagreement",
    async (failure) => {
      const f = await fixture();
      if (failure === "chain") f.page.after_directive_sha256 = "ff".repeat(32);
      if (failure === "channel")
        f.signed.directive.channel_id = "ff".repeat(32);
      if (failure === "sequence") f.signed.directive.sequence++;
      if (failure === "manifest")
        f.signed.directive.replay_package.manifest_sha256 = "ff".repeat(32);
      f.objects.set(f.afterRoute, bytes(f.page));
      if (failure === "one-hop") f.page.directives = [];
      f.objects.set(f.exactRoute, bytes(f.page));
      source(f.objects);
      await expect(tick(config)).rejects.toThrow();
      expect(await env.FEED.head(prefix + f.afterRoute)).toBeNull();
    },
  );

  it("binds restart to the same source and initial cursor", async () => {
    const f = await fixture();
    source(f.objects);
    await tick(config);
    await expect(
      tick({ ...config, SOURCE_ORIGIN: "https://different.example" }),
    ).rejects.toThrow();
    await expect(
      tick({ ...config, INITIAL_CURSOR: "3/18/" + "ff".repeat(32) }),
    ).rejects.toThrow();
  });

  it.each([
    "http://source.example",
    "https://user:pass@source.example",
    "https://source.example/path",
    "https://source.example?x=1",
  ])("rejects source origin %s", async (origin) => {
    await expect(tick({ ...config, SOURCE_ORIGIN: origin })).rejects.toThrow();
    expect((await env.FEED.list()).objects).toHaveLength(0);
  });

  it("fails on an oversized control page even without Content-Length", async () => {
    const f = await fixture();
    source(f.objects, () => new Response(" ".repeat(1024 * 1024 + 1)));
    await expect(tick(config)).rejects.toThrow();
    expect((await env.FEED.list()).objects).toHaveLength(0);
  });
});
