import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it } from "vitest";

import worker from "../src/index";

const TEST_SECRET = "11".repeat(32);
const TEST_VALIDATOR_SECRET = "22".repeat(32);
const TEST_OTHER_VALIDATOR_SECRET = "33".repeat(32);
const TEST_VALIDATOR_SUBMISSION_ID = "bc".repeat(32);
const encoder = new TextEncoder();

function testEnv(
  validatorAllowlist = JSON.stringify({
    [TEST_VALIDATOR_SUBMISSION_ID]: TEST_VALIDATOR_SECRET,
  }),
): Env {
  return {
    EVIDENCE_BUCKET: env.EVIDENCE_BUCKET,
    UPLOAD_HMAC_SECRET: TEST_SECRET,
    VALIDATOR_BOOTSTRAP_UPLOAD_HMAC_ALLOWLIST: validatorAllowlist,
  };
}

function toHex(value: ArrayBuffer): string {
  return [...new Uint8Array(value)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

async function digest(body: Uint8Array): Promise<string> {
  return toHex(await crypto.subtle.digest("SHA-256", body));
}

async function authorization(
  pathname: string,
  timestamp: string,
  contentLength: number,
  contentType: string,
  contentSha256: string,
  secret = TEST_SECRET,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    hexToBytes(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const canonical = [
    "umi-r2-upload-v1",
    "PUT",
    pathname,
    timestamp,
    String(contentLength),
    contentType,
    contentSha256,
  ].join("\n");
  return `UMI-HMAC-SHA256 ${toHex(await crypto.subtle.sign("HMAC", key, encoder.encode(canonical)))}`;
}

async function makeUpload(
  pathname: string,
  bodyText: string,
  contentType: "application/gzip" | "application/json",
  overrides: Readonly<Record<string, string>> = {},
  secret = TEST_SECRET,
): Promise<Request> {
  const body = encoder.encode(bodyText);
  const contentSha256 = overrides["X-UMI-Content-SHA256"] ?? await digest(body);
  const timestamp = overrides["X-UMI-Timestamp"] ?? String(Math.floor(Date.now() / 1000));
  const contentLength = overrides["Content-Length"] ?? String(body.byteLength);
  const auth = overrides.Authorization ?? await authorization(
    pathname,
    timestamp,
    Number(contentLength),
    contentType,
    contentSha256,
    secret,
  );
  return new Request(`https://uploader.example${pathname}`, {
    method: "PUT",
    headers: {
      Authorization: auth,
      "Content-Length": contentLength,
      "Content-Type": contentType,
      "X-UMI-Content-SHA256": contentSha256,
      "X-UMI-Timestamp": timestamp,
      ...overrides,
    },
    body,
  });
}

async function removeAllObjects(): Promise<void> {
  let cursor: string | undefined;
  do {
    const listed = await env.EVIDENCE_BUCKET.list(
      cursor === undefined ? {} : { cursor },
    );
    if (listed.objects.length > 0) {
      await env.EVIDENCE_BUCKET.delete(listed.objects.map((object) => object.key));
    }
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor !== undefined);
}

afterEach(async () => {
  await removeAllObjects();
});

describe("public pilot R2 uploader", () => {
  it("stores a valid sealed case with immutable metadata and a verified checksum", async () => {
    const body = "bounded sealed case";
    const sha256 = await digest(encoder.encode(body));
    const pathname = `/public-pilot-cases/${sha256}/sealed-case.tar.gz`;
    const response = await worker.fetch(await makeUpload(pathname, body, "application/gzip"), env);

    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({
      status: "created",
      key: pathname.slice(1),
      sha256,
      size: encoder.encode(body).byteLength,
    });
    const stored = await env.EVIDENCE_BUCKET.get(pathname.slice(1));
    expect(stored).not.toBeNull();
    expect(await stored?.text()).toBe(body);
    expect(stored?.httpMetadata?.contentType).toBe("application/gzip");
    expect(stored?.httpMetadata?.cacheControl).toBe("public, max-age=31536000, immutable");
    expect(stored?.httpMetadata?.contentDisposition).toBe('attachment; filename="sealed-case.tar.gz"');
    expect(stored?.customMetadata?.sha256).toBe(sha256);
  });

  it("stores an automation result under its authorization id", async () => {
    const body = '{"schema":"umi-public-pilot-automation-result/1"}';
    const authorizationId = "ab".repeat(32);
    const pathname = `/public-pilot-automation/results/${authorizationId}.json`;
    const response = await worker.fetch(await makeUpload(pathname, body, "application/json"), env);

    expect(response.status).toBe(201);
    const stored = await env.EVIDENCE_BUCKET.get(pathname.slice(1));
    expect(await stored?.text()).toBe(body);
    expect(stored?.httpMetadata?.contentType).toBe("application/json");
  });

  it("stores a validator bootstrap result only with its separate credential", async () => {
    const body = '{"schema":"umi-validator-supervisor-bootstrap-result/1"}';
    const pathname = `/validator-bootstrap-results/${TEST_VALIDATOR_SUBMISSION_ID}.json`;
    const wrongCredential = await worker.fetch(
      await makeUpload(pathname, body, "application/json", {}, TEST_OTHER_VALIDATOR_SECRET),
      testEnv(),
    );
    const accepted = await worker.fetch(
      await makeUpload(
        pathname,
        body,
        "application/json",
        {},
        TEST_VALIDATOR_SECRET,
      ),
      testEnv(),
    );

    expect(wrongCredential.status).toBe(401);
    expect(accepted.status).toBe(201);
    const stored = await env.EVIDENCE_BUCKET.get(pathname.slice(1));
    expect(await stored?.text()).toBe(body);
    expect(stored?.customMetadata?.uploadKind).toBe("validator_bootstrap_result");
  });

  it("rejects an unmapped validator bootstrap submission id", async () => {
    const body = '{"schema":"umi-validator-supervisor-bootstrap-result/1"}';
    const unknownSubmissionId = "bd".repeat(32);
    const pathname = `/validator-bootstrap-results/${unknownSubmissionId}.json`;
    const response = await worker.fetch(
      await makeUpload(pathname, body, "application/json", {}, TEST_VALIDATOR_SECRET),
      testEnv(),
    );

    expect(response.status).toBe(401);
    expect(await env.EVIDENCE_BUCKET.head(pathname.slice(1))).toBeNull();
  });

  it.each([
    ["malformed JSON", "{"],
    ["non-object JSON", "[]"],
    [
      "duplicate submission ids",
      `{${JSON.stringify(TEST_VALIDATOR_SUBMISSION_ID)}:${JSON.stringify(TEST_VALIDATOR_SECRET)},${JSON.stringify(TEST_VALIDATOR_SUBMISSION_ID)}:${JSON.stringify(TEST_OTHER_VALIDATOR_SECRET)}}`,
    ],
    [
      "noncanonical entry order",
      JSON.stringify({
        ["ff".repeat(32)]: TEST_OTHER_VALIDATOR_SECRET,
        [TEST_VALIDATOR_SUBMISSION_ID]: TEST_VALIDATOR_SECRET,
      }),
    ],
    [
      "invalid credential",
      JSON.stringify({ [TEST_VALIDATOR_SUBMISSION_ID]: "not-a-credential" }),
    ],
    ["oversized input", " ".repeat(4 * 1024 + 1)],
  ])("fails closed for a %s validator credential allowlist", async (_label, allowlist) => {
    const body = '{"schema":"umi-validator-supervisor-bootstrap-result/1"}';
    const pathname = `/validator-bootstrap-results/${TEST_VALIDATOR_SUBMISSION_ID}.json`;
    const response = await worker.fetch(
      await makeUpload(pathname, body, "application/json", {}, TEST_VALIDATOR_SECRET),
      testEnv(allowlist),
    );

    expect(response.status).toBe(500);
    expect(await env.EVIDENCE_BUCKET.head(pathname.slice(1))).toBeNull();
  });

  it("stores a valid evidence archive with immutable attachment metadata", async () => {
    const body = "bounded public pilot evidence";
    const sha256 = await digest(encoder.encode(body));
    const pathname = `/public-pilot-evidence/${sha256}/evidence.tar.gz`;
    const response = await worker.fetch(await makeUpload(pathname, body, "application/gzip"), env);

    expect(response.status).toBe(201);
    const stored = await env.EVIDENCE_BUCKET.get(pathname.slice(1));
    expect(await stored?.text()).toBe(body);
    expect(stored?.httpMetadata?.contentType).toBe("application/gzip");
    expect(stored?.httpMetadata?.contentDisposition).toBe('attachment; filename="evidence.tar.gz"');
    expect(stored?.customMetadata?.uploadKind).toBe("evidence_archive");
    expect(stored?.customMetadata?.sha256).toBe(sha256);
  });

  it("stores a valid attempt journal with immutable attachment metadata", async () => {
    const body = "bounded incomplete attempt journal";
    const sha256 = await digest(encoder.encode(body));
    const pathname = `/public-pilot-attempts/${sha256}/attempt-journal.tar.gz`;
    const response = await worker.fetch(await makeUpload(pathname, body, "application/gzip"), env);

    expect(response.status).toBe(201);
    const stored = await env.EVIDENCE_BUCKET.get(pathname.slice(1));
    expect(await stored?.text()).toBe(body);
    expect(stored?.httpMetadata?.contentType).toBe("application/gzip");
    expect(stored?.httpMetadata?.contentDisposition).toBe('attachment; filename="attempt-journal.tar.gz"');
    expect(stored?.customMetadata?.uploadKind).toBe("attempt_journal");
    expect(stored?.customMetadata?.sha256).toBe(sha256);
  });

  it("returns 409 without replacing an existing object", async () => {
    const original = "first immutable value";
    const sha256 = await digest(encoder.encode(original));
    const pathname = `/public-pilot-cases/${sha256}/sealed-case.tar.gz`;
    const first = await worker.fetch(await makeUpload(pathname, original, "application/gzip"), env);
    const second = await worker.fetch(await makeUpload(pathname, original, "application/gzip"), env);

    expect(first.status).toBe(201);
    expect(second.status).toBe(409);
    expect(await env.EVIDENCE_BUCKET.get(pathname.slice(1)).then((object) => object?.text())).toBe(original);
  });

  it("lets only one concurrent conditional write succeed", async () => {
    const body = '{"terminal":true}';
    const authorizationId = "cd".repeat(32);
    const pathname = `/public-pilot-automation/results/${authorizationId}.json`;
    const [first, second] = await Promise.all([
      makeUpload(pathname, body, "application/json"),
      makeUpload(pathname, body, "application/json"),
    ]).then(async ([firstRequest, secondRequest]) => Promise.all([
      worker.fetch(firstRequest, env),
      worker.fetch(secondRequest, env),
    ]));

    expect([first.status, second.status].sort()).toEqual([201, 412]);
  });

  it("rejects a bad signature without reading or writing the body", async () => {
    const body = "sealed";
    const sha256 = await digest(encoder.encode(body));
    const pathname = `/public-pilot-cases/${sha256}/sealed-case.tar.gz`;
    const request = await makeUpload(pathname, body, "application/gzip", {
      Authorization: `UMI-HMAC-SHA256 ${"00".repeat(32)}`,
    });
    const response = await worker.fetch(request, env);

    expect(response.status).toBe(401);
    expect(await env.EVIDENCE_BUCKET.head(pathname.slice(1))).toBeNull();
  });

  it("rejects stale authorization", async () => {
    const body = "sealed";
    const sha256 = await digest(encoder.encode(body));
    const pathname = `/public-pilot-cases/${sha256}/sealed-case.tar.gz`;
    const timestamp = String(Math.floor(Date.now() / 1000) - 301);
    const request = await makeUpload(pathname, body, "application/gzip", {
      "X-UMI-Timestamp": timestamp,
    });

    expect((await worker.fetch(request, env)).status).toBe(401);
  });

  it("rejects an archive whose path and declared digest differ", async () => {
    const body = "sealed";
    const actual = await digest(encoder.encode(body));
    const pathname = `/public-pilot-cases/${"ef".repeat(32)}/sealed-case.tar.gz`;
    const request = await makeUpload(pathname, body, "application/gzip", {
      "X-UMI-Content-SHA256": actual,
    });

    expect((await worker.fetch(request, env)).status).toBe(400);
  });

  it("requires an evidence archive path to match its declared digest", async () => {
    const body = "evidence";
    const actual = await digest(encoder.encode(body));
    const pathname = `/public-pilot-evidence/${"12".repeat(32)}/evidence.tar.gz`;
    const request = await makeUpload(pathname, body, "application/gzip", {
      "X-UMI-Content-SHA256": actual,
    });

    expect((await worker.fetch(request, env)).status).toBe(400);
  });

  it("requires an attempt journal path to match its declared digest", async () => {
    const body = "attempt";
    const actual = await digest(encoder.encode(body));
    const pathname = `/public-pilot-attempts/${"34".repeat(32)}/attempt-journal.tar.gz`;
    const request = await makeUpload(pathname, body, "application/gzip", {
      "X-UMI-Content-SHA256": actual,
    });

    expect((await worker.fetch(request, env)).status).toBe(400);
  });

  it("enforces the evidence archive size limit", async () => {
    const body = "evidence";
    const sha256 = await digest(encoder.encode(body));
    const pathname = `/public-pilot-evidence/${sha256}/evidence.tar.gz`;
    const request = await makeUpload(pathname, body, "application/gzip", {
      "Content-Length": String(96 * 1024 * 1024 + 1),
    });

    expect((await worker.fetch(request, env)).status).toBe(413);
  });

  it("enforces the attempt journal size limit", async () => {
    const body = "attempt";
    const sha256 = await digest(encoder.encode(body));
    const pathname = `/public-pilot-attempts/${sha256}/attempt-journal.tar.gz`;
    const request = await makeUpload(pathname, body, "application/gzip", {
      "Content-Length": String(96 * 1024 * 1024 + 1),
    });

    expect((await worker.fetch(request, env)).status).toBe(413);
  });

  it("uses the R2 checksum guard to reject bytes that do not match the declared digest", async () => {
    const declared = await digest(encoder.encode("different bytes"));
    const pathname = `/public-pilot-cases/${declared}/sealed-case.tar.gz`;
    const request = await makeUpload(pathname, "actual bytes", "application/gzip", {
      "X-UMI-Content-SHA256": declared,
    });
    const response = await worker.fetch(request, env);

    expect(response.status).toBe(422);
    expect(await env.EVIDENCE_BUCKET.head(pathname.slice(1))).toBeNull();
  });

  it("requires a bounded canonical content length", async () => {
    const body = "sealed";
    const sha256 = await digest(encoder.encode(body));
    const pathname = `/public-pilot-cases/${sha256}/sealed-case.tar.gz`;
    const missingLength = await makeUpload(pathname, body, "application/gzip");
    missingLength.headers.delete("Content-Length");
    const oversized = await makeUpload(pathname, body, "application/gzip", {
      "Content-Length": String(96 * 1024 * 1024 + 1),
    });

    expect((await worker.fetch(missingLength, env)).status).toBe(411);
    expect((await worker.fetch(oversized, env)).status).toBe(413);
  });

  it("rejects wrong media types, content encoding, queries, and unknown paths", async () => {
    const body = "sealed";
    const sha256 = await digest(encoder.encode(body));
    const pathname = `/public-pilot-cases/${sha256}/sealed-case.tar.gz`;
    const wrongType = await makeUpload(pathname, body, "application/gzip", {
      "Content-Type": "application/octet-stream",
    });
    const encoded = await makeUpload(pathname, body, "application/gzip", {
      "Content-Encoding": "gzip",
    });

    expect((await worker.fetch(wrongType, env)).status).toBe(415);
    expect((await worker.fetch(encoded, env)).status).toBe(415);
    expect((await worker.fetch(new Request(`https://uploader.example${pathname}?replace=true`, {
      method: "PUT",
    }), env)).status).toBe(404);
    expect((await worker.fetch(new Request("https://uploader.example/anything", {
      method: "PUT",
    }), env)).status).toBe(404);
  });

  it("rejects all non-PUT methods", async () => {
    const response = await worker.fetch(new Request("https://uploader.example/", {
      method: "GET",
    }), env);

    expect(response.status).toBe(405);
    expect(response.headers.get("Allow")).toBe("PUT");
  });
});
