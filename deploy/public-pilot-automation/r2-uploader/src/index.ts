const AUTH_SCHEME = "UMI-HMAC-SHA256";
const AUTH_DOMAIN = "umi-r2-upload-v1";
const MAX_CLOCK_SKEW_SECONDS = 300;
const MAX_PUBLIC_ARCHIVE_BYTES = 96 * 1024 * 1024;
const MAX_RESULT_BYTES = 256 * 1024;
const MAX_VALIDATOR_BOOTSTRAP_RESULT_BYTES = 4 * 1024 * 1024;
const MAX_VALIDATOR_BOOTSTRAP_UPLOAD_HMAC_ALLOWLIST_BYTES = 4 * 1024;
const MAX_VALIDATOR_BOOTSTRAP_UPLOAD_HMAC_ALLOWLIST_ENTRIES = 32;
const IMMUTABLE_CACHE_CONTROL = "public, max-age=31536000, immutable";

const LOWER_HEX_64 = /^[0-9a-f]{64}$/;
const ARCHIVE_PATH = /^\/public-pilot-cases\/([0-9a-f]{64})\/sealed-case\.tar\.gz$/;
const EVIDENCE_PATH = /^\/public-pilot-evidence\/([0-9a-f]{64})\/evidence\.tar\.gz$/;
const ATTEMPT_PATH = /^\/public-pilot-attempts\/([0-9a-f]{64})\/attempt-journal\.tar\.gz$/;
const RESULT_PATH = /^\/public-pilot-automation\/results\/([0-9a-f]{64})\.json$/;
const VALIDATOR_BOOTSTRAP_RESULT_PATH =
  /^\/validator-bootstrap-results\/([0-9a-f]{64})\.json$/;

type UploadRoute = Readonly<{
  key: string;
  kind:
    | "sealed_case"
    | "evidence_archive"
    | "attempt_journal"
    | "automation_result"
    | "validator_bootstrap_result";
  authentication: "pilot" | "validator_bootstrap";
  identifier: string;
  maximumBytes: number;
  contentType: "application/gzip" | "application/json";
  contentDisposition?: string;
  digestMustMatchIdentifier: boolean;
}>;

type AuthenticatedUpload = Readonly<{
  route: UploadRoute;
  contentLength: number;
  contentSha256: string;
}>;

function jsonResponse(status: number, payload: Readonly<Record<string, unknown>>): Response {
  return Response.json(payload, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function parseRoute(pathname: string): UploadRoute | null {
  const archive = ARCHIVE_PATH.exec(pathname);
  if (archive?.[1] !== undefined) {
    return {
      key: pathname.slice(1),
      kind: "sealed_case",
      authentication: "pilot",
      identifier: archive[1],
      maximumBytes: MAX_PUBLIC_ARCHIVE_BYTES,
      contentType: "application/gzip",
      contentDisposition: 'attachment; filename="sealed-case.tar.gz"',
      digestMustMatchIdentifier: true,
    };
  }

  const evidence = EVIDENCE_PATH.exec(pathname);
  if (evidence?.[1] !== undefined) {
    return {
      key: pathname.slice(1),
      kind: "evidence_archive",
      authentication: "pilot",
      identifier: evidence[1],
      maximumBytes: MAX_PUBLIC_ARCHIVE_BYTES,
      contentType: "application/gzip",
      contentDisposition: 'attachment; filename="evidence.tar.gz"',
      digestMustMatchIdentifier: true,
    };
  }

  const attempt = ATTEMPT_PATH.exec(pathname);
  if (attempt?.[1] !== undefined) {
    return {
      key: pathname.slice(1),
      kind: "attempt_journal",
      authentication: "pilot",
      identifier: attempt[1],
      maximumBytes: MAX_PUBLIC_ARCHIVE_BYTES,
      contentType: "application/gzip",
      contentDisposition: 'attachment; filename="attempt-journal.tar.gz"',
      digestMustMatchIdentifier: true,
    };
  }

  const result = RESULT_PATH.exec(pathname);
  if (result?.[1] !== undefined) {
    return {
      key: pathname.slice(1),
      kind: "automation_result",
      authentication: "pilot",
      identifier: result[1],
      maximumBytes: MAX_RESULT_BYTES,
      contentType: "application/json",
      digestMustMatchIdentifier: false,
    };
  }

  const validatorBootstrapResult = VALIDATOR_BOOTSTRAP_RESULT_PATH.exec(pathname);
  if (validatorBootstrapResult?.[1] !== undefined) {
    return {
      key: pathname.slice(1),
      kind: "validator_bootstrap_result",
      authentication: "validator_bootstrap",
      identifier: validatorBootstrapResult[1],
      maximumBytes: MAX_VALIDATOR_BOOTSTRAP_RESULT_BYTES,
      contentType: "application/json",
      digestMustMatchIdentifier: false,
    };
  }

  return null;
}

function parseContentLength(header: string | null): number | null {
  if (header === null || !/^[1-9][0-9]*$/.test(header)) {
    return null;
  }
  const value = Number(header);
  return Number.isSafeInteger(value) ? value : null;
}

function parseTimestamp(header: string | null): number | null {
  if (header === null || !/^(0|[1-9][0-9]{0,15})$/.test(header)) {
    return null;
  }
  const value = Number(header);
  return Number.isSafeInteger(value) ? value : null;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    const byte = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
    bytes[index] = byte;
  }
  return bytes;
}

function bytesEqual(left: ArrayBuffer, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  return crypto.subtle.timingSafeEqual(left, right);
}

function validatorBootstrapUploadSecret(
  serializedAllowlist: string,
  submissionId: string,
): string | null {
  if (
    new TextEncoder().encode(serializedAllowlist).byteLength
      > MAX_VALIDATOR_BOOTSTRAP_UPLOAD_HMAC_ALLOWLIST_BYTES
  ) {
    throw new Error("validator bootstrap upload HMAC allowlist is too large");
  }

  let decoded: unknown;
  try {
    decoded = JSON.parse(serializedAllowlist);
  } catch {
    throw new Error("validator bootstrap upload HMAC allowlist is invalid");
  }
  if (
    decoded === null
    || typeof decoded !== "object"
    || Array.isArray(decoded)
  ) {
    throw new Error("validator bootstrap upload HMAC allowlist is invalid");
  }

  const entries = Object.entries(decoded as Record<string, unknown>);
  if (entries.length > MAX_VALIDATOR_BOOTSTRAP_UPLOAD_HMAC_ALLOWLIST_ENTRIES) {
    throw new Error("validator bootstrap upload HMAC allowlist has too many entries");
  }
  const normalized: Record<string, string> = {};
  let previousSubmissionId: string | null = null;
  for (const [candidateSubmissionId, candidateSecret] of entries) {
    if (
      !LOWER_HEX_64.test(candidateSubmissionId)
      || typeof candidateSecret !== "string"
      || !LOWER_HEX_64.test(candidateSecret)
      || (previousSubmissionId !== null && candidateSubmissionId <= previousSubmissionId)
    ) {
      throw new Error("validator bootstrap upload HMAC allowlist is invalid");
    }
    normalized[candidateSubmissionId] = candidateSecret;
    previousSubmissionId = candidateSubmissionId;
  }
  if (JSON.stringify(normalized) !== serializedAllowlist) {
    // Requiring exact canonical bytes also rejects duplicate object keys, which
    // JSON.parse would otherwise silently collapse to the final value.
    throw new Error("validator bootstrap upload HMAC allowlist is noncanonical");
  }
  return Object.hasOwn(normalized, submissionId) ? normalized[submissionId] ?? null : null;
}

function canonicalAuthMessage(
  pathname: string,
  timestamp: string,
  contentLength: number,
  contentType: string,
  contentSha256: string,
): string {
  return [
    AUTH_DOMAIN,
    "PUT",
    pathname,
    timestamp,
    String(contentLength),
    contentType,
    contentSha256,
  ].join("\n");
}

async function verifyAuthorization(
  request: Request,
  secretHex: string,
  pathname: string,
  contentLength: number,
  contentType: string,
  contentSha256: string,
): Promise<boolean> {
  if (!LOWER_HEX_64.test(secretHex)) {
    throw new Error("upload HMAC secret must encode exactly 32 bytes");
  }

  const authorization = request.headers.get("Authorization");
  const match = authorization === null
    ? null
    : new RegExp(`^${AUTH_SCHEME} ([0-9a-f]{64})$`).exec(authorization);
  if (match?.[1] === undefined) {
    return false;
  }

  const timestampHeader = request.headers.get("X-UMI-Timestamp");
  const timestamp = parseTimestamp(timestampHeader);
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (
    timestamp === null
    || timestampHeader === null
    || Math.abs(nowSeconds - timestamp) > MAX_CLOCK_SKEW_SECONDS
  ) {
    return false;
  }

  const key = await crypto.subtle.importKey(
    "raw",
    hexToBytes(secretHex),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const message = new TextEncoder().encode(canonicalAuthMessage(
    pathname,
    timestampHeader,
    contentLength,
    contentType,
    contentSha256,
  ));
  return crypto.subtle.verify("HMAC", key, hexToBytes(match[1]), message);
}

async function authenticateUpload(
  request: Request,
  env: Env,
  url: URL,
): Promise<AuthenticatedUpload | Response> {
  const route = parseRoute(url.pathname);
  if (route === null || url.search !== "") {
    return jsonResponse(404, { error: "not_found" });
  }

  const contentLengthHeader = request.headers.get("Content-Length");
  if (contentLengthHeader === null) {
    return jsonResponse(411, { error: "content_length_required" });
  }
  const contentLength = parseContentLength(contentLengthHeader);
  if (contentLength === null) {
    return jsonResponse(400, { error: "invalid_content_length" });
  }
  if (contentLength > route.maximumBytes) {
    return jsonResponse(413, { error: "content_too_large" });
  }

  const contentType = request.headers.get("Content-Type");
  if (contentType !== route.contentType || request.headers.has("Content-Encoding")) {
    return jsonResponse(415, { error: "unsupported_media_type" });
  }

  const contentSha256 = request.headers.get("X-UMI-Content-SHA256");
  if (contentSha256 === null || !LOWER_HEX_64.test(contentSha256)) {
    return jsonResponse(400, { error: "invalid_content_sha256" });
  }
  if (route.digestMustMatchIdentifier && contentSha256 !== route.identifier) {
    return jsonResponse(400, { error: "path_digest_mismatch" });
  }

  const uploadSecret = route.authentication === "pilot"
    ? env.UPLOAD_HMAC_SECRET
    : validatorBootstrapUploadSecret(
      env.VALIDATOR_BOOTSTRAP_UPLOAD_HMAC_ALLOWLIST,
      route.identifier,
    );
  if (uploadSecret === null) {
    return jsonResponse(401, { error: "unauthorized" });
  }
  const authorized = await verifyAuthorization(
    request,
    uploadSecret,
    url.pathname,
    contentLength,
    contentType,
    contentSha256,
  );
  if (!authorized) {
    return jsonResponse(401, { error: "unauthorized" });
  }

  return { route, contentLength, contentSha256 };
}

async function handlePut(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const authenticated = await authenticateUpload(request, env, url);
  if (authenticated instanceof Response) {
    return authenticated;
  }
  if (request.body === null) {
    return jsonResponse(400, { error: "request_body_required" });
  }

  const { route, contentLength, contentSha256 } = authenticated;
  const existing = await env.EVIDENCE_BUCKET.head(route.key);
  if (existing !== null) {
    return jsonResponse(409, { error: "object_exists" });
  }

  let stored: R2Object | null;
  try {
    stored = await env.EVIDENCE_BUCKET.put(route.key, request.body, {
      onlyIf: { etagDoesNotMatch: "*" },
      sha256: hexToBytes(contentSha256),
      httpMetadata: {
        contentType: route.contentType,
        cacheControl: IMMUTABLE_CACHE_CONTROL,
        ...(route.contentDisposition === undefined
          ? {}
          : { contentDisposition: route.contentDisposition }),
      },
      customMetadata: {
        sha256: contentSha256,
        uploadKind: route.kind,
      },
    });
  } catch {
    console.error(JSON.stringify({
      event: "r2_put_rejected",
      key: route.key,
      requestId: request.headers.get("CF-Ray"),
    }));
    return jsonResponse(422, { error: "upload_rejected" });
  }

  if (stored === null) {
    return jsonResponse(412, { error: "precondition_failed" });
  }

  const expectedChecksum = hexToBytes(contentSha256);
  if (
    stored.size !== contentLength
    || stored.checksums.sha256 === undefined
    || !bytesEqual(stored.checksums.sha256, expectedChecksum)
  ) {
    console.error(JSON.stringify({
      event: "r2_put_verification_failed",
      key: route.key,
      requestId: request.headers.get("CF-Ray"),
    }));
    return jsonResponse(500, { error: "stored_object_verification_failed" });
  }

  console.log(JSON.stringify({
    event: "r2_object_created",
    key: route.key,
    kind: route.kind,
    size: stored.size,
    sha256: contentSha256,
    requestId: request.headers.get("CF-Ray"),
  }));
  return jsonResponse(201, {
    status: "created",
    key: route.key,
    sha256: contentSha256,
    size: stored.size,
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== "PUT") {
      return new Response(JSON.stringify({ error: "method_not_allowed" }), {
        status: 405,
        headers: {
          Allow: "PUT",
          "Cache-Control": "no-store",
          "Content-Type": "application/json; charset=utf-8",
          "X-Content-Type-Options": "nosniff",
        },
      });
    }

    try {
      return await handlePut(request, env);
    } catch {
      console.error(JSON.stringify({
        event: "request_failed",
        requestId: request.headers.get("CF-Ray"),
      }));
      return jsonResponse(500, { error: "internal_error" });
    }
  },
} satisfies ExportedHandler<Env>;
