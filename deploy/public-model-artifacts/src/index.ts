type Artifact = Readonly<{
  path: string;
  key: string;
  kind: "model" | "runtime";
  identitySha256: string;
  archiveSha256: string;
  bytes: number;
  mediaType: "application/x-tar";
  filename: string;
}>;

export type Catalog = readonly Artifact[];

const MODEL = "6fe8df59ec11ba89f4dfe0474a673fe757e378cd9184449965861c5a7c59b641";
const RUNTIME = "f025ceb38cacc5c71873d94b8f2010aae10a0193a0e410e410a202f4def3b7b0";

export const CATALOG: Catalog = [
  {
    path: `/v1/models/${MODEL}/umi-model-bundle.tar`,
    key: `public/v1/models/${MODEL}/umi-model-bundle.tar`,
    kind: "model",
    identitySha256: MODEL,
    archiveSha256: "ea9e3e3e46cb95bb8177b2362050d0396da058868a37f6a89f43f783291d699a",
    bytes: 2_935_470_080,
    mediaType: "application/x-tar",
    filename: `umi-model-bundle-${MODEL}.tar`,
  },
  {
    path: `/v1/runtimes/${RUNTIME}/offline-cpu-runtime.oci.tar`,
    key: `public/v1/runtimes/${RUNTIME}/offline-cpu-runtime.oci.tar`,
    kind: "runtime",
    identitySha256: RUNTIME,
    archiveSha256: "37e09eae8f862d75ddc25fe6b3eadc2fa8d9d7c6b03bfe5d7af4da6b3f97974a",
    bytes: 2_215_539_200,
    mediaType: "application/x-tar",
    filename: `offline-cpu-runtime-${RUNTIME}.oci.tar`,
  },
];

const SECURITY_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Cross-Origin-Resource-Policy": "cross-origin",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Robots-Tag": "noindex, nofollow, noarchive",
};

type Bindings = Env & { ARTIFACTS: R2Bucket };
type ByteRange = Readonly<{ offset: number; length: number }>;

function absent(status = 404, headers: HeadersInit = {}): Response {
  return new Response(null, { status, headers: { ...SECURITY_HEADERS, ...headers } });
}

function requestedRange(value: string | null, size: number): ByteRange | null | "invalid" {
  if (value === null) return null;
  const match = /^bytes=([0-9]*)-([0-9]*)$/.exec(value);
  if (!match || (match[1] === "" && match[2] === "")) return "invalid";
  const left = match[1] === "" ? null : Number(match[1]);
  const right = match[2] === "" ? null : Number(match[2]);
  if (
    (left !== null && (!Number.isSafeInteger(left) || left < 0))
    || (right !== null && (!Number.isSafeInteger(right) || right < 0))
  ) return "invalid";
  if (left === null) {
    if (right === null || right === 0) return "invalid";
    const length = Math.min(right, size);
    return { offset: size - length, length };
  }
  if (left >= size || (right !== null && right < left)) return "invalid";
  const end = right === null ? size - 1 : Math.min(right, size - 1);
  return { offset: left, length: end - left + 1 };
}

function metadataMatches(object: R2Object, artifact: Artifact): boolean {
  const metadata = object.customMetadata;
  return object.size === artifact.bytes
    && metadata !== undefined
    && metadata.sha256 === artifact.archiveSha256
    && metadata.identity === artifact.identitySha256
    && metadata.kind === artifact.kind;
}

function artifactHeaders(artifact: Artifact, length: number): Headers {
  const headers = new Headers(SECURITY_HEADERS);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Cache-Control", "public, max-age=31536000, immutable");
  headers.set("Content-Disposition", `attachment; filename="${artifact.filename}"`);
  headers.set("Content-Length", String(length));
  headers.set("Content-Type", artifact.mediaType);
  headers.set("ETag", `"${artifact.archiveSha256}"`);
  return headers;
}

function indexResponse(request: Request, catalog: Catalog): Response {
  const origin = new URL(request.url).origin;
  const body = {
    schema: "umi-public-model-artifact-index/1",
    artifacts: catalog.map((artifact) => ({
      kind: artifact.kind,
      identity_sha256: artifact.identitySha256,
      archive_sha256: artifact.archiveSha256,
      archive_bytes: artifact.bytes,
      media_type: artifact.mediaType,
      url: `${origin}${artifact.path}`,
    })),
  };
  return Response.json(body, {
    headers: {
      ...SECURITY_HEADERS,
      "Cache-Control": "public, max-age=300",
    },
  });
}

async function serveArtifact(
  request: Request,
  env: Bindings,
  artifact: Artifact,
): Promise<Response> {
  const range = requestedRange(request.headers.get("Range"), artifact.bytes);
  if (range === "invalid") {
    return absent(416, {
      "Accept-Ranges": "bytes",
      "Content-Range": `bytes */${artifact.bytes}`,
    });
  }

  let object: R2Object | null;
  let body: ReadableStream | null = null;
  if (request.method === "HEAD") {
    object = await env.ARTIFACTS.head(artifact.key);
  } else {
    const fetched = await env.ARTIFACTS.get(
      artifact.key,
      range === null ? undefined : { range },
    );
    object = fetched;
    body = fetched?.body ?? null;
  }
  if (!object || !metadataMatches(object, artifact)) {
    if (body) await body.cancel();
    return absent();
  }

  const etag = `"${artifact.archiveSha256}"`;
  const ifNoneMatch = request.headers.get("If-None-Match");
  if (ifNoneMatch?.split(",").map((value) => value.trim()).includes(etag)) {
    if (body) await body.cancel();
    return absent(304, { ETag: etag });
  }
  const ifMatch = request.headers.get("If-Match");
  if (ifMatch !== null && ifMatch !== "*" && !ifMatch.split(",").map((value) => value.trim()).includes(etag)) {
    if (body) await body.cancel();
    return absent(412);
  }

  const responseRange = request.method === "HEAD" ? null : range;
  const length = responseRange?.length ?? artifact.bytes;
  const headers = artifactHeaders(artifact, length);
  if (responseRange !== null) {
    headers.set(
      "Content-Range",
      `bytes ${responseRange.offset}-${responseRange.offset + responseRange.length - 1}/${artifact.bytes}`,
    );
  }
  return new Response(body, { status: responseRange === null ? 200 : 206, headers });
}

export async function serve(
  request: Request,
  env: Bindings,
  catalog: Catalog = CATALOG,
): Promise<Response> {
  const url = new URL(request.url);
  if (url.protocol !== "https:" || url.search || !["GET", "HEAD"].includes(request.method)) {
    return absent();
  }
  if (url.pathname === "/v1/index.json") {
    if (request.headers.has("Range")) return absent(416);
    const response = indexResponse(request, catalog);
    return request.method === "HEAD"
      ? new Response(null, { status: response.status, headers: response.headers })
      : response;
  }
  const artifact = catalog.find((candidate) => candidate.path === url.pathname);
  if (!artifact) return absent();
  try {
    return await serveArtifact(request, env, artifact);
  } catch {
    console.error(JSON.stringify({ event: "public_model_artifact_storage_unavailable" }));
    return absent(503, { "Retry-After": "30" });
  }
}

export default {
  fetch(request: Request, env: Bindings): Promise<Response> {
    return serve(request, env);
  },
} satisfies ExportedHandler<Bindings>;
