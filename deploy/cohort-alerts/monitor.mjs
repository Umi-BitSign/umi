export const CHECK_INTERVAL_MS = 60_000;
export const STALE_AFTER_MS = 5 * 60_000;
export const REMINDER_MS = 60 * 60_000;
export const NOTICE_COOLDOWN_MS = 5 * 60_000;

const RESOURCE_METRIC = /^[a-z0-9][a-z0-9_.-]{0,63}\/available_bytes$/;
const LIFECYCLE_LABEL = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const HEX32 = /^[0-9a-f]{64}$/;
const BOUNDED_NAME = /^[a-z][a-z0-9_]{0,63}$/;
const ERROR_NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const PHASES = new Set(["intake", "preparation", "requests", "reference_commit",
  "reference_reveal", "evaluation", "evidence", "certification", "complete", "revoked"]);
const ROUND_REQUIRED = new Set(["requests", "reference_commit", "reference_reveal",
  "evaluation", "evidence", "certification", "complete"]);

function validLifecycle(value) {
  if (value === null) return true;
  const keys = ["cohort_sha256", "plan_sequence", "phase", "sequence", "target_block",
    "stage", "status", "progress_completion", "progress_observed_at_block",
    "unavailable_blocks", "expected_round_sha256", "error_type", "public_round_sequence",
    "public_round_present"].sort().join();
  return value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).sort().join() === keys && HEX32.test(value.cohort_sha256) &&
    Number.isSafeInteger(value.plan_sequence) && value.plan_sequence >= 1 &&
    PHASES.has(value.phase) && Number.isSafeInteger(value.sequence) && value.sequence >= 0 &&
    (value.target_block === null || Number.isSafeInteger(value.target_block) && value.target_block >= 0) &&
    BOUNDED_NAME.test(value.stage) && BOUNDED_NAME.test(value.status) &&
    [null, "pending", "complete"].includes(value.progress_completion) &&
    (value.progress_observed_at_block === null ||
      Number.isSafeInteger(value.progress_observed_at_block) && value.progress_observed_at_block >= 0) &&
    (value.unavailable_blocks === null ||
      Number.isSafeInteger(value.unavailable_blocks) && value.unavailable_blocks >= 0) &&
    (value.progress_completion === null ? value.progress_observed_at_block === null &&
      value.unavailable_blocks === null : value.progress_observed_at_block !== null &&
      value.unavailable_blocks !== null) &&
    (value.error_type === null || typeof value.error_type === "string" && ERROR_NAME.test(value.error_type)) &&
    (value.expected_round_sha256 === null || HEX32.test(value.expected_round_sha256)) &&
    Number.isSafeInteger(value.public_round_sequence) && value.public_round_sequence >= 0 &&
    (value.public_round_present === null || typeof value.public_round_present === "boolean") &&
    (value.expected_round_sha256 === null) === (value.public_round_present === null);
}

function lifecycleIssue(value) {
  if (value === null) return "observation_missing";
  if (value.error_type !== null || value.status.endsWith("_retry")) {
    return `runtime_retry:${value.error_type ?? value.status}`;
  }
  if (value.progress_completion === "complete") return "completed_progress_unpublished";
  if (value.progress_completion === "pending" && value.target_block !== null &&
      value.progress_observed_at_block >= value.target_block + value.unavailable_blocks) {
    return "target_complete_not_detected";
  }
  if (ROUND_REQUIRED.has(value.phase) && value.public_round_present !== true) {
    return "public_round_missing";
  }
  return null;
}

export function validateHeartbeat(value, expected, limits = {}, resourceMinimums = {}, lifecycleLimits = {}) {
  const tracking = Object.keys(limits).length > 0;
  const resourceTracking = Object.keys(resourceMinimums).length > 0;
  const lifecycleTracking = Object.keys(lifecycleLimits).length > 0;
  const version = lifecycleTracking ? 4 : resourceTracking ? 3 : tracking ? 2 : 1;
  const keys = ["schema", "services", ...(tracking ? ["progress"] : []),
    ...(resourceTracking ? ["resources"] : []),
    ...(lifecycleTracking ? ["lifecycles"] : [])].sort().join();
  if (!value || value.schema !== `umi-service-heartbeat/${version}` ||
      Object.keys(value).sort().join() !== keys ||
      !value.services || Array.isArray(value.services) ||
      Object.keys(value.services).sort().join() !== [...expected].sort().join() ||
      Object.values(value.services).some(v => v !== "running" && v !== "failed")) {
    throw new Error("invalid_heartbeat");
  }
  if (tracking) {
    if (!value.progress || Array.isArray(value.progress) ||
        Object.keys(value.progress).sort().join() !== Object.keys(limits).sort().join() ||
        Object.values(value.progress).some(v => v !== null && (!Number.isSafeInteger(v) || v < 0))) {
      throw new Error("invalid_progress");
    }
  }
  if (resourceTracking) {
    if (!value.resources || Array.isArray(value.resources) ||
        Object.keys(value.resources).sort().join() !== Object.keys(resourceMinimums).sort().join() ||
        Object.values(value.resources).some(v => !Number.isSafeInteger(v) || v < 0)) {
      throw new Error("invalid_resources");
    }
  }
  if (lifecycleTracking) {
    if (!value.lifecycles || Array.isArray(value.lifecycles) ||
        Object.keys(value.lifecycles).sort().join() !== Object.keys(lifecycleLimits).sort().join() ||
        Object.values(value.lifecycles).some(v => !validLifecycle(v))) {
      throw new Error("invalid_lifecycles");
    }
  }
  return { schema: value.schema, services: { ...value.services },
    ...(tracking ? { progress: { ...value.progress } } : {}),
    ...(resourceTracking ? { resources: { ...value.resources } } : {}),
    ...(lifecycleTracking ? { lifecycles: structuredClone(value.lifecycles) } : {}) };
}

export function observation(heartbeat, now, limits = {}, resourceMinimums = {}, lifecycleLimits = {}) {
  if (!heartbeat) return { state: "unarmed", failed: [] };
  if (now - heartbeat.received_at >= STALE_AFTER_MS) {
    return { state: "heartbeat_missing", failed: [] };
  }
  const failed = Object.entries(heartbeat.services)
    .filter(([, status]) => status !== "running").map(([name]) => name).sort();
  const stalled = Object.entries(limits).filter(([name, limit]) => {
    const progress = heartbeat.progress?.[name];
    return !progress || !progress.present || now - progress.advanced_at >= limit;
  }).map(([name]) => name).sort();
  const low = Object.entries(resourceMinimums)
    .filter(([name, minimum]) => heartbeat.resources[name] < minimum)
    .map(([name]) => name).sort();
  const lifecycles = Object.fromEntries(Object.keys(lifecycleLimits).map(name => [name,
    heartbeat.lifecycles?.[name] ?? { issue: "observation_missing",
      issue_since: heartbeat.received_at }]));
  const lifecycle = Object.entries(lifecycleLimits)
    .filter(([name, limit]) => lifecycles[name].issue !== null &&
      now - lifecycles[name].issue_since >= limit)
    .map(([name]) => name).sort();
  return { state: failed.length ? "service_failed" : lifecycle.length ? "lifecycle_stalled" :
    stalled.length ? "progress_stalled" : low.length ? "resource_low" : "healthy", failed,
    ...(Object.keys(limits).length ? { stalled, progress: structuredClone(heartbeat.progress) } : {}),
    ...(Object.keys(resourceMinimums).length ? { low, resources: { ...heartbeat.resources } } : {}),
    ...(Object.keys(lifecycleLimits).length ? { lifecycle,
      lifecycles: structuredClone(lifecycles) } : {}) };
}

// Heartbeats and notification receipts use separate durable keys. A heartbeat
// received during email I/O must never be overwritten by an older alarm.
export class Monitor {
  constructor(storage, notify, expected, now = Date.now, limits = {}, resourceMinimums = {},
    lifecycleLimits = {}) {
    if (!limits || typeof limits !== "object" || Array.isArray(limits) || Object.keys(limits).length > 20 ||
        Object.entries(limits).some(([name, limit]) => {
          const [service, metric, extra] = name.split("/");
          return extra !== undefined || !expected.includes(service) ||
            !["finalized_block", "weight_update_block"].includes(metric) ||
            !Number.isSafeInteger(limit) || limit < STALE_AFTER_MS || limit > 24 * 60 * 60_000;
        })) throw new Error("invalid_progress_limits");
    if (!resourceMinimums || typeof resourceMinimums !== "object" ||
        Array.isArray(resourceMinimums) || Object.keys(resourceMinimums).length > 10 ||
        Object.entries(resourceMinimums).some(([name, minimum]) =>
          !RESOURCE_METRIC.test(name) || !Number.isSafeInteger(minimum) ||
          minimum < 64 * 1024 ** 2 || minimum > 1024 ** 5)) {
      throw new Error("invalid_resource_minimums");
    }
    if (!lifecycleLimits || typeof lifecycleLimits !== "object" ||
        Array.isArray(lifecycleLimits) || Object.keys(lifecycleLimits).length > 10 ||
        Object.entries(lifecycleLimits).some(([name, limit]) => !LIFECYCLE_LABEL.test(name) ||
          !Number.isSafeInteger(limit) || limit < STALE_AFTER_MS || limit > 24 * 60 * 60_000)) {
      throw new Error("invalid_lifecycle_limits");
    }
    this.storage = storage;
    this.notify = notify;
    this.expected = expected;
    this.now = now;
    this.limits = limits;
    this.resourceMinimums = resourceMinimums;
    this.lifecycleLimits = lifecycleLimits;
  }

  async heartbeat(value) {
    const valid = validateHeartbeat(value, this.expected, this.limits, this.resourceMinimums,
      this.lifecycleLimits);
    const received_at = this.now();
    if (valid.progress) {
      const prior = await this.storage.get("heartbeat");
      valid.progress = Object.fromEntries(Object.entries(valid.progress).map(([name, cursor]) => {
        const old = prior?.progress?.[name];
        const advanced = cursor !== null && (old?.cursor == null || cursor > old.cursor);
        return [name, { cursor: advanced ? cursor : old?.cursor ?? null,
          advanced_at: advanced ? received_at : old?.advanced_at ?? received_at,
          present: cursor !== null }];
      }));
    }
    if (valid.lifecycles) {
      const prior = await this.storage.get("heartbeat");
      valid.lifecycles = Object.fromEntries(Object.entries(valid.lifecycles).map(([name, value]) => {
        const issue = lifecycleIssue(value);
        const old = prior?.lifecycles?.[name];
        const same = issue !== null && old?.issue != null &&
          (value === null || old?.cohort_sha256 === value.cohort_sha256 &&
            old?.phase === value.phase && old?.sequence === value.sequence);
        return [name, { ...(value ?? old ?? {}), issue,
          issue_since: issue === null ? received_at : same ? old.issue_since : received_at }];
      }));
    }
    await this.storage.put("heartbeat", { ...valid, received_at });
    if (await this.storage.getAlarm() === null) {
      await this.storage.setAlarm(received_at + CHECK_INTERVAL_MS);
    }
    return { accepted: true, received_at };
  }

  async status() {
    const heartbeat = await this.storage.get("heartbeat");
    return { ...observation(heartbeat, this.now(), this.limits, this.resourceMinimums,
      this.lifecycleLimits),
      received_at: heartbeat?.received_at ?? null,
      next_check: await this.storage.getAlarm(),
      notification: await this.storage.get("notification") ?? null };
  }

  async alarm() {
    const now = this.now();
    // Schedule the next check before external I/O. A prolonged email-provider
    // failure must not exhaust Cloudflare's finite automatic alarm retries.
    await this.storage.setAlarm(now + CHECK_INTERVAL_MS);
    const heartbeat = await this.storage.get("heartbeat");
    const current = observation(heartbeat, now, this.limits, this.resourceMinimums,
      this.lifecycleLimits);
    if (current.state === "unarmed") return;
    const prior = await this.storage.get("notification");
    const healthy = current.state === "healthy";
    if (healthy && (!prior || prior.state === "healthy")) return;
    // Debounce flapping while still allowing a new incident after recovery.
    if (prior && now - prior.sent_at < NOTICE_COOLDOWN_MS) return;
    if (!healthy && prior && prior.state !== "healthy" &&
        now - prior.sent_at < REMINDER_MS) return;
    const receipt = await this.notify({ ...current, observed_at: now,
      received_at: heartbeat.received_at });
    await this.storage.put("notification", { ...current, sent_at: now,
      message_id: receipt.messageId });
  }
}
