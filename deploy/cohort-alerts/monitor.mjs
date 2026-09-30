export const CHECK_INTERVAL_MS = 60_000;
export const STALE_AFTER_MS = 5 * 60_000;
export const REMINDER_MS = 60 * 60_000;
export const NOTICE_COOLDOWN_MS = 5 * 60_000;

export function validateHeartbeat(value, expected, limits = {}) {
  const tracking = Object.keys(limits).length > 0;
  if (!value || value.schema !== `umi-service-heartbeat/${tracking ? 2 : 1}` ||
      Object.keys(value).sort().join() !== (tracking ? "progress,schema,services" : "schema,services") ||
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
    return { schema: value.schema, services: { ...value.services }, progress: { ...value.progress } };
  }
  return { schema: value.schema, services: { ...value.services } };
}

export function observation(heartbeat, now, limits = {}) {
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
  return { state: failed.length ? "service_failed" : stalled.length ? "progress_stalled" : "healthy",
    failed, ...(Object.keys(limits).length ? { stalled } : {}) };
}

// Heartbeats and notification receipts use separate durable keys. A heartbeat
// received during email I/O must never be overwritten by an older alarm.
export class Monitor {
  constructor(storage, notify, expected, now = Date.now, limits = {}) {
    if (!limits || typeof limits !== "object" || Array.isArray(limits) || Object.keys(limits).length > 20 ||
        Object.entries(limits).some(([name, limit]) => {
          const [service, metric, extra] = name.split("/");
          return extra !== undefined || !expected.includes(service) ||
            !["finalized_block", "weight_update_block"].includes(metric) ||
            !Number.isSafeInteger(limit) || limit < STALE_AFTER_MS || limit > 24 * 60 * 60_000;
        })) throw new Error("invalid_progress_limits");
    this.storage = storage;
    this.notify = notify;
    this.expected = expected;
    this.now = now;
    this.limits = limits;
  }

  async heartbeat(value) {
    const valid = validateHeartbeat(value, this.expected, this.limits);
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
    await this.storage.put("heartbeat", { ...valid, received_at });
    if (await this.storage.getAlarm() === null) {
      await this.storage.setAlarm(received_at + CHECK_INTERVAL_MS);
    }
    return { accepted: true, received_at };
  }

  async status() {
    const heartbeat = await this.storage.get("heartbeat");
    return { ...observation(heartbeat, this.now(), this.limits),
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
    const current = observation(heartbeat, now, this.limits);
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
