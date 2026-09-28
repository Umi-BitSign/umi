export const CHECK_INTERVAL_MS = 60_000;
export const STALE_AFTER_MS = 5 * 60_000;
export const REMINDER_MS = 60 * 60_000;
export const NOTICE_COOLDOWN_MS = 5 * 60_000;

export function validateHeartbeat(value, expected) {
  if (!value || value.schema !== "umi-service-heartbeat/1" ||
      Object.keys(value).sort().join() !== "schema,services" ||
      !value.services || Array.isArray(value.services) ||
      Object.keys(value.services).sort().join() !== [...expected].sort().join() ||
      Object.values(value.services).some(v => v !== "running" && v !== "failed")) {
    throw new Error("invalid_heartbeat");
  }
  return { schema: value.schema, services: { ...value.services } };
}

export function observation(heartbeat, now) {
  if (!heartbeat) return { state: "unarmed", failed: [] };
  if (now - heartbeat.received_at >= STALE_AFTER_MS) {
    return { state: "heartbeat_missing", failed: [] };
  }
  const failed = Object.entries(heartbeat.services)
    .filter(([, status]) => status !== "running").map(([name]) => name).sort();
  return { state: failed.length ? "service_failed" : "healthy", failed };
}

// Heartbeats and notification receipts use separate durable keys. A heartbeat
// received during email I/O must never be overwritten by an older alarm.
export class Monitor {
  constructor(storage, notify, expected, now = Date.now) {
    this.storage = storage;
    this.notify = notify;
    this.expected = expected;
    this.now = now;
  }

  async heartbeat(value) {
    const valid = validateHeartbeat(value, this.expected);
    const received_at = this.now();
    await this.storage.put("heartbeat", { ...valid, received_at });
    if (await this.storage.getAlarm() === null) {
      await this.storage.setAlarm(received_at + CHECK_INTERVAL_MS);
    }
    return { accepted: true, received_at };
  }

  async status() {
    const heartbeat = await this.storage.get("heartbeat");
    return { ...observation(heartbeat, this.now()),
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
    const current = observation(heartbeat, now);
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
