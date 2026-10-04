import assert from "node:assert/strict";
import { test } from "node:test";
import { Monitor, STALE_AFTER_MS, REMINDER_MS, NOTICE_COOLDOWN_MS } from "./monitor.mjs";

function fixture(limits = {}, resourceMinimums = {}, lifecycleLimits = {}) {
  let now = 1_000_000;
  let alarm = null;
  const data = new Map();
  const messages = [];
  const storage = {
    async put(key, value) { data.set(key, structuredClone(value)); },
    async get(key) { return structuredClone(data.get(key)); },
    async getAlarm() { return alarm; },
    async setAlarm(value) { alarm = value; },
  };
  const notify = async message => {
    messages.push(message);
    return { messageId: `id-${messages.length}` };
  };
  const make = (send = notify) => new Monitor(storage, send, ["vali.service"], () => now,
    limits, resourceMinimums, lifecycleLimits);
  return { data, storage, messages, make, advance: n => { now += n; } };
}
const healthy = { schema: "umi-service-heartbeat/1", services: { "vali.service": "running" } };
const failed = { schema: "umi-service-heartbeat/1", services: { "vali.service": "failed" } };

test("a missing heartbeat alerts after restart and repeats only hourly", async () => {
  const f = fixture();
  await f.make().heartbeat(healthy);
  f.advance(STALE_AFTER_MS - 1);
  await f.make().alarm();
  assert.equal(f.messages.length, 0);
  f.advance(1);
  await f.make().alarm();
  assert.equal(f.messages[0].state, "heartbeat_missing");
  f.advance(REMINDER_MS - 1);
  await f.make().alarm();
  assert.equal(f.messages.length, 1);
  f.advance(1);
  await f.make().alarm();
  assert.equal(f.messages.length, 2);
});

test("healthy polls do not emit mail; service failure and recovery do", async () => {
  const f = fixture();
  await f.make().heartbeat(healthy);
  await f.make().alarm();
  assert.equal(f.messages.length, 0);
  await f.make().heartbeat(failed);
  await f.make().alarm();
  assert.deepEqual(f.messages[0].failed, ["vali.service"]);
  await f.make().heartbeat(healthy);
  await f.make().alarm();
  assert.equal(f.messages.length, 1);
  f.advance(NOTICE_COOLDOWN_MS);
  await f.make().heartbeat(healthy);
  await f.make().alarm();
  assert.equal(f.messages[1].state, "healthy");
  f.advance(NOTICE_COOLDOWN_MS);
  await f.make().heartbeat(failed);
  await f.make().alarm();
  assert.equal(f.messages[2].state, "service_failed");
});

test("failed email schedules another check and does not record delivery", async () => {
  const f = fixture();
  await f.make().heartbeat(failed);
  await assert.rejects(f.make(async () => { throw new Error("unavailable"); }).alarm());
  assert.equal(f.data.has("notification"), false);
  assert.ok(await f.storage.getAlarm());
  await f.make().alarm();
  assert.equal(f.messages.length, 1);
});

test("a heartbeat during email delivery survives the alarm's receipt write", async () => {
  const f = fixture();
  await f.make().heartbeat(failed);
  await f.make(async () => {
    f.advance(1);
    await f.make().heartbeat(healthy);
    return { messageId: "accepted" };
  }).alarm();
  assert.equal((await f.make().status()).state, "healthy");
});

test("unexpected/missing services and arbitrary text cannot refresh freshness", async () => {
  const f = fixture();
  for (const value of [null, {}, { ...healthy, extra: true },
    { ...healthy, services: {} },
    { ...healthy, services: { "other.service": "running" } },
    { ...healthy, services: { "vali.service": "secret" } }]) {
    await assert.rejects(f.make().heartbeat(value));
  }
  assert.equal((await f.make().status()).state, "unarmed");
  assert.equal(await f.storage.getAlarm(), null);
});

test("frequent failing heartbeats cannot postpone an existing alarm", async () => {
  const f = fixture();
  await f.make().heartbeat(failed);
  const alarm = await f.storage.getAlarm();
  f.advance(10_000);
  await f.make().heartbeat(failed);
  assert.equal(await f.storage.getAlarm(), alarm);
  await f.make().alarm();
  assert.equal(f.messages[0].state, "service_failed");
});

const progressLimits = { "vali.service/finalized_block": STALE_AFTER_MS,
  "vali.service/weight_update_block": 30 * 60_000 };
const native = (head, update) => ({ ...healthy, schema: "umi-service-heartbeat/2", progress: {
  "vali.service/finalized_block": head, "vali.service/weight_update_block": update,
} });

const resourceMinimums = { "coordinator-root/available_bytes": 8 * 1024 ** 3 };
const resourceHeartbeat = available => ({ ...healthy, schema: "umi-service-heartbeat/3",
  resources: { "coordinator-root/available_bytes": available } });

test("low storage alerts and a sustained recovery clears the incident", async () => {
  const f = fixture({}, resourceMinimums);
  await f.make().heartbeat(resourceHeartbeat(7 * 1024 ** 3));
  await f.make().alarm();
  assert.equal(f.messages[0].state, "resource_low");
  assert.deepEqual(f.messages[0].low, ["coordinator-root/available_bytes"]);
  assert.equal(f.messages[0].resources["coordinator-root/available_bytes"], 7 * 1024 ** 3);
  await f.make().heartbeat(resourceHeartbeat(9 * 1024 ** 3));
  await f.make().alarm();
  assert.equal(f.messages.length, 1);
  f.advance(NOTICE_COOLDOWN_MS);
  await f.make().heartbeat(resourceHeartbeat(9 * 1024 ** 3));
  await f.make().alarm();
  assert.equal(f.messages[1].state, "healthy");
});

test("resource monitoring rejects malformed configuration and heartbeats", async () => {
  for (const minimums of [null, 42, [], { bad: 8 * 1024 ** 3 },
    { "root/available_bytes": 1 },
    Object.fromEntries(Array.from({ length: 11 }, (_, n) =>
      [`disk-${n}/available_bytes`, 8 * 1024 ** 3]))]) {
    assert.throws(() => fixture({}, minimums).make(), /invalid_resource_minimums/);
  }
  const f = fixture({}, resourceMinimums);
  for (const value of [healthy, { ...resourceHeartbeat(1), resources: {} },
    resourceHeartbeat(-1), resourceHeartbeat("secret"),
    resourceHeartbeat(Number.MAX_SAFE_INTEGER + 1)]) {
    await assert.rejects(f.make().heartbeat(value));
  }
  assert.equal((await f.make().status()).state, "unarmed");
});

test("running validators with moving heads but stuck weights alert across monitor restart", async () => {
  const f = fixture(progressLimits);
  await f.make().heartbeat(native(1000, 900));
  for (let i = 1; i <= 30; i++) {
    f.advance(60_000);
    await f.make().heartbeat(native(1000 + i, 900));
    await f.make().alarm();
  }
  assert.equal(f.messages.length, 1);
  assert.equal(f.messages[0].state, "progress_stalled");
  assert.deepEqual(f.messages[0].stalled, ["vali.service/weight_update_block"]);
  f.advance(NOTICE_COOLDOWN_MS);
  await f.make().heartbeat(native(1031, 1030));
  await f.make().alarm();
  assert.equal(f.messages[1].state, "healthy");
});

test("fresh heartbeats, counter regression and missing data cannot reset stalled progress", async () => {
  const f = fixture(progressLimits);
  await f.make().heartbeat(native(1000, 900));
  for (let i = 0; i < 5; i++) {
    f.advance(60_000);
    await f.make().heartbeat(native(999, 899));
  }
  await f.make().alarm();
  assert.deepEqual(f.messages[0].stalled, ["vali.service/finalized_block"]);
  await f.make().heartbeat(native(null, null));
  assert.deepEqual((await f.make().status()).stalled, Object.keys(progressLimits));
  await f.make().heartbeat(native(1000, 900));
  assert.equal((await f.make().status()).state, "progress_stalled");
  await f.make().heartbeat(native(1001, 901));
  assert.equal((await f.make().status()).state, "healthy");
});

test("native monitoring cannot be silently disabled or accept arbitrary counters", async () => {
  for (const limits of [null, 42, [], { "vali.service/other": 300000 },
    { "other.service/finalized_block": 300000 }, { "vali.service/finalized_block": 1 }]) {
    assert.throws(() => fixture(limits).make(), /invalid_progress_limits/);
  }
  const f = fixture(progressLimits);
  for (const value of [healthy, { ...native(1, 1), progress: {} }, native(-1, 1),
    native("secret", 1), native(Number.MAX_SAFE_INTEGER + 1, 1), native(true, 1)]) {
    await assert.rejects(f.make().heartbeat(value));
  }
  await f.make().heartbeat(native(null, null));
  await f.make().alarm();
  assert.equal(f.messages[0].state, "progress_stalled");
  assert.deepEqual(f.messages[0].stalled, Object.keys(progressLimits));
});

const lifecycleLimits = { "active-cohort": 10 * 60_000 };
const lifecycle = (overrides = {}) => ({ ...healthy, schema: "umi-service-heartbeat/4",
  lifecycles: { "active-cohort": {
    cohort_sha256: "a".repeat(64), plan_sequence: 5, phase: "intake", sequence: 0,
    target_block: 100, stage: "progress_review", status: "phase_progress_review_started",
    progress_completion: "pending", progress_observed_at_block: 99, unavailable_blocks: 0,
    expected_round_sha256: null, error_type: null, public_round_sequence: 4,
    public_round_present: null, ...overrides,
  } } });

test("completed phase progress alerts only after its bounded review interval", async () => {
  const f = fixture({}, {}, lifecycleLimits);
  await f.make().heartbeat(lifecycle({ progress_completion: "complete",
    progress_observed_at_block: 120 }));
  f.advance(10 * 60_000 - 1);
  await f.make().heartbeat(lifecycle({ progress_completion: "complete",
    progress_observed_at_block: 120 }));
  await f.make().alarm();
  assert.equal(f.messages.length, 0);
  f.advance(1);
  await f.make().alarm();
  assert.equal(f.messages[0].state, "lifecycle_stalled");
  assert.deepEqual(f.messages[0].lifecycle, ["active-cohort"]);
  assert.equal(f.messages[0].lifecycles["active-cohort"].issue,
    "completed_progress_unpublished");
});

test("missing follow-up evidence cannot reset an existing lifecycle incident", async () => {
  const f = fixture({}, {}, lifecycleLimits);
  await f.make().heartbeat(lifecycle({ progress_completion: "complete",
    progress_observed_at_block: 120 }));
  f.advance(5 * 60_000);
  await f.make().heartbeat({ ...healthy, schema: "umi-service-heartbeat/4",
    lifecycles: { "active-cohort": null } });
  f.advance(5 * 60_000);
  await f.make().heartbeat({ ...healthy, schema: "umi-service-heartbeat/4",
    lifecycles: { "active-cohort": null } });
  const status = await f.make().status();
  assert.equal(status.state, "lifecycle_stalled");
  assert.equal(status.lifecycles["active-cohort"].issue, "observation_missing");
  assert.equal(status.lifecycles["active-cohort"].phase, "intake");
});

test("phase transition clears a lifecycle incident and missing round publication alerts", async () => {
  const f = fixture({}, {}, lifecycleLimits);
  await f.make().heartbeat(lifecycle({ progress_completion: "complete",
    progress_observed_at_block: 120 }));
  f.advance(10 * 60_000);
  await f.make().heartbeat(lifecycle({ progress_completion: "complete",
    progress_observed_at_block: 120 }));
  await f.make().alarm();
  await f.make().heartbeat(lifecycle({ phase: "requests", sequence: 2, target_block: 300,
    stage: "phase_start", status: "phase_decision_published", progress_completion: null,
    progress_observed_at_block: null, unavailable_blocks: null,
    expected_round_sha256: "b".repeat(64), public_round_present: false }));
  assert.equal((await f.make().status()).state, "healthy");
  f.advance(10 * 60_000);
  await f.make().heartbeat(lifecycle({ phase: "requests", sequence: 2, target_block: 300,
    stage: "phase_start", status: "phase_decision_published", progress_completion: null,
    progress_observed_at_block: null, unavailable_blocks: null,
    expected_round_sha256: "b".repeat(64), public_round_present: false }));
  const missing = await f.make().status();
  assert.equal(missing.state, "lifecycle_stalled");
  assert.equal(missing.lifecycles["active-cohort"].issue, "public_round_missing");
  await f.make().heartbeat(lifecycle({ phase: "requests", sequence: 2, target_block: 300,
    stage: "phase_start", status: "phase_decision_published", progress_completion: null,
    progress_observed_at_block: null, unavailable_blocks: null,
    expected_round_sha256: "b".repeat(64), public_round_present: true,
    public_round_sequence: 5 }));
  assert.equal((await f.make().status()).state, "healthy");
});

test("lifecycle reports reject arbitrary fields and invalid limits", async () => {
  for (const limits of [null, [], { "bad/name": 600000 }, { c5: 1 }]) {
    assert.throws(() => fixture({}, {}, limits).make(), /invalid_lifecycle_limits/);
  }
  const f = fixture({}, {}, lifecycleLimits);
  for (const value of [healthy, lifecycle({ phase: "unknown" }),
    lifecycle({ cohort_sha256: "secret" }), lifecycle({ private: "secret" })]) {
    await assert.rejects(f.make().heartbeat(value));
  }
});

test("enabling lifecycle tracking handles the prior stored heartbeat", async () => {
  const f = fixture({}, {}, lifecycleLimits);
  f.data.set("heartbeat", { ...healthy, received_at: 1_000_000 });
  f.advance(10 * 60_000);
  const status = await f.make().status();
  assert.equal(status.state, "heartbeat_missing");
});
