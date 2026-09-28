import assert from "node:assert/strict";
import { test } from "node:test";
import { Monitor, STALE_AFTER_MS, REMINDER_MS, NOTICE_COOLDOWN_MS } from "./monitor.mjs";

function fixture() {
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
  const make = (send = notify) => new Monitor(storage, send, ["vali.service"], () => now);
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
