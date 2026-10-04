import assert from "node:assert/strict";
import { test } from "node:test";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const { Miniflare, convertV4MiniflareOptions } = createRequire(import.meta.url)("miniflare");

for (const [withProgress, withResources, withLifecycle] of [
  [false, false, false], [true, false, false], [false, true, false], [true, true, false],
  [false, true, true],
]) {
test(`Workers runtime persists bounded heartbeat (native=${withProgress}, resources=${withResources}, lifecycle=${withLifecycle})`, async () => {
  const mf = new Miniflare(convertV4MiniflareOptions({
    modulesRoot: fileURLToPath(new URL(".", import.meta.url)),
    modules: ["worker.mjs", "monitor.mjs"].map(name => ({
      type: "ESModule", path: fileURLToPath(new URL(name, import.meta.url)),
    })),
    compatibilityDate: "2026-09-28", compatibilityFlags: ["nodejs_compat"],
    durableObjects: { MONITORS: { className: "CohortMonitor", useSQLite: true } },
    bindings: {
      HEARTBEAT_TOKEN: "test-only", NODE_NAME: "test", EXPECTED_SERVICES: "vali.service",
      ALERT_TO: "operator@example.com", ALERT_FROM: "cohorts@alerts.example.com",
      PROGRESS_LIMITS: withProgress ? JSON.stringify({
        "vali.service/finalized_block": 300000, "vali.service/weight_update_block": 1800000,
      }) : "{}",
      RESOURCE_MINIMUMS: withResources ? JSON.stringify({
        "coordinator-root/available_bytes": 8 * 1024 ** 3,
      }) : "{}",
      LIFECYCLE_LIMITS: withLifecycle ? JSON.stringify({ "cohort-5": 600000 }) : "{}",
    },
  }));
  try {
    const headers = { Authorization: "Bearer test-only" };
    assert.equal((await mf.dispatchFetch("https://monitor/status")).status, 401);
    assert.equal((await mf.dispatchFetch("https://monitor/status", {
      headers: { Authorization: "Bearer wrong-key" },
    })).status, 401);
    assert.equal((await mf.dispatchFetch("https://monitor/heartbeat", {
      headers, method: "POST", body: "x".repeat(16385),
    })).status, 413);
    assert.equal((await mf.dispatchFetch("https://monitor/heartbeat", {
      headers, method: "POST", body: JSON.stringify({ schema: "umi-service-heartbeat/1", services: {} }),
    })).status, 400);
    assert.equal((await (await mf.dispatchFetch("https://monitor/status", { headers })).json()).state, "unarmed");
    const response = await mf.dispatchFetch("https://monitor/heartbeat", {
      headers, method: "POST", body: JSON.stringify({
        schema: `umi-service-heartbeat/${withLifecycle ? 4 : withResources ? 3 : withProgress ? 2 : 1}`,
        services: { "vali.service": "running" },
        ...(withProgress ? { progress: { "vali.service/finalized_block": 1000,
          "vali.service/weight_update_block": 950 } } : {}),
        ...(withResources ? { resources: {
          "coordinator-root/available_bytes": 9 * 1024 ** 3,
        } } : {}),
        ...(withLifecycle ? { lifecycles: { "cohort-5": {
          cohort_sha256: "a".repeat(64), plan_sequence: 5, phase: "intake", sequence: 0,
          target_block: 100, stage: "progress_sampling", status: "waiting_phase_progress",
          progress_completion: "pending", progress_observed_at_block: 99, unavailable_blocks: 0,
          expected_round_sha256: null, error_type: null, public_round_sequence: 3,
          public_round_present: null,
        } } } : {}),
      }),
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).accepted, true);
    const status = await (await mf.dispatchFetch("https://monitor/status", { headers })).json();
    assert.equal(status.state, "healthy");
    assert.ok(status.next_check > status.received_at);
    assert.equal(status.notification, null);
    if (withProgress) {
      assert.equal((await mf.dispatchFetch("https://monitor/heartbeat", {
        headers, method: "POST", body: JSON.stringify({
          schema: "umi-service-heartbeat/1", services: { "vali.service": "running" },
        }),
      })).status, 400);
      await mf.dispatchFetch("https://monitor/heartbeat", {
        headers, method: "POST", body: JSON.stringify({
          schema: `umi-service-heartbeat/${withResources ? 3 : 2}`,
          services: { "vali.service": "running" },
          progress: { "vali.service/finalized_block": null, "vali.service/weight_update_block": null },
          ...(withResources ? { resources: {
            "coordinator-root/available_bytes": 9 * 1024 ** 3,
          } } : {}),
        }),
      });
      assert.equal((await (await mf.dispatchFetch("https://monitor/status", { headers })).json()).state,
        "progress_stalled");
    } else if (withResources && !withLifecycle) {
      await mf.dispatchFetch("https://monitor/heartbeat", {
        headers, method: "POST", body: JSON.stringify({
          schema: "umi-service-heartbeat/3", services: { "vali.service": "running" },
          resources: { "coordinator-root/available_bytes": 7 * 1024 ** 3 },
        }),
      });
      assert.equal((await (await mf.dispatchFetch("https://monitor/status", { headers })).json()).state,
        "resource_low");
    } else if (withLifecycle) {
      assert.equal((await mf.dispatchFetch("https://monitor/heartbeat", {
        headers, method: "POST", body: JSON.stringify({
          schema: "umi-service-heartbeat/3", services: { "vali.service": "running" },
          resources: { "coordinator-root/available_bytes": 9 * 1024 ** 3 },
        }),
      })).status, 400);
    }
  } finally {
    await mf.dispose();
  }
});
}
