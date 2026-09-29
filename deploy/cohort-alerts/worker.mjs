import { DurableObject } from "cloudflare:workers";
import { timingSafeEqual } from "node:crypto";
import { Monitor } from "./monitor.mjs";

export class CohortMonitor extends DurableObject {
  monitor() {
    return new Monitor(this.ctx.storage, notice => this.env.EMAIL.send({
      to: this.env.ALERT_TO,
      from: this.env.ALERT_FROM,
      subject: `UMI ${this.env.NODE_NAME}: ${notice.state}`,
      text: [
        `Node: ${this.env.NODE_NAME}`,
        `State: ${notice.state}`,
        `Observed (UTC): ${new Date(notice.observed_at).toISOString()}`,
        `Last heartbeat (UTC): ${new Date(notice.received_at).toISOString()}`,
        `Failed services: ${notice.failed.join(", ") || "none reported"}`,
        `Stalled or missing progress: ${notice.stalled?.join(", ") || "none reported"}`,
        "",
        "Observations come from the configured host. A weight update does not",
        "by itself establish correct allocation or received reward payments.",
      ].join("\n"),
    }), this.env.EXPECTED_SERVICES.split(","), Date.now,
    JSON.parse(this.env.PROGRESS_LIMITS || "{}"));
  }
  async heartbeat(value) { return this.monitor().heartbeat(value); }
  async status() { return this.monitor().status(); }
  async alarm() {
    try {
      await this.monitor().alarm();
    } catch {
      console.error(JSON.stringify({ event: "cohort_monitor_check_failed" }));
      throw new Error("cohort_monitor_check_failed");
    }
  }
}

export default {
  async fetch(request, env) {
    const supplied = new TextEncoder().encode(request.headers.get("authorization") ?? "");
    const expected = new TextEncoder().encode(`Bearer ${env.HEARTBEAT_TOKEN}`);
    if (!env.HEARTBEAT_TOKEN || supplied.length !== expected.length ||
        !timingSafeEqual(supplied, expected)) {
      return new Response("Unauthorized", { status: 401 });
    }
    const path = new URL(request.url).pathname;
    const monitor = env.MONITORS.getByName(env.NODE_NAME);
    if (path === "/status" && request.method === "GET") {
      return Response.json(await monitor.status(), { headers: { "cache-control": "no-store" } });
    }
    if (path !== "/heartbeat" || request.method !== "POST") {
      return new Response("Not found", { status: 404 });
    }
    const reader = request.body?.getReader();
    if (!reader) return new Response("Invalid heartbeat", { status: 400 });
    let length = 0;
    const chunks = [];
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        length += value.length;
        if (length > 16384) {
          await reader.cancel();
          return new Response("Too large", { status: 413 });
        }
        chunks.push(value);
      }
      const body = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
      const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
      return Response.json(await monitor.heartbeat(value));
    } catch {
      return new Response("Heartbeat not accepted", { status: 400 });
    } finally {
      reader.releaseLock();
    }
  },
};
