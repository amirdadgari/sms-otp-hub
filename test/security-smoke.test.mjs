import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

test("admin login, token separation, OTP filtering and persistence", { timeout: 30000 }, async () => {
  const dataDir = await mkdtemp(join(tmpdir(), "sms-otp-smoke-"));
  const env = { ...process.env, PORT: "18080", DATA_DIR: dataDir,
    APP_SECRET: randomUUID(), ADMIN_USERNAME: "smoke-admin", ADMIN_PASSWORD: randomUUID(),
    TRUST_PROXY: "false", COOKIE_SECURE: "false" };
  const request = (path, options = {}) => fetch(`http://127.0.0.1:18080${path}`, { redirect: "manual", ...options });
  let server;
  let db;
  let output = "";
  const stop = async () => {
    if (!server || server.exitCode !== null || server.signalCode !== null) return;
    const exited = once(server, "exit");
    server.kill("SIGTERM");
    await exited;
  };
  const start = async () => {
    server = spawn(process.execPath, ["--experimental-sqlite", "src/server.js"], { env, stdio: ["ignore", "pipe", "pipe"] });
    server.stdout.on("data", chunk => { output += chunk; });
    server.stderr.on("data", chunk => { output += chunk; });
    for (let attempt = 0; attempt < 100; attempt++) {
      if (server.exitCode !== null) throw new Error(`Server exited: ${output}`);
      try { if ((await request("/health")).status === 200) return; } catch {}
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw new Error(`Server did not become ready: ${output}`);
  };
  try {
    await start();
    assert.equal((await request("/")).status, 302);
    assert.equal((await request("/login")).status, 200);
    const form = body => ({ method: "POST", body: new URLSearchParams(body) });
    assert.equal((await request("/login", form({ username: env.ADMIN_USERNAME, password: "wrong" }))).status, 401);
    const login = await request("/login", form({ username: env.ADMIN_USERNAME, password: env.ADMIN_PASSWORD }));
    assert.equal(login.status, 302);
    const setCookie = login.headers.get("set-cookie");
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Lax/);
    const cookie = setCookie.split(";")[0];
    const adminForm = body => ({ ...form(body), headers: { cookie } });
    assert.equal((await request("/clients", adminForm({ name: "Smoke client", slug: "smoke-client" }))).status, 302);
    db = new DatabaseSync(join(dataDir, "sms-otp-hub.sqlite"));
    const client = db.prepare("SELECT * FROM clients WHERE slug = ?").get("smoke-client");
    assert.notEqual(client.ingest_token, client.read_token);
    assert.equal((await request("/apps", adminForm({ client_id: client.id, name: "Smoke app", slug: "smoke-app", sender_match: "bank", ttl_seconds: 600 }))).status, 302);
    const webhook = "/api/webhook/smoke-client/smoke-app";
    const latest = "/api/latest/smoke-client/smoke-app";
    const sms = (token, from, body) => ({ method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify({ from, body }) });
    const read = token => ({ headers: { authorization: `Bearer ${token}` } });
    assert.equal((await request(webhook, sms(client.read_token, "TestBank", "OTP 123456"))).status, 401);
    assert.equal((await request(latest, read(client.ingest_token))).status, 401);
    assert.equal((await request(latest, read(client.read_token))).status, 404);
    assert.equal((await request(webhook, sms(client.ingest_token, "Other", "OTP 123456"))).status, 202);
    assert.equal((await request(webhook, sms(client.ingest_token, "TestBank", "No numeric code"))).status, 422);
    assert.equal((await request(webhook, sms(client.ingest_token, "TestBank", "OTP 123456"))).status, 200);
    assert.equal((await (await request(latest, read(client.read_token))).json()).code, "123456");
    db.prepare("UPDATE codes SET received_at = datetime('now', '-2 days')").run();
    assert.equal((await (await request(latest, read(client.read_token))).json()).error, "code_expired");
    assert.equal((await request(webhook, sms(client.ingest_token, "TestBank", "OTP 654321"))).status, 200);
    db.close();
    db = null;
    await stop();
    await start();
    assert.equal((await (await request(latest, read(client.read_token))).json()).code, "654321");
    assert.equal((await request("/", { headers: { cookie } })).status, 200);
    db = new DatabaseSync(join(dataDir, "sms-otp-hub.sqlite"));
    assert.equal(db.prepare("PRAGMA integrity_check").get().integrity_check, "ok");
    assert.equal((await request(`/clients/${client.id}/delete`, adminForm({}))).status, 302);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM apps").get().n, 0);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM codes").get().n, 0);
  } finally {
    db?.close();
    await stop();
    await rm(dataDir, { recursive: true, force: true });
  }
});
