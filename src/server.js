import "./config.js";
import crypto from "node:crypto";
import express from "express";
import { db } from "./db.js";
import {
  escapeHtml,
  extractBearer,
  formatDate,
  randomToken,
  slugify,
  timingSafeEqualText
} from "./util.js";

const app = express();
const port = Number(process.env.PORT || 8080);
const secret = process.env.APP_SECRET || "change-this-secret";
const adminUser = process.env.ADMIN_USERNAME || "admin";
const adminPassword = process.env.ADMIN_PASSWORD || "admin";

if (process.env.TRUST_PROXY === "true") app.set("trust proxy", 1);

app.use(express.json({ limit: "128kb" }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));

function sign(value) {
  return crypto.createHmac("sha256", secret).update(value).digest("hex");
}

function parseCookies(req) {
  return Object.fromEntries(
    String(req.get("cookie") || "")
      .split(";")
      .map((part) => part.trim().split("="))
      .filter(([key, value]) => key && value)
  );
}

function isAuthed(req) {
  const token = parseCookies(req).session || "";
  const [value, mac] = token.split(".");
  return value === "admin" && mac && timingSafeEqualText(mac, sign(value));
}

function requireAuth(req, res, next) {
  if (isAuthed(req)) return next();
  res.redirect("/login");
}

function setSession(res) {
  const value = "admin";
  const secure = process.env.COOKIE_SECURE === "true" ? " Secure;" : "";
  res.setHeader("Set-Cookie", `session=${value}.${sign(value)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800;${secure}`);
}

function clearSession(res) {
  res.setHeader("Set-Cookie", "session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
}

function render(res, view, data = {}) {
  const html = views[view](data);
  res.type("html").send(layout(html, data));
}

function getDashboardData() {
  const clients = db.prepare("SELECT * FROM clients ORDER BY name").all();
  const apps = db.prepare(`
    SELECT apps.*, clients.name AS client_name, clients.slug AS client_slug
    FROM apps
    JOIN clients ON clients.id = apps.client_id
    ORDER BY clients.name, apps.name
  `).all();
  const codes = db.prepare(`
    SELECT codes.*, clients.name AS client_name, clients.slug AS client_slug, apps.name AS app_name, apps.slug AS app_slug
    FROM codes
    JOIN clients ON clients.id = codes.client_id
    JOIN apps ON apps.id = codes.app_id
    ORDER BY codes.id DESC
    LIMIT 50
  `).all();
  return { clients, apps, codes };
}

function getBaseUrl(req) {
  return `${req.protocol}://${req.get("host")}`;
}

function maskToken(token) {
  const value = String(token || "");
  if (value.length <= 12) return value;
  return `${value.slice(0, 6)}...${value.slice(-6)}`;
}

app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/login", (req, res) => render(res, "login", { title: "Sign In", authed: false }));

app.post("/login", (req, res) => {
  const usernameOk = timingSafeEqualText(req.body.username, adminUser);
  const passwordOk = timingSafeEqualText(req.body.password, adminPassword);
  if (!usernameOk || !passwordOk) {
    render(res.status(401), "login", { title: "Sign In", error: "Invalid username or password", authed: false });
    return;
  }
  setSession(res);
  res.redirect("/");
});

app.post("/logout", (req, res) => {
  clearSession(res);
  res.redirect("/login");
});

app.get("/", requireAuth, (req, res) => render(res, "dashboard", {
  title: "OTP Hub",
  authed: true,
  baseUrl: getBaseUrl(req),
  ...getDashboardData()
}));

app.post("/clients", requireAuth, (req, res) => {
  const name = String(req.body.name || "").trim();
  const slug = slugify(req.body.slug || name);
  if (!name || !slug) return res.status(400).send("Missing name or slug");
  db.prepare("INSERT INTO clients (name, slug, ingest_token, read_token) VALUES (?, ?, ?, ?)")
    .run(name, slug, randomToken(), randomToken());
  res.redirect("/");
});

app.post("/clients/:id/delete", requireAuth, (req, res) => {
  db.prepare("DELETE FROM clients WHERE id = ?").run(req.params.id);
  res.redirect("/");
});

app.post("/apps", requireAuth, (req, res) => {
  const clientId = Number(req.body.client_id);
  const name = String(req.body.name || "").trim();
  const slug = slugify(req.body.slug || name);
  const senderMatch = String(req.body.sender_match || "").trim();
  const codeRegex = String(req.body.code_regex || "(?<!\\d)(\\d{6})(?!\\d)").trim();
  const ttl = Math.max(30, Math.min(86400, Number(req.body.ttl_seconds || 600)));
  if (!clientId || !name || !slug) return res.status(400).send("Missing app fields");
  db.prepare("INSERT INTO apps (client_id, name, slug, sender_match, code_regex, ttl_seconds) VALUES (?, ?, ?, ?, ?, ?)")
    .run(clientId, name, slug, senderMatch, codeRegex, ttl);
  res.redirect("/");
});

app.post("/apps/:id/delete", requireAuth, (req, res) => {
  db.prepare("DELETE FROM apps WHERE id = ?").run(req.params.id);
  res.redirect("/");
});

app.post("/api/webhook/:clientSlug/:appSlug", (req, res) => {
  const requestMeta = {
    client: req.params.clientSlug,
    app: req.params.appSlug,
    contentType: req.get("content-type") || "",
    keys: req.body && typeof req.body === "object" ? Object.keys(req.body) : [],
    sender: String(req.body?.from || req.body?.sender || "").slice(0, 80)
  };
  const client = db.prepare("SELECT * FROM clients WHERE slug = ?").get(req.params.clientSlug);
  if (!client || !timingSafeEqualText(extractBearer(req), client.ingest_token)) {
    console.warn("webhook unauthorized", requestMeta);
    return res.status(401).json({ error: "unauthorized" });
  }

  const appRow = db.prepare("SELECT * FROM apps WHERE client_id = ? AND slug = ?").get(client.id, req.params.appSlug);
  if (!appRow) {
    console.warn("webhook app_not_found", requestMeta);
    return res.status(404).json({ error: "app_not_found" });
  }

  const sender = String(req.body.from || req.body.sender || "");
  const body = String(req.body.body || req.body.message || req.body.text || req.body.sms || JSON.stringify(req.body));
  if (appRow.sender_match && !sender.toLowerCase().includes(appRow.sender_match.toLowerCase())) {
    console.info("webhook ignored sender_mismatch", { ...requestMeta, sender, senderMatch: appRow.sender_match });
    return res.status(202).json({ ok: true, ignored: "sender_mismatch" });
  }

  let regex;
  try {
    regex = new RegExp(appRow.code_regex);
  } catch {
    regex = /(?<!\d)(\d{6})(?!\d)/;
  }
  const match = body.match(regex);
  const code = match?.[1] || match?.[0];
  if (!code) {
    console.warn("webhook no_code_found", {
      ...requestMeta,
      bodyPreview: body.slice(0, 240),
      regex: appRow.code_regex
    });
    return res.status(422).json({ error: "no_code_found" });
  }

  db.prepare("INSERT INTO codes (client_id, app_id, code, sender, body) VALUES (?, ?, ?, ?, ?)")
    .run(client.id, appRow.id, code, sender, body);
  console.info("webhook code_stored", { ...requestMeta, code, sender });
  res.json({ ok: true });
});

app.get("/api/latest/:clientSlug/:appSlug", (req, res) => {
  const client = db.prepare("SELECT * FROM clients WHERE slug = ?").get(req.params.clientSlug);
  if (!client || !timingSafeEqualText(extractBearer(req), client.read_token)) {
    return res.status(401).json({ error: "unauthorized" });
  }
  const row = db.prepare(`
    SELECT codes.*, apps.ttl_seconds, apps.slug AS app_slug, apps.name AS app_name
    FROM codes
    JOIN apps ON apps.id = codes.app_id
    WHERE codes.client_id = ? AND apps.slug = ?
    ORDER BY codes.id DESC
    LIMIT 1
  `).get(client.id, req.params.appSlug);
  if (!row) return res.status(404).json({ error: "no_code" });

  const ageSeconds = (Date.now() - Date.parse(`${row.received_at}Z`)) / 1000;
  if (ageSeconds > row.ttl_seconds) return res.status(404).json({ error: "code_expired" });

  res.json({
    code: row.code,
    client: client.slug,
    app: row.app_slug,
    receivedAt: new Date(`${row.received_at}Z`).toISOString()
  });
});

function layout(content, data) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(data.title || "SMS OTP Hub")}</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/">SMS OTP Hub</a>
    ${data.authed ? '<form method="post" action="/logout"><button class="ghost" type="submit">Sign out</button></form>' : ""}
  </header>
  <main>${content}</main>
  <script>
    document.querySelectorAll("[data-tab-target]").forEach((button) => {
      button.addEventListener("click", () => {
        const target = button.dataset.tabTarget;
        document.querySelectorAll("[data-tab-target]").forEach((tab) => {
          const active = tab === button;
          tab.classList.toggle("active", active);
          tab.setAttribute("aria-selected", String(active));
        });
        document.querySelectorAll("[data-tab-panel]").forEach((panel) => {
          panel.hidden = panel.dataset.tabPanel !== target;
        });
      });
    });

    document.querySelectorAll("[data-copy]").forEach((button) => {
      button.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(button.dataset.copy || "");
          const label = button.textContent;
          button.textContent = "Copied";
          window.setTimeout(() => { button.textContent = label; }, 1200);
        } catch {
          button.textContent = "Copy failed";
        }
      });
    });
  </script>
</body>
</html>`;
}

const views = {
  login: ({ error }) => `
    <section class="login-shell">
      <form class="panel login-panel" method="post" action="/login">
        <h1>Sign in</h1>
        ${error ? `<p class="alert">${escapeHtml(error)}</p>` : ""}
        <label>Username<input name="username" autocomplete="username" required></label>
        <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
        <button class="primary" type="submit">Sign in</button>
      </form>
    </section>
  `,
  dashboard: ({ clients, apps, codes, baseUrl }) => `
    <section class="tabs-shell">
      <div class="tabs" role="tablist" aria-label="Dashboard sections">
        <button class="tab active" type="button" role="tab" aria-selected="true" data-tab-target="messages">Recent messages</button>
        <button class="tab" type="button" role="tab" aria-selected="false" data-tab-target="apps">Apps</button>
        <button class="tab" type="button" role="tab" aria-selected="false" data-tab-target="clients">Clients</button>
      </div>

      <div class="panel" data-tab-panel="messages">
        <h1>Recent messages</h1>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Code</th><th>Client</th><th>App</th><th>Sender</th><th>Received</th><th>Message</th><th></th></tr></thead>
            <tbody>${codes.map((code) => `
              <tr>
                <td><strong>${escapeHtml(code.code)}</strong></td>
                <td>${escapeHtml(code.client_name)}</td>
                <td>${escapeHtml(code.app_name)}</td>
                <td>${escapeHtml(code.sender)}</td>
                <td>${escapeHtml(formatDate(code.received_at))}</td>
                <td class="truncate">${escapeHtml(code.body)}</td>
                <td><button class="copy" type="button" data-copy="${escapeHtml(code.body)}">Copy</button></td>
              </tr>`).join("") || '<tr><td colspan="7">No codes received yet.</td></tr>'}</tbody>
          </table>
        </div>
      </div>

      <div class="panel" data-tab-panel="apps" hidden>
        <h1>Apps</h1>
        <form class="app-form" method="post" action="/apps">
          <select name="client_id" required>
            <option value="">Client</option>
            ${clients.map((client) => `<option value="${client.id}">${escapeHtml(client.name)}</option>`).join("")}
          </select>
          <input name="name" placeholder="App name" required>
          <input name="slug" placeholder="slug optional">
          <input name="sender_match" placeholder="sender contains">
          <input name="code_regex" value="(?<!\\d)(\\d{6})(?!\\d)">
          <input name="ttl_seconds" type="number" min="30" max="86400" value="600">
          <button class="primary" type="submit">Add app</button>
        </form>
        <div class="help-section">
          <h2>Webhook format</h2>
          <div class="help-grid">
            <div>
              <h3>Headers</h3>
              <code>Authorization: Bearer {client ingest token}</code>
              <code>Content-Type: application/json</code>
            </div>
            <div>
              <h3>Body</h3>
              <code>{"from":"Bank","body":"Your code is 123456"}</code>
              <p>Accepted message keys: <code>body</code>, <code>message</code>, <code>text</code>, or <code>sms</code>. Accepted sender keys: <code>from</code> or <code>sender</code>.</p>
            </div>
          </div>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Client</th><th>App</th><th>Webhook</th><th>Latest API</th><th></th></tr></thead>
            <tbody>${apps.map((app) => {
              const webhookUrl = `${baseUrl}/api/webhook/${app.client_slug}/${app.slug}`;
              const latestUrl = `${baseUrl}/api/latest/${app.client_slug}/${app.slug}`;
              return `
              <tr>
                <td>${escapeHtml(app.client_name)}</td>
                <td>${escapeHtml(app.name)} <code>${escapeHtml(app.slug)}</code></td>
                <td><div class="copy-row"><code>${escapeHtml(webhookUrl)}</code><button class="copy" type="button" data-copy="${escapeHtml(webhookUrl)}">Copy</button></div></td>
                <td><div class="copy-row"><code>${escapeHtml(latestUrl)}</code><button class="copy" type="button" data-copy="${escapeHtml(latestUrl)}">Copy</button></div></td>
                <td><form method="post" action="/apps/${app.id}/delete"><button class="danger" type="submit">Delete</button></form></td>
              </tr>`;
            }).join("") || '<tr><td colspan="5">No apps yet.</td></tr>'}</tbody>
          </table>
        </div>
      </div>

      <div class="panel" data-tab-panel="clients" hidden>
        <h1>Clients</h1>
        <form class="inline-form" method="post" action="/clients">
          <input name="name" placeholder="Client name" required>
          <input name="slug" placeholder="slug optional">
          <button class="primary" type="submit">Add</button>
        </form>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Slug</th><th>Ingest Token</th><th>Read Token</th><th></th></tr></thead>
            <tbody>${clients.map((client) => `
              <tr>
                <td>${escapeHtml(client.name)}</td>
                <td><code>${escapeHtml(client.slug)}</code></td>
                <td><div class="copy-row"><span class="token-mask">${escapeHtml(maskToken(client.ingest_token))}</span><button class="copy" type="button" data-copy="${escapeHtml(client.ingest_token)}">Copy</button></div></td>
                <td><div class="copy-row"><span class="token-mask">${escapeHtml(maskToken(client.read_token))}</span><button class="copy" type="button" data-copy="${escapeHtml(client.read_token)}">Copy</button></div></td>
                <td><form method="post" action="/clients/${client.id}/delete"><button class="danger" type="submit">Delete</button></form></td>
              </tr>`).join("") || '<tr><td colspan="5">No clients yet.</td></tr>'}</tbody>
          </table>
        </div>
      </div>
    </section>
  `
};

app.listen(port, () => {
  console.log(`SMS OTP Hub listening on ${port}`);
});
