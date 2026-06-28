import "./config.js";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";

const dataDir = process.env.DATA_DIR || join(process.cwd(), "data");
mkdirSync(dataDir, { recursive: true });

export const dbPath = join(dataDir, "sms-otp-hub.sqlite");
export const db = new DatabaseSync(dbPath);
db.exec("PRAGMA journal_mode = WAL");
db.exec("PRAGMA foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    ingest_token TEXT NOT NULL,
    read_token TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS apps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    sender_match TEXT NOT NULL DEFAULT '',
    code_regex TEXT NOT NULL DEFAULT '(?<!\\\\d)(\\\\d{6})(?!\\\\d)',
    ttl_seconds INTEGER NOT NULL DEFAULT 600,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(client_id, slug)
  );

  CREATE TABLE IF NOT EXISTS codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    app_id INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    sender TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    received_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_codes_latest ON codes(client_id, app_id, id DESC);
`);
