const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL || process.env.DATABASE_URL_POSTGRES || process.env.POSTGRES_URL;

const pool = DATABASE_URL
  ? new Pool({
      connectionString: DATABASE_URL,
      ssl: { rejectUnauthorized: false },
    })
  : null;

async function initSchema() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS zones (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      sort INT DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      zone_id TEXT REFERENCES zones(id) ON DELETE SET NULL,
      method TEXT DEFAULT 'GET',
      url TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      fio TEXT NOT NULL,
      phone TEXT UNIQUE NOT NULL,
      role TEXT DEFAULT 'user',
      status TEXT DEFAULT 'active',
      pin TEXT,
      zones TEXT[] DEFAULT '{}'::text[]
    );

    CREATE TABLE IF NOT EXISTS audit (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      actor TEXT,
      action TEXT,
      object_type TEXT,
      object_id TEXT,
      ip TEXT,
      details JSONB
    );

    CREATE TABLE IF NOT EXISTS transit_events (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      point TEXT,
      event TEXT,
      actor TEXT,
      result TEXT,
      session_id TEXT
    );
  `);
}

module.exports = { pool, initSchema };
