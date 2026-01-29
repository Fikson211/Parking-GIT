'use strict';

const { Pool } = require('pg');

// Railway: DATABASE_URL
// Local: PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE
const connectionString = process.env.DATABASE_URL || null;

const pool = new Pool(
  connectionString
    ? {
        connectionString,
        // Railway Postgres обычно работает через SSL
        ssl: { rejectUnauthorized: false },
      }
    : {
        host: process.env.PGHOST || '127.0.0.1',
        port: Number(process.env.PGPORT || 5432),
        user: process.env.PGUSER || 'postgres',
        password: process.env.PGPASSWORD || '',
        database: process.env.PGDATABASE || 'postgres',
      }
);

async function dbQuery(text, params) {
  return pool.query(text, params);
}

async function ensureSchema() {
  // Таблицы (минимально необходимое)
  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.users (
      id          text PRIMARY KEY,
      fio         text,
      phone       text,
      pin         text,
      role        text DEFAULT 'user',
      zones       jsonb DEFAULT '[]'::jsonb,
      is_active   boolean DEFAULT true,
      created_at  timestamptz DEFAULT NOW()
    );
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.zones (
      id    text PRIMARY KEY,
      name  text,
      sort  integer DEFAULT 0
    );
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.devices (
      id        text PRIMARY KEY,
      name      text,
      zone_id   text,
      method    text,
      url       text,
      sort      integer DEFAULT 0,
      is_active boolean DEFAULT true
    );
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.audit (
      id          bigserial PRIMARY KEY,
      ts          timestamptz DEFAULT NOW(),
      actor_id    text,
      actor_phone text,
      actor_fio   text,
      action      text,
      target_type text,
      target_id   text,
      details     text,
      ip          text,
      ua          text
    );
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.transit_events (
      id       bigserial PRIMARY KEY,
      datetime timestamptz DEFAULT NOW(),
      point    text,
      event    text,
      source   text,
      result   text,
      session  text
    );
  `);

  // На всякий случай: если таблицы были старые без sort
  await dbQuery(`ALTER TABLE IF EXISTS public.users   ADD COLUMN IF NOT EXISTS sort integer DEFAULT 0;`);
  await dbQuery(`ALTER TABLE IF EXISTS public.zones   ADD COLUMN IF NOT EXISTS sort integer DEFAULT 0;`);
  await dbQuery(`ALTER TABLE IF EXISTS public.devices ADD COLUMN IF NOT EXISTS sort integer DEFAULT 0;`);

  // Миграции для старых схем (чтобы приложение не падало на "column ... does not exist")
  await dbQuery(`ALTER TABLE IF EXISTS public.users   ADD COLUMN IF NOT EXISTS is_active boolean DEFAULT true;`);
  await dbQuery(`ALTER TABLE IF EXISTS public.users   ADD COLUMN IF NOT EXISTS created_at timestamptz DEFAULT NOW();`);

  await dbQuery(`ALTER TABLE IF EXISTS public.zones   ADD COLUMN IF NOT EXISTS is_active boolean DEFAULT true;`);
  await dbQuery(`ALTER TABLE IF EXISTS public.devices ADD COLUMN IF NOT EXISTS is_active boolean DEFAULT true;`);
}

module.exports = { pool, dbQuery, ensureSchema };
