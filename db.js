"use strict";

const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Railway обычно требует SSL; self-signed/managed — ставим rejectUnauthorized=false
  ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false },
});

async function dbQuery(text, params) {
  return pool.query(text, params);
}

async function ensureSchema() {
  // Таблицы + "мягкие" миграции (добавляем недостающие колонки)
  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.users (
      id TEXT PRIMARY KEY,
      fio TEXT NOT NULL DEFAULT '',
      phone TEXT NOT NULL DEFAULT '',
      pin TEXT,
      role TEXT NOT NULL DEFAULT 'user',
      zones TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.zones (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      sort INTEGER NOT NULL DEFAULT 0,
      is_active BOOLEAN NOT NULL DEFAULT TRUE
    );
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.devices (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      zone_id TEXT NOT NULL REFERENCES public.zones(id) ON DELETE CASCADE,
      url TEXT NOT NULL,
      method TEXT NOT NULL DEFAULT 'GET',
      sort INTEGER NOT NULL DEFAULT 0,
      is_active BOOLEAN NOT NULL DEFAULT TRUE
    );
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.transit_events (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      point TEXT NOT NULL DEFAULT '',
      event TEXT NOT NULL DEFAULT '',
      source TEXT NOT NULL DEFAULT '',
      result TEXT NOT NULL DEFAULT '',
      session TEXT NOT NULL DEFAULT ''
    );
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.audit (
      id BIGSERIAL PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      actor_id TEXT NOT NULL DEFAULT '',
      action TEXT NOT NULL DEFAULT '',
      object TEXT NOT NULL DEFAULT '',
      details TEXT NOT NULL DEFAULT ''
    );
  `);

  // --- мягкие миграции для старых схем ---
  // users: status -> is_active, zones jsonb -> text[] и т.д. (пишем безопасно)

  // добавляем колонки если их нет
  await dbQuery(`DO $$
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='is_active') THEN
      ALTER TABLE public.users ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='created_at') THEN
      ALTER TABLE public.users ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='zones' AND column_name='sort') THEN
      ALTER TABLE public.zones ADD COLUMN sort INTEGER NOT NULL DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='zones' AND column_name='is_active') THEN
      ALTER TABLE public.zones ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='devices' AND column_name='sort') THEN
      ALTER TABLE public.devices ADD COLUMN sort INTEGER NOT NULL DEFAULT 0;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='devices' AND column_name='is_active') THEN
      ALTER TABLE public.devices ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE;
    END IF;

    -- devices.zone_id: миграция со старой колонки "zone"
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='devices' AND column_name='zone_id') THEN
      ALTER TABLE public.devices ADD COLUMN zone_id TEXT;
    END IF;
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='devices' AND column_name='zone') THEN
      UPDATE public.devices SET zone_id = zone WHERE zone_id IS NULL OR zone_id = '';
    END IF;
    -- гарантируем, что есть базовая зона и все устройства привязаны к ней
    INSERT INTO public.zones(id,name,sort,is_active)
      VALUES ('default','По умолчанию',0,TRUE)
      ON CONFLICT (id) DO NOTHING;
    UPDATE public.devices SET zone_id = 'default' WHERE zone_id IS NULL OR zone_id = '';
    -- если старая колонка zone существует — синхронизируем назад
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='devices' AND column_name='zone') THEN
      UPDATE public.devices SET zone = zone_id WHERE zone IS NULL OR zone = '';
    END IF;
    -- пытаемся сделать NOT NULL (если не получается — не валим запуск)
    BEGIN
      ALTER TABLE public.devices ALTER COLUMN zone_id SET NOT NULL;
    EXCEPTION WHEN others THEN
      NULL;
    END;

    -- audit.created_at (для старых схем)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='audit' AND column_name='created_at') THEN
      ALTER TABLE public.audit ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
    END IF;

    -- audit.* (для старых схем, когда таблица уже была создана с другим набором колонок)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='audit' AND column_name='actor_id') THEN
      ALTER TABLE public.audit ADD COLUMN actor_id text;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='audit' AND column_name='action') THEN
      ALTER TABLE public.audit ADD COLUMN action text;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='audit' AND column_name='object_type') THEN
      ALTER TABLE public.audit ADD COLUMN object_type text;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='audit' AND column_name='object_id') THEN
      ALTER TABLE public.audit ADD COLUMN object_id text;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='audit' AND column_name='detail') THEN
      ALTER TABLE public.audit ADD COLUMN detail text;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='transit_events' AND column_name='created_at') THEN
      ALTER TABLE public.transit_events ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
    END IF;
  END $$;`);

  // если в users есть колонка status (text) — пытаемся конвертнуть в is_active
  await dbQuery(`DO $$
  BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='status') THEN
      UPDATE public.users
      SET is_active = CASE WHEN LOWER(COALESCE(status,'')) IN ('active','1','true','yes') THEN TRUE ELSE FALSE END
      WHERE is_active IS NULL;
    END IF;
  END $$;`);

  // если zones в users было jsonb, а мы хотим text[] — попробуем привести
  // (не падаем, если тип уже text[])
  await dbQuery(`DO $$
  DECLARE t TEXT;
  BEGIN
    SELECT data_type INTO t
    FROM information_schema.columns
    WHERE table_schema='public' AND table_name='users' AND column_name='zones';

    IF t = 'jsonb' THEN
      ALTER TABLE public.users
        ALTER COLUMN zones TYPE TEXT[]
        USING (
          SELECT COALESCE(array_agg(value::text), ARRAY[]::text[])
          FROM jsonb_array_elements_text(zones)
        );
    END IF;
  EXCEPTION WHEN others THEN
    -- игнорируем, если преобразование невозможно
    NULL;
  END $$;`);
}

module.exports = {
  pool,
  dbQuery,
  ensureSchema,
};
