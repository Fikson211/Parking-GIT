const { Pool } = require('pg');

const DATABASE_URL = process.env.DATABASE_URL || process.env.PG_URL || '';

// Railway/Render/Heroku часто требуют SSL.
// Чтобы не ловить ошибки сертификата — используем rejectUnauthorized:false.
const useSSL =
  String(process.env.PGSSL || '').toLowerCase() === 'true' ||
  /sslmode=require/i.test(DATABASE_URL);

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: useSSL ? { rejectUnauthorized: false } : undefined,
});

function dbQuery(text, params) {
  return pool.query(text, params);
}

async function ensureSchema() {
  // 1) Создаём таблицы, если их ещё нет
  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.users (
      id TEXT PRIMARY KEY,
      fio TEXT,
      phone TEXT,
      pin TEXT,
      role TEXT DEFAULT 'user',
                  is_is_admin BOOLEAN DEFAULT FALSE,
organization TEXT,
      position TEXT,
zones TEXT[] NOT NULL DEFAULT '{}'::text[],
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.zones (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      sort INT DEFAULT 0,
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.devices (
      id TEXT PRIMARY KEY,
      name TEXT,
      zone_id TEXT,
      zone TEXT,
      type TEXT,
      method TEXT,
      url TEXT,
      ip TEXT,
      relay TEXT,
      params JSONB,
      enabled BOOLEAN DEFAULT TRUE,
      sort INT DEFAULT 0,
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.transit_logs (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ DEFAULT NOW(),
      user_id TEXT,
      user_phone TEXT,
      user_fio TEXT,
      device_id TEXT,
      device_name TEXT,
      zone_id TEXT,
      action TEXT,
      success BOOLEAN DEFAULT TRUE,
      details JSONB,
      ip TEXT,
      ua TEXT
    );
  `);

  // Transit journal (UI: "Журнал транзита")
  // Used by /logs, /logs.csv and /logs/clear
  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.transit_events (
      id BIGSERIAL PRIMARY KEY,
      datetime TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      point TEXT,
      event TEXT,
      source TEXT,
      result TEXT,
      session TEXT
    );
  `);

  // Helpful index for recent-first queries
  await dbQuery(`CREATE INDEX IF NOT EXISTS idx_transit_events_datetime_desc ON public.transit_events(datetime DESC);`);

  await dbQuery(`
    CREATE TABLE IF NOT EXISTS public.audit (
      id BIGSERIAL PRIMARY KEY,
      ts TIMESTAMPTZ DEFAULT NOW(),
      actor_id TEXT,
      actor_phone TEXT,
      actor_fio TEXT,
      action TEXT,
      target_type TEXT,
      target_id TEXT,
      -- старые поля (если проект раньше так назывался)
      object_type TEXT,
      object_id TEXT,
      details JSONB,
      ip TEXT,
      ua TEXT
    );
  `);

  // 2) МИГРАЦИИ: добавляем недостающие колонки в существующих таблицах
  // users
  await dbQuery(`ALTER TABLE public.users ADD COLUMN IF NOT EXISTS fio TEXT;`);
  await dbQuery(`ALTER TABLE public.users ADD COLUMN IF NOT EXISTS phone TEXT;`);
  await dbQuery(`ALTER TABLE public.users ADD COLUMN IF NOT EXISTS pin TEXT;`);
  await dbQuery(`ALTER TABLE public.users ADD COLUMN IF NOT EXISTS role TEXT;`);
  await dbQuery(`ALTER TABLE public.users ADD COLUMN IF NOT EXISTS is_is_admin BOOLEAN DEFAULT FALSE;`);
  await dbQuery(`ALTER TABLE public.users ADD COLUMN IF NOT EXISTS organization TEXT;`);
  await dbQuery(`ALTER TABLE public.users ADD COLUMN IF NOT EXISTS position TEXT;`);
  await dbQuery(`ALTER TABLE public.users ADD COLUMN IF NOT EXISTS zones TEXT[];`);
  await dbQuery(`ALTER TABLE public.users ADD COLUMN IF NOT EXISTS is_active BOOLEAN;`);
  await dbQuery(`ALTER TABLE public.users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;`);
  await dbQuery(`ALTER TABLE public.users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;`);
  await dbQuery(`UPDATE public.users SET is_is_admin = COALESCE(is_is_admin, FALSE);`);

  // migrate zones jsonb -> text[] (if needed)
  try {
    const zt = await dbQuery(
      `SELECT data_type, udt_name
       FROM information_schema.columns
       WHERE table_schema='public' AND table_name='users' AND column_name='zones'
       LIMIT 1`
    );
    if (zt.rows.length) {
      const { data_type, udt_name } = zt.rows[0];
      const isJsonb = data_type === 'jsonb' || udt_name === 'jsonb';
      if (isJsonb) {
        await dbQuery(`
          ALTER TABLE public.users
          ALTER COLUMN zones TYPE TEXT[]
          USING (
            CASE
              WHEN zones IS NULL THEN '{}'::text[]
              WHEN jsonb_typeof(zones)='array' THEN (
                SELECT COALESCE(array_agg(value), '{}'::text[])
                FROM jsonb_array_elements_text(zones) AS t(value)
              )
              ELSE '{}'::text[]
            END
          );
        `);
      }
    }
  } catch (e) {
    console.warn('⚠️ zones type check/migrate failed:', e?.message || e);
  }

  await dbQuery(`ALTER TABLE public.users ALTER COLUMN role SET DEFAULT 'user';`);
  await dbQuery(`ALTER TABLE public.users ALTER COLUMN zones SET DEFAULT '{}'::text[];`);
  await dbQuery(`ALTER TABLE public.users ALTER COLUMN is_active SET DEFAULT TRUE;`);
  await dbQuery(`ALTER TABLE public.users ALTER COLUMN created_at SET DEFAULT NOW();`);
  await dbQuery(`ALTER TABLE public.users ALTER COLUMN updated_at SET DEFAULT NOW();`);
  await dbQuery(`UPDATE public.users SET role = COALESCE(role,'user') WHERE role IS NULL;`);
  await dbQuery(`UPDATE public.users SET zones = COALESCE(zones,'{}'::text[]) WHERE zones IS NULL;`);
  await dbQuery(`UPDATE public.users SET is_active = COALESCE(is_active, TRUE) WHERE is_active IS NULL;`);
  await dbQuery(`UPDATE public.users SET created_at = COALESCE(created_at, NOW()) WHERE created_at IS NULL;`);
  await dbQuery(`UPDATE public.users SET updated_at = COALESCE(updated_at, NOW()) WHERE updated_at IS NULL;`);


  // zones
  await dbQuery(`ALTER TABLE public.zones ADD COLUMN IF NOT EXISTS name TEXT;`);
  await dbQuery(`ALTER TABLE public.zones ADD COLUMN IF NOT EXISTS description TEXT;`);
  await dbQuery(`ALTER TABLE public.zones ADD COLUMN IF NOT EXISTS sort INT;`);
  await dbQuery(`ALTER TABLE public.zones ADD COLUMN IF NOT EXISTS is_active BOOLEAN;`);
  await dbQuery(`ALTER TABLE public.zones ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;`);
  await dbQuery(`ALTER TABLE public.zones ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;`);
  await dbQuery(`ALTER TABLE public.zones ALTER COLUMN sort SET DEFAULT 0;`);
  await dbQuery(`ALTER TABLE public.zones ALTER COLUMN is_active SET DEFAULT TRUE;`);
  await dbQuery(`ALTER TABLE public.zones ALTER COLUMN created_at SET DEFAULT NOW();`);
  await dbQuery(`ALTER TABLE public.zones ALTER COLUMN updated_at SET DEFAULT NOW();`);
  await dbQuery(`UPDATE public.zones SET sort = COALESCE(sort, 0) WHERE sort IS NULL;`);
  await dbQuery(`UPDATE public.zones SET is_active = COALESCE(is_active, TRUE) WHERE is_active IS NULL;`);
  await dbQuery(`UPDATE public.zones SET created_at = COALESCE(created_at, NOW()) WHERE created_at IS NULL;`);
  await dbQuery(`UPDATE public.zones SET updated_at = COALESCE(updated_at, NOW()) WHERE updated_at IS NULL;`);

  // devices
  await dbQuery(`ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS name TEXT;`);
  await dbQuery(`ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS zone_id TEXT;`);
  await dbQuery(`ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS zone TEXT;`);
  await dbQuery(`ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS type TEXT;`);
  await dbQuery(`ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS method TEXT;`);
  await dbQuery(`ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS url TEXT;`);
  await dbQuery(`ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS ip TEXT;`);
  await dbQuery(`ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS relay TEXT;`);
  await dbQuery(`ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS params JSONB;`);
  await dbQuery(`ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS enabled BOOLEAN;`);
  await dbQuery(`ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS sort INT;`);
  await dbQuery(`ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS is_active BOOLEAN;`);
  await dbQuery(`ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ;`);
  await dbQuery(`ALTER TABLE public.devices ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ;`);
  await dbQuery(`ALTER TABLE public.devices ALTER COLUMN enabled SET DEFAULT TRUE;`);
  await dbQuery(`ALTER TABLE public.devices ALTER COLUMN sort SET DEFAULT 0;`);
  await dbQuery(`ALTER TABLE public.devices ALTER COLUMN is_active SET DEFAULT TRUE;`);
  await dbQuery(`ALTER TABLE public.devices ALTER COLUMN created_at SET DEFAULT NOW();`);
  await dbQuery(`ALTER TABLE public.devices ALTER COLUMN updated_at SET DEFAULT NOW();`);
  await dbQuery(`UPDATE public.devices SET enabled = COALESCE(enabled, TRUE) WHERE enabled IS NULL;`);
  await dbQuery(`UPDATE public.devices SET sort = COALESCE(sort, 0) WHERE sort IS NULL;`);
  await dbQuery(`UPDATE public.devices SET is_active = COALESCE(is_active, TRUE) WHERE is_active IS NULL;`);
  await dbQuery(`UPDATE public.devices SET created_at = COALESCE(created_at, NOW()) WHERE created_at IS NULL;`);
  await dbQuery(`UPDATE public.devices SET updated_at = COALESCE(updated_at, NOW()) WHERE updated_at IS NULL;`);
  // Совместимость: если раньше была колонка zone (текст), заполняем zone_id
  await dbQuery(
    `UPDATE public.devices SET zone_id = COALESCE(zone_id, zone) WHERE zone_id IS NULL AND zone IS NOT NULL;`
  );

  // transit_logs
  await dbQuery(`ALTER TABLE public.transit_logs ADD COLUMN IF NOT EXISTS ts TIMESTAMPTZ;`);
  await dbQuery(`ALTER TABLE public.transit_logs ADD COLUMN IF NOT EXISTS user_id TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_logs ADD COLUMN IF NOT EXISTS user_phone TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_logs ADD COLUMN IF NOT EXISTS user_fio TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_logs ADD COLUMN IF NOT EXISTS user_organization TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_logs ADD COLUMN IF NOT EXISTS user_position TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_logs ADD COLUMN IF NOT EXISTS device_id TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_logs ADD COLUMN IF NOT EXISTS device_name TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_logs ADD COLUMN IF NOT EXISTS zone_id TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_logs ADD COLUMN IF NOT EXISTS action TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_logs ADD COLUMN IF NOT EXISTS success BOOLEAN;`);
  await dbQuery(`ALTER TABLE public.transit_logs ADD COLUMN IF NOT EXISTS details JSONB;`);
  await dbQuery(`ALTER TABLE public.transit_logs ADD COLUMN IF NOT EXISTS ip TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_logs ADD COLUMN IF NOT EXISTS ua TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_logs ALTER COLUMN ts SET DEFAULT NOW();`);
  await dbQuery(`ALTER TABLE public.transit_logs ALTER COLUMN success SET DEFAULT TRUE;`);
  await dbQuery(`UPDATE public.transit_logs SET ts = COALESCE(ts, NOW()) WHERE ts IS NULL;`);
  await dbQuery(`UPDATE public.transit_logs SET success = COALESCE(success, TRUE) WHERE success IS NULL;`);

  // transit_events (journal)
  await dbQuery(`CREATE TABLE IF NOT EXISTS public.transit_events (id BIGSERIAL PRIMARY KEY);`);
  await dbQuery(`ALTER TABLE public.transit_events ADD COLUMN IF NOT EXISTS datetime TIMESTAMPTZ;`);
  await dbQuery(`ALTER TABLE public.transit_events ADD COLUMN IF NOT EXISTS point TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_events ADD COLUMN IF NOT EXISTS event TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_events ADD COLUMN IF NOT EXISTS source TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_events ADD COLUMN IF NOT EXISTS result TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_events ADD COLUMN IF NOT EXISTS session TEXT;`);
  // Кто сделал действие (для UI "Журнал транзита")
  await dbQuery(`ALTER TABLE public.transit_events ADD COLUMN IF NOT EXISTS actor_id TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_events ADD COLUMN IF NOT EXISTS actor_phone TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_events ADD COLUMN IF NOT EXISTS actor_fio TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_events ADD COLUMN IF NOT EXISTS actor_organization TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_events ADD COLUMN IF NOT EXISTS actor_position TEXT;`);
  await dbQuery(`ALTER TABLE public.transit_events ALTER COLUMN datetime SET DEFAULT NOW();`);
  await dbQuery(`UPDATE public.transit_events SET datetime = COALESCE(datetime, NOW()) WHERE datetime IS NULL;`);
  await dbQuery(`CREATE INDEX IF NOT EXISTS idx_transit_events_session ON public.transit_events (session);`);

  // Подтянуть старые записи (если раньше писали только source)
  await dbQuery(
    `UPDATE public.transit_events
     SET actor_phone = COALESCE(actor_phone, source)
     WHERE actor_phone IS NULL AND source IS NOT NULL;`
  );
  await dbQuery(
    `UPDATE public.transit_events te
     SET actor_id = u.id,
         actor_fio = COALESCE(te.actor_fio, u.fio),
         actor_organization = COALESCE(te.actor_organization, u.organization),
         actor_position = COALESCE(te.actor_position, u.position)
     FROM public.users u
     WHERE regexp_replace(coalesce(u.phone,''), '[^0-9]', '', 'g') = regexp_replace(coalesce(te.actor_phone, te.source,''), '[^0-9]', '', 'g');`
  );

  // audit
  await dbQuery(`ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS ts TIMESTAMPTZ;`);
  await dbQuery(`ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS actor_id TEXT;`);
  await dbQuery(`ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS actor_phone TEXT;`);
  await dbQuery(`ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS actor_fio TEXT;`);
  await dbQuery(`ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS actor_organization TEXT;`);
  await dbQuery(`ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS actor_position TEXT;`);
  await dbQuery(`ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS action TEXT;`);
  await dbQuery(`ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS target_type TEXT;`);
  await dbQuery(`ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS target_id TEXT;`);
  await dbQuery(`ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS object_type TEXT;`);
  await dbQuery(`ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS object_id TEXT;`);
  await dbQuery(`ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS details JSONB;`);
  await dbQuery(`ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS ip TEXT;`);
  await dbQuery(`ALTER TABLE public.audit ADD COLUMN IF NOT EXISTS ua TEXT;`);
  await dbQuery(`ALTER TABLE public.audit ALTER COLUMN ts SET DEFAULT NOW();`);
  await dbQuery(`UPDATE public.audit SET ts = COALESCE(ts, NOW()) WHERE ts IS NULL;`);
  // Совместимость: если раньше писали в object_type/object_id
  await dbQuery(
    `UPDATE public.audit SET target_type = COALESCE(target_type, object_type), target_id = COALESCE(target_id, object_id)
     WHERE target_type IS NULL OR target_id IS NULL;`
  );

  // Индексы (безопасно: IF NOT EXISTS)
  await dbQuery(
    `CREATE INDEX IF NOT EXISTS users_phone_digits_idx
     ON public.users (regexp_replace(coalesce(phone,''), '[^0-9]', '', 'g'));`
  );
  await dbQuery(`CREATE INDEX IF NOT EXISTS devices_zone_id_idx ON public.devices (zone_id);`);
  await dbQuery(`CREATE INDEX IF NOT EXISTS transit_logs_ts_idx ON public.transit_logs (ts DESC);`);
  await dbQuery(`CREATE INDEX IF NOT EXISTS audit_ts_idx ON public.audit (ts DESC);`);
}

module.exports = { dbQuery, ensureSchema };
