'use strict';

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const { dbQuery, ensureSchema } = require('./db');

// Fallback file log (when DB is temporarily unavailable)
const FALLBACK_TRANSIT_LOG = path.join(__dirname, 'data', 'transit_events.jsonl');

const app = express();
app.set('trust proxy', 1);


// --- базовые настройки ---
const PORT = Number(process.env.PORT || 8080);
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-in-railway';

app.disable('x-powered-by');
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    // Railway / reverse-proxy: helps secure cookies + sessions work correctly
    proxy: true,
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

// Static assets: allow both /app.css and /public/app.css
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'public')));

// Default locals for all templates (prevents EJS ReferenceError on missing vars)
app.use((req, res, next) => {
  res.locals.title = res.locals.title || 'Parking GIT';
  res.locals.bodyClass = res.locals.bodyClass || '';
  res.locals.user = req.session?.user || null;
  next();
});

// If browser auto-translation rewrites URLs into Russian, keep the app working.
// (e.g. "/администратор/устройства" -> "/admin/devices")
app.use((req, res, next) => {
  const original = req.originalUrl || '';
  const rules = [
    { from: '/администратор', to: '/admin' },
    { from: '/войти в систему', to: '/login' },
    { from: '/вход', to: '/login' },
    { from: '/выход', to: '/logout' },
    { from: '/выход из системы', to: '/logout' },
    { from: '/журнал', to: '/logs' },
  ];

  for (const r of rules) {
    if (original === r.from || original.startsWith(r.from + '/') || original.startsWith(encodeURI(r.from) + '/')) {
      const suffix = original.startsWith(r.from) ? original.slice(r.from.length) : original.slice(encodeURI(r.from).length);
      const newUrl = r.to + suffix;
      // For GET/HEAD it's safe to redirect.
      if (req.method === 'GET' || req.method === 'HEAD') return res.redirect(302, newUrl);
      // For POST/PUT/etc. keep the method and internally rewrite the URL.
      req.url = newUrl;
      return next();
    }
  }

  next();
});

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.engine('ejs', require('ejs').__express);

// статика (если есть)

// --- утилиты ---
function digitsOnly(s) {
  return String(s || '').replace(/[^\d]/g, '');
}

function parseZonesInput(v) {
  if (!v) return [];
  const raw = Array.isArray(v) ? v.join(',') : String(v);
  return raw
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
}

function genPin(len = 4) {
  const n = crypto.randomInt(0, 10 ** len);
  return String(n).padStart(len, '0');
}

function toMapById(rows) {
  const out = {};
  (rows || []).forEach((r) => {
    out[r.id] = r;
  });
  return out;
}

async function appendTransitEvent({ point, event, source, result, session: sessionId, actor_id, actor_phone, actor_fio }) {
  const entry = {
    datetime: new Date().toISOString(),
    point: point ?? null,
    event: event ?? null,
    source: source ?? null,
    result: result ?? null,
    session: sessionId ?? null,
    actor_id: actor_id ?? null,
    actor_phone: actor_phone ?? null,
    actor_fio: actor_fio ?? null,
  };

  try {
    await dbQuery(
      `INSERT INTO public.transit_events(datetime, point, event, source, result, session, actor_id, actor_phone, actor_fio)
       VALUES (NOW(), $1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        entry.point,
        entry.event,
        entry.source || null,
        entry.result || null,
        entry.session || null,
        entry.actor_id || null,
        entry.actor_phone || null,
        entry.actor_fio || null,
      ]
    );
    return;
  } catch (e) {
    // DB может быть временно недоступна (например, при рестарте). Тогда пишем в файл, чтобы журнал не "умирал".
    try {
      fs.mkdirSync(path.dirname(FALLBACK_TRANSIT_LOG), { recursive: true });
      fs.appendFileSync(FALLBACK_TRANSIT_LOG, JSON.stringify(entry) + '\n', 'utf-8');
    } catch (fe) {
      // если даже файл не пишется — просто логируем
    }
    console.error('⚠️ transit log write failed:', e?.message || e);
  }
}



function readFallbackTransitEvents(limit = 500) {
  try {
    if (!fs.existsSync(FALLBACK_TRANSIT_LOG)) return [];
    const raw = fs.readFileSync(FALLBACK_TRANSIT_LOG, 'utf-8');
    const lines = raw.split(/\r?\n/).filter(Boolean);
    const tail = lines.slice(Math.max(0, lines.length - limit));
    const items = [];
    for (const line of tail) {
      try {
        const o = JSON.parse(line);
        items.push(o);
      } catch {
        // skip bad line
      }
    }
    // newest first
    items.sort((a, b) => String(b.datetime || '').localeCompare(String(a.datetime || '')));
    return items;
  } catch {
    return [];
  }
}

async function appendAudit(req, action, targetType, targetId, details) {
  try {
    const actor = req.session?.user || null;
    await dbQuery(
      `INSERT INTO public.audit(ts, actor_id, actor_phone, actor_fio, action, target_type, target_id, details, ip, ua)
       VALUES (NOW(), $1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        actor?.id || null,
        actor?.phone || null,
        actor?.fio || null,
        action,
        targetType,
        targetId,
        details ? JSON.stringify(details) : null,
        req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() || req.socket?.remoteAddress || null,
        req.headers['user-agent'] || null,
      ]
    );
  } catch (e) {
    // ignore
  }
}

async function loadAll() {
  // Важно: никаких ORDER BY sort если колонки нет — ensureSchema её добавит.
  const [users, zones, devices] = await Promise.all([
    dbQuery(`SELECT id,fio,phone,pin,role,zones,is_active FROM public.users ORDER BY created_at ASC`),
    dbQuery(`SELECT id,name,sort FROM public.zones ORDER BY sort ASC, name ASC`),
    dbQuery(`SELECT id,name,zone_id,type,method,url,ip,relay,enabled,sort,is_active FROM public.devices ORDER BY sort ASC, name ASC`),
  ]);

  return {
    users: toMapById(users.rows.map((u) => ({
      id: u.id,
      fio: u.fio,
      phone: u.phone,
      pin: u.pin,
      role: u.role || 'user',
      zones: Array.isArray(u.zones) ? u.zones : [],
      is_active: u.is_active !== false,
    }))),
    zones: toMapById(zones.rows.map((z) => ({ id: z.id, name: z.name, sort: z.sort ?? 0 }))),
    devices: toMapById(devices.rows.map((d) => ({
      id: d.id,
      name: d.name,
      zoneId: d.zone_id,
      type: d.type || 'http',
      method: d.method,
      url: d.url,
      ip: d.ip || null,
      relay: (d.relay ?? null),
      enabled: d.enabled !== false,
      sort: d.sort ?? 0,
      is_active: d.is_active !== false,
    }))),
  };
}

// --- Seed defaults (zones + devices) -----------------------------------------
const DEFAULT_ZONES = [
  { id: 'buffer',      name: 'Буферная зона',          sort: 10 },
  { id: 'europlan',    name: 'Европлан',               sort: 20 },
  { id: 'overground',  name: 'Надземная',              sort: 30 },
  { id: 'pedestrian',  name: 'Пешеходный доступ',      sort: 40 },
  { id: 'underground', name: 'Подземная',              sort: 50 },
  { id: 'transit',     name: 'Транзитная зона',        sort: 60 },
];

async function ensureDefaultZones() {
  const res = await dbQuery('SELECT COUNT(*)::int AS c FROM public.zones');
  if ((res.rows?.[0]?.c ?? 0) > 0) return;

  const values = [];
  const params = [];
  let i = 1;
  for (const z of DEFAULT_ZONES) {
    values.push(`($${i++}, $${i++}, $${i++}, TRUE, NOW())`);
    params.push(z.id, z.name, z.sort);
  }
  await dbQuery(
    `INSERT INTO public.zones (id, name, sort, is_active, created_at)
     VALUES ${values.join(',')}
     ON CONFLICT (id) DO UPDATE SET
       name = EXCLUDED.name,
       sort = EXCLUDED.sort,
       is_active = TRUE`,
    params
  );
}

function parseDevicesJson(raw) {
  if (!raw) return [];
  // allowed formats:
  // 1) { "id1": {...}, "id2": {...} }
  // 2) [ {...}, {...} ]
  if (Array.isArray(raw)) return raw;
  if (typeof raw === 'object') {
    return Object.entries(raw).map(([id, v]) => ({ id, ...(v || {}) }));
  }
  return [];
}

function testDevices() {
  return [
    {
      id: 'test_gate_in',
      name: 'Тест: Ворота Въезд',
      zone_id: 'transit',
      type: 'http',
      method: 'POST',
      url: 'http://example.local/open/in',
      sort: 10,
      enabled: true,
    },
    {
      id: 'test_gate_out',
      name: 'Тест: Ворота Выезд',
      zone_id: 'transit',
      type: 'http',
      method: 'POST',
      url: 'http://example.local/open/out',
      sort: 20,
      enabled: true,
    },
    {
      id: 'test_door_1',
      name: 'Тест: Дверь 1',
      zone_id: 'pedestrian',
      type: 'http',
      method: 'POST',
      url: 'http://example.local/open/door1',
      sort: 30,
      enabled: true,
    },
  ];
}

async function seedDevicesFromJson() {
  // Seed only when DB is empty, so we don't overwrite devices created in админке
  try {
    const c = await dbQuery('SELECT COUNT(*)::int AS c FROM public.devices');
    if ((c.rows?.[0]?.c ?? 0) > 0) return;
  } catch (e) {
    console.error('seedDevicesFromJson: COUNT(*) failed', e?.message || e);
    // continue, schema may be just created
  }

  const testDevices = () => ([
    {
      id: 'test_gate_in',
      name: 'Тестовые ворота (въезд)',
      zone: 'transit',
      type: 'http',
      method: 'POST',
      url: 'http://example.local/open/in'
    },
    {
      id: 'test_gate_out',
      name: 'Тестовые ворота (выезд)',
      zone: 'transit',
      type: 'http',
      method: 'POST',
      url: 'http://example.local/open/out'
    },
    {
      id: 'test_door_1',
      name: 'Тестовая дверь #1',
      zone: 'pedestrian',
      type: 'http',
      method: 'POST',
      url: 'http://example.local/open/door1'
    },
  ]);

  const candidates = [
    path.join(__dirname, 'devices.json'),
    path.join(__dirname, 'data', 'devices.json'),
  ];
  const p = candidates.find(fp => fs.existsSync(fp));

  let list = [];

  if (p) {
    try {
      const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
      list = parseDevicesJson(raw);
    } catch (e) {
      console.error('devices.json: parse error', e?.message || e);
      list = [];
    }
  }

  // If file is missing/empty — create demo devices so UI works out of the box
  if (!list.length) {
    console.log('ℹ️ devices.json пустой/не найден — создаю тестовые устройства');
    list = testDevices();
  }

  for (const d of list) {
    const id = String(d.id || '').trim();
    if (!id) continue;

    const name = String(d.name || id).trim();
    const type = String(d.type || 'http').trim() || 'http';
    const method = String(d.method || 'POST').toUpperCase();
    const url = String(d.url || d.endpoint || d.link || '').trim();
    const ip = url && !/^https?:\/\//i.test(url) ? url : null;
    const zoneId = String(d.zone_id || d.zone || '').trim() || 'buffer';
    const sort = Number.isFinite(Number(d.sort)) ? Number(d.sort) : 0;
    const enabled = typeof d.enabled === 'boolean' ? d.enabled : true;

    // allow url empty (some devices can be placeholders), but keep it consistent
    await dbQuery(
      `INSERT INTO public.devices (id, name, zone_id, type, method, url, ip, enabled, sort, is_active, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE, NOW())
       ON CONFLICT (id) DO UPDATE SET
         name = EXCLUDED.name,
         zone_id = COALESCE(EXCLUDED.zone_id, public.devices.zone_id),
         type = EXCLUDED.type,
         method = EXCLUDED.method,
         url = EXCLUDED.url,
         ip = EXCLUDED.ip,
         enabled = EXCLUDED.enabled,
         sort = EXCLUDED.sort,
         is_active = TRUE,
         updated_at = NOW()`,
      [id, name, zoneId, type, method, url, ip, enabled, sort]
    );
  }
}

function authRequired(req, res, next) {
  if (!req.session?.user) return res.redirect('/login');
  next();
}

function adminRequired(req, res, next) {
  if (!req.session?.user) return res.redirect('/login');
  // Для обычных пользователей закрываем всё, кроме Дашборда.
  // Вместо 403 делаем редирект на главную, чтобы UI выглядел как приложение, а не как ошибка.
  if (req.session.user.role !== 'admin') return res.redirect('/');
  next();
}

// --- health ---
app.get('/health', async (req, res) => {
  try {
    await dbQuery('SELECT 1 AS ok');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// --- login/logout ---
app.get('/login', (req, res) => {
  res.render('login', {
    title: 'Вход • Parking GIT',
    bodyClass: 'auth-page',
    error: null,
  });
});

app.post('/login', async (req, res) => {
  const phoneIn = digitsOnly(req.body.phone);
  const pinIn = digitsOnly(req.body.pin);

  try {
    const r = await dbQuery(
      `SELECT id,fio,phone,pin,role,zones,is_active
       FROM public.users
       WHERE regexp_replace(coalesce(phone,''), '[^0-9]', '', 'g') = $1
       LIMIT 1`,
      [phoneIn]
    );

    const u = r.rows[0];
    if (!u || u.is_active === false) {
      return res.status(401).render('login', { title: 'Вход • Parking GIT', bodyClass: 'auth-page', error: 'Телефон не найден' });
    }

    const expectedPin = digitsOnly(u.pin) || phoneIn.slice(-4);
    if (pinIn !== expectedPin) {
      return res.status(401).render('login', { title: 'Вход • Parking GIT', bodyClass: 'auth-page', error: 'Неверный PIN' });
    }

    req.session.user = {
      id: u.id,
      fio: u.fio,
      phone: u.phone,
      role: u.role || 'user',
      zones: Array.isArray(u.zones) ? u.zones : [],
    };

	    await appendAudit(req, 'login', 'user', u.id, { phone: u.phone });
	    // Ensure session is persisted before redirect (important behind some proxies/stores)
	    return req.session.save((err) => {
	      if (err) console.error('session save error:', err);
	      res.redirect('/');
	    });
  } catch (e) {
    return res.status(500).render('login', { title: 'Вход • Parking GIT', bodyClass: 'auth-page', error: 'Ошибка БД: ' + String(e?.message || e) });
  }
});


// Allow GET /logout because UI uses a link. (POST is kept too.)
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// --- dashboard ---
app.get('/', authRequired, async (req, res) => {
  const { zones, devices } = await loadAll();
  const user = req.session.user;

  const allowedZoneIds = (user.role === 'admin')
    ? Object.keys(zones)
    : (Array.isArray(user.zones) ? user.zones : []);
  const devicesArr = Object.values(devices).filter((d) => d.is_active !== false);

  // группируем устройства по зонам доступа пользователя
  const byZone = [];
  allowedZoneIds.forEach((zid) => {
    const z = zones[zid];
    const dz = devicesArr.filter((d) => d.zoneId === zid);
    if (z && dz.length) {
      byZone.push({ zoneId: zid, zoneName: z.name, devices: dz });
    }
  });

  res.render('dashboard', {
    title: 'Parking GIT',
    bodyClass: 'dash-page',
    user,
    byZone,
  });
});

// --- API open device ---
app.post('/api/open/:deviceId', authRequired, async (req, res) => {
  const deviceId = String(req.params.deviceId);
  const { zones, devices } = await loadAll();
  const user = req.session.user;

  const d = devices[deviceId];
  if (!d || d.is_active === false) {
    return res.status(404).json({ ok: false, error: 'Устройство не найдено' });
  }
  if (d.enabled === false) {
    // device disabled in admin
    await appendTransitEvent({
      point: d.name || deviceId,
      event: 'open',
      source: user.phone || user.id,
      result: 'disabled',
      session: String(req.sessionID || ''),
      actor_id: user.id,
      actor_phone: user.phone,
      actor_fio: user.fio,
    });
    return res.status(409).json({ ok: false, error: 'Устройство отключено' });
  }

  const allowed = (user.role === 'admin') || (Array.isArray(user.zones) && user.zones.includes(d.zoneId));
  if (!allowed) {
    // log denied attempts too (helps расследования)
    await appendTransitEvent({
      point: d.name || deviceId,
      event: 'open',
      source: user.phone || user.id,
      result: 'denied',
      session: String(req.sessionID || ''),
      actor_id: user.id,
      actor_phone: user.phone,
      actor_fio: user.fio,
    });
    return res.status(403).json({ ok: false, error: 'Нет доступа' });
  }

  // Пока только логируем событие (реальный вызов реле/контроллера можно добавить позже).
  const zoneName = zones[d.zoneId]?.name;
  const point = zoneName ? `${d.name || deviceId} — ${zoneName}` : (d.name || deviceId);

  await appendTransitEvent({
    point,
    event: 'open',
    source: user.phone || user.id,
    result: 'ok',
    session: String(req.sessionID || ''),
      actor_id: user.id,
      actor_phone: user.phone,
      actor_fio: user.fio,
  });

  await appendAudit(req, 'open', 'device', deviceId, { zoneId: d.zoneId });
  return res.json({ ok: true });
});


// --- logs ---
// Журнал транзита доступен только администратору
app.get('/logs', adminRequired, async (req, res) => {
  const user = req.session.user;

  const filters = {
    point: req.query.point || '',
    event: req.query.event || '',
    date_from: req.query.date_from || '',
    date_to: req.query.date_to || '',
  };

  const wh = [];
  const args = [];
  const push = (sql, val) => {
    args.push(val);
    wh.push(sql.replace('$X', `$${args.length}`));
  };

  if (filters.point) push(`point = $X`, filters.point);
  if (filters.event) push(`event = $X`, filters.event);
  if (filters.date_from) push(`datetime >= ($X::date)`, filters.date_from);
  if (filters.date_to) push(`datetime < (($X::date) + interval '1 day')`, filters.date_to);

  const whereSql = wh.length ? `WHERE ${wh.join(' AND ')}` : '';

  let logs = [];
  let points = [];
  let events = [];

  try {
    const r = await dbQuery(
      `SELECT datetime, point, event, source, result, session, actor_fio, actor_phone
       FROM public.transit_events
       ${whereSql}
       ORDER BY datetime DESC
       LIMIT 500`,
      args
    );
    logs = r.rows;

    // options for filters
    const pts = await dbQuery(`SELECT DISTINCT point FROM public.transit_events ORDER BY point ASC LIMIT 200`);
    const evs = await dbQuery(`SELECT DISTINCT event FROM public.transit_events ORDER BY event ASC LIMIT 200`);
    points = pts.rows.map((x) => x.point).filter(Boolean);
    events = evs.rows.map((x) => x.event).filter(Boolean);
  } catch (e) {
    // Fallback to local file (useful when DB is restarting / temporary outage)
    const all = readFallbackTransitEvents(2000);

    const from = filters.date_from ? new Date(filters.date_from + 'T00:00:00Z') : null;
    const to = filters.date_to ? new Date(filters.date_to + 'T00:00:00Z') : null;

    const filtered = all.filter((x) => {
      if (filters.point && x.point !== filters.point) return false;
      if (filters.event && x.event !== filters.event) return false;
      const dt = x.datetime ? new Date(x.datetime) : null;
      if (from && dt && dt < from) return false;
      if (to && dt && dt >= new Date(to.getTime() + 24 * 60 * 60 * 1000)) return false;
      return true;
    });

    logs = filtered.slice(0, 500);

    points = Array.from(new Set(all.map((x) => x.point).filter(Boolean))).sort((a, b) => String(a).localeCompare(String(b)));
    events = Array.from(new Set(all.map((x) => x.event).filter(Boolean))).sort((a, b) => String(a).localeCompare(String(b)));

    console.warn('⚠️ /logs using fallback file because DB query failed:', e?.message || e);
  }


  res.render('logs', {
    title: 'Журнал транзита',
    bodyClass: 'logs-page',
    user,
    logs,
    filters,
    options: { points, events },
    exportUrlBase: '/logs.csv',
  });
});

app.get('/logs.csv', adminRequired, async (req, res) => {
  let rows = [];
  try {
    const r = await dbQuery(
      `SELECT datetime, point, event, source, result, session, actor_fio, actor_phone
       FROM public.transit_events
       ORDER BY datetime DESC
       LIMIT 500`
    );
    rows = r.rows;
  } catch (e) {
    rows = readFallbackTransitEvents(500);
    console.warn('⚠️ /logs.csv using fallback file because DB query failed:', e?.message || e);
  }

  const lines = ['datetime,point,event,actor_fio,actor_phone,source,result,session'];
  rows.forEach((l) => {
    const esc = (v) => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    lines.push([l.datetime, l.point, l.event, l.actor_fio, l.actor_phone, l.source, l.result, l.session].map(esc).join(','));
  });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.send(lines.join('\n'));
});


app.post('/logs/clear', adminRequired, async (req, res) => {
  try {
    await dbQuery('TRUNCATE TABLE public.transit_events');
    await appendAudit(req, 'clear_transit_log', 'transit_events', '*', {});
  } catch (e) {
    console.error('clear_transit_log error', e);
  }

  // Clear fallback file too
  try {
    if (fs.existsSync(FALLBACK_TRANSIT_LOG)) fs.writeFileSync(FALLBACK_TRANSIT_LOG, '', 'utf-8');
  } catch {}

  return res.redirect('/logs');
});


// --- admin: users/devices/zones/audit ---
app.get('/admin/users', adminRequired, async (req, res) => {
  const { users, zones } = await loadAll();
  res.render('admin_users', {
    title: 'Админ • Пользователи',
    bodyClass: 'admin-page',
    user: req.session.user,
    users: Object.values(users),
    zones: Object.values(zones),
  });
});

app.post('/admin/users/create', adminRequired, async (req, res) => {
  const id = crypto.randomUUID();
  const fio = String(req.body.fio || '').trim();
  const phone = digitsOnly(req.body.phone);
  const role = req.body.role === 'admin' ? 'admin' : 'user';
  const zones = parseZonesInput(req.body.zones);

  // PIN: можно задать вручную (как пароль), либо автоген
  const pinFromForm = digitsOnly(req.body.pin);
  const pin = (pinFromForm && pinFromForm.length >= 4) ? pinFromForm : genPin(4);

  await dbQuery(
    `INSERT INTO public.users(id,fio,phone,pin,role,zones,is_active)
     VALUES ($1,$2,$3,$4,$5,$6,true)`,
    [id, fio || null, phone, pin, role, zones]
  );

  await appendAudit(req, 'create', 'user', id, { fio, phone, role, zones, pin_set: !!pinFromForm, pin_generated: !pinFromForm });
  res.redirect('/admin/users');
});

app.post('/admin/users/:id/update', adminRequired, async (req, res) => {
  const id = String(req.params.id);
  const fio = String(req.body.fio || '').trim();
  const phone = digitsOnly(req.body.phone);
  const role = req.body.role === 'admin' ? 'admin' : 'user';
  const isActive = req.body.is_active === 'on' || req.body.is_active === 'true';
  const zones = parseZonesInput(req.body.zones);
  const pinFromForm = digitsOnly(req.body.pin);
  const pin = (pinFromForm && pinFromForm.length >= 4) ? pinFromForm : null;

  await dbQuery(
    `UPDATE public.users
     SET fio=$2, phone=$3, role=$4, zones=$5, is_active=$6,
         pin = COALESCE($7, pin),
         updated_at = NOW()
     WHERE id=$1`,
    [id, fio || null, phone, role, zones, isActive, pin]
  );

  await appendAudit(req, 'update', 'user', id, { fio, phone, role, zones, isActive, pin_changed: !!pin });
  res.redirect('/admin/users');
});

app.post('/admin/users/:id/reset_pin', adminRequired, async (req, res) => {
  const id = String(req.params.id);
  const pin = genPin(4);
  await dbQuery(`UPDATE public.users SET pin=$2 WHERE id=$1`, [id, pin]);
  await appendAudit(req, 'reset_pin', 'user', id, { pin_generated: true });
  res.redirect('/admin/users');
});

app.get('/admin/devices', adminRequired, async (req, res) => {
  const { devices, zones } = await loadAll();
  res.render('admin_devices', {
    title: 'Админ • Устройства',
    bodyClass: 'admin-page',
    user: req.session.user,
    devices: Object.values(devices),
    zones: Object.values(zones),
  });
});

app.post('/admin/devices/create', adminRequired, async (req, res) => {
  const id = String(req.body.id || '').trim() || crypto.randomUUID();
  const name = String(req.body.name || '').trim();
  const zoneId = String(req.body.zoneId || '').trim();
  const method = String(req.body.method || 'http').trim();
  const endpoint = String(req.body.url || '').trim();
  const ip = endpoint && !/^https?:\/\//i.test(endpoint) ? endpoint : null;
  const url = endpoint;

  await dbQuery(
    `INSERT INTO public.devices(id,name,zone_id,method,url,ip,sort,is_active)
     VALUES ($1,$2,$3,$4,$5,$6,0,true)
     ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, zone_id=EXCLUDED.zone_id, method=EXCLUDED.method, url=EXCLUDED.url, ip=EXCLUDED.ip`,
    [id, name, zoneId || null, method, url, ip]
  );

  await appendAudit(req, 'create', 'device', id, { name, zoneId, method, url, ip });
  res.redirect('/admin/devices');
});

app.post('/admin/devices/:id/update', adminRequired, async (req, res) => {
  const id = String(req.params.id);
  const name = String(req.body.name || '').trim();
  const zoneId = String(req.body.zoneId || '').trim();
  const method = String(req.body.method || 'http').trim();
  const endpoint = String(req.body.url || '').trim();
  const ip = endpoint && !/^https?:\/\//i.test(endpoint) ? endpoint : null;
  const url = endpoint;
  const isActive = req.body.is_active === 'on' || req.body.is_active === 'true';

  await dbQuery(
    `UPDATE public.devices
     SET name=$2, zone_id=$3, method=$4, url=$5, ip=$6, is_active=$7
     WHERE id=$1`,
    [id, name, zoneId || null, method, url, ip, isActive]
  );

  await appendAudit(req, 'update', 'device', id, { name, zoneId, method, url, ip, isActive });
  res.redirect('/admin/devices');
});

app.get('/admin/zones', adminRequired, async (req, res) => {
  const { zones, devices } = await loadAll();

  // group devices by zone_id for удобного отображения в админке
  const devicesByZone = {};
  for (const d of Object.values(devices || {})) {
    const zid = String(d.zoneId || d.zone_id || d.zone || '').trim();
    if (!zid) continue;
    (devicesByZone[zid] ||= []).push(d);
  }
  for (const zid of Object.keys(devicesByZone)) {
    devicesByZone[zid].sort((a, b) => String(a.name || a.id).localeCompare(String(b.name || b.id), 'ru'));
  }

  res.render('admin_zones', {
    title: 'Админ • Зоны',
    bodyClass: 'admin-page',
    user: req.session.user,
    zones: Object.values(zones),
    devicesByZone,
  });
});

app.post('/admin/zones/create', adminRequired, async (req, res) => {
  const id = String(req.body.id || '').trim() || crypto.randomUUID();
  const name = String(req.body.name || '').trim();
  await dbQuery(
    `INSERT INTO public.zones(id,name,sort)
     VALUES ($1,$2,0)
     ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name`,
    [id, name]
  );
  await appendAudit(req, 'create', 'zone', id, { name });
  res.redirect('/admin/zones');
});

app.get('/admin/audit', adminRequired, async (req, res) => {
  const r = await dbQuery(
    `SELECT ts, actor_id, actor_phone, actor_fio, action, target_type, target_id, details, ip, ua
     FROM public.audit
     ORDER BY ts DESC
     LIMIT 500`
  );

  const entries = r.rows.map((e) => ({
    ts: e.ts,
    actorId: e.actor_id,
    actorPhone: e.actor_phone,
    actorFio: e.actor_fio,
    action: e.action,
    targetType: e.target_type,
    targetId: e.target_id,
    details: (() => {
      if (!e.details) return null;
      if (typeof e.details === "string") {
        try {
          return JSON.parse(e.details);
        } catch {
          return e.details;
        }
      }
      return e.details;
    })(),
    ip: e.ip,
    ua: e.ua,
  }));

  res.render('admin_audit', {
    user: req.session.user,
    bodyClass: 'admin-page',
    entries,
  });
});

// Export audit as CSV
app.get('/admin/audit.csv', adminRequired, async (req, res) => {
  const r = await dbQuery(
    `SELECT ts, actor_id, actor_phone, actor_fio, action, target_type, target_id, details, ip, ua
     FROM public.audit
     ORDER BY ts DESC
     LIMIT 5000`
  );

  const rows = r.rows.map((e) => [
    e.ts,
    e.actor_id,
    e.actor_phone,
    e.actor_fio,
    e.action,
    e.target_type,
    e.target_id,
    typeof e.details === 'string' ? e.details : JSON.stringify(e.details || null),
    e.ip,
    e.ua,
  ]);

  const header = ['ts', 'actor_id', 'actor_phone', 'actor_fio', 'action', 'target_type', 'target_id', 'details', 'ip', 'ua'];
  const csv = [header, ...rows]
    .map((r) => r.map((v) => {
      const s = v == null ? '' : String(v);
      const escaped = s.replace(/"/g, '""');
      return /[",\n\r]/.test(escaped) ? `"${escaped}"` : escaped;
    }).join(','))
    .join('\n');

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="audit.csv"');
  res.send(csv);
});

// Clear audit log
app.post('/admin/audit/clear', adminRequired, async (req, res) => {
  await dbQuery('DELETE FROM public.audit');
  res.redirect('/admin/audit');
});

// --- bootstrap: create default admin if missing ---
async function ensureDefaultAdmin() {
  const adminPhone = digitsOnly(process.env.ADMIN_PHONE || '79991112233');
  const adminPin = digitsOnly(process.env.ADMIN_PIN || '1234');

  const exists = await dbQuery(
    `SELECT id FROM public.users WHERE regexp_replace(coalesce(phone,''), '[^0-9]', '', 'g') = $1 LIMIT 1`,
    [adminPhone]
  );

  if (exists.rows.length) return;

  const id = 'admin';
  const fio = process.env.ADMIN_FIO || 'Администратор';
  // если зон ещё нет — оставляем пусто, можно назначить в админке
  await dbQuery(
    `INSERT INTO public.users(id,fio,phone,pin,role,zones,is_active)
     VALUES ($1,$2,$3,$4,'admin',$5,true)
     ON CONFLICT (id) DO NOTHING`,
    [id, fio, adminPhone, adminPin, []]
  );

  console.log('✅ Создан админ по умолчанию:', adminPhone, 'PIN:', adminPin);
}

(async () => {
  try {
    await ensureSchema();
    // 1) создаём стандартные зоны
    await ensureDefaultZones();
    // 2) загружаем устройства из devices.json или создаём тестовые
    await seedDevicesFromJson();
    // 3) создаём админа по умолчанию
    await ensureDefaultAdmin();
    // 4) прогреваем кэш
    await loadAll();
  } catch (e) {
    console.error('DB init error:', e);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Parking GIT запущен: http://0.0.0.0:${PORT}`);
  });
})();
