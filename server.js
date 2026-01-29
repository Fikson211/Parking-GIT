'use strict';

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');

const { dbQuery, ensureSchema } = require('./db');

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
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: 'auto',
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.engine('ejs', require('ejs').__express);

// статика (если есть)
app.use(express.static(path.join(__dirname, 'public')));

// --- утилиты ---
function digitsOnly(s) {
  return String(s || '').replace(/[^\d]/g, '');
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

async function appendTransitEvent({ point, event, source, result, session: sessionId }) {
  try {
    await dbQuery(
      `INSERT INTO public.transit_events(datetime, point, event, source, result, session)
       VALUES (NOW(), $1, $2, $3, $4, $5)`,
      [point, event, source || null, result || null, sessionId || null]
    );
  } catch (e) {
    // не падаем из-за логов
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
    dbQuery(`SELECT id,name,zone_id,method,url,sort,is_active FROM public.devices ORDER BY sort ASC, name ASC`),
  ]);

  return {
    users: toMapById(users.rows.map((u) => ({
      id: u.id,
      fio: u.fio,
      phone: u.phone,
      pin: u.pin,
      role: u.role || 'user',
      zones: u.zones || [],
      is_active: u.is_active !== false,
    }))),
    zones: toMapById(zones.rows.map((z) => ({ id: z.id, name: z.name, sort: z.sort ?? 0 }))),
    devices: toMapById(devices.rows.map((d) => ({
      id: d.id,
      name: d.name,
      zoneId: d.zone_id,
      method: d.method,
      url: d.url,
      sort: d.sort ?? 0,
      is_active: d.is_active !== false,
    }))),
  };
}

function authRequired(req, res, next) {
  if (!req.session?.user) return res.redirect('/login');
  next();
}

function adminRequired(req, res, next) {
  if (!req.session?.user) return res.redirect('/login');
  if (req.session.user.role !== 'admin') return res.status(403).send('Доступ запрещён');
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
      zones: u.zones || [],
    };

    await appendAudit(req, 'login', 'user', u.id, { phone: u.phone });
    return res.redirect('/');
  } catch (e) {
    return res.status(500).render('login', { title: 'Вход • Parking GIT', bodyClass: 'auth-page', error: 'Ошибка БД: ' + String(e?.message || e) });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// --- dashboard ---
app.get('/', authRequired, async (req, res) => {
  const { zones, devices } = await loadAll();
  const user = req.session.user;

  const allowedZoneIds = Array.isArray(user.zones) ? user.zones : [];
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
  if (!d || d.is_active === false) return res.status(404).json({ ok: false, error: 'Устройство не найдено' });

  const allowed = Array.isArray(user.zones) && user.zones.includes(d.zoneId);
  if (!allowed) return res.status(403).json({ ok: false, error: 'Нет доступа' });

  // В этом шаблоне мы просто логируем событие. Реальный вызов реле/контроллера можно добавить позже.
  await appendTransitEvent({
    point: zones[d.zoneId]?.name || d.zoneId,
    event: 'open',
    source: user.phone || user.id,
    result: 'ok',
    session: String(req.sessionID || ''),
  });

  await appendAudit(req, 'open', 'device', deviceId, { zoneId: d.zoneId });
  return res.json({ ok: true });
});

// --- logs ---
app.get('/logs', authRequired, async (req, res) => {
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

  const r = await dbQuery(
    `SELECT datetime, point, event, source, result, session
     FROM public.transit_events
     ${whereSql}
     ORDER BY datetime DESC
     LIMIT 500`,
    args
  );

  // options for filters
  const pts = await dbQuery(`SELECT DISTINCT point FROM public.transit_events ORDER BY point ASC LIMIT 200`);
  const evs = await dbQuery(`SELECT DISTINCT event FROM public.transit_events ORDER BY event ASC LIMIT 200`);

  res.render('logs', {
    title: 'Журнал транзита',
    bodyClass: 'logs-page',
    user,
    logs: r.rows,
    filters,
    options: { points: pts.rows.map((x) => x.point).filter(Boolean), events: evs.rows.map((x) => x.event).filter(Boolean) },
    exportUrlBase: '/logs.csv',
  });
});

app.get('/logs.csv', authRequired, async (req, res) => {
  const r = await dbQuery(
    `SELECT datetime, point, event, source, result, session
     FROM public.transit_events
     ORDER BY datetime DESC
     LIMIT 500`
  );

  const lines = ['datetime,point,event,source,result,session'];
  r.rows.forEach((l) => {
    const esc = (v) => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    lines.push([l.datetime, l.point, l.event, l.source, l.result, l.session].map(esc).join(','));
  });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.send(lines.join('\n'));
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
  const zones = Array.isArray(req.body.zones) ? req.body.zones : (req.body.zones ? [req.body.zones] : []);

  // PIN: автоген
  const pin = genPin(4);

  await dbQuery(
    `INSERT INTO public.users(id,fio,phone,pin,role,zones,is_active)
     VALUES ($1,$2,$3,$4,$5,$6::jsonb,true)`,
    [id, fio || null, phone, pin, role, JSON.stringify(zones)]
  );

  await appendAudit(req, 'create', 'user', id, { fio, phone, role, zones, pin_generated: true });
  res.redirect('/admin/users');
});

app.post('/admin/users/:id/update', adminRequired, async (req, res) => {
  const id = String(req.params.id);
  const fio = String(req.body.fio || '').trim();
  const phone = digitsOnly(req.body.phone);
  const role = req.body.role === 'admin' ? 'admin' : 'user';
  const isActive = req.body.is_active === 'on' || req.body.is_active === 'true';
  const zones = Array.isArray(req.body.zones) ? req.body.zones : (req.body.zones ? [req.body.zones] : []);

  await dbQuery(
    `UPDATE public.users
     SET fio=$2, phone=$3, role=$4, zones=$5::jsonb, is_active=$6
     WHERE id=$1`,
    [id, fio || null, phone, role, JSON.stringify(zones), isActive]
  );

  await appendAudit(req, 'update', 'user', id, { fio, phone, role, zones, isActive });
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
  const url = String(req.body.url || '').trim();

  await dbQuery(
    `INSERT INTO public.devices(id,name,zone_id,method,url,sort,is_active)
     VALUES ($1,$2,$3,$4,$5,0,true)
     ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, zone_id=EXCLUDED.zone_id, method=EXCLUDED.method, url=EXCLUDED.url`,
    [id, name, zoneId || null, method, url]
  );

  await appendAudit(req, 'create', 'device', id, { name, zoneId, method, url });
  res.redirect('/admin/devices');
});

app.post('/admin/devices/:id/update', adminRequired, async (req, res) => {
  const id = String(req.params.id);
  const name = String(req.body.name || '').trim();
  const zoneId = String(req.body.zoneId || '').trim();
  const method = String(req.body.method || 'http').trim();
  const url = String(req.body.url || '').trim();
  const isActive = req.body.is_active === 'on' || req.body.is_active === 'true';

  await dbQuery(
    `UPDATE public.devices
     SET name=$2, zone_id=$3, method=$4, url=$5, is_active=$6
     WHERE id=$1`,
    [id, name, zoneId || null, method, url, isActive]
  );

  await appendAudit(req, 'update', 'device', id, { name, zoneId, method, url, isActive });
  res.redirect('/admin/devices');
});

app.get('/admin/zones', adminRequired, async (req, res) => {
  const { zones } = await loadAll();
  res.render('admin_zones', {
    title: 'Админ • Зоны',
    bodyClass: 'admin-page',
    user: req.session.user,
    zones: Object.values(zones),
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
      try {
        return e.details ? JSON.parse(e.details) : null;
      } catch {
        return e.details;
      }
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
     VALUES ($1,$2,$3,$4,'admin','[]'::jsonb,true)
     ON CONFLICT (id) DO NOTHING`,
    [id, fio, adminPhone, adminPin]
  );

  console.log('✅ Создан админ по умолчанию:', adminPhone, 'PIN:', adminPin);
}

(async () => {
  try {
    await ensureSchema();
    await ensureDefaultAdmin();
  } catch (e) {
    console.error('DB init error:', e);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Parking GIT запущен: http://0.0.0.0:${PORT}`);
  });
})();
