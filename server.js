require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const { pool } = require('./db');


const app = express();

// Helpers available in all EJS templates
app.use((req, res, next) => {
  res.locals.qs = (obj = {}) => {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(obj)) {
      if (v === undefined || v === null || v === '') continue;
      params.append(k, String(v));
    }
    const q = params.toString();
    return q ? `?${q}` : '';
  };
  next();
});

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_secret_change_me';

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ZONES_FILE = path.join(DATA_DIR, 'zones.json');
const DEVICES_FILE = path.join(DATA_DIR, 'devices.json');
const ROLES_FILE = path.join(DATA_DIR, 'roles.json');
const LOGS_FILE = path.join(DATA_DIR, 'logs.json');
const TRANSIT_FILE = path.join(DATA_DIR, 'transit_events.json');
const AUDIT_FILE = path.join(DATA_DIR, 'audit.json');

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf-8'));
  } catch (e) {
    return fallback;
  }
}
function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function loadAll() {
  return {
    users: readJson(USERS_FILE, {}),
    zones: readJson(ZONES_FILE, {}),
    devices: readJson(DEVICES_FILE, {}),
    roles: readJson(ROLES_FILE, {}),
    logs: readJson(LOGS_FILE, []),
    transit: readJson(TRANSIT_FILE, []),
    audit: readJson(AUDIT_FILE, []),
  };
}

function findUserIdByPhone(users, phoneRaw) {
  const phone = String(phoneRaw || '').replace(/\D/g, '');
  for (const [id, u] of Object.entries(users)) {
    if (String(u.phone || '').replace(/\D/g, '') === phone) return id;
  }
  return null;
}

function userPin(u) {
  // Если pin не задан, используем последние 4 цифры телефона как "пин по умолчанию"
  const phone = String(u.phone || '').replace(/\D/g, '');
  const fallback = phone.length >= 4 ? phone.slice(-4) : '';
  return String(u.pin || fallback);
}

function isAdmin(u) {
  return u && (u.role === 'admin');
}


function devicePointLabel(device, deviceId) {
  const name = (device?.name || deviceId || 'Точка');
  const n = name.toLowerCase();
  let kind = 'Устройство';
  if (n.includes('шлагбаум')) kind = 'Шлагбаум';
  else if (n.includes('ворота')) kind = 'Ворота';
  else if (n.includes('двер')) kind = 'Дверь';
  else if (n.includes('калит')) kind = 'Дверь';
  return `${kind}: ${name}`;
}

async function appendTransitEvent({ point, event, source, result, session }) {
  try {
    await pool.query(
      `INSERT INTO public.transit_events(datetime, point, event, source, result, session)
       VALUES (NOW(), $1, $2, $3, $4, $5)`,
      [point, event, source || null, result || null, session || null]
    );
  } catch (e) {}
}

function getTransitFilterOptions(transitList) {
  const points = new Set();
  const events = new Set();
  for (const e of transitList) {
    if (e?.point) points.add(String(e.point));
    if (e?.event) events.add(String(e.event));
  }
  return {
    points: Array.from(points).sort((a,b)=>a.localeCompare(b,'ru')),
    events: Array.from(events).sort((a,b)=>a.localeCompare(b,'ru')),
  };
}

function applyTransitFilters(list, q) {
  const point = (q.point || '').trim();
  const event = (q.event || '').trim();
  const dateFrom = (q.date_from || '').trim(); // YYYY-MM-DD
  const dateTo = (q.date_to || '').trim();     // YYYY-MM-DD

  let from = null, to = null;
  if (dateFrom) {
    const d = new Date(dateFrom + 'T00:00:00');
    if (!isNaN(d.getTime())) from = d;
  }
  if (dateTo) {
    const d = new Date(dateTo + 'T23:59:59.999');
    if (!isNaN(d.getTime())) to = d;
  }

  return list.filter(e => {
    if (point && String(e.point || '') !== point) return false;
    if (event && String(e.event || '') !== event) return false;

    if (from || to) {
      const dt = new Date(e.datetime);
      if (isNaN(dt.getTime())) return false;
      if (from && dt < from) return false;
      if (to && dt > to) return false;
    }
    return true;
  });
}

function transitToCsvRows(list) {
  const header = ['Дата/время','Точка','Событие','Пользователь/источник','Результат','Сессия'];
  const rows = list.map(e => ([
    e?.datetime ? new Date(e.datetime).toLocaleString('ru-RU') : '',
    e?.point || '',
    e?.event || '',
    e?.source || '',
    e?.result || '',
    e?.session || ''
  ]));
  return [header, ...rows];
}

function sendCsv(res, filename, rows) {
  // Simple RFC4180 CSV with ; separator (часто удобнее для RU Excel)
  const sep = ';';
  const escape = (v) => {
    const s = String(v ?? '');
    if (s.includes('"') || s.includes('\n') || s.includes('\r') || s.includes(sep)) {
      return '"' + s.replace(/"/g,'""') + '"';
    }
    return s;
  };
  const csv = rows.map(r => r.map(escape).join(sep)).join('\r\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  // BOM для корректного UTF-8 в Excel
  res.send('\ufeff' + csv);
}

async function appendAudit(req, action, targetType, targetId, details) {
  try {
    const { users } = loadAll(); // временно, пока users ещё в json
    const actor = users[req.session?.userId] || null;

    await pool.query(
      `INSERT INTO public.audit(ts, actor_id, actor_phone, actor_fio, action, target_type, target_id, details, ip, ua)
       VALUES (NOW(), $1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        req.session?.userId || null,
        actor?.phone || null,
        actor?.fio || null,
        action,
        targetType,
        targetId,
        String(details ?? '').replace(/[^\d]/g,'') || null,
        req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() || req.socket?.remoteAddress || null,
        req.headers['user-agent'] || null
      ]
    );
  } catch (e) {
    console.error('Audit error:', e.message);
  }
}

async function openDevice(device) {
  if (device.method === 'GET') {
    return axios.get(device.url, {
      timeout: 5000,
      auth: device.auth ? { username: device.auth.user, password: device.auth.pass } : undefined
    });
  }
  throw new Error('Неизвестный метод устройства: ' + device.method);
}

function authRequired(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

function adminRequired(req, res, next) {
  const { users } = loadAll();
  const u = users[req.session.userId];
  if (!u || !isAdmin(u)) return res.status(403).send('Доступ запрещён');
  next();
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true }
}));

app.get('/login', (req, res) => {
  res.render('login', { error: null, title: 'Вход • Parking Git', bodyClass: 'theme-premium page-login' });
});

app.post('/login', async (req, res) => {
  const { phone, pin } = req.body;
  const phoneDigits = String(phone || '').replace(/\D/g, '');

  try {
    const r = await pool.query(
      `SELECT id, fio, phone, role, status, pin
       FROM public.users
       WHERE regexp_replace(phone, '\\D', '', 'g') = $1
       LIMIT 1`,
      [phoneDigits]
    );

    const u = r.rows[0];
    if (!u) {
      return res.status(401).render('login', { error: 'Телефон не найден', title: 'Вход • Parking Git', bodyClass: 'theme-premium page-login' });
    }

    if (u.status && u.status !== 'active') {
      return res.status(403).render('login', { error: 'Пользователь не активен', title: 'Вход • Parking Git', bodyClass: 'theme-premium page-login' });
    }

    const pinExpected = String(u.pin || '').trim() || (phoneDigits.length >= 4 ? phoneDigits.slice(-4) : '');
    if (String(pin || '').trim() !== pinExpected) {
      return res.status(401).render('login', { error: 'Неверный PIN', title: 'Вход • Parking Git', bodyClass: 'theme-premium page-login' });
    }

    req.session.userId = u.id;

    // audit login (теперь appendAudit у тебя лучше тоже сделать async и писать в БД)
    appendAudit(req, 'login', 'user', u.id, { phone: u.phone });

    res.redirect('/');
  } catch (e) {
    return res.status(500).render('login', { error: 'Ошибка БД: ' + (e.message || e), title: 'Вход • Parking Git', bodyClass: 'theme-premium page-login' });
  }
});

app.get('/logout', (req, res) => {
  appendAudit(req, 'logout', 'user', req.session.userId, null);
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/', authRequired, (req, res) => {
  const { users, zones, devices } = loadAll();
  const user = users[req.session.userId];

  const allowedZones = new Set(user.zones || []);
  const allowedDevices = Object.entries(devices)
    .filter(([id, d]) => allowedZones.has(d.zone))
    .map(([id, d]) => ({ id, ...d, zoneName: zones[d.zone]?.title || d.zone }));

  // группировка по зонам
  const byZone = {};
  for (const d of allowedDevices) {
    const key = d.zone;
    byZone[key] = byZone[key] || { zone: key, zoneName: d.zoneName, devices: [] };
    byZone[key].devices.push(d);
  }

  res.render('dashboard', {
    user,
    byZone: Object.values(byZone).sort((a,b)=>a.zoneName.localeCompare(b.zoneName,'ru')),
    title: 'Зоны • Parking Git',
    bodyClass: 'theme-premium page-dashboard'
  });
});

app.post('/api/open/:deviceId', authRequired, async (req, res) => {
  const deviceId = req.params.deviceId;
  const { users, devices, logs } = loadAll();
  const user = users[req.session.userId];
  const device = devices[deviceId];

  if (!device) return res.status(404).json({ ok: false, error: 'Устройство не найдено' });

  const allowedZones = new Set(user.zones || []);
  if (!allowedZones.has(device.zone)) return res.status(403).json({ ok: false, error: 'Нет доступа к зоне' });

  try {
    await openDevice(device);
await appendTransitEvent({
  point: devicePointLabel(device, deviceId),
  event: 'Открытие',
  source: user?.fio ? `Оператор: ${user.fio}` : 'Система',
  result: 'Успешно',
  session: req.sessionID || null
});
res.json({ ok: true });
  } catch (e) {
    await appendTransitEvent({
  point: devicePointLabel(device, deviceId),
  event: 'Ошибка',
  source: user?.fio ? `Оператор: ${user.fio}` : 'Система',
  result: 'Ошибка: ' + String(e.message || e),
  session: req.sessionID || null
});
res.status(500).json({ ok: false, error: 'Ошибка открытия: ' + (e.message || e) });
  }
});


app.get('/logs', authRequired, (req, res) => {
  const { users, transit } = loadAll();
  const user = users[req.session.userId];

  const fio = String(user.fio || '').trim();
  const phone = String(user.phone || '').replace(/\D/g, '');

  const base = transit
    .slice()
    .reverse()
    .filter(e => {
      const src = String(e.source || '');
      const srcDigits = src.replace(/\D/g, '');
      return (fio && src.includes(fio)) || (phone && srcDigits.includes(phone));
    });

  const options = getTransitFilterOptions(base);
  const filtered = applyTransitFilters(base, req.query).slice(0, 500);

  res.render('logs', {
    title: 'Журнал событий (транзитные проходы) — мои',
    logs: filtered,
    user,
    bodyClass: 'theme-premium',
    options,
    filters: {
      point: (req.query.point || '').trim(),
      event: (req.query.event || '').trim(),
      date_from: (req.query.date_from || '').trim(),
      date_to: (req.query.date_to || '').trim()
    },
    exportUrlBase: '/logs.csv'
  });
});

app.get('/logs.csv', authRequired, (req, res) => {
  const { users, transit } = loadAll();
  const user = users[req.session.userId];

  const fio = String(user.fio || '').trim();
  const phone = String(user.phone || '').replace(/\D/g, '');

  const base = transit
    .slice()
    .reverse()
    .filter(e => {
      const src = String(e.source || '');
      const srcDigits = src.replace(/\D/g, '');
      return (fio && src.includes(fio)) || (phone && srcDigits.includes(phone));
    });

  const filtered = applyTransitFilters(base, req.query);
  const rows = transitToCsvRows(filtered);
  const stamp = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
  sendCsv(res, `transit-my-${stamp}.csv`, rows);
});



app.get('/admin/logs', authRequired, adminRequired, (req, res) => {
  res.redirect('/admin/transit');
});


// ------------------- ADMIN -------------------
app.get('/admin', authRequired, adminRequired, (req, res) => {
  res.redirect('/admin/users');
});

app.get('/admin/users', authRequired, adminRequired, (req, res) => {
  const { users, zones, roles } = loadAll();
  res.render('admin_users', { users, zones, roles, msg: null, user: users[req.session.userId], bodyClass: 'theme-premium' });
});


app.post('/admin/users/new', authRequired, adminRequired, (req, res) => {
  const { users } = loadAll();
  const fio = String(req.body.fio || '').trim();
  const phone = String(req.body.phone || '').trim();
  const role = String(req.body.role || 'user').trim();
  const status = String(req.body.status || 'active').trim();
  const pinRaw = String(req.body.pin || '').trim();

  if (!phone) return res.status(400).send('Телефон обязателен');
  // ensure phone unique
  const existing = findUserIdByPhone(users, phone);
  if (existing) return res.status(400).send('Пользователь с таким телефоном уже есть');

  const id = 'u_' + Date.now();
  const zonesBody = req.body.zones;
  let zones = [];
  if (Array.isArray(zonesBody)) zones = zonesBody;
  else if (typeof zonesBody === 'string') zones = [zonesBody];

  users[id] = {
    fio: fio || '',
    phone,
    role,
    status,
    zones,
  };
  if (pinRaw) users[id].pin = pinRaw;

  writeJson(USERS_FILE, users);
  appendAudit(req, 'user_create', 'user', id, { fio, phone, role, status, zones });
  res.redirect('/admin/users');
});

app.post('/admin/users/:id/delete', authRequired, adminRequired, (req, res) => {
  const userId = req.params.id;
  const { users } = loadAll();
  const u = users[userId];
  if (!u) return res.status(404).send('User not found');
  delete users[userId];
  writeJson(USERS_FILE, users);
  appendAudit(req, 'user_delete', 'user', userId, { phone: u.phone, fio: u.fio });
  res.redirect('/admin/users');
});

app.post('/admin/users/:id', authRequired, adminRequired, (req, res) => {
  const userId = req.params.id;
  const { users } = loadAll();
  if (!users[userId]) return res.status(404).send('User not found');

  users[userId].fio = req.body.fio ?? users[userId].fio;
  users[userId].phone = req.body.phone ?? users[userId].phone;
  users[userId].role = req.body.role ?? users[userId].role;
  users[userId].status = req.body.status ?? users[userId].status;

  // zones[] (checkboxes)
  const zones = req.body.zones;
  if (Array.isArray(zones)) users[userId].zones = zones;
  if (typeof zones === 'string') users[userId].zones = [zones];
  if (!zones) users[userId].zones = [];

  // pin optional
  if (req.body.pin !== undefined && String(req.body.pin).trim() !== '') {
    users[userId].pin = String(req.body.pin).trim();
  }

  writeJson(USERS_FILE, users);
  appendAudit(req, 'user_update', 'user', userId, { fio: users[userId].fio, phone: users[userId].phone, role: users[userId].role, status: users[userId].status, zones: users[userId].zones, pinSet: (users[userId].pin?true:false) });
  res.redirect('/admin/users');
});

app.get('/admin/devices', authRequired, adminRequired, (req, res) => {
  const { users, devices, zones } = loadAll();
  res.render('admin_devices', { devices, zones, msg: null, user: users[req.session.userId], bodyClass: 'theme-premium' });
});


app.post('/admin/devices/new', authRequired, adminRequired, (req, res) => {
  const id = String(req.body.id || '').trim();
  if (!id) return res.status(400).send('Device id required');
  req.params.id = id;
  // переиспользуем обработчик /admin/devices/:id
  res.redirect(307, '/admin/devices/' + encodeURIComponent(id));
});
app.post('/admin/devices/:id', authRequired, adminRequired, (req, res) => {
  const deviceId = req.params.id;
  const { devices } = loadAll();
  if (!devices[deviceId]) devices[deviceId] = {};
  devices[deviceId].name = req.body.name || deviceId;
  devices[deviceId].zone = req.body.zone;
  devices[deviceId].type = req.body.type || 'rodos';
  devices[deviceId].method = req.body.method || 'GET';

  // URL: можно хранить сразу с http://user:pass@ip/...
  devices[deviceId].url = req.body.url;

  writeJson(DEVICES_FILE, devices);
  appendAudit(req, 'device_upsert', 'device', id, { name, zone, method, url });
  res.redirect('/admin/devices');
});

app.post('/admin/devices/:id/delete', authRequired, adminRequired, (req, res) => {
  const deviceId = req.params.id;
  const { devices } = loadAll();
  delete devices[deviceId];
  writeJson(DEVICES_FILE, devices);
  appendAudit(req, 'device_upsert', 'device', id, { name, zone, method, url });
  res.redirect('/admin/devices');
});


app.get('/admin/transit', authRequired, adminRequired, (req, res) => {
  const { users, transit } = loadAll();
  const user = users[req.session.userId];

  const base = transit.slice().reverse(); // newest first
  const options = getTransitFilterOptions(base);
  const filtered = applyTransitFilters(base, req.query).slice(0, 2000);

  res.render('logs', {
    title: 'Журнал событий (транзитные проходы) — все',
    logs: filtered,
    user,
    bodyClass: 'theme-premium',
    options,
    filters: {
      point: (req.query.point || '').trim(),
      event: (req.query.event || '').trim(),
      date_from: (req.query.date_from || '').trim(),
      date_to: (req.query.date_to || '').trim()
    },
    exportUrlBase: '/admin/transit.csv'
  });
});

app.get('/admin/transit.csv', authRequired, adminRequired, (req, res) => {
  const { transit } = loadAll();
  const base = transit.slice().reverse();
  const filtered = applyTransitFilters(base, req.query);
  const rows = transitToCsvRows(filtered);
  const stamp = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
  sendCsv(res, `transit-all-${stamp}.csv`, rows);
});


app.get('/admin/audit', authRequired, adminRequired, (req, res) => {
  const { users, audit } = loadAll();
  const list = audit.slice().reverse().slice(0, 1000);
  res.render('admin_audit', { title: 'Админ • Журнал действий', entries: list, user: users[req.session.userId], bodyClass: 'theme-premium' });
});

app.listen(PORT, () => {
  console.log(`✅ SKUD WebApp запущен: http://localhost:${PORT}`);
  console.log(`PIN по умолчанию: последние 4 цифры телефона (если pin не задан в users.json)`);
});