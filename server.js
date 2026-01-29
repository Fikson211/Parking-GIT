"use strict";

/**
 * Parking-GIT (Postgres)
 * Единый рабочий server.js (старый JSON-код удалён).
 *
 * ENV:
 *   DATABASE_URL      — строка подключения к Postgres (Railway)
 *   SESSION_SECRET    — секрет для сессий
 *
 * Опционально:
 *   ADMIN_PHONE, ADMIN_PIN, ADMIN_FIO
 */

require("dotenv").config();

const path = require("path");
const express = require("express");
const session = require("express-session");

const { ensureSchema, dbQuery } = require("./db");

const app = express();

// --- базовые настройки ---
const PORT = Number(process.env.PORT || 8080);
const SESSION_SECRET = process.env.SESSION_SECRET || "change-me-in-railway";

app.disable("x-powered-by");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.engine("ejs", require("ejs").__express);

// статические
app.use("/public", express.static(path.join(__dirname, "public")));

// --- helpers ---
function digitsOnly(s) {
  return String(s || "").replace(/\D+/g, "");
}

function last4(phoneDigits) {
  const p = digitsOnly(phoneDigits);
  return p.slice(-4);
}

function normalizePhone(input) {
  let p = digitsOnly(input);
  // если ввели без 7/8 и длина 10 — добавим 7
  if (p.length === 10) p = "7" + p;
  // если ввели с 8 и длина 11 — заменим на 7
  if (p.length === 11 && p.startsWith("8")) p = "7" + p.slice(1);
  return p;
}

async function audit(actorId, action, objectType, objectId, detail) {
  try {
    await dbQuery(
      `INSERT INTO public.audit(created_at, actor_id, action, object_type, object_id, detail)
       VALUES (now(), $1, $2, $3, $4, $5)`,
      [actorId || null, action, objectType || null, objectId || null, detail || null]
    );
  } catch {
    // аудит не должен валить приложение
  }
}

// --- auth middleware ---
function requireAuth(req, res, next) {
  if (req.session?.user?.id) return next();
  return res.redirect("/login");
}

function requireAdmin(req, res, next) {
  if (req.session?.user?.role === "admin") return next();
  return res.status(403).send("Forbidden");
}

// --- DB bootstrap: default admin ---
async function ensureDefaultAdmin() {
  const adminPhone = normalizePhone(process.env.ADMIN_PHONE || "79991112233");
  const adminPin = digitsOnly(process.env.ADMIN_PIN || "1234");
  const fio = process.env.ADMIN_FIO || "Администратор";

  const exists = await dbQuery(
    `SELECT id FROM public.users
     WHERE regexp_replace(coalesce(phone,''), '[^0-9]', '', 'g') = $1
     LIMIT 1`,
    [adminPhone]
  );

  if (exists.rows.length) return;

  await dbQuery(
    `INSERT INTO public.users(id,fio,phone,pin,role,zones,is_active,status,created_at)
     VALUES ($1,$2,$3,$4,'admin',ARRAY[]::text[],true,'active',now())
     ON CONFLICT (id) DO NOTHING`,
    ["u_admin", fio, adminPhone, adminPin]
  );

  console.log("✅ Создан админ по умолчанию:", adminPhone, "PIN:", adminPin);
}

// --- pages ---
app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/login", (req, res) => {
  if (req.session?.user?.id) return res.redirect("/");
  return res.render("login", { error: null, brandTitle: "Parking GIT" });
});

app.post("/login", async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const pinInput = digitsOnly(req.body.pin);

  if (!phone || !pinInput) {
    return res.status(400).render("login", {
      error: "Введите телефон и PIN",
      brandTitle: "Parking GIT",
    });
  }

  const r = await dbQuery(
    `SELECT id,fio,phone,role,pin,zones,is_active,status
     FROM public.users
     WHERE regexp_replace(coalesce(phone,''), '[^0-9]', '', 'g') = $1
     LIMIT 1`,
    [phone]
  );

  if (!r.rows.length) {
    return res.status(401).render("login", {
      error: "Телефон не найден",
      brandTitle: "Parking GIT",
    });
  }

  const user = r.rows[0];

  // активность: поддерживаем и is_active и status
  const active =
    (typeof user.is_active === "boolean" ? user.is_active : true) &&
    (user.status ? String(user.status).toLowerCase() !== "blocked" : true);

  if (!active) {
    return res.status(403).render("login", {
      error: "Пользователь заблокирован",
      brandTitle: "Parking GIT",
    });
  }

  const storedPin = digitsOnly(user.pin);
  const effectivePin = storedPin || last4(user.phone);
  if (pinInput !== effectivePin) {
    await audit(user.id, "login_failed", "user", user.id, "wrong_pin");
    return res.status(401).render("login", {
      error: "Неверный PIN",
      brandTitle: "Parking GIT",
    });
  }

  req.session.user = {
    id: user.id,
    fio: user.fio,
    phone: normalizePhone(user.phone),
    role: user.role,
    zones: Array.isArray(user.zones) ? user.zones : [],
  };

  await audit(user.id, "login", "user", user.id, null);
  return res.redirect("/");
});

app.post("/logout", (req, res) => {
  const uid = req.session?.user?.id;
  req.session.destroy(() => {
    if (uid) audit(uid, "logout", "user", uid, null);
    res.redirect("/login");
  });
});

// --- dashboard ---
app.get("/", requireAuth, async (req, res) => {
  const me = req.session.user;

  const [zonesRes, devicesRes] = await Promise.all([
    dbQuery(
      `SELECT id,name,sort,is_active FROM public.zones
       WHERE coalesce(is_active,true) = true
       ORDER BY sort ASC, name ASC`,
      []
    ),
    dbQuery(
      `SELECT id,name,zone_id,method,url,sort,is_active FROM public.devices
       WHERE coalesce(is_active,true) = true
       ORDER BY sort ASC, name ASC`,
      []
    ),
  ]);

  const allowed = new Set(me.role === "admin" ? zonesRes.rows.map((z) => z.id) : me.zones);

  const zones = zonesRes.rows
    .filter((z) => allowed.has(z.id))
    .map((z) => ({
      ...z,
      devices: devicesRes.rows.filter((d) => d.zone_id === z.id),
    }));

  res.render("dashboard", {
    me,
    zones,
    brandTitle: "Parking GIT",
  });
});

// --- open device ---
app.post("/api/open/:deviceId", requireAuth, async (req, res) => {
  const me = req.session.user;
  const deviceId = req.params.deviceId;

  const dRes = await dbQuery(
    `SELECT id,name,zone_id,method,url
     FROM public.devices
     WHERE id = $1 AND coalesce(is_active,true)=true
     LIMIT 1`,
    [deviceId]
  );
  if (!dRes.rows.length) return res.status(404).json({ ok: false, error: "Device not found" });

  const device = dRes.rows[0];
  const allowed = me.role === "admin" || (Array.isArray(me.zones) && me.zones.includes(device.zone_id));
  if (!allowed) return res.status(403).json({ ok: false, error: "Forbidden" });

  // Вызов URL устройства
  const url = device.url;
  const method = (device.method || "GET").toUpperCase();

  let result = "success";
  try {
    const r = await fetch(url, { method });
    if (!r.ok) {
      result = `http_${r.status}`;
      throw new Error(`Device HTTP ${r.status}`);
    }

    await dbQuery(
      `INSERT INTO public.transit_events(created_at, point, event, source, result, session)
       VALUES (now(), $1, $2, $3, $4, $5)`,
      [device.name, "open", me.fio || me.id, "ok", req.sessionID]
    );
    await audit(me.id, "open", "device", device.id, device.name);
    return res.json({ ok: true });
  } catch (e) {
    await dbQuery(
      `INSERT INTO public.transit_events(created_at, point, event, source, result, session)
       VALUES (now(), $1, $2, $3, $4, $5)`,
      [device.name, "open", me.fio || me.id, String(e.message || "error"), req.sessionID]
    );
    await audit(me.id, "open_failed", "device", device.id, String(e.message || "error"));
    return res.status(502).json({ ok: false, error: "Device call failed" });
  }
});

// --- logs (transit events) ---
app.get("/logs", requireAuth, async (req, res) => {
  const me = req.session.user;
  const qPoint = req.query.point ? String(req.query.point) : "";
  const qEvent = req.query.event ? String(req.query.event) : "";
  const qFrom = req.query.from ? String(req.query.from) : "";
  const qTo = req.query.to ? String(req.query.to) : "";

  const params = [];
  const where = [];

  // если не админ — показываем только свои события
  if (me.role !== "admin") {
    params.push(me.fio || me.id);
    where.push(`source = $${params.length}`);
  }

  if (qPoint) {
    params.push(qPoint);
    where.push(`point = $${params.length}`);
  }
  if (qEvent) {
    params.push(qEvent);
    where.push(`event = $${params.length}`);
  }
  if (qFrom) {
    params.push(qFrom);
    where.push(`created_at >= $${params.length}::timestamp`);
  }
  if (qTo) {
    params.push(qTo);
    where.push(`created_at <= $${params.length}::timestamp`);
  }

  const sql = `
    SELECT created_at, point, event, source, result, session
    FROM public.transit_events
    ${where.length ? "WHERE " + where.join(" AND ") : ""}
    ORDER BY created_at DESC
    LIMIT 500
  `;

  const logsRes = await dbQuery(sql, params);

  // для фильтров
  const pointsRes = await dbQuery(`SELECT DISTINCT point FROM public.transit_events ORDER BY point`, []);
  const eventsRes = await dbQuery(`SELECT DISTINCT event FROM public.transit_events ORDER BY event`, []);

  res.render("logs", {
    me,
    brandTitle: "Parking GIT",
    logs: logsRes.rows,
    points: pointsRes.rows.map((r) => r.point),
    events: eventsRes.rows.map((r) => r.event),
    filters: { point: qPoint, event: qEvent, from: qFrom, to: qTo },
  });
});

// --- admin: audit log page ---
app.get("/admin/audit", requireAuth, requireAdmin, async (req, res) => {
  const me = req.session.user;
  const aRes = await dbQuery(
    `SELECT created_at, actor_id, action, object_type, object_id, detail
     FROM public.audit
     ORDER BY created_at DESC
     LIMIT 1000`,
    []
  );
  res.render("admin_audit", { me, brandTitle: "Parking GIT", rows: aRes.rows });
});

// --- admin: users list (simple) ---
app.get("/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const me = req.session.user;
  const uRes = await dbQuery(
    `SELECT id,fio,phone,role,pin,zones,is_active,status,created_at
     FROM public.users
     ORDER BY created_at DESC NULLS LAST, id ASC`,
    []
  );
  res.render("admin_users", { me, brandTitle: "Parking GIT", users: uRes.rows, error: null });
});

app.post("/admin/users/save", requireAuth, requireAdmin, async (req, res) => {
  const me = req.session.user;
  const id = String(req.body.id || "").trim() || `u_${Date.now()}`;
  const fio = String(req.body.fio || "").trim() || "Без имени";
  const phone = normalizePhone(req.body.phone);
  const role = String(req.body.role || "user").trim();
  const pin = digitsOnly(req.body.pin || "") || null;
  const zones = Array.isArray(req.body.zones)
    ? req.body.zones.map(String)
    : String(req.body.zones || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
  const isActive = String(req.body.is_active || "true") !== "false";
  const status = isActive ? "active" : "blocked";

  await dbQuery(
    `INSERT INTO public.users(id,fio,phone,role,pin,zones,is_active,status,created_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,coalesce($9,now()))
     ON CONFLICT (id) DO UPDATE SET
       fio=excluded.fio,
       phone=excluded.phone,
       role=excluded.role,
       pin=excluded.pin,
       zones=excluded.zones,
       is_active=excluded.is_active,
       status=excluded.status`,
    [id, fio, phone, role, pin, zones, isActive, status, null]
  );

  await audit(me.id, "user_save", "user", id, phone);
  return res.redirect("/admin/users");
});

// --- not found ---
app.use((req, res) => {
  res.status(404).send("Not Found");
});

// --- start ---
(async () => {
  await ensureSchema();
  await ensureDefaultAdmin();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`✅ Parking GIT запущен: http://0.0.0.0:${PORT}`);
  });
})();
