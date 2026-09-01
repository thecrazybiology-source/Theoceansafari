// ============================================================
// THE OCEAN SAFARI — backend consolidado em um único arquivo.
// Todas as rotas de /api/* passam por aqui via rewrite no vercel.json.
// ============================================================
const crypto = require('crypto');
const { Pool } = require('pg');

// ---------- Banco de dados ----------
let pool;
function getPool() {
  if (!pool) {
    if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL não configurada.');
    pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 5 });
  }
  return pool;
}

// ---------- Sessão de admin (cookie assinado, sem dependências extras) ----------
const SECRET = process.env.ADMIN_SESSION_SECRET || 'dev-only-change-me';
const SESSION_MAX_AGE = 8 * 60 * 60; // 8 horas

function b64url(buf) { return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function fromB64url(str) { return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64'); }

function signSession(payloadObj) {
  const payload = { ...payloadObj, exp: Date.now() + SESSION_MAX_AGE * 1000 };
  const json = b64url(Buffer.from(JSON.stringify(payload)));
  const sig = b64url(crypto.createHmac('sha256', SECRET).update(json).digest());
  return `${json}.${sig}`;
}
function verifySession(token) {
  if (!token || !token.includes('.')) return null;
  const [json, sig] = token.split('.');
  const expected = b64url(crypto.createHmac('sha256', SECRET).update(json).digest());
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(fromB64url(json).toString());
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}
function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  });
  return out;
}
function requireAdmin(req) {
  const session = verifySession(parseCookies(req).admin_session);
  return !!(session && session.role === 'admin');
}
function setAdminCookie(res, token) {
  const isProd = process.env.NODE_ENV === 'production';
  const parts = [`admin_session=${token}`, 'HttpOnly', 'Path=/', 'SameSite=Strict', `Max-Age=${SESSION_MAX_AGE}`];
  if (isProd) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function clearAdminCookie(res) {
  res.setHeader('Set-Cookie', 'admin_session=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0');
}

// ---------- Body helper ----------
function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string' && req.body.length) { try { return JSON.parse(req.body); } catch { return {}; } }
  return {};
}

// ---------- Settings ----------
async function getHoldMinutes(pool) {
  try {
    const { rows } = await pool.query(`SELECT value FROM settings WHERE key = 'hold_duration_minutes'`);
    const n = rows.length ? Number(rows[0].value) : NaN;
    return Number.isFinite(n) && n > 0 ? n : 120;
  } catch { return 120; }
}

// ---------- Util ----------
function genCode(year, n) { return `OCS-${year}-${String(n).padStart(5, '0')}`; }
function isValidCpfFormat(cpf) { return String(cpf || '').replace(/\D/g, '').length === 11; }
function dateStr(v) { return v instanceof Date ? v.toISOString().slice(0, 10) : v; }

const VALID_STATUSES = ['AGUARDANDO_CONTATO', 'AGUARDANDO_PAGAMENTO', 'CONFIRMADA', 'CANCELADA', 'EXPIRADA'];
const ACTIVE_STATUSES = ['AGUARDANDO_CONTATO', 'AGUARDANDO_PAGAMENTO'];

// ============================================================
// ROTAS PÚBLICAS
// ============================================================

async function tripsGet(req, res) {
  const pool = getPool();
  const from = req.query.from || new Date().toISOString().slice(0, 10);
  const to = req.query.to;
  const params = [from];
  let sql = `SELECT date, start_time, end_time, meeting_point, price_cents, capacity, confirmed, held, status FROM trips WHERE date >= $1`;
  if (to) { params.push(to); sql += ` AND date <= $2`; }
  sql += ' ORDER BY date ASC';
  const { rows } = await pool.query(sql, params);
  const trips = rows.map((t) => ({
    date: dateStr(t.date), start: t.start_time, end: t.end_time, point: t.meeting_point,
    price: t.price_cents / 100, capacity: t.capacity,
    available: t.status === 'blocked' ? 0 : Math.max(0, t.capacity - t.confirmed - t.held),
    status: t.status
  }));
  res.status(200).json({ trips });
}

async function holdsPost(req, res) {
  const body = readBody(req);
  const { date, qty, responsible, participants, healthAnswer, healthNote, healthConsent, termsVersion, documentHash } = body;

  if (!date || !qty || !Number.isInteger(qty) || qty < 1) return res.status(400).json({ error: 'invalid_date_or_qty' });
  if (!responsible || !responsible.name || !responsible.phone || !responsible.cpf) return res.status(400).json({ error: 'missing_responsible_data' });
  if (!isValidCpfFormat(responsible.cpf)) return res.status(400).json({ error: 'invalid_cpf_format' });
  if (!termsVersion || !documentHash) return res.status(400).json({ error: 'terms_not_accepted' });
  if (healthConsent !== true) return res.status(400).json({ error: 'health_consent_required' });

  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const holdRes = await client.query(
      `UPDATE trips SET held = held + $1, updated_at = now()
       WHERE date = $2 AND status = 'scheduled' AND (capacity - confirmed - held) >= $1
       RETURNING date`, [qty, date]
    );
    if (holdRes.rowCount === 0) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'not_enough_availability' }); }

    const seqRes = await client.query(`SELECT nextval('hold_code_seq') AS n`);
    const year = new Date(`${date}T00:00:00Z`).getUTCFullYear();
    const code = genCode(year, seqRes.rows[0].n);
    const holdMinutes = await getHoldMinutes(pool);
    const expiresAt = new Date(Date.now() + holdMinutes * 60 * 1000);
    const ip = String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim();
    const ua = req.headers['user-agent'] || '';

    const insertRes = await client.query(
      `INSERT INTO holds (code, trip_date, qty, status, responsible_name, responsible_email, responsible_phone,
         responsible_cpf, participants, health_answer, health_note, health_consent, terms_version,
         terms_document_hash, accept_ip, accept_user_agent, expires_at)
       VALUES ($1,$2,$3,'AGUARDANDO_CONTATO',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
       RETURNING code, expires_at`,
      [code, date, qty, responsible.name, responsible.email || null, responsible.phone, responsible.cpf,
        JSON.stringify(participants || []), healthAnswer === true, healthNote || null, healthConsent === true,
        termsVersion, documentHash, ip, ua, expiresAt]
    );
    await client.query('COMMIT');
    res.status(201).json({ code: insertRes.rows[0].code, expiresAt: insertRes.rows[0].expires_at, status: 'AGUARDANDO_CONTATO' });
  } catch (err) {
    await client.query('ROLLBACK'); console.error('holdsPost', err);
    res.status(500).json({ error: 'internal_error' });
  } finally { client.release(); }
}

async function holdsStatusGet(req, res) {
  const code = String(req.query.code || '').trim().toUpperCase();
  if (!code) return res.status(400).json({ error: 'missing_code' });
  const pool = getPool();
  const { rows } = await pool.query(`SELECT code, trip_date, qty, status, expires_at FROM holds WHERE code = $1`, [code]);
  if (!rows.length) return res.status(404).json({ error: 'not_found' });
  const h = rows[0];
  res.status(200).json({ code: h.code, date: dateStr(h.trip_date), qty: h.qty, status: h.status, expiresAt: h.expires_at });
}

// ============================================================
// ROTAS ADMIN
// ============================================================

async function adminLoginPost(req, res) {
  const { password } = readBody(req);
  const expected = process.env.ADMIN_PASSWORD;
  if (!expected) return res.status(500).json({ error: 'admin_password_not_configured' });
  const a = Buffer.from(String(password || '').trim()), b = Buffer.from(String(expected).trim());
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!ok) return res.status(401).json({ error: 'invalid_password' });
  setAdminCookie(res, signSession({ role: 'admin' }));
  res.status(200).json({ ok: true });
}
async function adminLogoutPost(req, res) { clearAdminCookie(res); res.status(200).json({ ok: true }); }
async function adminSessionGet(req, res) { requireAdmin(req) ? res.status(200).json({ ok: true }) : res.status(401).json({ ok: false }); }

async function adminSettings(req, res) {
  const pool = getPool();
  if (req.method === 'GET') return res.status(200).json({ holdMinutes: await getHoldMinutes(pool) });
  if (req.method === 'PATCH') {
    const { holdMinutes } = readBody(req);
    const n = Number(holdMinutes);
    if (!Number.isFinite(n) || n < 5 || n > 1440) return res.status(400).json({ error: 'invalid_hold_minutes' });
    await pool.query(`INSERT INTO settings (key, value) VALUES ('hold_duration_minutes', $1)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, [String(n)]);
    return res.status(200).json({ ok: true, holdMinutes: n });
  }
  res.status(405).json({ error: 'method_not_allowed' });
}

async function adminTrips(req, res) {
  const pool = getPool();
  if (req.method === 'GET') {
    const { rows } = await pool.query(`SELECT * FROM trips ORDER BY date ASC`);
    return res.status(200).json({
      trips: rows.map((t) => ({
        date: dateStr(t.date), start: t.start_time, end: t.end_time, point: t.meeting_point,
        price: t.price_cents / 100, capacity: t.capacity, confirmed: t.confirmed, held: t.held, status: t.status
      }))
    });
  }
  if (req.method === 'POST') {
    const { date, capacity, start, end, point, price } = readBody(req);
    if (!date || !capacity || capacity < 1) return res.status(400).json({ error: 'missing_or_invalid_fields' });
    await pool.query(
      `INSERT INTO trips (date, start_time, end_time, meeting_point, price_cents, capacity)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (date) DO UPDATE SET capacity=EXCLUDED.capacity, start_time=EXCLUDED.start_time,
         end_time=EXCLUDED.end_time, meeting_point=EXCLUDED.meeting_point, price_cents=EXCLUDED.price_cents, updated_at=now()`,
      [date, start || '06:00', end || '12:00', point || 'Ilhabela', Math.round((price || 649) * 100), capacity]
    );
    return res.status(201).json({ ok: true });
  }
  if (req.method === 'PATCH') {
    const { date, capacity, price, status } = readBody(req);
    if (!date) return res.status(400).json({ error: 'missing_date' });
    const fields = [], values = []; let i = 1;
    if (capacity != null) { fields.push(`capacity = $${i++}`); values.push(capacity); }
    if (price != null) { fields.push(`price_cents = $${i++}`); values.push(Math.round(price * 100)); }
    if (status) {
      if (!['scheduled', 'blocked'].includes(status)) return res.status(400).json({ error: 'invalid_status' });
      fields.push(`status = $${i++}`); values.push(status);
    }
    if (!fields.length) return res.status(400).json({ error: 'nothing_to_update' });
    values.push(date);
    const result = await pool.query(`UPDATE trips SET ${fields.join(', ')}, updated_at = now() WHERE date = $${i}`, values);
    if (result.rowCount === 0) return res.status(404).json({ error: 'trip_not_found' });
    return res.status(200).json({ ok: true });
  }
  if (req.method === 'DELETE') {
    const { date } = readBody(req);
    if (!date) return res.status(400).json({ error: 'missing_date' });
    const { rows } = await pool.query(`SELECT held, confirmed FROM trips WHERE date = $1`, [date]);
    if (!rows.length) return res.status(404).json({ error: 'trip_not_found' });
    if (rows[0].held > 0 || rows[0].confirmed > 0) return res.status(409).json({ error: 'trip_has_active_bookings' });
    await pool.query(`DELETE FROM trips WHERE date = $1`, [date]);
    return res.status(200).json({ ok: true });
  }
  res.status(405).json({ error: 'method_not_allowed' });
}

async function adminTripsBulkPost(req, res) {
  const { months, capacity, price, point, daysOfWeek } = readBody(req);
  const monthsAhead = Number(months) > 0 ? Number(months) : 12;
  const cap = Number(capacity) > 0 ? Number(capacity) : 10;
  const priceCents = Math.round((Number(price) > 0 ? Number(price) : 649) * 100);
  const dows = Array.isArray(daysOfWeek) && daysOfWeek.length ? daysOfWeek : [0, 6];

  const today = new Date(); today.setHours(0, 0, 0, 0);
  const limit = new Date(today); limit.setMonth(limit.getMonth() + monthsAhead);
  const dates = [];
  const cursor = new Date(today); cursor.setDate(cursor.getDate() + 1);
  while (cursor <= limit) { if (dows.includes(cursor.getDay())) dates.push(dateStr(new Date(cursor))); cursor.setDate(cursor.getDate() + 1); }

  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let created = 0;
    for (const date of dates) {
      const result = await client.query(
        `INSERT INTO trips (date, start_time, end_time, meeting_point, price_cents, capacity)
         VALUES ($1,'06:00','12:00',$2,$3,$4) ON CONFLICT (date) DO NOTHING`,
        [date, point || 'Ilhabela', priceCents, cap]
      );
      created += result.rowCount;
    }
    await client.query('COMMIT');
    res.status(200).json({ ok: true, requested: dates.length, created, skippedExisting: dates.length - created });
  } catch (err) {
    await client.query('ROLLBACK'); console.error('adminTripsBulkPost', err);
    res.status(500).json({ error: 'internal_error' });
  } finally { client.release(); }
}

async function adminHoldsGet(req, res) {
  const pool = getPool();
  const { rows } = await pool.query(`SELECT * FROM holds ORDER BY created_at DESC LIMIT 500`);
  res.status(200).json({
    holds: rows.map((h) => ({
      code: h.code, date: dateStr(h.trip_date), qty: h.qty, status: h.status,
      responsible: { name: h.responsible_name, email: h.responsible_email, phone: h.responsible_phone, cpf: h.responsible_cpf },
      participants: h.participants, healthAnswer: h.health_answer, healthNote: h.health_note,
      termsVersion: h.terms_version, termsAcceptedAt: h.terms_accepted_at, documentHash: h.terms_document_hash,
      acceptIp: h.accept_ip, createdAt: h.created_at, expiresAt: h.expires_at,
      confirmedAt: h.confirmed_at, cancelledAt: h.cancelled_at, adminNotes: h.admin_notes
    }))
  });
}

async function adminHoldsActionPost(req, res) {
  const { code, action, hours, status } = readBody(req);
  if (!code || !action) return res.status(400).json({ error: 'missing_fields' });
  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(`SELECT * FROM holds WHERE code = $1 FOR UPDATE`, [String(code).toUpperCase()]);
    if (!rows.length) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'not_found' }); }
    const hold = rows[0];

    if (action === 'confirm') {
      if (!ACTIVE_STATUSES.includes(hold.status)) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'invalid_state', current: hold.status }); }
      await client.query(`UPDATE trips SET held = GREATEST(held - $1, 0), confirmed = confirmed + $1, updated_at = now() WHERE date = $2`, [hold.qty, hold.trip_date]);
      await client.query(`UPDATE holds SET status = 'CONFIRMADA', confirmed_at = now() WHERE code = $1`, [hold.code]);
    } else if (action === 'cancel') {
      if (hold.status === 'CONFIRMADA') await client.query(`UPDATE trips SET confirmed = GREATEST(confirmed - $1, 0), updated_at = now() WHERE date = $2`, [hold.qty, hold.trip_date]);
      else if (ACTIVE_STATUSES.includes(hold.status)) await client.query(`UPDATE trips SET held = GREATEST(held - $1, 0), updated_at = now() WHERE date = $2`, [hold.qty, hold.trip_date]);
      await client.query(`UPDATE holds SET status = 'CANCELADA', cancelled_at = now() WHERE code = $1`, [hold.code]);
    } else if (action === 'extend') {
      if (!ACTIVE_STATUSES.includes(hold.status)) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'invalid_state', current: hold.status }); }
      const addHours = Number(hours) > 0 ? Number(hours) : 2;
      await client.query(`UPDATE holds SET expires_at = expires_at + ($1 || ' hours')::interval WHERE code = $2`, [addHours, hold.code]);
    } else if (action === 'set_status') {
      if (!VALID_STATUSES.includes(status)) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'invalid_status' }); }
      const wasActive = ACTIVE_STATUSES.includes(hold.status), wasConfirmed = hold.status === 'CONFIRMADA';
      const willBeActive = ACTIVE_STATUSES.includes(status), willBeConfirmed = status === 'CONFIRMADA';
      if (wasConfirmed && !willBeConfirmed) await client.query(`UPDATE trips SET confirmed = GREATEST(confirmed - $1, 0), updated_at = now() WHERE date = $2`, [hold.qty, hold.trip_date]);
      if (wasActive && !willBeActive) await client.query(`UPDATE trips SET held = GREATEST(held - $1, 0), updated_at = now() WHERE date = $2`, [hold.qty, hold.trip_date]);
      if (!wasConfirmed && willBeConfirmed) await client.query(`UPDATE trips SET confirmed = confirmed + $1, updated_at = now() WHERE date = $2`, [hold.qty, hold.trip_date]);
      if (!wasActive && willBeActive) await client.query(`UPDATE trips SET held = held + $1, updated_at = now() WHERE date = $2`, [hold.qty, hold.trip_date]);
      await client.query(`UPDATE holds SET status = $1 WHERE code = $2`, [status, hold.code]);
    } else { await client.query('ROLLBACK'); return res.status(400).json({ error: 'unknown_action' }); }

    await client.query('COMMIT');
    res.status(200).json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK'); console.error('adminHoldsActionPost', err);
    res.status(500).json({ error: 'internal_error' });
  } finally { client.release(); }
}

async function adminHoldsManualPost(req, res) {
  const { date, qty, responsible, adminNotes } = readBody(req);
  if (!date || !qty || !Number.isInteger(qty) || qty < 1) return res.status(400).json({ error: 'invalid_date_or_qty' });
  if (!responsible || !responsible.name || !responsible.phone) return res.status(400).json({ error: 'missing_responsible_data' });

  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const upd = await client.query(
      `UPDATE trips SET confirmed = confirmed + $1, updated_at = now()
       WHERE date = $2 AND (capacity - confirmed - held) >= $1 RETURNING date`, [qty, date]
    );
    if (upd.rowCount === 0) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'not_enough_availability' }); }

    const seqRes = await client.query(`SELECT nextval('hold_code_seq') AS n`);
    const year = new Date(`${date}T00:00:00Z`).getUTCFullYear();
    const code = genCode(year, seqRes.rows[0].n);

    const insertRes = await client.query(
      `INSERT INTO holds (code, trip_date, qty, status, responsible_name, responsible_email, responsible_phone,
         responsible_cpf, terms_version, terms_accepted_at, expires_at, confirmed_at, admin_notes)
       VALUES ($1,$2,$3,'CONFIRMADA',$4,$5,$6,$7,'MANUAL', now(), now(), now(), $8) RETURNING code`,
      [code, date, qty, responsible.name, responsible.email || null, responsible.phone, responsible.cpf || null,
        adminNotes || 'Reserva fechada diretamente pelo WhatsApp e lançada manualmente pelo admin.']
    );
    await client.query('COMMIT');
    res.status(201).json({ code: insertRes.rows[0].code, status: 'CONFIRMADA' });
  } catch (err) {
    await client.query('ROLLBACK'); console.error('adminHoldsManualPost', err);
    res.status(500).json({ error: 'internal_error' });
  } finally { client.release(); }
}

// ============================================================
// CRON
// ============================================================
async function cronExpire(req, res) {
  if (process.env.CRON_SECRET) {
    if (req.headers['authorization'] !== `Bearer ${process.env.CRON_SECRET}`) return res.status(401).json({ error: 'unauthorized' });
  }
  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `SELECT code, trip_date, qty FROM holds WHERE status IN ('AGUARDANDO_CONTATO','AGUARDANDO_PAGAMENTO') AND expires_at < now() FOR UPDATE`
    );
    for (const h of rows) {
      await client.query(`UPDATE trips SET held = GREATEST(held - $1, 0), updated_at = now() WHERE date = $2`, [h.qty, h.trip_date]);
      await client.query(`UPDATE holds SET status = 'EXPIRADA' WHERE code = $1`, [h.code]);
    }
    await client.query('COMMIT');
    res.status(200).json({ expired: rows.length, codes: rows.map((r) => r.code) });
  } catch (err) {
    await client.query('ROLLBACK'); console.error('cronExpire', err);
    res.status(500).json({ error: 'internal_error' });
  } finally { client.release(); }
}

// ============================================================
// ROTEADOR — usa req.query.path (vindo do rewrite do vercel.json)
// ============================================================
module.exports = async (req, res) => {
  try {
    const rawPath = req.query.path || '';
    const segments = String(rawPath).split('/').filter(Boolean);
    const path = '/' + segments.join('/');
    const method = req.method;

    if (path === '/trips' && method === 'GET') return await tripsGet(req, res);
    if (path === '/holds' && method === 'POST') return await holdsPost(req, res);
    if (path === '/holds/status' && method === 'GET') return await holdsStatusGet(req, res);

    if (path === '/admin/login' && method === 'POST') return await adminLoginPost(req, res);
    if (path === '/admin/logout' && method === 'POST') return await adminLogoutPost(req, res);
    if (path === '/admin/session' && method === 'GET') return await adminSessionGet(req, res);

    if (path.startsWith('/admin/') && path !== '/admin/login') {
      if (!requireAdmin(req)) return res.status(401).json({ error: 'unauthorized' });
    }
    if (path === '/admin/settings') return await adminSettings(req, res);
    if (path === '/admin/trips') return await adminTrips(req, res);
    if (path === '/admin/trips/bulk' && method === 'POST') return await adminTripsBulkPost(req, res);
    if (path === '/admin/holds' && method === 'GET') return await adminHoldsGet(req, res);
    if (path === '/admin/holds/action' && method === 'POST') return await adminHoldsActionPost(req, res);
    if (path === '/admin/holds/manual' && method === 'POST') return await adminHoldsManualPost(req, res);

    if (path === '/cron/expire') return await cronExpire(req, res);

    res.status(404).json({ error: 'not_found', path });
  } catch (err) {
    console.error('router error', err);
    res.status(500).json({ error: 'internal_error' });
  }
};
