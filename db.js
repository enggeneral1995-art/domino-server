/*
 * Domino Block Online Server
 * Auth + Profile + USDT Wallet + Free/Paid 1v1 matchmaking
 * + Online Draw / Boneyard
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('./db');

const JWT_SECRET =
  process.env.JWT_SECRET ||
  'change_this_secret_in_railway';

if (!process.env.JWT_SECRET) {
  console.error('='.repeat(70));
  console.error('SECURITY WARNING: JWT_SECRET is not set in Railway Variables.');
  console.error('='.repeat(70));
}

const ADMIN_TOKEN =
  process.env.ADMIN_TOKEN || '';

const NOWPAYMENTS_API_KEY =
  process.env.NOWPAYMENTS_API_KEY || '';

const NOWPAYMENTS_IPN_SECRET =
  process.env.NOWPAYMENTS_IPN_SECRET || '';

const NOWPAYMENTS_EMAIL =
  process.env.NOWPAYMENTS_EMAIL || '';

const NOWPAYMENTS_PASSWORD =
  process.env.NOWPAYMENTS_PASSWORD || '';

const NOWPAYMENTS_2FA_SECRET =
  process.env.NOWPAYMENTS_2FA_SECRET || '';

const NOWPAYMENTS_IPN_URL =
  process.env.NOWPAYMENTS_IPN_URL ||
  'https://domino-server-production-dcd7.up.railway.app/api/nowpayments/ipn';

const TELEGRAM_CHANNEL_LINK =
  process.env.TELEGRAM_CHANNEL_LINK ||
  'https://t.me/yalladomino';

const TELEGRAM_JOIN_BONUS_AMOUNT =
  Number(
    process.env.TELEGRAM_JOIN_BONUS_AMOUNT || 0.50
  );

const NOWPAYMENTS_API_BASE =
  'https://api.nowpayments.io/v1';

const NOWPAYMENTS_NETWORK_CURRENCY = {
  TRC20: 'USDTTRC20',
  BEP20: 'USDTBSC',
  ERC20: 'USDTERC20'
};

function sortObjectDeep(value) {
  if (Array.isArray(value)) {
    return value.map(sortObjectDeep);
  }

  if (
    value &&
    typeof value === 'object'
  ) {
    return Object.keys(value)
      .sort()
      .reduce((result, key) => {
        result[key] =
          sortObjectDeep(value[key]);
        return result;
      }, {});
  }

  return value;
}

function canonicalizeNowPaymentsPayload(rawText) {
  const NUM_MARK = '@@NPNUM@@';

  const marked =
    rawText.replace(
      /([:,\[]\s*)(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)(?=\s*[,}\]])/g,
      (m, prefix, num) =>
        prefix + '"' + NUM_MARK + num + NUM_MARK + '"'
    );

  const parsed = JSON.parse(marked);
  const sorted = sortObjectDeep(parsed);
  const stringified = JSON.stringify(sorted);

  const markRe =
    new RegExp(
      '"' + NUM_MARK + '([^"]*)' + NUM_MARK + '"',
      'g'
    );

  return stringified.replace(markRe, '$1');
}

function verifyNowPaymentsIpn(body, receivedSig, rawBody) {
  if (
    !NOWPAYMENTS_IPN_SECRET ||
    !receivedSig
  ) {
    return false;
  }

  let canonical;
  let usedRawBody = false;

  try {
    if (rawBody) {
      canonical = canonicalizeNowPaymentsPayload(rawBody);
      usedRawBody = true;
    } else {
      canonical = JSON.stringify(sortObjectDeep(body || {}));
    }
  } catch (e) {
    canonical =
      JSON.stringify(sortObjectDeep(body || {}));
  }

  const expected =
    crypto
      .createHmac(
        'sha512',
        NOWPAYMENTS_IPN_SECRET
      )
      .update(
        canonical
      )
      .digest('hex');

  const a =
    Buffer.from(
      expected,
      'utf8'
    );

  const b =
    Buffer.from(
      String(receivedSig),
      'utf8'
    );

  const match =
    a.length === b.length &&
    crypto.timingSafeEqual(a, b);

  return match;
}

async function nowPaymentsRequest(
  path,
  options = {}
) {
  if (!NOWPAYMENTS_API_KEY) {
    throw new Error(
      'nowpayments_api_key_missing'
    );
  }

  const headers = {
    'Content-Type':
      'application/json',

    'x-api-key':
      NOWPAYMENTS_API_KEY,

    ...(options.headers || {})
  };

  const response =
    await fetch(
      NOWPAYMENTS_API_BASE + path,
      {
        method:
          options.method ||
          'GET',

        headers,

        body:
          options.body === undefined
            ? undefined
            : JSON.stringify(
                options.body
              )
      }
    );

  const text =
    await response.text();

  let data = null;

  try {
    data =
      text
        ? JSON.parse(text)
        : {};
  } catch {
    data = {
      raw: text
    };
  }

  if (!response.ok) {
    const error =
      new Error(
        'nowpayments_request_failed'
      );

    error.status =
      response.status;

    error.data =
      data;

    throw error;
  }

  return data;
}

async function getNowPaymentsJwt() {
  if (
    !NOWPAYMENTS_EMAIL ||
    !NOWPAYMENTS_PASSWORD
  ) {
    throw new Error(
      'nowpayments_payout_credentials_missing'
    );
  }

  const response =
    await fetch(
      NOWPAYMENTS_API_BASE +
        '/auth',
      {
        method: 'POST',

        headers: {
          'Content-Type':
            'application/json'
        },

        body:
          JSON.stringify({
            email:
              NOWPAYMENTS_EMAIL,

            password:
              NOWPAYMENTS_PASSWORD
          })
      }
    );

  const data =
    await response.json();

  if (
    !response.ok ||
    !data.token
  ) {
    const error =
      new Error(
        'nowpayments_auth_failed'
      );

    error.data =
      data;

    throw error;
  }

  return data.token;
}

function base32ToBuffer(base32) {
  const alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  const clean =
    String(base32 || '')
      .replace(/\s+/g, '')
      .replace(/=+$/g, '')
      .toUpperCase();

  let bits = '';

  for (const ch of clean) {
    const value =
      alphabet.indexOf(ch);

    if (value < 0) {
      throw new Error(
        'invalid_2fa_secret'
      );
    }

    bits +=
      value
        .toString(2)
        .padStart(5, '0');
  }

  const bytes = [];

  for (
    let i = 0;
    i + 8 <= bits.length;
    i += 8
  ) {
    bytes.push(
      parseInt(
        bits.slice(
          i,
          i + 8
        ),
        2
      )
    );
  }

  return Buffer.from(bytes);
}

function generateTotp(secret) {
  const key =
    base32ToBuffer(secret);

  const counter =
    Math.floor(
      Date.now() /
      1000 /
      30
    );

  const msg =
    Buffer.alloc(8);

  let n =
    BigInt(counter);

  for (
    let i = 7;
    i >= 0;
    i--
  ) {
    msg[i] =
      Number(
        n & 0xffn
      );

    n >>= 8n;
  }

  const hmac =
    crypto
      .createHmac(
        'sha1',
        key
      )
      .update(msg)
      .digest();

  const offset =
    hmac[
      hmac.length - 1
    ] & 0x0f;

  const code =
    (
      (
        hmac[offset] &
        0x7f
      ) << 24
    ) |
    (
      hmac[offset + 1]
      << 16
    ) |
    (
      hmac[offset + 2]
      << 8
    ) |
    hmac[offset + 3];

  return String(
    code % 1000000
  ).padStart(6, '0');
}

const app = express();

app.use(
  express.json({
    limit: '1mb',
    verify: (req, res, buf) => {
      req.rawBody = buf.toString('utf8');
    }
  })
);

app.use((req, res, next) => {
  res.header(
    'Access-Control-Allow-Origin',
    '*'
  );

  res.header(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, X-Admin-Token'
  );

  res.header(
    'Access-Control-Allow-Methods',
    'GET, POST, OPTIONS'
  );

  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }

  next();
});

const server =
  http.createServer(app);

const io =
  new Server(server, {
    cors: {
      origin: '*'
    },
    pingInterval: 25000,
    pingTimeout: 45000
  });

const BLOCKED_EMAIL_DOMAINS = new Set([
  'test.com', 'example.com', 'example.org', 'example.net',
  'mailinator.com', 'tempmail.com', 'temp-mail.org', 'guerrillamail.com',
  'guerrillamail.info', 'sharklasers.com', '10minutemail.com', '10minutemail.net',
  'yopmail.com', 'throwawaymail.com', 'trashmail.com', 'getnada.com',
  'dispostable.com', 'maildrop.cc', 'fakeinbox.com', 'mohmal.com',
  'emailondeck.com', 'moakt.com', 'tempmailo.com', 'mailnesia.com',
  'spam4.me', 'inboxbear.com', 'temp-mail.io', 'mail.tm', 'burnermail.io'
]);

const TYPO_EMAIL_DOMAINS = new Set([
  'gmial.com', 'gmail.co', 'gmail.con', 'gmai.com', 'gmail.cm',
  'gmaill.com', 'gmailc.om', 'hotmial.com', 'hotmail.co', 'hotmial.co',
  'yahoo.co', 'yaho.com', 'yahho.com', 'outlok.com', 'outloo.com'
]);

function validateEmail(rawEmail) {
  const email =
    String(rawEmail || '')
      .trim()
      .toLowerCase();

  if (!email) {
    return { ok: false, error: 'email_required' };
  }

  if (email.length > 254) {
    return { ok: false, error: 'email_invalid' };
  }

  const shape =
    /^[a-z0-9]([a-z0-9._%+-]*[a-z0-9])?@([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;

  if (!shape.test(email)) {
    return { ok: false, error: 'email_invalid' };
  }

  if (email.includes('..')) {
    return { ok: false, error: 'email_invalid' };
  }

  const domain = email.split('@')[1];
  const tld = domain.split('.').pop();

  if (!tld || tld.length < 2) {
    return { ok: false, error: 'email_invalid' };
  }

  if (BLOCKED_EMAIL_DOMAINS.has(domain)) {
    return { ok: false, error: 'email_disposable' };
  }

  if (TYPO_EMAIL_DOMAINS.has(domain)) {
    return { ok: false, error: 'email_typo' };
  }

  return { ok: true, email };
}

function hashPassword(password) {
  const salt =
    crypto
      .randomBytes(16)
      .toString('hex');

  const derived =
    crypto
      .scryptSync(
        password,
        salt,
        64
      )
      .toString('hex');

  return (
    salt +
    ':' +
    derived
  );
}

function verifyPassword(
  password,
  stored
) {
  try {
    const [salt, key] =
      String(stored)
        .split(':');

    const derived =
      crypto
        .scryptSync(
          password,
          salt,
          64
        )
        .toString('hex');

    const a =
      Buffer.from(
        key,
        'hex'
      );

    const b =
      Buffer.from(
        derived,
        'hex'
      );

    return (
      a.length === b.length &&
      crypto.timingSafeEqual(
        a,
        b
      )
    );

  } catch {
    return false;
  }
}

function makeToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email
    },
    JWT_SECRET,
    {
      expiresIn: '30d'
    }
  );
}

function verifyMatchToken(token) {
  if (!token) {
    return null;
  }

  try {
    return jwt.verify(
      String(token),
      JWT_SECRET
    );
  } catch {
    return null;
  }
}

function defaultName(user) {
  return (
    user.username ||
    String(
      user.email ||
      'player'
    ).split('@')[0]
  );
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    phone: user.phone || null,
    balance: Number(user.balance || 0),
    coins: Number(user.coins != null ? user.coins : 500),
    username: defaultName(user),
    wins: Number(user.wins || 0),
    losses: Number(user.losses || 0),
    avatar: user.avatar || null,
    photo_url: user.photo_url || null,
    is_chat_moderator: !!user.is_chat_moderator
  };
}

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'no_token' });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'bad_token' });
  }
}

function adminOnly(req, res, next) {
  if (
    !ADMIN_TOKEN ||
    req.headers['x-admin-token'] !== ADMIN_TOKEN
  ) {
    return res.status(403).json({ error: 'admin_forbidden' });
  }
  next();
}

function getClientIp(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '')
    .split(',')[0].trim();
  const raw = forwarded || req.socket?.remoteAddress || '';
  return raw.replace(/^::ffff:/, '');
}

function isPublicIp(ip) {
  if (!ip || ip === '::1' || ip === '127.0.0.1') return false;
  if (/^10\./.test(ip) || /^192\.168\./.test(ip) || /^169\.254\./.test(ip)) return false;
  const m = ip.match(/^172\.(\d+)\./);
  if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return false;
  return true;
}

async function updateUserLocation(userId, req) {
  try {
    const ip = getClientIp(req);
    let country = String(
      req.headers['cf-ipcountry'] ||
      req.headers['x-vercel-ip-country'] || ''
    ).trim() || null;
    let city = String(
      req.headers['cf-ipcity'] ||
      req.headers['x-vercel-ip-city'] || ''
    ).trim() || null;

    if ((!country || !city) && isPublicIp(ip) && typeof fetch === 'function') {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 1800);
      try {
        const r = await fetch(
          'https://ipwho.is/' + encodeURIComponent(ip),
          { signal: controller.signal }
        );
        if (r.ok) {
          const geo = await r.json();
          if (geo && geo.success !== false) {
            country = country || geo.country || geo.country_code || null;
            city = city || geo.city || null;
          }
        }
      } finally {
        clearTimeout(timer);
      }
    }

    await db.query(
      `UPDATE users
       SET last_ip=$1,
           country=COALESCE($2, country),
           city=COALESCE($3, city),
           last_seen_at=NOW()
       WHERE id=$4`,
      [ip || null, country, city, userId]
    );
  } catch (e) {
    console.warn('location update skipped:', e.message);
  }
}

async function initAdminUserTools() {
  await db.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS country TEXT,
      ADD COLUMN IF NOT EXISTS city TEXT,
      ADD COLUMN IF NOT EXISTS last_ip TEXT,
      ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS photo_url TEXT,
      ADD COLUMN IF NOT EXISTS banned BOOLEAN NOT NULL DEFAULT false,
      ADD COLUMN IF NOT EXISTS ban_reason TEXT,
      ADD COLUMN IF NOT EXISTS banned_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS is_chat_moderator BOOLEAN NOT NULL DEFAULT false
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS admin_balance_audit (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      amount NUMERIC(20,8) NOT NULL,
      balance_before NUMERIC(20,8) NOT NULL,
      balance_after NUMERIC(20,8) NOT NULL,
      reason TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await db.query(`
    CREATE INDEX IF NOT EXISTS admin_balance_audit_user_idx
    ON admin_balance_audit(user_id, created_at DESC)
  `);
}

app.get('/', (_req, res) => {
  res.json({
    ok: true,
    service: 'Domino Block',
    version: 'v8.1-fixed-real-pvp'
  });
});

app.post('/api/register', async (req, res) => {
  try {
    let { email, phone, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: 'email_and_password_required' });
    }

    const emailCheck = validateEmail(email);
    if (!emailCheck.ok) {
      return res.status(400).json({ error: emailCheck.error });
    }

    email = emailCheck.email;

    if (String(password).length < 6) {
      return res.status(400).json({ error: 'password_too_short' });
    }

    const exists = await db.query(
      `SELECT id FROM users WHERE email=$1`, [email]
    );

    if (exists.rows.length) {
      return res.status(409).json({ error: 'email_already_used' });
    }

    const result = await db.query(
      `INSERT INTO users (email, phone, password_hash)
       VALUES ($1, $2, $3) RETURNING *`,
      [email, phone || null, hashPassword(password)]
    );

    const user = result.rows[0];
    await updateUserLocation(user.id, req);

    const refreshed = await db.query(
      `SELECT * FROM users WHERE id=$1`, [user.id]
    );

    const loginUser = refreshed.rows[0] || user;

    res.json({
      token: makeToken(loginUser),
      user: publicUser(loginUser)
    });
  } catch (e) {
    console.error('register error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

const loginAttempts = new Map();
const LOGIN_MAX_ATTEMPTS = 10;
const LOGIN_WINDOW_MS = 10 * 60 * 1000;

function checkLoginRateLimit(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now - entry.firstAttemptAt > LOGIN_WINDOW_MS) {
    loginAttempts.set(ip, { count: 1, firstAttemptAt: now });
    return true;
  }
  entry.count++;
  return entry.count <= LOGIN_MAX_ATTEMPTS;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of loginAttempts.entries()) {
    if (now - entry.firstAttemptAt > LOGIN_WINDOW_MS) loginAttempts.delete(ip);
  }
}, 30 * 60 * 1000);

app.post('/api/login', async (req, res) => {
  try {
    const loginIp = getClientIp(req);
    if (!checkLoginRateLimit(loginIp)) {
      return res.status(429).json({ error: 'too_many_attempts' });
    }
    let { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: 'email_and_password_required' });
    }

    email = String(email).trim().toLowerCase();

    const result = await db.query(
      `SELECT * FROM users WHERE email=$1`, [email]
    );

    if (!result.rows.length) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    const user = result.rows[0];

    if (!verifyPassword(password, user.password_hash)) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }

    if (user.banned) {
      return res.status(403).json({
        error: 'account_banned',
        ban_reason: user.ban_reason || null
      });
    }

    await updateUserLocation(user.id, req);
    recordVisit(user.id);
    recordAppOpen();

    res.json({
      token: makeToken(user),
      user: publicUser(user)
    });
  } catch (e) {
    console.error('login error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/me', auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT * FROM users WHERE id=$1`, [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: 'not_found' });
    }

    recordVisit(req.user.id);
    recordAppOpen();

    res.json({ user: publicUser(result.rows[0]) });
  } catch {
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/admin-messages/unread', auth, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT id, text, created_at
      FROM admin_messages
      WHERE user_id=$1 AND read=false
      ORDER BY created_at ASC
    `, [req.user.id]);

    res.json({
      messages: result.rows.map(row => ({
        id: row.id,
        text: row.text,
        ts: new Date(row.created_at).getTime()
      }))
    });
  } catch (e) {
    console.error('admin-messages/unread error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin-messages/:id/read', auth, async (req, res) => {
  try {
    const messageId = Number(req.params.id);
    if (!Number.isInteger(messageId)) {
      return res.status(400).json({ error: 'valid_id_required' });
    }
    await db.query(`
      UPDATE admin_messages SET read=true WHERE id=$1 AND user_id=$2
    `, [messageId, req.user.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('admin-messages/read error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/profile', auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT * FROM users WHERE id=$1`, [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: 'not_found' });
    }

    res.json({ user: publicUser(result.rows[0]) });
  } catch {
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/profile', auth, async (req, res) => {
  try {
    let { username, avatar } = req.body || {};
    const sets = [];
    const values = [];
    let index = 1;

    if (username !== undefined && username !== null) {
      username = String(username).trim();
      if (username.length < 2 || username.length > 20) {
        return res.status(400).json({ error: 'username_length' });
      }
      sets.push(`username=$${index++}`);
      values.push(username);
    }

    if (avatar !== undefined && avatar !== null) {
      avatar = String(avatar).trim();
      if (avatar.length > 40) {
        return res.status(400).json({ error: 'avatar_invalid' });
      }
      sets.push(`avatar=$${index++}`);
      values.push(avatar);
    }

    let photo_url = req.body && req.body.photo_url;
    if (photo_url !== undefined && photo_url !== null) {
      photo_url = String(photo_url).trim();
      if (photo_url === '') {
        sets.push(`photo_url=$${index++}`);
        values.push(null);
      } else {
        if (!/^data:image\/(png|jpeg|jpg|webp);base64,/.test(photo_url)) {
          return res.status(400).json({ error: 'photo_invalid_format' });
        }
        if (photo_url.length > 400000) {
          return res.status(400).json({ error: 'photo_too_large' });
        }
        sets.push(`photo_url=$${index++}`);
        values.push(photo_url);
      }
    }

    if (!sets.length) {
      return res.status(400).json({ error: 'nothing_to_update' });
    }

    values.push(req.user.id);

    const result = await db.query(
      `UPDATE users SET ${sets.join(', ')} WHERE id=$${index} RETURNING *`,
      values
    );

    res.json({ user: publicUser(result.rows[0]) });
  } catch (e) {
    console.error('profile update error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'missing_fields' });
    }

    if (String(newPassword).length < 6) {
      return res.status(400).json({ error: 'password_too_short' });
    }

    const result = await db.query(
      `SELECT * FROM users WHERE id=$1`, [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: 'not_found' });
    }

    const user = result.rows[0];

    if (!verifyPassword(currentPassword, user.password_hash)) {
      return res.status(401).json({ error: 'incorrect_current_password' });
    }

    const newHash = hashPassword(newPassword);
    await db.query(
      `UPDATE users SET password_hash=$1 WHERE id=$2`, [newHash, req.user.id]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error('change-password error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

async function initAppConfig() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS app_config (
      id INTEGER PRIMARY KEY DEFAULT 1,
      paid_enabled BOOLEAN NOT NULL DEFAULT true,
      online_baseline INTEGER NOT NULL DEFAULT 1000,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT app_config_singleton CHECK (id = 1)
    )
  `);
  await db.query(`ALTER TABLE app_config ADD COLUMN IF NOT EXISTS online_baseline INTEGER NOT NULL DEFAULT 1000`);
  await db.query(`ALTER TABLE app_config ADD COLUMN IF NOT EXISTS paid_schedule_enabled BOOLEAN NOT NULL DEFAULT false`);
  await db.query(`ALTER TABLE app_config ADD COLUMN IF NOT EXISTS paid_open_time TEXT NOT NULL DEFAULT '20:00'`);
  await db.query(`ALTER TABLE app_config ADD COLUMN IF NOT EXISTS paid_close_time TEXT NOT NULL DEFAULT '00:00'`);
  await db.query(`ALTER TABLE app_config ADD COLUMN IF NOT EXISTS paid_timezone TEXT NOT NULL DEFAULT 'Asia/Baghdad'`);
  await db.query(`ALTER TABLE app_config ADD COLUMN IF NOT EXISTS bot_enabled BOOLEAN NOT NULL DEFAULT false`);
  await db.query(`ALTER TABLE app_config ADD COLUMN IF NOT EXISTS bot_difficulty TEXT NOT NULL DEFAULT 'hard'`);
  await db.query(`ALTER TABLE app_config ADD COLUMN IF NOT EXISTS chat_enabled BOOLEAN NOT NULL DEFAULT true`);
  await db.query(`
    INSERT INTO app_config (id, paid_enabled, online_baseline)
    VALUES (1, true, 1000)
    ON CONFLICT (id) DO NOTHING
  `);
}

async function initAdminMessagesTable() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS admin_messages (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      read BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await db.query(`
    ALTER TABLE admin_messages
      ADD COLUMN IF NOT EXISTS text TEXT,
      ADD COLUMN IF NOT EXISTS read BOOLEAN NOT NULL DEFAULT false
  `);
}

async function initGlobalChatTable() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS global_chat_messages (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      name TEXT NOT NULL,
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await db.query(`ALTER TABLE global_chat_messages ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT false`);
  await db.query(`
    CREATE INDEX IF NOT EXISTS global_chat_messages_created_idx
    ON global_chat_messages(created_at DESC)
  `);
}

app.get('/api/global-chat/history', async (req, res) => {
  try {
    const result = await db.query(`
      SELECT id, user_id, name, text, created_at
      FROM (
        SELECT id, user_id, name, text, created_at
        FROM global_chat_messages
        WHERE created_at > NOW() - INTERVAL '12 hours'
          AND deleted = false
        ORDER BY created_at DESC
        LIMIT 200
      ) recent
      ORDER BY created_at ASC
    `);

    res.json({
      messages: result.rows.map(row => ({
        id: row.id,
        userId: row.user_id,
        name: row.name,
        text: row.text,
        ts: new Date(row.created_at).getTime()
      }))
    });
  } catch (e) {
    console.error('global-chat/history error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

async function initTelegramJoinTable() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS telegram_join_claims (
      user_id INTEGER PRIMARY KEY REFERENCES users(id),
      claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

app.get('/api/telegram/join-info', auth, async (req, res) => {
  try {
    const already = await db.query(
      `SELECT 1 FROM telegram_join_claims WHERE user_id=$1`, [req.user.id]
    );

    res.json({
      alreadyClaimed: already.rows.length > 0,
      channelLink: TELEGRAM_CHANNEL_LINK,
      amount: TELEGRAM_JOIN_BONUS_AMOUNT
    });
  } catch (e) {
    console.error('telegram/join-info error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/telegram/claim-bonus', auth, async (req, res) => {
  try {
    const result = await db.query(
      `INSERT INTO telegram_join_claims (user_id)
       VALUES ($1)
       ON CONFLICT (user_id) DO NOTHING
       RETURNING user_id`,
      [req.user.id]
    );

    if (!result.rows.length) {
      return res.json({ alreadyClaimed: true });
    }

    await db.query(
      `UPDATE users SET balance = balance + $1 WHERE id=$2`,
      [TELEGRAM_JOIN_BONUS_AMOUNT, req.user.id]
    );

    res.json({
      credited: true,
      amount: TELEGRAM_JOIN_BONUS_AMOUNT
    });
  } catch (e) {
    console.error('telegram/claim-bonus error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

function currentTimeInZone(timezone) {
  try {
    const fmt = new Intl.DateTimeFormat('en-GB', {
      timeZone: timezone || 'Asia/Baghdad',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    });
    return fmt.format(new Date());
  } catch (e) {
    const fmt = new Intl.DateTimeFormat('en-GB', {
      timeZone: 'UTC', hour: '2-digit', minute: '2-digit', hour12: false
    });
    return fmt.format(new Date());
  }
}

function isWithinScheduleWindow(nowHHMM, openHHMM, closeHHMM) {
  if (openHHMM === closeHHMM) return true;
  const toMinutes = (s) => {
    const parts = String(s).split(':');
    const h = parseInt(parts[0], 10) || 0;
    const m = parseInt(parts[1], 10) || 0;
    return h * 60 + m;
  };
  const now = toMinutes(nowHHMM);
  const open = toMinutes(openHHMM);
  const close = toMinutes(closeHHMM);
  if (open < close) {
    return now >= open && now < close;
  }
  return now >= open || now < close;
}

async function isPaidEnabled() {
  try {
    const result = await db.query(
      `SELECT paid_enabled, paid_schedule_enabled, paid_open_time, paid_close_time, paid_timezone
       FROM app_config WHERE id=1`
    );
    if (!result.rows.length) return true;
    const row = result.rows[0];

    if (row.paid_enabled === false) return false;

    if (row.paid_schedule_enabled) {
      const now = currentTimeInZone(row.paid_timezone);
      return isWithinScheduleWindow(now, row.paid_open_time, row.paid_close_time);
    }

    return row.paid_enabled !== false;
  } catch (e) {
    return true;
  }
}

app.get('/api/app-config', async (req, res) => {
  try {
    const cfg = await db.query(
      `SELECT paid_enabled, online_baseline, paid_schedule_enabled, paid_open_time, paid_close_time, paid_timezone, bot_enabled, bot_difficulty, chat_enabled
       FROM app_config WHERE id=1`
    );
    const row = cfg.rows[0] || {};
    res.json({
      paid_enabled: row.paid_enabled !== false,
      chat_enabled: row.chat_enabled !== false,
      online_baseline: row.online_baseline != null ? Number(row.online_baseline) : 1000,
      paid_schedule_enabled: !!row.paid_schedule_enabled,
      paid_open_time: row.paid_open_time || '20:00',
      paid_close_time: row.paid_close_time || '00:00',
      paid_timezone: row.paid_timezone || 'Asia/Baghdad',
      bot_enabled: !!row.bot_enabled,
      bot_difficulty: ['easy','hard','expert'].includes(String(row.bot_difficulty||'').toLowerCase()) ? String(row.bot_difficulty).toLowerCase() : 'hard',
      paid_live_now: await isPaidEnabled()
    });
  } catch (e) {
    res.json({ paid_enabled: true, chat_enabled: true, online_baseline: 1000, paid_schedule_enabled: false, paid_open_time: '20:00', paid_close_time: '00:00', paid_timezone: 'Asia/Baghdad', bot_enabled: false, bot_difficulty: 'hard', paid_live_now: true });
  }
});

app.get('/api/online-count', async (req, res) => {
  try {
    const cfg = await db.query(`SELECT online_baseline FROM app_config WHERE id=1`);
    const baseline = cfg.rows.length ? Number(cfg.rows[0].online_baseline) || 0 : 1000;
    const live = io.engine ? io.engine.clientsCount : 0;
    res.json({ online: baseline + live, live_real: live, baseline: baseline });
  } catch (e) {
    res.json({ online: 1000, live_real: 0, baseline: 1000 });
  }
});

app.post('/api/admin/app-config', adminOnly, async (req, res) => {
  try {
    const paidEnabled = req.body?.paid_enabled;
    const onlineBaseline = req.body?.online_baseline;
    const scheduleEnabled = req.body?.paid_schedule_enabled;
    const openTime = req.body?.paid_open_time;
    const closeTime = req.body?.paid_close_time;
    const timezone = req.body?.paid_timezone;
    const botEnabled = req.body?.bot_enabled;
    const botDifficulty = req.body?.bot_difficulty;
    const chatEnabled = req.body?.chat_enabled;

    const hasPaid = typeof paidEnabled === 'boolean';
    const hasBaseline = onlineBaseline !== undefined && onlineBaseline !== null;
    const hasSchedule = typeof scheduleEnabled === 'boolean';
    const timeRe = /^([01]\d|2[0-3]):([0-5]\d)$/;
    const hasOpenTime = openTime !== undefined && openTime !== null;
    const hasCloseTime = closeTime !== undefined && closeTime !== null;
    const hasTimezone = typeof timezone === 'string' && timezone.trim() !== '';
    const hasBotEnabled = typeof botEnabled === 'boolean';
    const hasBotDifficulty = typeof botDifficulty === 'string' && botDifficulty.trim() !== '';
    const hasChatEnabled = typeof chatEnabled === 'boolean';

    if (!hasPaid && !hasBaseline && !hasSchedule && !hasOpenTime && !hasCloseTime && !hasTimezone && !hasBotEnabled && !hasBotDifficulty && !hasChatEnabled) {
      return res.status(400).json({ error: 'nothing_to_update' });
    }
    if (hasBaseline && (!Number.isInteger(onlineBaseline) || onlineBaseline < 0)) {
      return res.status(400).json({ error: 'invalid_online_baseline' });
    }
    if (hasOpenTime && !timeRe.test(openTime)) {
      return res.status(400).json({ error: 'invalid_open_time' });
    }
    if (hasCloseTime && !timeRe.test(closeTime)) {
      return res.status(400).json({ error: 'invalid_close_time' });
    }
    if (hasTimezone) {
      try { new Intl.DateTimeFormat('en-GB', { timeZone: timezone }); }
      catch (e) { return res.status(400).json({ error: 'invalid_timezone' }); }
    }
    if (hasBotDifficulty && !['easy','hard','expert'].includes(botDifficulty.trim().toLowerCase())) {
      return res.status(400).json({ error: 'invalid_bot_difficulty' });
    }

    await db.query(`
      UPDATE app_config
      SET paid_enabled=COALESCE($1, paid_enabled),
          online_baseline=COALESCE($2, online_baseline),
          paid_schedule_enabled=COALESCE($3, paid_schedule_enabled),
          paid_open_time=COALESCE($4, paid_open_time),
          paid_close_time=COALESCE($5, paid_close_time),
          paid_timezone=COALESCE($6, paid_timezone),
          bot_enabled=COALESCE($7, bot_enabled),
          bot_difficulty=COALESCE($8, bot_difficulty),
          chat_enabled=COALESCE($9, chat_enabled),
          updated_at=NOW()
      WHERE id=1
    `, [
      hasPaid ? paidEnabled : null,
      hasBaseline ? onlineBaseline : null,
      hasSchedule ? scheduleEnabled : null,
      hasOpenTime ? openTime : null,
      hasCloseTime ? closeTime : null,
      hasTimezone ? timezone : null,
      hasBotEnabled ? botEnabled : null,
      hasBotDifficulty ? botDifficulty.trim().toLowerCase() : null,
      hasChatEnabled ? chatEnabled : null
    ]);

    if (hasChatEnabled) {
      try { io.emit('chat_enabled_changed', { enabled: chatEnabled }); } catch (e) {}
    }

    res.json({ ok: true });
  } catch (e) {
    console.error('app-config update error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

const USDT_NETWORKS = new Set(['BEP20', 'ERC20']);

const USDT_ADDRESSES = {
  TRC20: process.env.USDT_TRC20_ADDRESS || '',
  BEP20: process.env.USDT_BEP20_ADDRESS || '',
  ERC20: process.env.USDT_ERC20_ADDRESS || ''
};

const MIN_DEPOSIT = Number(process.env.USDT_MIN_DEPOSIT || 5);
const MIN_WITHDRAW = Number(process.env.USDT_MIN_WITHDRAW || 15);
const MAX_WITHDRAW = Number(process.env.USDT_MAX_WITHDRAW || 10000);
const WITHDRAW_FEE = Number(process.env.USDT_WITHDRAW_FEE || 0);

function validUsdtAddress(network, address) {
  address = String(address || '').trim();

  if (network === 'TRC20') {
    return /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(address);
  }

  if (network === 'BEP20' || network === 'ERC20') {
    return /^0x[a-fA-F0-9]{40}$/.test(address);
  }

  return false;
}

async function initWalletTables() {
  await db.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS wallet_locked NUMERIC(20,8) NOT NULL DEFAULT 0
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type VARCHAR(16) NOT NULL CHECK(type IN ('deposit', 'withdraw')),
      network VARCHAR(10) NOT NULL,
      amount NUMERIC(20,8) NOT NULL CHECK(amount >= 0),
      address TEXT,
      tx_hash TEXT,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      fee NUMERIC(20,8) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await db.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS wallet_deposit_tx_unique
    ON wallet_transactions(tx_hash)
    WHERE tx_hash IS NOT NULL
  `);

  await db.query(`
    CREATE INDEX IF NOT EXISTS wallet_user_idx
    ON wallet_transactions(user_id, created_at DESC)
  `);

  await db.query(`ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS provider TEXT`);
  await db.query(`ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS provider_payment_id TEXT`);
  await db.query(`ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS provider_payout_id TEXT`);
  await db.query(`ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS provider_status TEXT`);
  await db.query(`ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS order_id TEXT`);

  await db.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS wallet_provider_payment_unique
    ON wallet_transactions(provider_payment_id)
    WHERE provider_payment_id IS NOT NULL
  `);
}

app.get('/api/wallet', auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT balance, wallet_locked FROM users WHERE id=$1`, [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: 'not_found' });
    }

    const balance = Number(result.rows[0].balance || 0);
    const locked = Number(result.rows[0].wallet_locked || 0);

    res.json({
      balance,
      locked_balance: locked,
      available_balance: Math.max(0, balance),
      currency: 'USDT',
      deposit_addresses: USDT_ADDRESSES,
      networks: Array.from(USDT_NETWORKS),
      min_deposit: MIN_DEPOSIT,
      min_withdraw: MIN_WITHDRAW,
      max_withdraw: MAX_WITHDRAW,
      withdraw_fee: WITHDRAW_FEE
    });
  } catch (e) {
    console.error('wallet get error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/nowpayments/deposit', auth, async (req, res) => {
  try {
    if (!(await isPaidEnabled())) {
      return res.status(403).json({ error: 'paid_features_disabled' });
    }

    const amount = Number(req.body?.amount);
    const network = String(req.body?.network || '').toUpperCase();

    if (!Number.isFinite(amount) || amount < MIN_DEPOSIT) {
      return res.status(400).json({
        error: 'minimum_deposit_is_' + MIN_DEPOSIT + '_usdt',
        min: MIN_DEPOSIT
      });
    }

    if (!USDT_NETWORKS.has(network)) {
      return res.status(400).json({ error: 'invalid_network' });
    }

    const payCurrency = NOWPAYMENTS_NETWORK_CURRENCY[network];

    try {
      const minAmountResp = await nowPaymentsRequest(
        '/min-amount?currency_from=' + payCurrency + '&currency_to=' + payCurrency + '&fiat_equivalent=usd',
        { method: 'GET' }
      );

      const nowPaymentsMin = Number(minAmountResp && minAmountResp.fiat_equivalent);

      if (Number.isFinite(nowPaymentsMin) && nowPaymentsMin > 0 && amount < nowPaymentsMin) {
        return res.status(400).json({
          error: 'minimum_deposit_for_network_is_' + Math.ceil(nowPaymentsMin) + '_usdt',
          min: Math.ceil(nowPaymentsMin),
          network
        });
      }
    } catch (e) {
      console.log('[min-amount lookup] failed, continuing:', e.message);
    }

    const orderId = ['yd', req.user.id, Date.now(), crypto.randomBytes(4).toString('hex')].join('-');

    const payment = await nowPaymentsRequest('/payment', {
      method: 'POST',
      body: {
        price_amount: Number(amount.toFixed(2)),
        price_currency: 'usd',
        pay_currency: payCurrency,
        ipn_callback_url: NOWPAYMENTS_IPN_URL,
        order_id: orderId,
        order_description: 'Yalla Domino USDT deposit',
        is_fixed_rate: false,
        is_fee_paid_by_user: false
      }
    });

    const paymentId = String(payment.payment_id || '');
    if (!paymentId) {
      return res.status(502).json({ error: 'payment_id_missing' });
    }

    await db.query(
      `INSERT INTO wallet_transactions
       (user_id, type, network, amount, address, status, provider, provider_payment_id, provider_status, order_id)
       VALUES ($1, 'deposit', $2, $3, $4, 'pending', 'nowpayments', $5, $6, $7)`,
      [
        req.user.id, network, amount, payment.pay_address || null,
        paymentId, payment.payment_status || 'waiting', orderId
      ]
    );

    res.json({
      ok: true,
      payment_id: paymentId,
      status: payment.payment_status,
      network,
      pay_currency: payment.pay_currency,
      pay_address: payment.pay_address,
      pay_amount: Number(payment.pay_amount || 0),
      price_amount: Number(payment.price_amount || amount),
      price_currency: payment.price_currency || 'usd',
      order_id: orderId,
      expires_at: payment.expiration_estimate_date || null
    });
  } catch (e) {
    console.error('NOWPayments deposit create error:', e.message, e.data || '');
    res.status(e.status || 500).json({
      error: 'nowpayments_deposit_failed',
      details: e.data || null
    });
  }
});

app.get('/api/nowpayments/payment/:id', auth, async (req, res) => {
  try {
    const local = await db.query(
      `SELECT id, user_id, status, provider_status, amount, network
       FROM wallet_transactions
       WHERE provider='nowpayments' AND provider_payment_id=$1 AND user_id=$2
       LIMIT 1`,
      [String(req.params.id), req.user.id]
    );

    if (!local.rows.length) {
      return res.status(404).json({ error: 'payment_not_found' });
    }

    const payment = await nowPaymentsRequest(
      '/payment/' + encodeURIComponent(req.params.id)
    );

    res.json({ ok: true, payment });
  } catch (e) {
    res.status(e.status || 500).json({
      error: 'payment_status_failed',
      details: e.data || null
    });
  }
});

app.post('/api/nowpayments/ipn', async (req, res) => {
  const signature = req.headers['x-nowpayments-sig'];
  if (!verifyNowPaymentsIpn(req.body, signature, req.rawBody)) {
    return res.status(401).json({ error: 'bad_ipn_signature' });
  }

  try {
    const payload = req.body || {};
    const paymentId = payload.payment_id != null ? String(payload.payment_id) : null;
    const payoutId = payload.id != null ? String(payload.id) : null;
    const status = String(payload.payment_status || payload.status || '').toLowerCase();

    if (paymentId) {
      const client = await db.pool.connect();
      try {
        await client.query('BEGIN');
        const tx = await client.query(
          `SELECT * FROM wallet_transactions
           WHERE provider='nowpayments' AND provider_payment_id=$1 AND type='deposit'
           FOR UPDATE`,
          [paymentId]
        );

        if (!tx.rows.length) {
          await client.query('ROLLBACK');
          return res.json({ ok: true, ignored: 'unknown_payment' });
        }

        const transaction = tx.rows[0];

        await client.query(
          `UPDATE wallet_transactions SET provider_status=$1, updated_at=NOW() WHERE id=$2`,
          [status, transaction.id]
        );

        if ((status === 'finished' || status === 'partially_paid') && transaction.status !== 'confirmed') {
          const requestedAmount = Number(transaction.amount);
          const actuallyPaid = Number(payload.actually_paid);
          const creditAmount = Number.isFinite(actuallyPaid) && actuallyPaid > 0
            ? actuallyPaid
            : (status === 'finished' ? requestedAmount : 0);

          if (creditAmount <= 0) {
            await client.query('ROLLBACK');
            return res.json({ ok: true, ignored: 'no_amount_received' });
          }

          await client.query(
            `UPDATE users SET balance = balance + $1 WHERE id=$2`,
            [creditAmount, transaction.user_id]
          );

          await client.query(
            `UPDATE wallet_transactions
             SET status='confirmed', provider_status=$2, amount=$3, updated_at=NOW()
             WHERE id=$1`,
            [transaction.id, status, creditAmount]
          );
        }

        if (['failed', 'expired', 'refunded'].includes(status) && transaction.status === 'pending') {
          await client.query(
            `UPDATE wallet_transactions SET status=$1, updated_at=NOW() WHERE id=$2`,
            [status, transaction.id]
          );
        }

        await client.query('COMMIT');
      } catch (e) {
        try { await client.query('ROLLBACK'); } catch {}
        throw e;
      } finally {
        client.release();
      }

      return res.json({ ok: true });
    }

    if (payoutId) {
      const tx = await db.query(
        `SELECT * FROM wallet_transactions
         WHERE provider='nowpayments' AND provider_payout_id=$1 AND type='withdraw'
         LIMIT 1`,
        [payoutId]
      );

      if (!tx.rows.length) {
        return res.json({ ok: true, ignored: 'unknown_payout' });
      }

      const transaction = tx.rows[0];

      await db.query(
        `UPDATE wallet_transactions SET provider_status=$1, updated_at=NOW() WHERE id=$2`,
        [status, transaction.id]
      );

      if (status === 'finished' && transaction.status === 'pending') {
        await db.query(
          `UPDATE users SET wallet_locked = GREATEST(0, wallet_locked - $1) WHERE id=$2`,
          [Number(transaction.amount), transaction.user_id]
        );

        await db.query(
          `UPDATE wallet_transactions SET status='completed', provider_status='finished', updated_at=NOW() WHERE id=$1`,
          [transaction.id]
        );
      }

      if (['failed', 'rejected'].includes(status) && transaction.status === 'pending') {
        const client = await db.pool.connect();
        try {
          await client.query('BEGIN');
          const locked = await client.query(
            `SELECT * FROM wallet_transactions WHERE id=$1 FOR UPDATE`, [transaction.id]
          );

          if (locked.rows.length && locked.rows[0].status === 'pending') {
            await client.query(
              `UPDATE users SET balance = balance + $1, wallet_locked = GREATEST(0, wallet_locked - $1) WHERE id=$2`,
              [Number(transaction.amount), transaction.user_id]
            );

            await client.query(
              `UPDATE wallet_transactions SET status=$1, provider_status=$1, updated_at=NOW() WHERE id=$2`,
              [status, transaction.id]
            );
          }
          await client.query('COMMIT');
        } catch (e) {
          try { await client.query('ROLLBACK'); } catch {}
          throw e;
        } finally {
          client.release();
        }
      }

      return res.json({ ok: true });
    }

    return res.json({ ok: true, ignored: 'unknown_callback' });
  } catch (e) {
    console.error('NOWPayments IPN error:', e);
    return res.status(500).json({ error: 'ipn_processing_failed' });
  }
});

app.post('/api/nowpayments/withdraw', auth, async (req, res) => {
  const client = await db.pool.connect();
  try {
    const network = String(req.body?.network || '').toUpperCase();
    const address = String(req.body?.address || '').trim();
    const amount = Number(req.body?.amount);

    if (!USDT_NETWORKS.has(network)) {
      return res.status(400).json({ error: 'invalid_network' });
    }

    if (!validUsdtAddress(network, address)) {
      return res.status(400).json({ error: 'invalid_address_for_network' });
    }

    if (!Number.isFinite(amount) || amount < MIN_WITHDRAW || amount > MAX_WITHDRAW) {
      return res.status(400).json({
        error: 'invalid_amount',
        min: MIN_WITHDRAW,
        max: MAX_WITHDRAW
      });
    }

    if (!NOWPAYMENTS_EMAIL || !NOWPAYMENTS_PASSWORD) {
      return res.status(503).json({
        error: 'payout_setup_required',
        missing: ['NOWPAYMENTS_EMAIL', 'NOWPAYMENTS_PASSWORD']
      });
    }

    if (!NOWPAYMENTS_2FA_SECRET) {
      return res.status(503).json({
        error: 'payout_2fa_setup_required',
        missing: ['NOWPAYMENTS_2FA_SECRET']
      });
    }

    await client.query('BEGIN');

    const userResult = await client.query(
      `SELECT balance, wallet_locked FROM users WHERE id=$1 FOR UPDATE`, [req.user.id]
    );

    if (!userResult.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }

    if (Number(userResult.rows[0].balance || 0) < amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'insufficient_balance' });
    }

    const currency = NOWPAYMENTS_NETWORK_CURRENCY[network];

    await nowPaymentsRequest('/payout/validate-address', {
      method: 'POST',
      body: { address, currency }
    });

    const reserved = await client.query(
      `UPDATE users
       SET balance = balance - $1, wallet_locked = wallet_locked + $1
       WHERE id=$2
       RETURNING balance, wallet_locked`,
      [amount, req.user.id]
    );

    const externalId = ['yd-withdraw', req.user.id, Date.now(), crypto.randomBytes(4).toString('hex')].join('-');

    const localTx = await client.query(
      `INSERT INTO wallet_transactions
       (user_id, type, network, amount, address, status, fee, provider, provider_status, order_id)
       VALUES ($1, 'withdraw', $2, $3, $4, 'pending', $5, 'nowpayments', 'creating', $6)
       RETURNING *`,
      [req.user.id, network, amount, address, WITHDRAW_FEE, externalId]
    );

    await client.query('COMMIT');

    let batchId = null;
    let payoutId = null;

    try {
      const jwtToken = await getNowPaymentsJwt();
      const payoutResponse = await nowPaymentsRequest('/payout', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + jwtToken },
        body: {
          ipn_callback_url: NOWPAYMENTS_IPN_URL,
          withdrawals: [{
            address,
            currency,
            amount: Number(amount.toFixed(6)),
            ipn_callback_url: NOWPAYMENTS_IPN_URL,
            unique_external_id: externalId
          }]
        }
      });

      batchId = String(payoutResponse.id || payoutResponse.batch_withdrawal_id || payoutResponse.batch_id || '');
      const firstWithdrawal = Array.isArray(payoutResponse.withdrawals) ? payoutResponse.withdrawals[0] : null;
      payoutId = firstWithdrawal?.id != null ? String(firstWithdrawal.id) : null;

      await db.query(
        `UPDATE wallet_transactions
         SET provider_payout_id=$1, provider_status=$2, tx_hash=$3, updated_at=NOW()
         WHERE id=$4`,
        [
          payoutId || batchId || null,
          String(firstWithdrawal?.status || payoutResponse.status || 'creating').toLowerCase(),
          batchId || null,
          localTx.rows[0].id
        ]
      );

      if (!batchId) {
        throw new Error('payout_batch_id_missing');
      }

      const verificationCode = generateTotp(NOWPAYMENTS_2FA_SECRET);

      await nowPaymentsRequest(
        '/payout/' + encodeURIComponent(batchId) + '/verify',
        {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + jwtToken },
          body: { verification_code: verificationCode }
        }
      );

      await db.query(
        `UPDATE wallet_transactions SET provider_status='waiting', updated_at=NOW() WHERE id=$1`,
        [localTx.rows[0].id]
      );

      return res.json({
        ok: true,
        transaction_id: localTx.rows[0].id,
        payout_id: payoutId,
        batch_id: batchId,
        status: 'waiting',
        balance: Number(reserved.rows[0].balance),
        locked_balance: Number(reserved.rows[0].wallet_locked)
      });

    } catch (payoutError) {
      const rollbackClient = await db.pool.connect();
      try {
        await rollbackClient.query('BEGIN');
        const lockedTx = await rollbackClient.query(
          `SELECT * FROM wallet_transactions WHERE id=$1 FOR UPDATE`, [localTx.rows[0].id]
        );

        if (lockedTx.rows.length && lockedTx.rows[0].status === 'pending') {
          await rollbackClient.query(
            `UPDATE users SET balance = balance + $1, wallet_locked = GREATEST(0, wallet_locked - $1) WHERE id=$2`,
            [amount, req.user.id]
          );

          await rollbackClient.query(
            `UPDATE wallet_transactions SET status='failed', provider_status='failed', updated_at=NOW() WHERE id=$1`,
            [localTx.rows[0].id]
          );
        }
        await rollbackClient.query('COMMIT');
      } catch {
        try { await rollbackClient.query('ROLLBACK'); } catch {}
      } finally {
        rollbackClient.release();
      }
      throw payoutError;
    }

  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('NOWPayments withdraw error:', e.message, e.data || '');
    res.status(e.status || 500).json({
      error: 'nowpayments_withdraw_failed',
      details: e.data || null
    });
  } finally {
    client.release();
  }
});

app.post('/api/deposit', auth, async (req, res) => {
  try {
    const network = String(req.body?.network || '').toUpperCase();
    const txHash = String(req.body?.tx_hash || '').trim();

    if (!USDT_NETWORKS.has(network)) {
      return res.status(400).json({ error: 'invalid_network' });
    }

    if (!txHash || txHash.length < 20 || txHash.length > 200) {
      return res.status(400).json({ error: 'invalid_tx_hash' });
    }

    const result = await db.query(
      `INSERT INTO wallet_transactions (user_id, type, network, amount, tx_hash, status)
       VALUES ($1, 'deposit', $2, 0, $3, 'pending')
       RETURNING id, type, network, amount, tx_hash, status, created_at`,
      [req.user.id, network, txHash]
    );

    res.json({
      ok: true,
      transaction: result.rows[0],
      message: 'deposit_submitted_for_review'
    });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({ error: 'tx_hash_already_submitted' });
    }
    console.error('deposit error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/withdraw', auth, async (req, res) => {
  const client = await db.pool.connect();
  try {
    const network = String(req.body?.network || '').toUpperCase();
    const address = String(req.body?.address || '').trim();
    const amount = Number(req.body?.amount);

    if (!USDT_NETWORKS.has(network)) {
      return res.status(400).json({ error: 'invalid_network' });
    }

    if (!validUsdtAddress(network, address)) {
      return res.status(400).json({ error: 'invalid_address_for_network' });
    }

    if (!Number.isFinite(amount) || amount < MIN_WITHDRAW || amount > MAX_WITHDRAW) {
      return res.status(400).json({
        error: 'invalid_amount',
        min: MIN_WITHDRAW,
        max: MAX_WITHDRAW
      });
    }

    await client.query('BEGIN');

    const userResult = await client.query(
      `SELECT balance, wallet_locked FROM users WHERE id=$1 FOR UPDATE`, [req.user.id]
    );

    if (!userResult.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }

    const balance = Number(userResult.rows[0].balance || 0);

    if (balance < amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'insufficient_balance' });
    }

    const updated = await client.query(
      `UPDATE users
       SET balance = balance - $1, wallet_locked = wallet_locked + $1
       WHERE id=$2
       RETURNING balance, wallet_locked`,
      [amount, req.user.id]
    );

    const withdrawal = await client.query(
      `INSERT INTO wallet_transactions (user_id, type, network, amount, address, status, fee)
       VALUES ($1, 'withdraw', $2, $3, $4, 'pending', $5)
       RETURNING id, type, network, amount, address, status, fee, created_at`,
      [req.user.id, network, amount, address, WITHDRAW_FEE]
    );

    await client.query('COMMIT');

    res.json({
      ok: true,
      transaction: withdrawal.rows[0],
      balance: Number(updated.rows[0].balance),
      locked_balance: Number(updated.rows[0].wallet_locked),
      message: 'withdrawal_submitted_for_review'
    });
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('withdraw error:', e.message);
    res.status(500).json({ error: 'server_error' });
  } finally {
    client.release();
  }
});

app.get('/api/wallet/transactions', auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, type, network, amount, address, tx_hash, status, fee, created_at, updated_at
       FROM wallet_transactions
       WHERE user_id=$1
         AND ((type='deposit' AND status='confirmed') OR (type='withdraw' AND status='completed'))
       ORDER BY created_at DESC
       LIMIT 50`,
      [req.user.id]
    );
    res.json({ transactions: result.rows });
  } catch {
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/matches/mine', auth, async (req, res) => {
  try {
    const result = await db.query(
      `SELECT
         m.id, m.stake, m.prize, m.status, m.winner_user_id, m.created_at, m.settled_at,
         CASE WHEN m.p1_user_id=$1 THEN m.p2_user_id ELSE m.p1_user_id END AS opponent_id,
         CASE WHEN m.p1_user_id=$1 THEN u2.username ELSE u1.username END AS opponent_username,
         CASE WHEN m.p1_user_id=$1 THEN u2.email ELSE u1.email END AS opponent_email
       FROM paid_matches m
       LEFT JOIN users u1 ON u1.id = m.p1_user_id
       LEFT JOIN users u2 ON u2.id = m.p2_user_id
       WHERE m.p1_user_id=$1 OR m.p2_user_id=$1
       ORDER BY m.created_at DESC
       LIMIT 50`,
      [req.user.id]
    );

    const matches = result.rows.map(row => ({
      id: row.id,
      stake: Number(row.stake),
      prize: Number(row.prize),
      status: row.status,
      won: row.winner_user_id != null && Number(row.winner_user_id) === Number(req.user.id),
      opponent_name: defaultName({ username: row.opponent_username, email: row.opponent_email }),
      created_at: row.created_at,
      settled_at: row.settled_at
    }));

    res.json({ matches });
  } catch (e) {
    console.error('matches/mine error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/admin/wallet/transactions', adminOnly, async (_req, res) => {
  try {
    const result = await db.query(
      `SELECT id, user_id, type, network, amount, address, tx_hash, status, fee, created_at, updated_at
       FROM wallet_transactions
       ORDER BY created_at DESC
       LIMIT 200`
    );
    res.json({ transactions: result.rows });
  } catch {
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/wallet/transactions/delete-all', adminOnly, async (_req, res) => {
  try {
    const result = await db.query(`DELETE FROM wallet_transactions`);
    res.json({ ok: true, deleted: result.rowCount });
  } catch (e) {
    console.error('wallet transactions delete-all error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/wallet/deposit/:id/approve', adminOnly, async (req, res) => {
  const client = await db.pool.connect();
  try {
    const amount = Number(req.body?.amount);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'verified_amount_required' });
    }

    await client.query('BEGIN');

    const tx = await client.query(
      `SELECT * FROM wallet_transactions WHERE id=$1 AND type='deposit' FOR UPDATE`,
      [req.params.id]
    );

    if (!tx.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }

    if (tx.rows[0].status !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'already_processed' });
    }

    const updated = await client.query(
      `UPDATE users SET balance = balance + $1 WHERE id=$2 RETURNING balance`,
      [amount, tx.rows[0].user_id]
    );

    await client.query(
      `UPDATE wallet_transactions SET amount=$1, status='confirmed', updated_at=NOW() WHERE id=$2`,
      [amount, tx.rows[0].id]
    );

    await client.query('COMMIT');
    res.json({ ok: true, balance: Number(updated.rows[0].balance) });
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    res.status(500).json({ error: 'server_error' });
  } finally {
    client.release();
  }
});

app.post('/api/admin/wallet/withdraw/:id/complete', adminOnly, async (req, res) => {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const tx = await client.query(
      `SELECT * FROM wallet_transactions WHERE id=$1 AND type='withdraw' FOR UPDATE`,
      [req.params.id]
    );

    if (!tx.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }

    if (tx.rows[0].status !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'already_processed' });
    }

    const amount = Number(tx.rows[0].amount);
    const updated = await client.query(
      `UPDATE users SET wallet_locked = GREATEST(0, wallet_locked - $1) WHERE id=$2
       RETURNING balance, wallet_locked`,
      [amount, tx.rows[0].user_id]
    );

    await client.query(
      `UPDATE wallet_transactions SET status='completed', updated_at=NOW() WHERE id=$1`,
      [tx.rows[0].id]
    );

    await client.query('COMMIT');
    res.json({
      ok: true,
      balance: Number(updated.rows[0].balance),
      locked_balance: Number(updated.rows[0].wallet_locked)
    });
  } catch {
    try { await client.query('ROLLBACK'); } catch {}
    res.status(500).json({ error: 'server_error' });
  } finally {
    client.release();
  }
});

app.post('/api/admin/wallet/withdraw/:id/reject', adminOnly, async (req, res) => {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const tx = await client.query(
      `SELECT * FROM wallet_transactions WHERE id=$1 AND type='withdraw' FOR UPDATE`,
      [req.params.id]
    );

    if (!tx.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }

    if (tx.rows[0].status !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'already_processed' });
    }

    const amount = Number(tx.rows[0].amount);
    const updated = await client.query(
      `UPDATE users
       SET balance = balance + $1, wallet_locked = GREATEST(0, wallet_locked - $1)
       WHERE id=$2 RETURNING balance, wallet_locked`,
      [amount, tx.rows[0].user_id]
    );

    await client.query(
      `UPDATE wallet_transactions SET status='rejected', updated_at=NOW() WHERE id=$1`,
      [tx.rows[0].id]
    );

    await client.query('COMMIT');
    res.json({
      ok: true,
      balance: Number(updated.rows[0].balance),
      locked_balance: Number(updated.rows[0].wallet_locked)
    });
  } catch {
    try { await client.query('ROLLBACK'); } catch {}
    res.status(500).json({ error: 'server_error' });
  } finally {
    client.release();
  }
});

const PAID_TIERS = new Map([
  [1, 1.90],
  [3, 5.60],
  [5, 9.00]
]);

async function initPaidMatchTables() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS paid_matches (
      id BIGSERIAL PRIMARY KEY,
      room_id TEXT UNIQUE NOT NULL,
      p1_user_id INTEGER NOT NULL REFERENCES users(id),
      p2_user_id INTEGER NOT NULL REFERENCES users(id),
      stake NUMERIC(20,8) NOT NULL,
      prize NUMERIC(20,8) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'active',
      p1_report VARCHAR(8),
      p2_report VARCHAR(8),
      winner_user_id INTEGER REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      settled_at TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await db.query(`
    CREATE INDEX IF NOT EXISTS paid_matches_status_idx
    ON paid_matches(status, created_at DESC)
  `);
}

const TOURNAMENT_MIN_MATCH_SECONDS = Math.max(0, Number(process.env.TOURNAMENT_MIN_MATCH_SECONDS || 30));

async function initTournamentTables() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS tournament_config (
      id INTEGER PRIMARY KEY DEFAULT 1,
      enabled BOOLEAN NOT NULL DEFAULT true,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT tournament_config_singleton CHECK (id = 1)
    )
  `);

  await db.query(`ALTER TABLE tournament_config ADD COLUMN IF NOT EXISTS fake_reset_period TEXT`);
  await db.query(`
    INSERT INTO tournament_config (id, enabled) VALUES (1, true) ON CONFLICT (id) DO NOTHING
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS tournament_tiers (
      id BIGSERIAL PRIMARY KEY,
      rank_from INTEGER NOT NULL,
      rank_to INTEGER NOT NULL,
      amount NUMERIC(20,8) NOT NULL,
      CHECK (rank_from >= 1 AND rank_to >= rank_from AND amount >= 0)
    )
  `);

  const tierCount = await db.query(`SELECT COUNT(*)::int AS n FROM tournament_tiers`);
  if (tierCount.rows[0].n === 0) {
    await db.query(`
      INSERT INTO tournament_tiers (rank_from, rank_to, amount) VALUES
        (1,  1,  110),
        (2,  2,  60),
        (3,  3,  40),
        (4,  5,  20),
        (6,  10, 12),
        (11, 20, 7),
        (21, 35, 5),
        (36, 50, 3)
    `);
  }

  await db.query(`
    CREATE TABLE IF NOT EXISTS tournament_winners (
      id BIGSERIAL PRIMARY KEY,
      period TEXT NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id),
      rank INTEGER NOT NULL,
      wins INTEGER NOT NULL,
      prize_amount NUMERIC(20,8) NOT NULL,
      paid_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await db.query(`ALTER TABLE tournament_winners DROP CONSTRAINT IF EXISTS tournament_winners_period_key`);
  await db.query(`ALTER TABLE tournament_winners ADD COLUMN IF NOT EXISTS rank INTEGER`);
  await db.query(`ALTER TABLE tournament_winners ADD COLUMN IF NOT EXISTS wins INTEGER`);
  await db.query(`UPDATE tournament_winners SET rank = 1 WHERE rank IS NULL`);
  await db.query(`UPDATE tournament_winners SET wins = games_played WHERE wins IS NULL AND games_played IS NOT NULL`);
  await db.query(`UPDATE tournament_winners SET wins = 0 WHERE wins IS NULL`);
  await db.query(`ALTER TABLE tournament_winners ALTER COLUMN rank SET NOT NULL`);
  await db.query(`ALTER TABLE tournament_winners ALTER COLUMN wins SET NOT NULL`);
  await db.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS tournament_winners_period_user_idx
    ON tournament_winners(period, user_id)
  `);
}

async function initVisitTables() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS daily_visits (
      visit_date DATE NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id),
      first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (visit_date, user_id)
    )
  `);
  await db.query(`CREATE INDEX IF NOT EXISTS daily_visits_date_idx ON daily_visits(visit_date DESC)`);

  await db.query(`
    CREATE TABLE IF NOT EXISTS app_open_counts (
      open_date DATE PRIMARY KEY,
      opens INTEGER NOT NULL DEFAULT 0
    )
  `);
}

function recordVisit(userId) {
  db.query(`
    INSERT INTO daily_visits (visit_date, user_id)
    VALUES (CURRENT_DATE, $1)
    ON CONFLICT (visit_date, user_id) DO NOTHING
  `, [userId]).catch(e => console.warn('recordVisit skipped:', e.message));
}

function recordAppOpen() {
  db.query(`
    INSERT INTO app_open_counts (open_date, opens)
    VALUES (CURRENT_DATE, 1)
    ON CONFLICT (open_date) DO UPDATE SET opens = app_open_counts.opens + 1
  `).catch(e => console.warn('recordAppOpen skipped:', e.message));
}

app.get('/api/admin/visits', adminOnly, async (req, res) => {
  try {
    const days = Math.min(90, Math.max(1, Number(req.query.days) || 30));
    const result = await db.query(`
      SELECT visit_date, COUNT(*) AS visitors
      FROM daily_visits
      WHERE visit_date >= CURRENT_DATE - ($1 || ' days')::interval
      GROUP BY visit_date
      ORDER BY visit_date DESC
    `, [days]);
    const today = await db.query(`SELECT COUNT(*) AS visitors FROM daily_visits WHERE visit_date = CURRENT_DATE`);
    const opensToday = await db.query(`SELECT opens FROM app_open_counts WHERE open_date = CURRENT_DATE`);
    res.json({
      today: Number(today.rows[0]?.visitors || 0),
      opens_today: Number(opensToday.rows[0]?.opens || 0),
      days: result.rows.map(r => ({
        date: r.visit_date.toISOString().slice(0, 10),
        visitors: Number(r.visitors)
      }))
    });
  } catch (e) {
    console.error('admin visits error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/admin/matches/today', adminOnly, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT
        COUNT(*) FILTER (WHERE stake = 0) AS free_count,
        COUNT(*) FILTER (WHERE stake > 0) AS paid_count
      FROM paid_matches
      WHERE created_at >= date_trunc('day', NOW())
    `);
    const row = result.rows[0] || {};
    res.json({
      free: Number(row.free_count || 0),
      paid: Number(row.paid_count || 0)
    });
  } catch (e) {
    console.error('admin matches/today error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

async function computeMatchStatsSince(sinceSql) {
  const totals = await db.query(`
    SELECT
      COUNT(*) AS total_matches,
      COUNT(*) FILTER (WHERE stake = 0) AS free_matches,
      COUNT(*) FILTER (WHERE stake > 0) AS paid_matches,
      COUNT(*) FILTER (WHERE room_id LIKE 'bot-%') AS bot_matches,
      COUNT(*) FILTER (WHERE room_id NOT LIKE 'bot-%' OR room_id IS NULL) AS real_opponent_matches
    FROM paid_matches
    WHERE created_at >= ${sinceSql}
  `);

  const uniquePlayers = await db.query(`
    SELECT COUNT(DISTINCT uid) AS n FROM (
      SELECT p1_user_id AS uid FROM paid_matches WHERE created_at >= ${sinceSql}
      UNION
      SELECT p2_user_id AS uid FROM paid_matches WHERE created_at >= ${sinceSql}
    ) x
  `);

  const topPaid = await db.query(`
    SELECT u.id, u.username, COUNT(*)::int AS matches
    FROM (
      SELECT p1_user_id AS uid FROM paid_matches WHERE stake > 0 AND created_at >= ${sinceSql}
      UNION ALL
      SELECT p2_user_id AS uid FROM paid_matches WHERE stake > 0 AND created_at >= ${sinceSql}
    ) x
    JOIN users u ON u.id = x.uid
    GROUP BY u.id, u.username
    ORDER BY matches DESC
    LIMIT 1
  `);

  const topFree = await db.query(`
    SELECT u.id, u.username, COUNT(*)::int AS matches
    FROM (
      SELECT p1_user_id AS uid FROM paid_matches WHERE stake = 0 AND created_at >= ${sinceSql}
      UNION ALL
      SELECT p2_user_id AS uid FROM paid_matches WHERE stake = 0 AND created_at >= ${sinceSql}
    ) x
    JOIN users u ON u.id = x.uid
    GROUP BY u.id, u.username
    ORDER BY matches DESC
    LIMIT 1
  `);

  const row = totals.rows[0] || {};
  return {
    total_matches: Number(row.total_matches || 0),
    free_matches: Number(row.free_matches || 0),
    paid_matches: Number(row.paid_matches || 0),
    bot_matches: Number(row.bot_matches || 0),
    real_opponent_matches: Number(row.real_opponent_matches || 0),
    unique_players: Number((uniquePlayers.rows[0] || {}).n || 0),
    top_paid_player: topPaid.rows[0] || null,
    top_free_player: topFree.rows[0] || null
  };
}

app.get('/api/admin/analytics/monthly', adminOnly, async (req, res) => {
  try {
    const [today, last30] = await Promise.all([
      computeMatchStatsSince(`date_trunc('day', NOW())`),
      computeMatchStatsSince(`NOW() - INTERVAL '30 days'`)
    ]);

    res.json({
      today,
      last_30_days: last30,
      currently_active_matches: rooms.size,
      currently_active_players: rooms.size * 2,
      currently_online_sockets: io.engine ? io.engine.clientsCount : 0
    });
  } catch (e) {
    console.error('admin analytics/monthly error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

function weekPeriodString(d) {
  const date = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const dayNum = (date.getUTCDay() + 6) % 7;
  date.setUTCDate(date.getUTCDate() - dayNum + 3);
  const firstThursday = new Date(Date.UTC(date.getUTCFullYear(), 0, 4));
  const weekNum = 1 + Math.round(
    ((date.getTime() - firstThursday.getTime()) / 86400000 - 3 + ((firstThursday.getUTCDay() + 6) % 7)) / 7
  );
  return date.getUTCFullYear() + '-W' + String(weekNum).padStart(2, '0');
}

function weekBounds(periodStr) {
  const [yStr, wStr] = periodStr.split('-W');
  const y = Number(yStr), w = Number(wStr);
  const jan4 = new Date(Date.UTC(y, 0, 4));
  const jan4Day = (jan4.getUTCDay() + 6) % 7;
  const week1Monday = new Date(jan4.getTime() - jan4Day * 86400000);
  const start = new Date(week1Monday.getTime() + (w - 1) * 7 * 86400000);
  const end = new Date(start.getTime() + 7 * 86400000);
  return { start, end };
}

function currentWeekPeriod() {
  return weekPeriodString(new Date());
}

async function getTiers() {
  const result = await db.query(`
    SELECT rank_from, rank_to, amount FROM tournament_tiers ORDER BY rank_from ASC
  `);
  return result.rows.map(r => ({
    rank_from: Number(r.rank_from),
    rank_to: Number(r.rank_to),
    amount: Number(r.amount)
  }));
}

function tierAmountForRank(tiers, rank) {
  const t = tiers.find(t => rank >= t.rank_from && rank <= t.rank_to);
  return t ? t.amount : 0;
}

async function getLeaderboardForPeriod(periodStr, limit) {
  const { start, end } = weekBounds(periodStr);
  const result = await db.query(`
    SELECT u.id, u.email, x.wins
    FROM (
      SELECT winner_user_id AS user_id, COUNT(*) AS wins
      FROM paid_matches
      WHERE status='settled' AND stake=0
        AND winner_user_id IS NOT NULL
        AND settled_at >= $1 AND settled_at < $2
        AND settled_at >= created_at + ($4 || ' seconds')::interval
      GROUP BY winner_user_id
    ) x
    JOIN users u ON u.id = x.user_id
    WHERE COALESCE(u.banned, false) = false
    ORDER BY x.wins DESC, u.id ASC
    LIMIT $3
  `, [start, end, limit || 50, String(TOURNAMENT_MIN_MATCH_SECONDS)]);
  return result.rows;
}

async function initClientErrorsTable() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS client_errors (
      id BIGSERIAL PRIMARY KEY,
      message TEXT,
      source TEXT,
      line INTEGER,
      col INTEGER,
      stack TEXT,
      user_id INTEGER,
      user_agent TEXT,
      url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await db.query(`ALTER TABLE client_errors ADD COLUMN IF NOT EXISTS match_id INTEGER, ADD COLUMN IF NOT EXISTS room_id TEXT`);
  await db.query(`ALTER TABLE paid_matches ADD COLUMN IF NOT EXISTS dispute_reason TEXT`);
  await db.query(`
    DELETE FROM client_errors WHERE id NOT IN (
      SELECT id FROM client_errors ORDER BY id DESC LIMIT 2000
    )
  `);
}

async function checkStalledPaidMatches() {
  try {
    const STALE_MS = 4 * 60 * 1000;
    const now = Date.now();
    for (const [roomId, room] of rooms.entries()) {
      if (!room.matchId) continue;
      const last = room.lastActivityAt || 0;
      if (now - last < STALE_MS) continue;
      if (room._flaggedStalled) continue;
      room._flaggedStalled = true;
      const refunded = await refundPaidMatch(room.matchId);
      if (refunded) {
        for (const sid of room.players || []) {
          io.to(sid).emit('match_disputed', { match_id: room.matchId, auto_refunded: true, reason: 'server_detected_inactivity' });
          socketRoom.delete(sid);
        }
        rooms.delete(roomId);
      }
    }
  } catch (e) {
    console.error('checkStalledPaidMatches error:', e.message);
  }
}

async function autoRefundOrphanedPaidMatches() {
  try {
    const result = await db.query(`
      SELECT id, room_id FROM paid_matches
      WHERE status = 'active' AND updated_at < NOW() - INTERVAL '30 minutes'
    `);
    for (const row of result.rows) {
      if (!rooms.has(row.room_id)) {
        const refunded = await refundPaidMatch(row.id);
        if (refunded) {
          console.log('[auto-refund] refunded orphaned paid match id=' + row.id + ' room=' + row.room_id);
        }
      }
    }
  } catch (e) {
    console.error('auto-refund orphaned matches error:', e.message);
  }
}

async function initFakeLeaderboard() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS fake_leaderboard (
      id BIGSERIAL PRIMARY KEY,
      display_name TEXT NOT NULL,
      wins INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await db.query(`
    ALTER TABLE fake_leaderboard
      ADD COLUMN IF NOT EXISTS last_auto_increment_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ADD COLUMN IF NOT EXISTS increment_interval_seconds INTEGER NOT NULL DEFAULT 420,
      ADD COLUMN IF NOT EXISTS auto_increment_enabled BOOLEAN NOT NULL DEFAULT true
  `);
}

function randomIncrementIntervalSeconds() {
  return 300 + Math.floor(Math.random() * 300);
}

async function tickFakeLeaderboard() {
  try {
    await db.query(`
      UPDATE fake_leaderboard
      SET wins = wins + (CASE WHEN random() < 0.15 THEN 2 ELSE 1 END),
          last_auto_increment_at = NOW(),
          increment_interval_seconds = 300 + floor(random() * 300)::int
      WHERE auto_increment_enabled
        AND NOW() - last_auto_increment_at >= (increment_interval_seconds || ' seconds')::interval
    `);
  } catch (e) {
    console.error('fake leaderboard auto-increment error:', e.message);
  }
}

async function getFakeLeaderboardEntries() {
  const result = await db.query(`
    SELECT id, display_name, wins, auto_increment_enabled FROM fake_leaderboard ORDER BY wins DESC, id ASC
  `);
  return result.rows.map(r => ({
    id: r.id,
    fake: true,
    display_name: r.display_name,
    wins: Number(r.wins),
    auto_increment_enabled: r.auto_increment_enabled !== false
  }));
}

async function getDisplayLeaderboard(periodStr, limit, tiers) {
  const [real, fake] = await Promise.all([
    getLeaderboardForPeriod(periodStr, Math.max(limit || 50, 200)),
    getFakeLeaderboardEntries()
  ]);
  const combined = [
    ...real.map((r, i) => ({
      user_id: r.id,
      email: r.email,
      wins: Number(r.wins),
      fake: false,
      real_rank: i + 1,
      prize_amount: tierAmountForRank(tiers, i + 1)
    })),
    ...fake.map(f => ({
      user_id: null,
      fake_id: f.id,
      display_name: f.display_name,
      wins: f.wins,
      fake: true,
      real_rank: null,
      prize_amount: 0
    }))
  ];
  combined.sort((a, b) => b.wins - a.wins);
  return combined.slice(0, limit || 50).map((row, i) => ({
    ...row,
    rank: i + 1
  }));
}

async function checkAndPayoutTournament(periodOverride) {
  const period = periodOverride || currentWeekPeriod();

  const cfg = await db.query(`SELECT * FROM tournament_config WHERE id=1`);
  if (!cfg.rows.length || !cfg.rows[0].enabled) {
    return { paid: false, period, reason: 'tournament_disabled' };
  }

  const already = await db.query(
    `SELECT id FROM tournament_winners WHERE period=$1 LIMIT 1`, [period]
  );
  if (already.rows.length) {
    return { paid: false, period, reason: 'already_paid' };
  }

  const tiers = await getTiers();
  if (!tiers.length) {
    return { paid: false, period, reason: 'no_tiers_configured' };
  }

  const maxRank = Math.max(...tiers.map(t => t.rank_to));
  const leaderboard = await getLeaderboardForPeriod(period, maxRank);
  if (!leaderboard.length) {
    return { paid: false, period, reason: 'no_eligible_winners' };
  }

  let paidCount = 0;
  let totalAmount = 0;

  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');

    for (let i = 0; i < leaderboard.length; i++) {
      const rank = i + 1;
      const amount = tierAmountForRank(tiers, rank);
      if (!(amount > 0)) continue;

      const row = leaderboard[i];
      const locked = await client.query(
        `SELECT id, balance FROM users WHERE id=$1 FOR UPDATE`, [row.id]
      );
      if (!locked.rows.length) continue;
      const before = Number(locked.rows[0].balance || 0);
      const after = before + amount;

      await client.query(`UPDATE users SET balance=$1 WHERE id=$2`, [after, row.id]);
      await client.query(`
        INSERT INTO admin_balance_audit (user_id, amount, balance_before, balance_after, reason)
        VALUES ($1,$2,$3,$4,$5)
      `, [row.id, amount, before, after,
        'Weekly free-play tournament prize for ' + period + ' (rank #' + rank + ', ' + row.wins + ' wins)']);

      await client.query(`
        INSERT INTO tournament_winners (period, user_id, rank, wins, prize_amount)
        VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT (period, user_id) DO NOTHING
      `, [period, row.id, rank, Number(row.wins), amount]);

      paidCount++;
      totalAmount += amount;
    }

    await client.query('COMMIT');
    console.log('Weekly tournament paid out for ' + period + ' (' + paidCount + ' winners, ' + totalAmount + ' USDT)');
    return { paid: true, period, count: paidCount, total_amount: totalAmount };
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('tournament payout error:', e.message);
    return { paid: false, period, reason: 'server_error' };
  } finally {
    client.release();
  }
}

app.get('/api/tournament/leaderboard', async (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  try {
    const cfg = await db.query(`SELECT enabled FROM tournament_config WHERE id=1`);
    const tiers = await getTiers();
    const totalPool = tiers.reduce((s, t) => s + t.amount * (t.rank_to - t.rank_from + 1), 0);
    const period = currentWeekPeriod();
    const maxRank = tiers.length ? Math.max(...tiers.map(t => t.rank_to)) : 50;
    const leaderboard = await getDisplayLeaderboard(period, maxRank, tiers);
    res.json({
      period,
      total_pool: totalPool,
      top_prize: tiers.length ? tierAmountForRank(tiers, 1) : 0,
      enabled: !!cfg.rows[0]?.enabled,
      tiers: tiers,
      leaderboard
    });
  } catch (e) {
    console.error('tournament leaderboard error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/admin/tournament', adminOnly, async (req, res) => {
  try {
    const cfg = await db.query(`SELECT enabled FROM tournament_config WHERE id=1`);
    const tiers = await getTiers();
    const totalPool = tiers.reduce((s, t) => s + t.amount * (t.rank_to - t.rank_from + 1), 0);
    const period = currentWeekPeriod();
    const maxRank = tiers.length ? Math.max(...tiers.map(t => t.rank_to)) : 50;
    const leaderboard = await getDisplayLeaderboard(period, maxRank, tiers);
    const fakeEntries = await getFakeLeaderboardEntries();
    const winners = await db.query(`
      SELECT tw.period, tw.user_id, u.email, tw.rank, tw.wins, tw.prize_amount, tw.paid_at
      FROM tournament_winners tw
      JOIN users u ON u.id = tw.user_id
      ORDER BY tw.period DESC, tw.rank ASC
      LIMIT 200
    `);
    res.json({
      period,
      total_pool: totalPool,
      enabled: !!cfg.rows[0]?.enabled,
      tiers: tiers.map((t, i) => ({ id_index: i, ...t })),
      tiers_raw: (await db.query(`SELECT id, rank_from, rank_to, amount FROM tournament_tiers ORDER BY rank_from ASC`)).rows.map(r => ({
        id: r.id, rank_from: Number(r.rank_from), rank_to: Number(r.rank_to), amount: Number(r.amount)
      })),
      leaderboard,
      fake_entries: fakeEntries,
      winners: winners.rows.map(w => ({
        period: w.period,
        user_id: w.user_id,
        email: w.email,
        rank: w.rank,
        wins: Number(w.wins),
        prize_amount: Number(w.prize_amount),
        paid_at: w.paid_at
      }))
    });
  } catch (e) {
    console.error('admin tournament error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/tournament/config', adminOnly, async (req, res) => {
  try {
    const enabled = req.body?.enabled;
    await db.query(`
      UPDATE tournament_config
      SET enabled=COALESCE($1, enabled), updated_at=NOW()
      WHERE id=1
    `, [typeof enabled === 'boolean' ? enabled : null]);
    res.json({ ok: true });
  } catch (e) {
    console.error('tournament config error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/tournament/tiers', adminOnly, async (req, res) => {
  try {
    const { rank_from, rank_to, amount } = req.body || {};
    const rf = Number(rank_from), rt = Number(rank_to), amt = Number(amount);
    if (!Number.isInteger(rf) || !Number.isInteger(rt) || rf < 1 || rt < rf) {
      return res.status(400).json({ error: 'invalid_rank_range' });
    }
    if (!Number.isFinite(amt) || amt < 0) {
      return res.status(400).json({ error: 'invalid_amount' });
    }
    const result = await db.query(`
      INSERT INTO tournament_tiers (rank_from, rank_to, amount) VALUES ($1,$2,$3)
      RETURNING id, rank_from, rank_to, amount
    `, [rf, rt, amt]);
    res.json({ ok: true, tier: result.rows[0] });
  } catch (e) {
    console.error('tournament tier add error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/tournament/tiers/:id', adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { rank_from, rank_to, amount } = req.body || {};
    const rf = Number(rank_from), rt = Number(rank_to), amt = Number(amount);
    if (!Number.isInteger(rf) || !Number.isInteger(rt) || rf < 1 || rt < rf) {
      return res.status(400).json({ error: 'invalid_rank_range' });
    }
    if (!Number.isFinite(amt) || amt < 0) {
      return res.status(400).json({ error: 'invalid_amount' });
    }
    await db.query(`
      UPDATE tournament_tiers SET rank_from=$1, rank_to=$2, amount=$3 WHERE id=$4
    `, [rf, rt, amt, id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('tournament tier update error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/tournament/tiers/:id/delete', adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    await db.query(`DELETE FROM tournament_tiers WHERE id=$1`, [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('tournament tier delete error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

const clientErrorRateLimit = new Map();
function isClientErrorRateLimited(ip) {
  const now = Date.now();
  const windowMs = 5 * 60 * 1000;
  const maxPerWindow = 20;
  const entry = clientErrorRateLimit.get(ip);
  if (!entry || now - entry.windowStart > windowMs) {
    clientErrorRateLimit.set(ip, { count: 1, windowStart: now });
    return false;
  }
  entry.count++;
  return entry.count > maxPerWindow;
}

app.post('/api/client-error', async (req, res) => {
  try {
    const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    if (isClientErrorRateLimited(ip)) {
      return res.status(429).json({ ok: false });
    }

    let userId = null;
    const header = req.headers.authorization || '';
    if (header.startsWith('Bearer ')) {
      try {
        const payload = jwt.verify(header.slice(7), JWT_SECRET);
        userId = payload && payload.id ? Number(payload.id) : null;
      } catch (e) {}
    }

    const message = String(req.body?.message || '').slice(0, 500);
    const source = String(req.body?.source || '').slice(0, 300);
    const line = Number.isInteger(req.body?.line) ? req.body.line : null;
    const col = Number.isInteger(req.body?.col) ? req.body.col : null;
    const stack = String(req.body?.stack || '').slice(0, 2000);
    const userAgent = String(req.headers['user-agent'] || '').slice(0, 300);
    const url = String(req.body?.url || '').slice(0, 300);
    const matchId = Number.isInteger(req.body?.match_id) ? req.body.match_id : null;
    const roomId = req.body?.room_id ? String(req.body.room_id).slice(0, 100) : null;

    if (!message) return res.status(400).json({ ok: false });

    await db.query(`
      INSERT INTO client_errors (message, source, line, col, stack, user_id, user_agent, url, match_id, room_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    `, [message, source, line, col, stack, userId, userAgent, url, matchId, roomId]);

    res.json({ ok: true });
  } catch (e) {
    res.status(200).json({ ok: false });
  }
});

app.post('/api/report-stuck-match', auth, async (req, res) => {
  try {
    const matchId = Number(req.body?.match_id);
    const reason = String(req.body?.reason || 'client_detected_freeze').slice(0, 200);
    if (!Number.isInteger(matchId)) return res.status(400).json({ ok: false });

    await db.query(`
      UPDATE paid_matches
      SET status = 'disputed', dispute_reason = $1, updated_at = NOW()
      WHERE id = $2 AND status = 'active'
    `, [reason, matchId]);

    res.json({ ok: true });
  } catch (e) {
    res.status(200).json({ ok: false });
  }
});

app.get('/api/admin/tournament/fraud', adminOnly, async (req, res) => {
  try {
    const period = String(req.query.period || currentWeekPeriod());
    const { start, end } = weekBounds(period);
    const minSec = TOURNAMENT_MIN_MATCH_SECONDS;

    const players = await db.query(`
      WITH free_matches AS (
        SELECT id, p1_user_id, p2_user_id, winner_user_id, created_at, settled_at,
          EXTRACT(EPOCH FROM (settled_at - created_at)) AS secs
        FROM paid_matches
        WHERE status='settled' AND stake=0 AND winner_user_id IS NOT NULL
          AND settled_at >= $1 AND settled_at < $2
      ),
      wins AS (
        SELECT winner_user_id AS user_id, COUNT(*) AS total_wins,
          COUNT(*) FILTER (WHERE secs < $3) AS fast_wins,
          ROUND(MIN(secs)) AS fastest_secs,
          ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY secs)) AS median_secs
        FROM free_matches
        GROUP BY winner_user_id
      ),
      top_opponent AS (
        SELECT DISTINCT ON (user_id) user_id, opponent_id, cnt
        FROM (
          SELECT winner_user_id AS user_id,
            CASE WHEN winner_user_id = p1_user_id THEN p2_user_id ELSE p1_user_id END AS opponent_id,
            COUNT(*) AS cnt
          FROM free_matches GROUP BY 1, 2
        ) t
        ORDER BY user_id, cnt DESC
      )
      SELECT u.id, u.username, u.email, COALESCE(u.banned, false) AS banned,
        w.total_wins, w.fast_wins, w.fastest_secs, w.median_secs,
        o.opponent_id AS top_opponent_id, ou.username AS top_opponent_username, o.cnt AS top_opponent_wins
      FROM wins w
      JOIN users u ON u.id = w.user_id
      LEFT JOIN top_opponent o ON o.user_id = w.user_id
      LEFT JOIN users ou ON ou.id = o.opponent_id
      ORDER BY w.total_wins DESC, u.id ASC
      LIMIT 200
    `, [start, end, minSec]);

    const rows = players.rows.map(r => {
      const totalWins = Number(r.total_wins) || 0;
      const fastWins = Number(r.fast_wins) || 0;
      const topOppWins = Number(r.top_opponent_wins) || 0;
      const flags = [];

      if (fastWins > 0) flags.push(fastWins + ' win(s) settled in under ' + minSec + 's');
      if (totalWins >= 5 && topOppWins / totalWins >= 0.7) {
        flags.push(Math.round((topOppWins / totalWins) * 100) + '% of wins against one opponent');
      }
      if (r.median_secs != null && Number(r.median_secs) < minSec * 2) {
        flags.push('median match only ' + Number(r.median_secs) + 's');
      }

      return {
        user_id: r.id,
        username: r.username,
        email: r.email,
        banned: r.banned,
        total_wins: totalWins,
        counted_wins: totalWins - fastWins,
        fast_wins: fastWins,
        fastest_secs: r.fastest_secs == null ? null : Number(r.fastest_secs),
        median_secs: r.median_secs == null ? null : Number(r.median_secs),
        top_opponent_id: r.top_opponent_id,
        top_opponent_username: r.top_opponent_username,
        top_opponent_wins: topOppWins,
        flags
      };
    });

    res.json({
      period,
      min_match_seconds: minSec,
      suspicious: rows.filter(r => r.flags.length),
      all: rows
    });
  } catch (e) {
    console.error('admin tournament fraud error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/admin/tournament/fraud/:id/matches', adminOnly, async (req, res) => {
  try {
    const userId = Number(req.params.id);
    if (!Number.isInteger(userId)) {
      return res.status(400).json({ error: 'bad_user_id' });
    }
    const period = String(req.query.period || currentWeekPeriod());
    const { start, end } = weekBounds(period);

    const result = await db.query(`
      SELECT m.id, m.room_id, m.created_at, m.settled_at,
        ROUND(EXTRACT(EPOCH FROM (m.settled_at - m.created_at))) AS secs,
        m.winner_user_id, (m.winner_user_id = $1) AS won,
        CASE WHEN m.p1_user_id = $1 THEN m.p2_user_id ELSE m.p1_user_id END AS opponent_id,
        ou.username AS opponent_username
      FROM paid_matches m
      LEFT JOIN users ou
        ON ou.id = CASE WHEN m.p1_user_id = $1 THEN m.p2_user_id ELSE m.p1_user_id END
      WHERE m.stake = 0 AND (m.p1_user_id = $1 OR m.p2_user_id = $1)
        AND m.settled_at >= $2 AND m.settled_at < $3
      ORDER BY m.settled_at DESC
      LIMIT 300
    `, [userId, start, end]);

    res.json({
      period,
      min_match_seconds: TOURNAMENT_MIN_MATCH_SECONDS,
      matches: result.rows.map(r => ({
        ...r,
        secs: r.secs == null ? null : Number(r.secs),
        counted: r.won && r.secs != null && Number(r.secs) >= TOURNAMENT_MIN_MATCH_SECONDS
      }))
    });
  } catch (e) {
    console.error('admin tournament fraud matches error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/admin/client-errors', adminOnly, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT message, source, line, col, COUNT(*)::int AS occurrences,
             MAX(created_at) AS last_seen, MIN(created_at) AS first_seen,
             COUNT(DISTINCT user_id)::int AS affected_users
      FROM client_errors
      WHERE created_at > NOW() - INTERVAL '7 days'
      GROUP BY message, source, line, col
      ORDER BY MAX(created_at) DESC
      LIMIT 100
    `);
    res.json({ errors: result.rows });
  } catch (e) {
    console.error('admin client-errors list error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/client-errors/clear', adminOnly, async (req, res) => {
  try {
    await db.query(`DELETE FROM client_errors`);
    res.json({ ok: true });
  } catch (e) {
    console.error('admin client-errors clear error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/tournament/fake', adminOnly, async (req, res) => {
  try {
    const name = String(req.body?.display_name || '').trim().slice(0, 40);
    const wins = Number(req.body?.wins);
    if (!name) return res.status(400).json({ error: 'display_name_required' });
    if (!Number.isInteger(wins) || wins < 0) return res.status(400).json({ error: 'invalid_wins' });
    const result = await db.query(`
      INSERT INTO fake_leaderboard (display_name, wins, last_auto_increment_at, increment_interval_seconds)
      VALUES ($1, $2, NOW(), $3)
      RETURNING id, display_name, wins
    `, [name, wins, randomIncrementIntervalSeconds()]);
    res.json({ ok: true, entry: result.rows[0] });
  } catch (e) {
    console.error('fake leaderboard add error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/tournament/fake/:id', adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const name = String(req.body?.display_name || '').trim().slice(0, 40);
    const wins = Number(req.body?.wins);
    if (!name) return res.status(400).json({ error: 'display_name_required' });
    if (!Number.isInteger(wins) || wins < 0) return res.status(400).json({ error: 'invalid_wins' });
    await db.query(`UPDATE fake_leaderboard SET display_name=$1, wins=$2 WHERE id=$3`, [name, wins, id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('fake leaderboard update error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/tournament/fake/:id/toggle-auto', adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const enabled = req.body?.enabled;
    if (typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'enabled_boolean_required' });
    }
    await db.query(`
      UPDATE fake_leaderboard
      SET auto_increment_enabled=$1,
          last_auto_increment_at=CASE WHEN $1 THEN NOW() ELSE last_auto_increment_at END,
          increment_interval_seconds=CASE WHEN $1 THEN $2 ELSE increment_interval_seconds END
      WHERE id=$3
    `, [enabled, randomIncrementIntervalSeconds(), id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('fake leaderboard toggle-auto error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/tournament/fake/:id/delete', adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    await db.query(`DELETE FROM fake_leaderboard WHERE id=$1`, [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('fake leaderboard delete error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/tournament/fake/delete-all', adminOnly, async (req, res) => {
  try {
    const result = await db.query(`DELETE FROM fake_leaderboard`);
    res.json({ ok: true, deleted: result.rowCount });
  } catch (e) {
    console.error('fake leaderboard delete-all error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

const FAKE_NAME_PARTS_A = ['ahmad','sara','karzan','lana','zana','newroz','ravan','shene','dilan','hero','peshraw','avan','soran','dashti','barham','hawar','ronak','avesta','helan','nazdar'];
const FAKE_NAME_PARTS_B = ['92','_k','88','.q','111','_h','.d','99','_g','07','_j','23','.m','55','_s'];

app.post('/api/admin/tournament/fake/refresh', adminOnly, async (req, res) => {
  try {
    await db.query(`UPDATE tournament_config SET fake_reset_period=NULL WHERE id=1`);
    const period = currentWeekPeriod();
    const result = await db.query(`
      WITH claim AS (
        UPDATE tournament_config SET fake_reset_period=$1, updated_at=NOW()
        WHERE id=1 AND fake_reset_period IS DISTINCT FROM $1 RETURNING id
      )
      UPDATE fake_leaderboard SET wins = 0 WHERE EXISTS (SELECT 1 FROM claim)
      RETURNING id
    `, [period]);
    res.json({ ok: true, entries_reset: result.rowCount });
  } catch (e) {
    console.error('fake leaderboard manual refresh error:', e.message);
    res.status(500).json({ error: 'server_error', detail: e.message });
  }
});

app.post('/api/admin/tournament/fake/generate', adminOnly, async (req, res) => {
  try {
    const count = Math.min(300, Math.max(1, Number(req.body?.count) || 100));
    const minWins = Math.max(0, Number(req.body?.min_wins) || 1);
    const maxWins = Math.max(minWins, Number(req.body?.max_wins) || 20);
    const rows = [];
    for (let i = 0; i < count; i++) {
      const a = FAKE_NAME_PARTS_A[Math.floor(Math.random() * FAKE_NAME_PARTS_A.length)];
      const b = FAKE_NAME_PARTS_B[Math.floor(Math.random() * FAKE_NAME_PARTS_B.length)];
      const name = (a + b).slice(0, 40);
      const wins = minWins + Math.floor(Math.random() * (maxWins - minWins + 1));
      rows.push({ name, wins });
    }
    const client = await db.pool.connect();
    try {
      await client.query('BEGIN');
      for (const r of rows) {
        await client.query(
          `INSERT INTO fake_leaderboard (display_name, wins, last_auto_increment_at, increment_interval_seconds)
           VALUES ($1,$2,NOW(),$3)`,
          [r.name, r.wins, randomIncrementIntervalSeconds()]
        );
      }
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
    res.json({ ok: true, added: rows.length });
  } catch (e) {
    console.error('fake leaderboard generate error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/tournament/payout', adminOnly, async (req, res) => {
  try {
    const period = req.body?.period ? String(req.body.period).trim() : undefined;
    const result = await checkAndPayoutTournament(period);
    res.json(result);
  } catch (e) {
    console.error('manual tournament payout error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

async function createFreeMatchRecord(roomId, p1UserId, p2UserId) {
  const result = await db.query(
    `INSERT INTO paid_matches (room_id, p1_user_id, p2_user_id, stake, prize, status)
     VALUES ($1, $2, $3, 0, 0, 'active')
     RETURNING id, room_id, stake, prize, status`,
    [roomId, p1UserId, p2UserId]
  );
  return result.rows[0];
}

async function reservePaidEntries(roomId, p1UserId, p2UserId, stake, prize) {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const ids = [Number(p1UserId), Number(p2UserId)].sort((a, b) => a - b);
    const locked = await client.query(
      `SELECT id, balance, wallet_locked FROM users WHERE id = ANY($1::int[]) ORDER BY id FOR UPDATE`,
      [ids]
    );

    if (locked.rows.length !== 2) {
      throw new Error('players_not_found');
    }

    const byId = new Map(locked.rows.map(row => [Number(row.id), row]));

    for (const id of ids) {
      const user = byId.get(id);
      if (Number(user.balance || 0) < stake) {
        throw new Error('insufficient_balance');
      }
    }

    await client.query(
      `UPDATE users SET balance = balance - $1, wallet_locked = wallet_locked + $1 WHERE id = ANY($2::int[])`,
      [stake, ids]
    );

    const match = await client.query(
      `INSERT INTO paid_matches (room_id, p1_user_id, p2_user_id, stake, prize, status)
       VALUES ($1, $2, $3, $4, $5, 'active')
       RETURNING id, room_id, stake, prize, status`,
      [roomId, p1UserId, p2UserId, stake, prize]
    );

    await client.query('COMMIT');
    return match.rows[0];
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    throw e;
  } finally {
    client.release();
  }
}

async function settlePaidMatchIfAgreed(matchId) {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(
      `SELECT * FROM paid_matches WHERE id=$1 FOR UPDATE`, [matchId]
    );

    if (!result.rows.length) {
      await client.query('ROLLBACK');
      return { status: 'missing' };
    }

    const match = result.rows[0];

    if (match.status === 'settled') {
      await client.query('ROLLBACK');
      return {
        status: 'settled',
        winnerUserId: Number(match.winner_user_id),
        prize: Number(match.prize),
        stake: Number(match.stake)
      };
    }

    if (!match.p1_report || !match.p2_report) {
      await client.query('COMMIT');
      return { status: 'waiting_reports' };
    }

    let winnerUserId = null;
    if (match.p1_report === 'win' && match.p2_report === 'loss') {
      winnerUserId = Number(match.p1_user_id);
    }
    if (match.p2_report === 'win' && match.p1_report === 'loss') {
      winnerUserId = Number(match.p2_user_id);
    }

    if (!winnerUserId) {
      await client.query(
        `UPDATE paid_matches SET status='disputed', updated_at=NOW() WHERE id=$1`, [matchId]
      );
      await client.query('COMMIT');
      return { status: 'disputed' };
    }

    const stake = Number(match.stake);
    const prize = Number(match.prize);
    const ids = [Number(match.p1_user_id), Number(match.p2_user_id)].sort((a, b) => a - b);

    await client.query(
      `SELECT id FROM users WHERE id = ANY($1::int[]) ORDER BY id FOR UPDATE`, [ids]
    );

    await client.query(
      `UPDATE users SET wallet_locked = GREATEST(0, wallet_locked - $1) WHERE id = ANY($2::int[])`,
      [stake, ids]
    );

    await client.query(
      `UPDATE users SET balance = balance + $1, wins = wins + 1 WHERE id=$2`,
      [prize, winnerUserId]
    );

    const loserUserId = winnerUserId === Number(match.p1_user_id)
      ? Number(match.p2_user_id)
      : Number(match.p1_user_id);

    await client.query(
      `UPDATE users SET losses = losses + 1 WHERE id=$1`, [loserUserId]
    );

    await client.query(
      `UPDATE paid_matches SET status='settled', winner_user_id=$1, settled_at=NOW(), updated_at=NOW() WHERE id=$2`,
      [winnerUserId, matchId]
    );

    await client.query('COMMIT');

    return {
      status: 'settled',
      winnerUserId,
      loserUserId,
      prize,
      stake
    };
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    throw e;
  } finally {
    client.release();
  }
}

async function settleForfeitMatch(matchId, winnerUserId) {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(
      `SELECT * FROM paid_matches WHERE id=$1 FOR UPDATE`, [matchId]
    );
    if (!result.rows.length) {
      await client.query('ROLLBACK');
      return { status: 'missing' };
    }
    const match = result.rows[0];
    if (match.status === 'settled') {
      await client.query('ROLLBACK');
      return {
        status: 'settled',
        winnerUserId: Number(match.winner_user_id),
        prize: Number(match.prize || 0),
        stake: Number(match.stake || 0)
      };
    }
    if (!['active','disputed'].includes(match.status)) {
      await client.query('ROLLBACK');
      return { status: match.status };
    }

    const p1 = Number(match.p1_user_id);
    const p2 = Number(match.p2_user_id);
    winnerUserId = Number(winnerUserId);
    if (![p1,p2].includes(winnerUserId)) {
      await client.query('ROLLBACK');
      return { status: 'invalid_winner' };
    }
    const loserUserId = winnerUserId === p1 ? p2 : p1;
    const ids = [p1,p2].sort((a,b)=>a-b);
    const stake = Number(match.stake || 0);
    const prize = Number(match.prize || 0);

    await client.query(
      `SELECT id FROM users WHERE id = ANY($1::int[]) ORDER BY id FOR UPDATE`, [ids]
    );
    await client.query(
      `UPDATE users SET wallet_locked = GREATEST(0, wallet_locked - $1) WHERE id = ANY($2::int[])`,
      [stake, ids]
    );
    await client.query(
      `UPDATE users SET balance=balance+$1, wins=wins+1 WHERE id=$2`, [prize, winnerUserId]
    );
    await client.query(
      `UPDATE users SET losses=losses+1 WHERE id=$1`, [loserUserId]
    );
    await client.query(
      `UPDATE paid_matches
       SET status='settled', winner_user_id=$1,
           p1_report=CASE WHEN p1_user_id=$1 THEN 'win' ELSE 'loss' END,
           p2_report=CASE WHEN p2_user_id=$1 THEN 'win' ELSE 'loss' END,
           settled_at=NOW(), updated_at=NOW()
       WHERE id=$2`,
      [winnerUserId, matchId]
    );
    await client.query('COMMIT');
    return { status:'settled', winnerUserId, loserUserId, prize, stake };
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    throw e;
  } finally {
    client.release();
  }
}

async function refundPaidMatch(matchId) {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(
      `SELECT * FROM paid_matches WHERE id=$1 FOR UPDATE`, [matchId]
    );

    if (!result.rows.length) {
      await client.query('ROLLBACK');
      return false;
    }

    const match = result.rows[0];
    if (!['active', 'disputed'].includes(match.status)) {
      await client.query('ROLLBACK');
      return false;
    }

    const stake = Number(match.stake);
    const ids = [Number(match.p1_user_id), Number(match.p2_user_id)].sort((a, b) => a - b);

    await client.query(
      `SELECT id FROM users WHERE id = ANY($1::int[]) ORDER BY id FOR UPDATE`, [ids]
    );

    await client.query(
      `UPDATE users SET balance = balance + $1, wallet_locked = GREATEST(0, wallet_locked - $1) WHERE id = ANY($2::int[])`,
      [stake, ids]
    );

    await client.query(
      `UPDATE paid_matches SET status='refunded', updated_at=NOW() WHERE id=$1`, [matchId]
    );

    await client.query('COMMIT');
    return true;
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    throw e;
  } finally {
    client.release();
  }
}

app.get('/api/admin/users', adminOnly, async (req, res) => {
  try {
    const q = String(req.query.q || '').trim();
    const params = [];
    let where = '';
    if (q) {
      params.push('%' + q + '%');
      where = `WHERE CAST(u.id AS TEXT) ILIKE $1
               OR COALESCE(u.username,'') ILIKE $1
               OR COALESCE(u.email,'') ILIKE $1
               OR COALESCE(u.phone,'') ILIKE $1`;
    }

    const result = await db.query(`
      SELECT
        u.id, u.username, u.email, u.phone,
        u.balance, u.wallet_locked, u.coins,
        u.wins, u.losses, u.avatar,
        u.country, u.city, u.last_seen_at,
        u.banned, u.ban_reason, u.banned_at, u.is_chat_moderator,
        COUNT(pm.id)::int AS matches_count,
        COUNT(pm.id) FILTER (WHERE pm.winner_user_id=u.id)::int AS matches_won,
        COUNT(pm.id) FILTER (
          WHERE pm.status IN ('settled','completed')
            AND pm.winner_user_id IS NOT NULL
            AND pm.winner_user_id<>u.id
        )::int AS matches_lost
      FROM users u
      LEFT JOIN paid_matches pm
        ON pm.p1_user_id=u.id OR pm.p2_user_id=u.id
      ${where}
      GROUP BY u.id
      ORDER BY u.id DESC
      LIMIT 500
    `, params);

    res.json({ users: result.rows.map(u => ({
      ...u,
      balance: Number(u.balance || 0),
      wallet_locked: Number(u.wallet_locked || 0),
      coins: Number(u.coins || 0),
      wins: Number(u.wins || 0),
      losses: Number(u.losses || 0),
      banned: !!u.banned,
      is_chat_moderator: !!u.is_chat_moderator
    })) });
  } catch (e) {
    console.error('admin users error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/admin/users/:id/matches', adminOnly, async (req, res) => {
  try {
    const userId = Number(req.params.id);
    if (!Number.isInteger(userId)) {
      return res.status(400).json({ error: 'bad_user_id' });
    }
    const result = await db.query(`
      SELECT * FROM paid_matches WHERE p1_user_id=$1 OR p2_user_id=$1 ORDER BY created_at DESC LIMIT 200
    `, [userId]);
    res.json({ matches: result.rows });
  } catch (e) {
    console.error('admin user matches error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/users/:id/balance', adminOnly, async (req, res) => {
  const client = await db.pool.connect();
  try {
    const userId = Number(req.params.id);
    const amount = Number(req.body?.amount);
    const reason = String(req.body?.reason || 'admin adjustment').trim().slice(0, 250);
    if (!Number.isInteger(userId) || !Number.isFinite(amount) || amount === 0) {
      return res.status(400).json({ error: 'valid_user_id_and_nonzero_amount_required' });
    }
    if (Math.abs(amount) > 1000000) {
      return res.status(400).json({ error: 'amount_too_large' });
    }

    await client.query('BEGIN');
    const locked = await client.query(
      `SELECT id, balance FROM users WHERE id=$1 FOR UPDATE`, [userId]
    );
    if (!locked.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'user_not_found' });
    }
    const before = Number(locked.rows[0].balance || 0);
    const after = before + amount;
    if (after < 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'balance_cannot_be_negative' });
    }

    const updated = await client.query(
      `UPDATE users SET balance=$1 WHERE id=$2 RETURNING balance`, [after, userId]
    );
    await client.query(`
      INSERT INTO admin_balance_audit (user_id, amount, balance_before, balance_after, reason)
      VALUES ($1,$2,$3,$4,$5)
    `, [userId, amount, before, after, reason || null]);
    await client.query('COMMIT');

    res.json({ ok: true, user_id: userId, amount, balance_before: before, balance: Number(updated.rows[0].balance) });
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('admin balance error:', e.message);
    res.status(500).json({ error: 'server_error' });
  } finally {
    client.release();
  }
});

app.post('/api/admin/users/:id/ban', adminOnly, async (req, res) => {
  try {
    const userId = Number(req.params.id);
    const banned = req.body?.banned;
    const reason = String(req.body?.reason || '').trim().slice(0, 250);
    if (!Number.isInteger(userId)) {
      return res.status(400).json({ error: 'valid_user_id_required' });
    }
    if (typeof banned !== 'boolean') {
      return res.status(400).json({ error: 'banned_boolean_required' });
    }

    const updated = await db.query(`
      UPDATE users
      SET banned=$1, ban_reason=$2, banned_at=CASE WHEN $1 THEN NOW() ELSE NULL END
      WHERE id=$3 RETURNING id, banned, ban_reason, banned_at
    `, [banned, banned ? (reason || null) : null, userId]);

    if (!updated.rows.length) {
      return res.status(404).json({ error: 'user_not_found' });
    }

    if (banned) {
      try { forceDisconnectUser(userId); } catch (e) {}
    }

    res.json({ ok: true, user: updated.rows[0] });
  } catch (e) {
    console.error('admin ban error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/users/:id/chat-mod', adminOnly, async (req, res) => {
  try {
    const userId = Number(req.params.id);
    const isModerator = req.body?.is_chat_moderator;
    if (!Number.isInteger(userId)) {
      return res.status(400).json({ error: 'valid_user_id_required' });
    }
    if (typeof isModerator !== 'boolean') {
      return res.status(400).json({ error: 'is_chat_moderator_boolean_required' });
    }

    const updated = await db.query(`
      UPDATE users SET is_chat_moderator=$1 WHERE id=$2 RETURNING id, is_chat_moderator
    `, [isModerator, userId]);

    if (!updated.rows.length) {
      return res.status(404).json({ error: 'user_not_found' });
    }

    res.json({ ok: true, user: updated.rows[0] });
  } catch (e) {
    console.error('admin chat-mod error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/users/:id/message', adminOnly, async (req, res) => {
  try {
    const userId = Number(req.params.id);
    const text = String(req.body?.text || '').trim().slice(0, 1000);
    if (!Number.isInteger(userId)) {
      return res.status(400).json({ error: 'valid_user_id_required' });
    }
    if (!text) {
      return res.status(400).json({ error: 'text_required' });
    }

    const inserted = await db.query(`
      INSERT INTO admin_messages (user_id, text) VALUES ($1, $2) RETURNING id, text, created_at
    `, [userId, text]);

    const message = inserted.rows[0];
    let deliveredLive = false;
    try {
      const ids = userSockets.get(userId);
      if (ids) {
        for (const socketId of ids) {
          const sock = io.sockets.sockets.get(socketId);
          if (sock) {
            sock.emit('admin_message', {
              id: message.id,
              text: message.text,
              ts: new Date(message.created_at).getTime()
            });
            deliveredLive = true;
          }
        }
      }
    } catch (e) {}

    res.json({ ok: true, message, delivered_live: deliveredLive });
  } catch (e) {
    console.error('admin message error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/admin/users/:id/balance-audit', adminOnly, async (req, res) => {
  try {
    const userId = Number(req.params.id);
    const result = await db.query(`
      SELECT id, user_id, amount, balance_before, balance_after, reason, created_at
      FROM admin_balance_audit WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100
    `, [userId]);
    res.json({ audit: result.rows });
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/admin/matches', adminOnly, async (_req, res) => {
  try {
    const result = await db.query(`
      SELECT pm.*, u1.username AS p1_username, u2.username AS p2_username, uw.username AS winner_username
      FROM paid_matches pm
      LEFT JOIN users u1 ON u1.id = pm.p1_user_id
      LEFT JOIN users u2 ON u2.id = pm.p2_user_id
      LEFT JOIN users uw ON uw.id = pm.winner_user_id
      ORDER BY pm.created_at DESC LIMIT 200
    `);
    res.json({ matches: result.rows });
  } catch {
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/matches/:id/refund', adminOnly, async (req, res) => {
  try {
    const ok = await refundPaidMatch(Number(req.params.id));
    if (!ok) {
      return res.status(409).json({ error: 'cannot_refund' });
    }
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/matches/:id/settle', adminOnly, async (req, res) => {
  const client = await db.pool.connect();
  try {
    const winnerUserId = Number(req.body?.winner_user_id);
    if (!Number.isInteger(winnerUserId)) {
      return res.status(400).json({ error: 'winner_user_id_required' });
    }

    await client.query('BEGIN');
    const result = await client.query(
      `SELECT * FROM paid_matches WHERE id=$1 FOR UPDATE`, [Number(req.params.id)]
    );

    if (!result.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'not_found' });
    }

    const match = result.rows[0];
    if (!['active', 'disputed'].includes(match.status)) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'already_processed' });
    }

    const p1 = Number(match.p1_user_id);
    const p2 = Number(match.p2_user_id);

    if (![p1, p2].includes(winnerUserId)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'winner_not_in_match' });
    }

    const loserUserId = winnerUserId === p1 ? p2 : p1;
    const ids = [p1, p2].sort((a, b) => a - b);
    const stake = Number(match.stake);
    const prize = Number(match.prize);

    await client.query(
      `SELECT id FROM users WHERE id = ANY($1::int[]) ORDER BY id FOR UPDATE`, [ids]
    );

    await client.query(
      `UPDATE users SET wallet_locked = GREATEST(0, wallet_locked - $1) WHERE id = ANY($2::int[])`,
      [stake, ids]
    );

    await client.query(
      `UPDATE users SET balance = balance + $1, wins = wins + 1 WHERE id=$2`,
      [prize, winnerUserId]
    );

    await client.query(`UPDATE users SET losses = losses + 1 WHERE id=$1`, [loserUserId]);

    await client.query(
      `UPDATE paid_matches SET status='settled', winner_user_id=$1, settled_at=NOW(), updated_at=NOW() WHERE id=$2`,
      [winnerUserId, Number(req.params.id)]
    );

    await client.query('COMMIT');
    res.json({ ok: true, winner_user_id: winnerUserId, prize });
  } catch {
    try { await client.query('ROLLBACK'); } catch {}
    res.status(500).json({ error: 'server_error' });
  } finally {
    client.release();
  }
});

app.post('/api/game-result', auth, async (req, res) => {
  try {
    const result = req.body?.result === 'win' ? 'win' : 'loss';
    let entry = parseInt(req.body?.entry, 10);
    if (![100, 200, 500].includes(entry)) {
      entry = 100;
    }

    const userResult = await db.query(`SELECT * FROM users WHERE id=$1`, [req.user.id]);
    if (!userResult.rows.length) {
      return res.status(404).json({ error: 'not_found' });
    }

    const user = userResult.rows[0];
    let coins = Number(user.coins || 0);
    let wins = Number(user.wins || 0);
    let losses = Number(user.losses || 0);

    if (result === 'win') {
      coins += entry;
      wins += 1;
    } else {
      coins = Math.max(0, coins - entry);
      losses += 1;
    }

    const updated = await db.query(
      `UPDATE users SET coins=$1, wins=$2, losses=$3 WHERE id=$4 RETURNING *`,
      [coins, wins, losses, req.user.id]
    );

    if (result === 'win') {
      try {
        const roomId = 'bot-' + req.user.id + '-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
        await db.query(
          `INSERT INTO paid_matches (room_id, p1_user_id, p2_user_id, stake, prize, status, winner_user_id, settled_at)
           VALUES ($1, $2, $2, 0, 0, 'settled', $2, NOW())`,
          [roomId, req.user.id]
        );
      } catch (e) {
        console.warn('bot-win tournament record skipped:', e.message);
      }
    }

    res.json({ user: publicUser(updated.rows[0]) });
  } catch {
    res.status(500).json({ error: 'server_error' });
  }
});

const TILE_VALUES = [
  [0, 0], [1, 2], [2, 3], [2, 4], [1, 5], [5, 5], [3, 6],
  [0, 1], [2, 2], [3, 3], [3, 4], [2, 5], [0, 6], [4, 6],
  [1, 1], [0, 3], [0, 4], [4, 4], [3, 5], [1, 6], [5, 6],
  [0, 2], [1, 3], [1, 4], [0, 5], [4, 5], [2, 6], [6, 6]
];

function shuffle(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

function dealRound() {
  const deck = shuffle([...Array(28).keys()]);
  const handA = deck.slice(0, 7);
  const handB = deck.slice(7, 14);
  const boneyard = deck.slice(14);

  let starterSeat = 0;
  let bestDouble = -1;
  let bestSum = -1;

  for (let seat = 0; seat < 2; seat++) {
    const hand = seat === 0 ? handA : handB;
    for (const value of hand) {
      const tile = TILE_VALUES[value];
      if (tile[0] === tile[1] && tile[0] > bestDouble) {
        bestDouble = tile[0];
        starterSeat = seat;
      }
    }
  }

  if (bestDouble < 0) {
    for (let seat = 0; seat < 2; seat++) {
      const hand = seat === 0 ? handA : handB;
      for (const value of hand) {
        const tile = TILE_VALUES[value];
        const sum = tile[0] + tile[1];
        if (sum > bestSum) {
          bestSum = sum;
          starterSeat = seat;
        }
      }
    }
  }

  return { handA, handB, boneyard, starterSeat };
}

const waitingQueues = new Map();
const rooms = new Map();
const socketRoom = new Map();
let sequence = 1;
const SERVER_BOOT_ID = Date.now().toString(36);

function otherPlayer(room, socketId) {
  if (!room || !Array.isArray(room.players)) return null;
  const seat = room.players.indexOf(socketId);
  if (seat === 0) return room.players[1] || null;
  if (seat === 1) return room.players[0] || null;
  return null;
}

const RECONNECT_GRACE_MS = 60000;
const pendingReconnects = new Map();
const userSockets = new Map();

function registerUserSocket(userId, socketId) {
  if (!userId || !socketId) return;
  if (!userSockets.has(userId)) userSockets.set(userId, new Set());
  userSockets.get(userId).add(socketId);
}

function unregisterSocketEverywhere(socketId) {
  for (const [uid, ids] of userSockets.entries()) {
    ids.delete(socketId);
    if (ids.size === 0) userSockets.delete(uid);
  }
}

function forceDisconnectUser(userId) {
  const ids = userSockets.get(userId);
  if (!ids) return;
  for (const socketId of Array.from(ids)) {
    try {
      const sock = io.sockets.sockets.get(socketId);
      if (sock) {
        sock.emit('force_disconnect', { reason: 'account_banned' });
      }
      handlePlayerLeftRoom(socketId, { immediate: true }).catch(() => {});
      if (sock) sock.disconnect(true);
    } catch (e) {}
  }
  userSockets.delete(userId);
}

function reconnectKey(roomId, userId) {
  return roomId + '|' + userId;
}

async function handlePlayerLeftRoom(socketId, opts) {
  const immediate = !!(opts && opts.immediate);
  const roomId = socketRoom.get(socketId);
  if (!roomId || !rooms.has(roomId)) return;

  const room = rooms.get(roomId);
  const opponent = otherPlayer(room, socketId);

  const hasTrackedMatch =
    room.matchId && room.userIds && room.userIds[0] && room.userIds[1];

  if (!immediate && hasTrackedMatch) {
    const seatIdx = Array.isArray(room.players) ? room.players.indexOf(socketId) : -1;
    if (seatIdx < 0) {
      socketRoom.delete(socketId);
      return;
    }
    const userId = room.userIds[seatIdx];
    const key = reconnectKey(roomId, userId);

    if (pendingReconnects.has(key)) return;
    socketRoom.delete(socketId);

    if (opponent) {
      io.to(opponent).emit('opponent_reconnecting', {
        match_id: room.matchId,
        grace_ms: RECONNECT_GRACE_MS
      });
    }

    const timer = setTimeout(async () => {
      pendingReconnects.delete(key);
      if (rooms.has(roomId)) {
        const liveRoom = rooms.get(roomId);
        if (!liveRoom || liveRoom.players[seatIdx] !== socketId ||
            Number(liveRoom.userIds && liveRoom.userIds[seatIdx]) !== Number(userId)) {
          return;
        }
        socketRoom.set(socketId, roomId);
        await finalizePlayerLeftRoom(socketId, { expectedSeatIdx: seatIdx, expectedUserId: userId });
      }
    }, RECONNECT_GRACE_MS);

    pendingReconnects.set(key, {
      timer,
      roomId,
      seatIdx,
      userId,
      deadSocketId: socketId,
      logMark: room.log ? room.log.length : 0
    });
    return;
  }

  await finalizePlayerLeftRoom(socketId);
}

async function finalizePlayerLeftRoom(socketId, guard) {
  const roomId = socketRoom.get(socketId);
  if (!roomId || !rooms.has(roomId)) return;

  const room = rooms.get(roomId);
  const actualSeatIdx = Array.isArray(room.players) ? room.players.indexOf(socketId) : -1;
  if (actualSeatIdx < 0) {
    socketRoom.delete(socketId);
    return;
  }
  if (guard && guard.expectedSeatIdx != null && actualSeatIdx !== Number(guard.expectedSeatIdx)) return;
  if (guard && guard.expectedUserId != null &&
      Number(room.userIds && room.userIds[actualSeatIdx]) !== Number(guard.expectedUserId)) return;

  if (room.finalizing) return;
  room.finalizing = true;

  clearRoomTurnTimer(room);
  const opponent = otherPlayer(room, socketId);
  const seatIdx = room.players[0] === socketId ? 0 : 1;
  const hasTrackedMatch =
    room.matchId && room.userIds && room.userIds[0] && room.userIds[1];

  if (room.userIds) {
    for (const uid of room.userIds) {
      const k = reconnectKey(roomId, uid);
      const pending = pendingReconnects.get(k);
      if (pending) {
        clearTimeout(pending.timer);
        pendingReconnects.delete(k);
      }
    }
  }

  try {
    if (hasTrackedMatch) {
      const winnerUserId = Number(room.userIds[seatIdx === 0 ? 1 : 0]);
      const result = await settleForfeitMatch(room.matchId, winnerUserId);

      if (opponent && result && result.status === 'settled' &&
          Number(result.winnerUserId) === winnerUserId) {
        io.to(opponent).emit('match_forfeit_win', {
          match_id: room.matchId,
          prize: result.prize,
          reason: 'disconnect_timeout'
        });
      } else if (Number(room.stake || 0) > 0) {
        let refunded = false;
        try { refunded = await refundPaidMatch(room.matchId); } catch (e) {
          console.error('forfeit refund fallback error:', e.message);
        }
        if (opponent) {
          io.to(opponent).emit('match_disputed', {
            match_id: room.matchId,
            auto_refunded: refunded,
            reason: 'forfeit_settlement_not_final'
          });
        }
      } else if (opponent) {
        io.to(opponent).emit('opponent_left', {
          paid: false,
          match_id: room.matchId,
          final: true
        });
      }
    } else if (opponent) {
      io.to(opponent).emit('opponent_left', {
        paid: Number(room.stake || 0) > 0,
        match_id: room.matchId,
        final: true
      });
    }
  } catch (e) {
    console.error('forfeit settlement fatal error:', e.message);
    if (Number(room.stake || 0) > 0 && room.matchId) {
      let refunded = false;
      try { refunded = await refundPaidMatch(room.matchId); } catch (e2) {}
      if (opponent) {
        io.to(opponent).emit('match_disputed', {
          match_id: room.matchId,
          auto_refunded: refunded,
          reason: 'forfeit_settlement_error'
        });
      }
    } else if (opponent) {
      io.to(opponent).emit('opponent_left', {
        paid: false,
        match_id: room.matchId,
        final: true
      });
    }
  } finally {
    room.players.forEach(id => { socketRoom.delete(id); });
    rooms.delete(roomId);
  }
}

const BANNED_WORDS = [
  'fuck', 'shit', 'bitch', 'asshole', 'bastard', 'dick', 'pussy',
  'cunt', 'whore', 'slut', 'nigger', 'nigga', 'faggot',
  'قوز', 'قون', 'حیز', 'گەواد', 'بێناموس', 'بێ ئەخلاق',
  'دایک', 'باوک', 'خوشک'
];

function normalizeForFilter(text) {
  return String(text || '').toLowerCase().replace(/[\s._\-*]+/g, '');
}

function censorText(text) {
  let result = String(text || '');
  for (const word of BANNED_WORDS) {
    const escaped = word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(escaped, 'gi');
    result = result.replace(re, match => '*'.repeat(match.length));
  }
  return result;
}

function queueKey(stake, goal) {
  return String(Number(stake || 0)) + ':' + String(Number(goal || 100));
}

function tileFitsEnd(value, endValue) {
  const t = TILE_VALUES[value];
  return !!t && endValue != null && (t[0] === endValue || t[1] === endValue);
}

function boardChainFor(room) {
  const chain = [];
  for (const entry of (room.log || [])) {
    if (!entry || entry.type !== 'move') continue;
    chain.push({
      value: entry.value,
      side: entry.side,
      rotation: entry.rotation,
      seat: entry.seat
    });
  }
  return chain;
}

function stateForSeat(room, seat) {
  const opp = seat === 0 ? 1 : 0;
  const hand = (room.hands && room.hands[seat]) || [];
  const oppHand = (room.hands && room.hands[opp]) || [];

  return {
    stateSerial: room.stateSerial || 0,
    roundSerial: room.roundSerial || 0,
    seat,
    goal: room.goal,
    scores: Array.isArray(room.scores) ? room.scores.slice() : [0, 0],
    board: boardChainFor(room),
    leftEnd: room.leftEnd,
    rightEnd: room.rightEnd,
    yourHand: hand.slice(),
    oppHandCount: oppHand.length,
    boneyardCount: (room.boneyard || []).length,
    turnSeat: room.turnSeat,
    yourTurn: room.turnSeat === seat,
    turnDeadline: room.turnDeadline || null,
    matchId: room.matchId || null,
    stake: room.stake,
    prize: room.prize
  };
}

function broadcastState(room, reason) {
  if (!room || !Array.isArray(room.players)) return;
  room.stateSerial = (room.stateSerial || 0) + 1;
  for (let seat = 0; seat < 2; seat++) {
    const sid = room.players[seat];
    if (!sid) continue;
    const payload = stateForSeat(room, seat);
    payload.reason = reason || 'update';
    io.to(sid).emit('game_state', payload);
  }
}

function hasLegalMove(room, seat) {
  const hand = room && room.hands && room.hands[seat];
  if (!hand) return false;
  if (room.leftEnd == null || room.rightEnd == null) return hand.length > 0;
  return hand.some(v => tileFitsEnd(v, room.leftEnd) || tileFitsEnd(v, room.rightEnd));
}

function derivePlacement(room, value, requestedSide) {
  const t = TILE_VALUES[value];
  if (!t) return null;
  const a = t[0], b = t[1];
  if (room.leftEnd == null || room.rightEnd == null) {
    return { side: 0, rotation: a === b ? 0 : -90, newLeft: a, newRight: b };
  }
  const side = Number(requestedSide);

  // ئەگەر ئەو لایەی داوای کردووە بگونجێت
  if (side === 1 && (a === room.leftEnd || b === room.leftEnd)) {
    return { side: 1, rotation: a === b ? 0 : (a === room.leftEnd ? 90 : -90), newLeft: (a === room.leftEnd ? b : a), newRight: room.rightEnd };
  }
  if (side === 2 && (a === room.rightEnd || b === room.rightEnd)) {
    return { side: 2, rotation: a === b ? 0 : (a === room.rightEnd ? -90 : 90), newLeft: room.leftEnd, newRight: (a === room.rightEnd ? b : a) };
  }

  // چاکسازی بۆ یاریزانی بەرامبەر: ئەگەر لای داواکراو نەگونجا بەهۆی دیدگای پێچەوانەوە، خۆی بیخەرە سەرە گونجاوەکە
  if (a === room.leftEnd || b === room.leftEnd) {
    return { side: 1, rotation: a === b ? 0 : (a === room.leftEnd ? 90 : -90), newLeft: (a === room.leftEnd ? b : a), newRight: room.rightEnd };
  }
  if (a === room.rightEnd || b === room.rightEnd) {
    return { side: 2, rotation: a === b ? 0 : (a === room.rightEnd ? -90 : 90), newLeft: room.leftEnd, newRight: (a === room.rightEnd ? b : a) };
  }
  return null;
}

function applyCanonicalMove(room, seat, value, requestedSide, requestedRotation, nonce) {
  if (!room || room.turnSeat !== seat) return { ok: false, error: 'not_your_turn' };
  if (!Number.isInteger(value) || value < 0 || value >= TILE_VALUES.length) return { ok: false, error: 'bad_tile' };
  const hand = room.hands && room.hands[seat];
  if (!hand) return { ok: false, error: 'bad_hand' };
  const idx = hand.indexOf(value);
  if (idx < 0) return { ok: false, error: 'tile_not_in_hand' };
  const placement = derivePlacement(room, value, requestedSide);
  if (!placement) return { ok: false, error: 'illegal_placement' };
  hand.splice(idx, 1);
  room.leftEnd = placement.newLeft;
  room.rightEnd = placement.newRight;
  room.moves = (room.moves || 0) + 1;
  if (room.log) room.log.push({ type: 'move', seat, value, side: placement.side, rotation: (requestedRotation != null ? requestedRotation : placement.rotation), nonce });
  room.lastActivityAt = Date.now();
  room.turnSeat = seat === 0 ? 1 : 0;
  return { ok: true, side: placement.side, rotation: (requestedRotation != null ? requestedRotation : placement.rotation) };
}

function performServerAutoTurn(room, seat) {
  if (!room || room.turnSeat !== seat || !room.hands || !room.hands[seat]) return;
  const actions = [];
  let hand = room.hands[seat];
  let value = hand.find(v => derivePlacement(room, v, null));

  while (value == null && room.boneyard && room.boneyard.length) {
    const drawn = room.boneyard.shift();
    hand.push(drawn);
    const drawAction = { type: 'draw', seat, value: drawn, boneyard_left: room.boneyard.length };
    if (room.log) room.log.push(drawAction);
    actions.push(drawAction);
    if (derivePlacement(room, drawn, null)) value = drawn;
  }
  if (value != null) {
    const placement = derivePlacement(room, value, null);
    const r = applyCanonicalMove(room, seat, value, placement.side, placement.rotation, 'server-auto-' + Date.now());
    if (r.ok) actions.push({ type: 'move', seat, value, side: r.side, rotation: r.rotation });
  } else {
    if (room.log) room.log.push({ type: 'pass', seat });
    actions.push({ type: 'pass', seat });
    room.lastActivityAt = Date.now();
    room.turnSeat = seat === 0 ? 1 : 0;
  }
  for (const sid of (room.players || [])) {
    if (sid) io.to(sid).emit('server_auto_actions', { roundSerial: room.roundSerial, seat, actions, turnSeat: room.turnSeat });
  }
  armRoomTurnTimer(room);
  broadcastState(room, 'auto_turn');
}

function clearRoomTurnTimer(room) {
  if (room && room._turnTimer) { clearTimeout(room._turnTimer); room._turnTimer = null; }
  if (room && room._turnFailTimer) { clearTimeout(room._turnFailTimer); room._turnFailTimer = null; }
}

function armRoomTurnTimer(room) {
  if (!room || room.turnSeat == null) return;
  clearRoomTurnTimer(room);
  const serial = room.roundSerial;
  const expectedSeat = room.turnSeat;
  // کاتی هەر نۆرەیەک زیادکرا بۆ ۲۵ چرکە تاوەکو لە کاتی هێڵی خاودا خۆکارانە یاری دانەنێت
  const TURN_TIMEOUT_MS = 25000;
  room.turnDeadline = Date.now() + TURN_TIMEOUT_MS;
  room._turnTimer = setTimeout(() => {
    if (!room || room.roundSerial !== serial || room.turnSeat !== expectedSeat) return;
    performServerAutoTurn(room, expectedSeat);
  }, TURN_TIMEOUT_MS);
}

function startRound(room) {
  const round = dealRound();

  room.deal = round;
  room.boneyard = round.boneyard.slice();
  room.hands = [round.handA.slice(), round.handB.slice()];
  room.initialHands = [round.handA.slice(), round.handB.slice()];
  room.initialBoneyardCount = round.boneyard.length;
  room.starterSeat = round.starterSeat;
  room.turnSeat = round.starterSeat;
  room.roundSerial = (room.roundSerial || 0) + 1;
  room.roundStartedAt = Date.now();
  room.lastActivityAt = Date.now();
  room.processedMoveNonces = [new Map(), new Map()];
  room.processedDrawNonces = [new Map(), new Map()];
  room.leftEnd = null;
  room.rightEnd = null;
  room.turnDeadline = Date.now() + 25000;
  room.log = [];

  emitWithRetry(
    room.players[0],
    'online_start',
    {
      seat: 0,
      yourHand: round.handA,
      oppHand: round.handB,
      starterSeat: round.starterSeat,
      boneyardCount: room.boneyard.length,
      goal: room.goal,
      match_id: room.matchId || null,
      stake: room.stake,
      prize: room.prize
    }
  );

  emitWithRetry(
    room.players[1],
    'online_start',
    {
      seat: 1,
      yourHand: round.handB,
      oppHand: round.handA,
      starterSeat: round.starterSeat,
      boneyardCount: room.boneyard.length,
      goal: room.goal,
      match_id: room.matchId || null,
      stake: room.stake,
      prize: room.prize
    }
  );

  armRoomTurnTimer(room);
  broadcastState(room, 'round_start');
}

function emitMatchError(socket, error, extra = {}) {
  socket.emit('match_error', { error, ...extra });
}

function emitWithRetry(socketId, event, payload, attempt) {
  attempt = attempt || 1;
  const sock = io.sockets.sockets.get(socketId);
  if (!sock) return;
  let acked = false;
  sock.emit(event, payload, () => { acked = true; });
  setTimeout(() => {
    if (acked) return;
    if (attempt < 5) {
      emitWithRetry(socketId, event, payload, attempt + 1);
    }
  }, 3000);
}

io.on('connection', socket => {
  socket.on('find_match', async (options = {}) => {
    try {
      const goal = [100, 200, 500].includes(Number(options.goal)) ? Number(options.goal) : 100;
      const stake = Number(options.stake || 0);
      const isFree = stake === 0;

      if (!isFree && !(await isPaidEnabled())) {
        return emitMatchError(socket, 'paid_features_disabled');
      }

      if (!isFree && !PAID_TIERS.has(stake)) {
        return emitMatchError(socket, 'invalid_stake');
      }

      let userId = null;
      const payload = verifyMatchToken(options.token);
      if (!payload || !payload.id) {
        return emitMatchError(socket, 'login_required');
      }

      userId = Number(payload.id);
      registerUserSocket(userId, socket.id);

      const banRow = await db.query(`SELECT banned FROM users WHERE id=$1`, [userId]);
      if (banRow.rows.length && banRow.rows[0].banned) {
        return emitMatchError(socket, 'account_banned');
      }

      if (!isFree) {
        const result = await db.query(`SELECT balance FROM users WHERE id=$1`, [userId]);
        if (!result.rows.length) return emitMatchError(socket, 'user_not_found');
        const balance = Number(result.rows[0].balance || 0);
        if (balance < stake) {
          return emitMatchError(socket, 'insufficient_balance', { required: stake, balance });
        }
      }

      const prize = isFree ? 0 : PAID_TIERS.get(stake);
      const rawPhoto = typeof options.photo === 'string' ? options.photo : '';
      const photo_url = /^data:image\/(png|jpeg|jpg|webp);base64,/.test(rawPhoto) && rawPhoto.length <= 400000
        ? rawPhoto : (/^https?:\/\//.test(rawPhoto) && rawPhoto.length <= 2000 ? rawPhoto : '');

      const playerInfo = {
        name: String(options.name || 'Player').slice(0, 24),
        avatar: String(options.avatar || '').slice(0, 8),
        photo_url
      };

      const key = queueKey(stake, goal);
      const waiting = waitingQueues.get(key);

      const WAITING_TTL_MS = 120000;
      const waitingIsStale = !!waiting && (Date.now() - (waiting.enqueuedAt || 0)) > WAITING_TTL_MS;

      if (waitingIsStale) {
        waitingQueues.delete(key);
      }

      const effectiveWaiting = waitingIsStale ? null : waiting;

      if (
        effectiveWaiting &&
        effectiveWaiting.socket &&
        effectiveWaiting.socket.connected &&
        effectiveWaiting.socket.id !== socket.id
      ) {
        // پشکنینی ڕێگری لێکردن بە بەراوردکاری ژمارەیی
        if (Number(effectiveWaiting.userId) === Number(userId)) {
          return emitMatchError(socket, 'same_account_not_allowed');
        }

        waitingQueues.delete(key);

        const player1 = effectiveWaiting.socket;
        const player2 = socket;
        const roomId = 'r' + SERVER_BOOT_ID + '-' + sequence++;
        let paidMatch = null;

        if (!isFree) {
          try {
            paidMatch = await reservePaidEntries(roomId, effectiveWaiting.userId, userId, stake, prize);
          } catch (e) {
            const error = e.message === 'insufficient_balance' ? 'insufficient_balance' : 'match_reservation_failed';
            emitMatchError(player1, error);
            emitMatchError(player2, error);
            return;
          }
        } else {
          try {
            paidMatch = await createFreeMatchRecord(roomId, effectiveWaiting.userId, userId);
          } catch (e) {}
        }

        const room = {
          roomId,
          players: [player1.id, player2.id],
          goal,
          stake,
          prize,
          matchId: paidMatch ? Number(paidMatch.id) : null,
          userIds: [effectiveWaiting.userId, userId],
          moves: 0,
          boneyard: [],
          hands: [[], []],
          log: [],
          lastActivityAt: Date.now()
        };

        rooms.set(roomId, room);
        socketRoom.set(player1.id, roomId);
        socketRoom.set(player2.id, roomId);
        player1.join(roomId);
        player2.join(roomId);

        io.to(player1.id).emit('matched', {
          room: roomId, seat: 0, goal, stake, prize,
          match_id: room.matchId, opp: playerInfo
        });

        io.to(player2.id).emit('matched', {
          room: roomId, seat: 1, goal, stake, prize,
          match_id: room.matchId, opp: effectiveWaiting.info
        });

        startRound(room);
      } else {
        waitingQueues.set(key, {
          socket, goal, stake, prize, info: playerInfo, userId, enqueuedAt: Date.now()
        });
        socket.emit('waiting', { stake, goal });
      }
    } catch (e) {
      console.error('find_match error:', e.message);
      emitMatchError(socket, 'server_error');
    }
  });

  socket.on('draw_tile', (payload) => {
    const roomId = socketRoom.get(socket.id);
    if (!roomId) return;
    const room = rooms.get(roomId);
    if (!room || !room.boneyard || !room.hands) return;

    const seat = room.players[0] === socket.id ? 0 : 1;
    const nonce = payload && payload.nonce;
    if (!room.processedDrawNonces) room.processedDrawNonces = [new Map(), new Map()];
    const drawNonceMap = room.processedDrawNonces[seat] || (room.processedDrawNonces[seat] = new Map());
    if (nonce && drawNonceMap.has(nonce)) {
      socket.emit('draw_tile_result', drawNonceMap.get(nonce));
      return;
    }

    const opponent = otherPlayer(room, socket.id);

    if (room.turnSeat != null && room.turnSeat !== seat) {
      socket.emit('draw_tile_result', { ok: false, error: 'not_your_turn', boneyard_left: room.boneyard.length });
      return;
    }

    // چاکسازی: ڕێگریی hasLegalMove لادرا تا بەهۆی ناڕێکی لە نێوان شاشەکان پەنجەرەی کێشانی بەرد بەستوو نەبێت

    if (room.boneyard.length === 0) {
      const result = { ok: false, empty: true, boneyard_left: 0 };
      if (nonce) {
        drawNonceMap.set(nonce, result);
        while (drawNonceMap.size > 64) drawNonceMap.delete(drawNonceMap.keys().next().value);
      }
      socket.emit('draw_tile_result', result);
      return;
    }

    const value = room.boneyard.shift();
    room.hands[seat].push(value);

    if (room.log) {
      room.log.push({ type: 'draw', seat, value, boneyard_left: room.boneyard.length });
    }
    room.lastActivityAt = Date.now();
    armRoomTurnTimer(room);
    broadcastState(room, 'draw');

    const result = { ok: true, value, boneyard_left: room.boneyard.length };
    if (nonce) {
      drawNonceMap.set(nonce, result);
      while (drawNonceMap.size > 64) drawNonceMap.delete(drawNonceMap.keys().next().value);
    }

    socket.emit('draw_tile_result', result);

    if (opponent) {
      io.to(opponent).emit('opponent_drew', {
        value,
        boneyard_left: room.boneyard.length
      });
    }
  });

  socket.on('chat_message', payload => {
    const roomId = socketRoom.get(socket.id);
    if (!roomId) return;
    const room = rooms.get(roomId);
    if (!room) return;
    const opponent = otherPlayer(room, socket.id);
    if (!opponent) return;

    const rawText = (payload && typeof payload.text === 'string') ? payload.text : '';
    const type = (payload && payload.type === 'emoji') ? 'emoji' : 'text';
    const maxLen = type === 'emoji' ? 16 : 300;
    const text = rawText.slice(0, maxLen).trim();
    if (!text) return;

    io.to(opponent).emit('chat_message', { text, type, ts: Date.now() });
  });

  socket.on('global_chat_message', async payload => {
    try {
      const tokenPayload = verifyMatchToken(payload?.token);
      if (!tokenPayload || !tokenPayload.id) {
        return emitMatchError(socket, 'login_required');
      }

      try {
        const chatCfg = await db.query('SELECT chat_enabled FROM app_config WHERE id=1');
        if (chatCfg.rows.length && chatCfg.rows[0].chat_enabled === false) {
          return emitMatchError(socket, 'chat_closed');
        }
      } catch (e) {}

      const rawText = (payload && typeof payload.text === 'string') ? payload.text : '';
      const text = censorText(rawText.slice(0, 300).trim());
      if (!text) return;

      const result = await db.query(`SELECT username, email FROM users WHERE id=$1`, [tokenPayload.id]);
      if (!result.rows.length) return;

      const name = defaultName(result.rows[0]);
      let newMessageId = null;
      try {
        const inserted = await db.query(
          `INSERT INTO global_chat_messages (user_id, name, text) VALUES ($1, $2, $3) RETURNING id`,
          [tokenPayload.id, name, text]
        );
        newMessageId = inserted.rows[0] && inserted.rows[0].id;
      } catch (e) {}

      io.emit('global_chat_message', {
        id: newMessageId, userId: tokenPayload.id, name, text, ts: Date.now()
      });
    } catch (e) {
      console.error('global_chat_message error:', e.message);
    }
  });

  socket.on('delete_global_chat_message', async payload => {
    try {
      const tokenPayload = verifyMatchToken(payload?.token);
      if (!tokenPayload || !tokenPayload.id) return;
      const messageId = Number(payload?.message_id);
      if (!Number.isInteger(messageId)) return;

      const modCheck = await db.query(
        `SELECT is_chat_moderator FROM users WHERE id=$1`, [tokenPayload.id]
      );
      if (!modCheck.rows.length || !modCheck.rows[0].is_chat_moderator) return;

      await db.query(`UPDATE global_chat_messages SET deleted=true WHERE id=$1`, [messageId]);
      io.emit('global_chat_message_deleted', { id: messageId });
    } catch (e) {}
  });

  socket.on('game_move', (message, ack) => {
    const roomId = socketRoom.get(socket.id);
    if (!roomId) {
      if (typeof ack === 'function') ack({ ok: false, error: 'no_active_room' });
      return;
    }

    const room = rooms.get(roomId);
    if (!room) {
      if (typeof ack === 'function') ack({ ok: false, error: 'room_gone' });
      return;
    }

    const seat = Array.isArray(room.players) ? room.players.indexOf(socket.id) : -1;
    if (seat < 0) {
      if (typeof ack === 'function') ack({ ok: false, error: 'not_in_room' });
      return;
    }
    const type = message && message.type;
    const value = Number(message && message.value);

    const nonce = message && message.nonce;
    if (!room.processedMoveNonces) room.processedMoveNonces = [new Map(), new Map()];
    const moveNonceMap = room.processedMoveNonces[seat] || (room.processedMoveNonces[seat] = new Map());
    if (nonce && moveNonceMap.has(nonce)) {
      if (typeof ack === 'function') ack(moveNonceMap.get(nonce));
      return;
    }

    if (room.turnSeat != null && room.turnSeat !== seat) {
      if (typeof ack === 'function') ack({ ok: false, error: 'not_your_turn' });
      return;
    }
    if (type !== 'move' && type !== 'pass') {
      if (typeof ack === 'function') ack({ ok: false, error: 'bad_move_type' });
      return;
    }

    let acceptedMessage = message;
    if (type === 'move') {
      const result = applyCanonicalMove(room, seat, value, message && message.side, message && message.rotation, nonce);
      if (!result.ok) {
        if (typeof ack === 'function') ack({ ok: false, error: result.error });
        return;
      }
      acceptedMessage = Object.assign({}, message, { side: result.side, rotation: result.rotation });
    } else {
      if ((room.boneyard && room.boneyard.length) || hasLegalMove(room, seat)) {
        if (typeof ack === 'function') ack({ ok: false, error: 'illegal_pass' });
        return;
      }
      room.moves = (room.moves || 0) + 1;
      if (room.log) room.log.push({ type: 'pass', seat, nonce });
      room.lastActivityAt = Date.now();
      room.turnSeat = seat === 0 ? 1 : 0;
    }

    if (nonce) {
      moveNonceMap.set(nonce, { ok: true });
      while (moveNonceMap.size > 64) moveNonceMap.delete(moveNonceMap.keys().next().value);
    }
    armRoomTurnTimer(room);
    broadcastState(room, 'move');

    const opponent = otherPlayer(room, socket.id);
    if (!opponent) {
      if (typeof ack === 'function') ack({ ok: true });
      return;
    }

    function deliverToOpponent(deliveryAttempt) {
      const opponentSocket = io.sockets.sockets.get(opponent);
      if (!opponentSocket) return;
      let delivered = false;
      opponentSocket.emit('game_move', acceptedMessage, () => { delivered = true; });
      setTimeout(() => {
        if (delivered) return;
        if (deliveryAttempt < 4) {
          deliverToOpponent(deliveryAttempt + 1);
        }
      }, 4000);
    }
    deliverToOpponent(1);

    if (typeof ack === 'function') ack({ ok: true });
  });

  socket.on('report_result', async payload => {
    try {
      const roomId = socketRoom.get(socket.id);
      if (!roomId) return;
      const room = rooms.get(roomId);
      if (!room) return;

      const seat0 = room.players[0] === socket.id ? 0 : 1;
      const userId0 = room.userIds[seat0];

      if (!room.matchId) {
        if (!userId0 || room._freeReported === socket.id) return;
        room._freeReported = socket.id;
        const didWin = !!(payload && payload.didWin);
        await db.query(
          `UPDATE users SET wins = wins + $1, losses = losses + $2 WHERE id=$3`,
          [didWin ? 1 : 0, didWin ? 0 : 1, userId0]
        );
        return;
      }

      const seat = room.players[0] === socket.id ? 0 : 1;
      const userId = room.userIds[seat];
      const token = verifyMatchToken(payload?.token);

      if (!token || Number(token.id) !== Number(userId)) {
        return emitMatchError(socket, 'bad_match_token');
      }

      const report = payload?.didWin === true ? 'win' : 'loss';
      const client = await db.pool.connect();
      try {
        await client.query('BEGIN');
        const match = await client.query(
          `SELECT * FROM paid_matches WHERE id=$1 FOR UPDATE`, [room.matchId]
        );

        if (!match.rows.length) {
          await client.query('ROLLBACK');
          return;
        }

        if (!['active', 'disputed'].includes(match.rows[0].status)) {
          await client.query('ROLLBACK');
          return;
        }

        const column = seat === 0 ? 'p1_report' : 'p2_report';
        await client.query(
          `UPDATE paid_matches SET ${column}=$1, updated_at=NOW() WHERE id=$2`,
          [report, room.matchId]
        );
        await client.query('COMMIT');
      } catch (e) {
        try { await client.query('ROLLBACK'); } catch {}
        throw e;
      } finally {
        client.release();
      }

      const result = await settlePaidMatchIfAgreed(room.matchId);

      if (result.status === 'settled') {
        for (let i = 0; i < 2; i++) {
          emitWithRetry(room.players[i], 'match_settled', {
            match_id: room.matchId,
            won: Number(room.userIds[i]) === Number(result.winnerUserId),
            prize: result.prize,
            stake: result.stake
          });
        }
      } else if (result.status === 'disputed') {
        try {
          await refundPaidMatch(room.matchId);
        } catch (e) {}

        io.to(roomId).emit('match_disputed', { match_id: room.matchId, auto_refunded: true });
      }
    } catch (e) {
      console.error('report_result error:', e.message);
      emitMatchError(socket, 'result_report_failed');
    }
  });

  socket.on('next_round', () => {
    const roomId = socketRoom.get(socket.id);
    if (!roomId) return;
    const room = rooms.get(roomId);
    if (!room) return;

    if (room._nextRoundLockUntil && Date.now() < room._nextRoundLockUntil) return;
    room._nextRoundLockUntil = Date.now() + 5000;
    startRound(room);
  });

  socket.on('cancel_find', () => {
    for (const [key, waiting] of waitingQueues.entries()) {
      if (waiting.socket.id === socket.id) {
        waitingQueues.delete(key);
      }
    }
  });

  socket.on('disconnect', async () => {
    for (const [key, waiting] of waitingQueues.entries()) {
      if (waiting.socket.id === socket.id) {
        waitingQueues.delete(key);
      }
    }
    await handlePlayerLeftRoom(socket.id);
    unregisterSocketEverywhere(socket.id);
  });

  socket.on('leave_match', async payload => {
    const roomId = socketRoom.get(socket.id);
    const room = roomId ? rooms.get(roomId) : null;
    const confirmed = !!(payload && payload.confirmed === true);
    if (room && Number(room.stake || 0) > 0 && !confirmed) {
      return;
    }
    await handlePlayerLeftRoom(socket.id, { immediate: confirmed });
  });

  socket.on('request_board_sync', (payload) => {
    try {
      const roomId = socketRoom.get(socket.id);
      if (!roomId) { socket.emit('board_sync_result', { ok: false }); return; }
      const room = rooms.get(roomId);
      if (!room) { socket.emit('board_sync_result', { ok: false }); return; }
      const seat = Array.isArray(room.players) ? room.players.indexOf(socket.id) : -1;
      if (seat < 0) { socket.emit('board_sync_result', { ok: false }); return; }

      socket.emit('board_sync_result', {
        ok: true,
        seat,
        yourHand: room.hands[seat],
        initialYourHand: room.initialHands ? room.initialHands[seat] : room.hands[seat],
        initialOppHand: room.initialHands ? room.initialHands[seat === 0 ? 1 : 0] : [],
        boneyardCount: room.boneyard.length,
        initialBoneyardCount: room.initialBoneyardCount != null ? room.initialBoneyardCount : 14,
        totalBoardMoves: (room.log || []).filter(e => e && e.type === 'move').length,
        starterSeat: room.starterSeat,
        turnSeat: room.turnSeat,
        roundSerial: room.roundSerial,
        leftEnd: room.leftEnd,
        rightEnd: room.rightEnd,
        turnDeadline: room.turnDeadline,
        log: room.log || []
      });
    } catch (e) {
      console.error('request_board_sync error:', e.message);
      socket.emit('board_sync_result', { ok: false });
    }
  });

  socket.on('resume_match', async (payload) => {
    try {
      const tokenPayload = verifyMatchToken(payload && payload.token);
      if (!tokenPayload || !tokenPayload.id) {
        socket.emit('resume_result', { ok: false, error: 'login_required' });
        return;
      }

      const userId = tokenPayload.id;
      registerUserSocket(userId, socket.id);

      const banRow = await db.query(`SELECT banned FROM users WHERE id=$1`, [userId]);
      if (banRow.rows.length && banRow.rows[0].banned) {
        socket.emit('resume_result', { ok: false, error: 'account_banned' });
        return;
      }

      let found = null;
      for (const [key, pending] of pendingReconnects.entries()) {
        if (Number(pending.userId) === Number(userId)) { found = { key, pending }; break; }
      }

      if (!found) {
        for (const [rid, activeRoom] of rooms.entries()) {
          if (!activeRoom || !Array.isArray(activeRoom.userIds)) continue;
          const seatIdx = activeRoom.userIds.findIndex(id => Number(id) === Number(userId));
          if (seatIdx >= 0) {
            found = {
              key: null,
              pending: {
                roomId: rid, seatIdx, userId, timer: null, logMark: 0, proactive: true
              }
            };
            break;
          }
        }
      }

      if (!found) {
        const ownRoomId = socketRoom.get(socket.id);
        const ownRoom = ownRoomId ? rooms.get(ownRoomId) : null;
        if (ownRoom && Array.isArray(ownRoom.players)) {
          const seatIdx = ownRoom.players.indexOf(socket.id);
          if (seatIdx >= 0) {
            found = {
              key: null,
              pending: {
                roomId: ownRoomId, seatIdx, userId, timer: null, logMark: 0, proactive: true
              }
            };
          }
        }
      }

      if (!found) {
        socket.emit('resume_result', { ok: false, error: 'no_match_to_resume' });
        return;
      }

      const key = found.key;
      const pending = found.pending;
      const room = rooms.get(pending.roomId);

      if (!room) {
        clearTimeout(pending.timer);
        pendingReconnects.delete(key);
        socket.emit('resume_result', { ok: false, error: 'match_gone' });
        return;
      }

      if (pending.timer) clearTimeout(pending.timer);
      if (key != null) pendingReconnects.delete(key);

      const oldSocketId = room.players[pending.seatIdx];
      if (oldSocketId && oldSocketId !== socket.id) {
        socketRoom.delete(oldSocketId);
        const oldSock = io.sockets.sockets.get(oldSocketId);
        if (oldSock) {
          try { oldSock.disconnect(true); } catch (e) {}
        }
      }
      room.players[pending.seatIdx] = socket.id;
      socketRoom.set(socket.id, pending.roomId);

      const opponent = otherPlayer(room, socket.id);
      if (opponent) {
        io.to(opponent).emit('opponent_resumed', { match_id: room.matchId });
      }

      const missed = room.log ? room.log.slice(pending.logMark || 0) : [];
      const needsFullRebuild = true;
      const opponentSeatIdx = pending.seatIdx === 0 ? 1 : 0;
      const opponentUserId = room.userIds ? room.userIds[opponentSeatIdx] : null;
      let opponentInfo = null;

      if (needsFullRebuild && opponentUserId) {
        try {
          const oppRow = await db.query(
            `SELECT username, avatar, photo_url FROM users WHERE id=$1`, [opponentUserId]
          );
          if (oppRow.rows.length) {
            opponentInfo = {
              name: oppRow.rows[0].username,
              avatar: oppRow.rows[0].avatar,
              photo_url: oppRow.rows[0].photo_url
            };
          }
        } catch (e) {}
      }

      socket.emit('resume_result', {
        ok: true,
        match_id: room.matchId,
        room_id: pending.roomId,
        seat: pending.seatIdx,
        needsFullRebuild,
        goal: room.goal,
        stake: room.stake,
        prize: room.prize,
        opponent: opponentInfo,
        resync: {
          yourHand: room.hands[pending.seatIdx].slice(),
          initialYourHand: room.initialHands ? room.initialHands[pending.seatIdx] : room.hands[pending.seatIdx],
          initialOppHand: room.initialHands ? room.initialHands[opponentSeatIdx] : [],
          boneyardCount: room.boneyard.length,
          initialBoneyardCount: room.initialBoneyardCount != null ? room.initialBoneyardCount : 14,
          starterSeat: room.starterSeat,
          turnSeat: room.turnSeat,
          roundSerial: room.roundSerial,
          leftEnd: room.leftEnd,
          rightEnd: room.rightEnd,
          turnDeadline: room.turnDeadline,
          totalBoardMoves: (room.log || []).filter(e => e && e.type === 'move').length,
          actions: (room.log || []).map(a => Object.assign({}, a)),
          missed: needsFullRebuild ? [] : missed
        }
      });

      broadcastState(room, 'resume');
    } catch (e) {
      console.error('resume_match error:', e.message);
      socket.emit('resume_result', { ok: false, error: 'server_error' });
    }
  });
});

const PORT = process.env.PORT || 3000;

setInterval(() => {
  db.query(`DELETE FROM global_chat_messages WHERE created_at < NOW() - INTERVAL '1 day'`)
    .catch(e => console.error('global_chat_messages cleanup error:', e.message));
}, 60 * 60 * 1000);

async function startServer() {
  try {
    await db.init();
    await initWalletTables();
    await initPaidMatchTables();
    await initAdminUserTools();
    await initAdminMessagesTable();
    await initTournamentTables();
    await initFakeLeaderboard();
    await initClientErrorsTable();

    setInterval(tickFakeLeaderboard, 60 * 1000);
    setInterval(autoRefundOrphanedPaidMatches, 5 * 60 * 1000);
    setInterval(checkStalledPaidMatches, 60 * 1000);

    await db.query(`UPDATE tournament_config SET fake_reset_period=NULL WHERE id=1`);
    await initVisitTables();
    await initGlobalChatTable();
    await initTelegramJoinTable();
    await initAppConfig();

    server.listen(PORT, () => {
      console.log('Domino server running on port ' + PORT);
      console.log('MIN_DEPOSIT effective value: ' + MIN_DEPOSIT);
    });
  } catch (error) {
    console.error('DB/server startup failed:', error);
    process.exit(1);
  }
}

startServer();
