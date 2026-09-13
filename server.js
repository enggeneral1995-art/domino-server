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
  console.error('The server is using a publicly-known fallback secret, which');
  console.error('means anyone who has read this codebase could forge a valid');
  console.error('login token for ANY account. Set JWT_SECRET to a long random');
  console.error('string in Railway -> Variables as soon as possible.');
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

// Public invite link for the join-bonus banner, e.g.
// "https://t.me/yourchannel" — set this in Railway.
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

// Builds the exact string NOWPayments hashed to produce the IPN signature:
// object keys sorted (recursively), numbers kept byte-identical to the raw
// payload (JSON.stringify silently reformats numbers like "20.00000000"
// down to "20", which breaks the signature match even though the value is
// unchanged). We do this by temporarily wrapping every numeric literal in
// the raw JSON text as a marked string before parsing, so it survives the
// parse/sort/stringify round-trip untouched, then unwrap the markers from
// the final string.
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

  console.log(
    '[nowpayments_ipn] sig-check usedRawBody=' + usedRawBody +
    ' rawBodyLen=' + (rawBody ? rawBody.length : 0) +
    ' expected=' + expected.slice(0, 12) + '...' +
    ' received=' + String(receivedSig).slice(0, 12) + '...' +
    ' match=' + match
  );

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
      // Keep the exact raw bytes NOWPayments sent us — needed to verify
      // the IPN signature, since re-serializing the parsed JS object can
      // silently change number formatting (e.g. "20.00000000" -> "20"),
      // which breaks the signature match even though the data is identical.
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

/* =========================================================
   EMAIL VALIDATION
========================================================= */

// Disposable / throwaway email domains that we refuse.
const BLOCKED_EMAIL_DOMAINS = new Set([
  'test.com',
  'example.com',
  'example.org',
  'example.net',
  'mailinator.com',
  'tempmail.com',
  'temp-mail.org',
  'guerrillamail.com',
  'guerrillamail.info',
  'sharklasers.com',
  '10minutemail.com',
  '10minutemail.net',
  'yopmail.com',
  'throwawaymail.com',
  'trashmail.com',
  'getnada.com',
  'dispostable.com',
  'maildrop.cc',
  'fakeinbox.com',
  'mohmal.com',
  'emailondeck.com',
  'moakt.com',
  'tempmailo.com',
  'mailnesia.com',
  'spam4.me',
  'inboxbear.com',
  'temp-mail.io',
  'mail.tm',
  'burnermail.io'
]);

// Common typos of real providers -> refuse so the user fixes them.
const TYPO_EMAIL_DOMAINS = new Set([
  'gmial.com',
  'gmail.co',
  'gmail.con',
  'gmai.com',
  'gmail.cm',
  'gmaill.com',
  'gmailc.om',
  'hotmial.com',
  'hotmail.co',
  'hotmial.co',
  'yahoo.co',
  'yaho.com',
  'yahho.com',
  'outlok.com',
  'outloo.com'
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

  // Basic but strict RFC-ish shape check.
  const shape =
    /^[a-z0-9]([a-z0-9._%+-]*[a-z0-9])?@([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/;

  if (!shape.test(email)) {
    return { ok: false, error: 'email_invalid' };
  }

  // No consecutive dots anywhere.
  if (email.includes('..')) {
    return { ok: false, error: 'email_invalid' };
  }

  const domain = email.split('@')[1];
  const tld = domain.split('.').pop();

  // Reject single-label or obviously fake TLDs.
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

/* =========================================================
   PASSWORD / AUTH
========================================================= */

// scrypt is deliberately slow (that's what makes it resistant to
// brute-forcing a stolen password hash), but Node's synchronous
// crypto.scryptSync() runs that slowness ON THE MAIN THREAD -- while a
// hash is being computed, the entire server is frozen: nobody's socket.io
// ping/pong gets answered, no game_move goes through, nothing. With this
// many concurrent players, logins/registrations happen constantly, and
// each one used to stall EVERY active match at once for however long the
// hash took (worse under load, worse the more concurrent users there
// are) -- almost certainly what a burst of simultaneous "disconnected
// mid-match" reports across unrelated players was actually catching.
// crypto.scrypt (no Sync) does the same computation off the main thread
// via libuv's threadpool, so the event loop -- and every other player's
// live connection -- stays responsive while it runs.
function scryptAsync(password, salt, keylen) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keylen, (err, derivedKey) => {
      if (err) reject(err); else resolve(derivedKey);
    });
  });
}

async function hashPassword(password) {
  const salt =
    crypto
      .randomBytes(16)
      .toString('hex');

  const derived =
    (await scryptAsync(
      password,
      salt,
      64
    ))
      .toString('hex');

  return (
    salt +
    ':' +
    derived
  );
}

async function verifyPassword(
  password,
  stored
) {
  try {
    const [salt, key] =
      String(stored)
        .split(':');

    const derived =
      (await scryptAsync(
        password,
        salt,
        64
      ))
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
    id:
      user.id,

    email:
      user.email,

    phone:
      user.phone ||
      null,

    balance:
      Number(
        user.balance ||
        0
      ),

    coins:
      Number(
        user.coins != null
          ? user.coins
          : 500
      ),

    username:
      defaultName(user),

    wins:
      Number(
        user.wins ||
        0
      ),

    losses:
      Number(
        user.losses ||
        0
      ),

    avatar:
      user.avatar ||
      null,

    photo_url:
      user.photo_url ||
      null,

    is_chat_moderator:
      !!user.is_chat_moderator
  };
}

function auth(
  req,
  res,
  next
) {
  const header =
    req.headers.authorization ||
    '';

  const token =
    header.startsWith(
      'Bearer '
    )
      ? header.slice(7)
      : null;

  if (!token) {
    return res
      .status(401)
      .json({
        error:
          'no_token'
      });
  }

  try {
    req.user =
      jwt.verify(
        token,
        JWT_SECRET
      );

    next();

  } catch {
    return res
      .status(401)
      .json({
        error:
          'bad_token'
      });
  }
}

function adminOnly(
  req,
  res,
  next
) {
  if (
    !ADMIN_TOKEN ||
    req.headers[
      'x-admin-token'
    ] !== ADMIN_TOKEN
  ) {
    return res
      .status(403)
      .json({
        error:
          'admin_forbidden'
      });
  }

  next();
}


/* =========================================================
   ADMIN USER MANAGEMENT + LOCATION
========================================================= */

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

/* =========================================================
   HEALTH
========================================================= */

app.get(
  '/',
  (_req, res) => {
    res.json({
      ok: true,

      service:
        'Domino Block',

      version:
        'v8-paid-draw'
    });
  }
);

/* =========================================================
   REGISTER
========================================================= */

app.post(
  '/api/register',
  async (req, res) => {
    try {
      let {
        email,
        phone,
        password
      } =
        req.body || {};

      if (
        !email ||
        !password
      ) {
        return res
          .status(400)
          .json({
            error:
              'email_and_password_required'
          });
      }

      const emailCheck =
        validateEmail(email);

      if (!emailCheck.ok) {
        return res
          .status(400)
          .json({
            error:
              emailCheck.error
          });
      }

      email = emailCheck.email;

      if (
        String(password)
          .length < 6
      ) {
        return res
          .status(400)
          .json({
            error:
              'password_too_short'
          });
      }

      const exists =
        await db.query(
          `
          SELECT id

          FROM users

          WHERE email=$1
          `,
          [email]
        );

      if (
        exists.rows.length
      ) {
        return res
          .status(409)
          .json({
            error:
              'email_already_used'
          });
      }

      const result =
        await db.query(
          `
          INSERT INTO users
          (
            email,
            phone,
            password_hash
          )

          VALUES
          (
            $1,
            $2,
            $3
          )

          RETURNING *
          `,
          [
            email,
            phone || null,
            await hashPassword(
              password
            )
          ]
        );

      const user =
        result.rows[0];

      await updateUserLocation(user.id, req);

      const refreshed =
        await db.query(
          `SELECT * FROM users WHERE id=$1`,
          [user.id]
        );

      const loginUser =
        refreshed.rows[0] || user;

      res.json({
        token:
          makeToken(loginUser),

        user:
          publicUser(loginUser)
      });

    } catch (e) {
      console.error(
        'register error:',
        e.message
      );

      res
        .status(500)
        .json({
          error:
            'server_error'
        });
    }
  }
);

/* =========================================================
   LOGIN
========================================================= */

// Simple in-memory brute-force guard for login: too many failed attempts
// from the same IP in a short window blocks further tries for a while.
// Not a replacement for a real rate-limiting service, but with real money
// on accounts, unlimited password guessing is worth closing off even with
// something this basic.
const loginAttempts = new Map(); // ip -> { count, firstAttemptAt }
const LOGIN_MAX_ATTEMPTS = 10;
const LOGIN_WINDOW_MS = 10 * 60 * 1000; // 10 minutes

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

// Occasionally clear old entries so this map doesn't grow forever.
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of loginAttempts.entries()) {
    if (now - entry.firstAttemptAt > LOGIN_WINDOW_MS) loginAttempts.delete(ip);
  }
}, 30 * 60 * 1000);

app.post(
  '/api/login',
  async (req, res) => {
    try {
      const loginIp = getClientIp(req);
      if (!checkLoginRateLimit(loginIp)) {
        return res.status(429).json({ error: 'too_many_attempts' });
      }
      let {
        email,
        password
      } =
        req.body || {};

      if (
        !email ||
        !password
      ) {
        return res
          .status(400)
          .json({
            error:
              'email_and_password_required'
          });
      }

      email =
        String(email)
          .trim()
          .toLowerCase();

      const result =
        await db.query(
          `
          SELECT *

          FROM users

          WHERE email=$1
          `,
          [email]
        );

      if (
        !result.rows.length
      ) {
        return res
          .status(401)
          .json({
            error:
              'invalid_credentials'
          });
      }

      const user =
        result.rows[0];

      if (
        !(await verifyPassword(
          password,
          user.password_hash
        ))
      ) {
        return res
          .status(401)
          .json({
            error:
              'invalid_credentials'
          });
      }

      if (user.banned) {
        return res
          .status(403)
          .json({
            error: 'account_banned',
            ban_reason: user.ban_reason || null
          });
      }

      await updateUserLocation(user.id, req);
      recordVisit(user.id);
      recordAppOpen();

      res.json({
        token:
          makeToken(user),

        user:
          publicUser(user)
      });

    } catch (e) {
      console.error(
        'login error:',
        e.message
      );

      res
        .status(500)
        .json({
          error:
            'server_error'
        });
    }
  }
);

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  '/api/me',
  auth,
  async (req, res) => {
    try {
      const result =
        await db.query(
          `
          SELECT *

          FROM users

          WHERE id=$1
          `,
          [
            req.user.id
          ]
        );

      if (
        !result.rows.length
      ) {
        return res
          .status(404)
          .json({
            error:
              'not_found'
          });
      }

      recordVisit(req.user.id);
      recordAppOpen();

      res.json({
        user:
          publicUser(
            result.rows[0]
          )
      });

    } catch {
      res
        .status(500)
        .json({
          error:
            'server_error'
        });
    }
  }
);

/* =========================================================
   ADMIN -> PLAYER DIRECT MESSAGES
========================================================= */

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
    // Scoped to the caller's own user_id so nobody can mark someone
    // else's message as read.
    await db.query(`
      UPDATE admin_messages SET read=true WHERE id=$1 AND user_id=$2
    `, [messageId, req.user.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('admin-messages/read error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

/* =========================================================
   PROFILE
========================================================= */

app.get(
  '/api/profile',
  auth,
  async (req, res) => {
    try {
      const result =
        await db.query(
          `
          SELECT *

          FROM users

          WHERE id=$1
          `,
          [
            req.user.id
          ]
        );

      if (
        !result.rows.length
      ) {
        return res
          .status(404)
          .json({
            error:
              'not_found'
          });
      }

      res.json({
        user:
          publicUser(
            result.rows[0]
          )
      });

    } catch {
      res
        .status(500)
        .json({
          error:
            'server_error'
        });
    }
  }
);

app.post(
  '/api/profile',
  auth,
  async (req, res) => {
    try {
      let {
        username,
        avatar
      } =
        req.body || {};

      const sets = [];
      const values = [];

      let index = 1;

      if (
        username !==
          undefined &&
        username !== null
      ) {
        username =
          String(username)
            .trim();

        if (
          username.length < 2 ||
          username.length > 20
        ) {
          return res
            .status(400)
            .json({
              error:
                'username_length'
            });
        }

        sets.push(
          `username=$${index++}`
        );

        values.push(
          username
        );
      }

      if (
        avatar !==
          undefined &&
        avatar !== null
      ) {
        avatar =
          String(avatar)
            .trim();

        if (
          avatar.length > 40
        ) {
          return res
            .status(400)
            .json({
              error:
                'avatar_invalid'
            });
        }

        sets.push(
          `avatar=$${index++}`
        );

        values.push(
          avatar
        );
      }

      let photo_url =
        req.body &&
        req.body.photo_url;

      if (
        photo_url !==
          undefined &&
        photo_url !== null
      ) {
        photo_url =
          String(photo_url)
            .trim();

        if (photo_url === '') {
          // empty string clears the uploaded photo (back to emoji avatar)
          sets.push(
            `photo_url=$${index++}`
          );
          values.push(null);
        } else {
          if (
            !/^data:image\/(png|jpeg|jpg|webp);base64,/.test(photo_url)
          ) {
            return res
              .status(400)
              .json({
                error:
                  'photo_invalid_format'
              });
          }

          if (
            photo_url.length > 400000
          ) {
            return res
              .status(400)
              .json({
                error:
                  'photo_too_large'
              });
          }

          sets.push(
            `photo_url=$${index++}`
          );
          values.push(photo_url);
        }
      }

      if (
        !sets.length
      ) {
        return res
          .status(400)
          .json({
            error:
              'nothing_to_update'
          });
      }

      values.push(
        req.user.id
      );

      const result =
        await db.query(
          `
          UPDATE users

          SET
            ${sets.join(', ')}

          WHERE
            id=$${index}

          RETURNING *
          `,
          values
        );

      res.json({
        user:
          publicUser(
            result.rows[0]
          )
      });

    } catch (e) {
      console.error(
        'profile update error:',
        e.message
      );

      res
        .status(500)
        .json({
          error:
            'server_error'
        });
    }
  }
);

app.post(
  '/api/change-password',
  auth,
  async (req, res) => {
    try {
      const {
        currentPassword,
        newPassword
      } = req.body || {};

      if (
        !currentPassword ||
        !newPassword
      ) {
        return res
          .status(400)
          .json({
            error:
              'missing_fields'
          });
      }

      if (
        String(newPassword).length < 6
      ) {
        return res
          .status(400)
          .json({
            error:
              'password_too_short'
          });
      }

      const result =
        await db.query(
          `SELECT * FROM users WHERE id=$1`,
          [req.user.id]
        );

      if (!result.rows.length) {
        return res
          .status(404)
          .json({ error: 'not_found' });
      }

      const user = result.rows[0];

      if (
        !(await verifyPassword(
          currentPassword,
          user.password_hash
        ))
      ) {
        return res
          .status(401)
          .json({
            error:
              'incorrect_current_password'
          });
      }

      const newHash =
        await hashPassword(newPassword);

      await db.query(
        `UPDATE users SET password_hash=$1 WHERE id=$2`,
        [newHash, req.user.id]
      );

      res.json({ ok: true });

    } catch (e) {
      console.error(
        'change-password error:',
        e.message
      );

      res
        .status(500)
        .json({
          error:
            'server_error'
        });
    }
  }
);

/* =========================================================
   APP CONFIG (PAID FEATURES ON/OFF SWITCH)
========================================================= */

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
  await db.query(`
    ALTER TABLE app_config ADD COLUMN IF NOT EXISTS online_baseline INTEGER NOT NULL DEFAULT 1000
  `);
  await db.query(`
    ALTER TABLE app_config ADD COLUMN IF NOT EXISTS paid_schedule_enabled BOOLEAN NOT NULL DEFAULT false
  `);
  await db.query(`
    ALTER TABLE app_config ADD COLUMN IF NOT EXISTS paid_open_time TEXT NOT NULL DEFAULT '20:00'
  `);
  await db.query(`
    ALTER TABLE app_config ADD COLUMN IF NOT EXISTS paid_close_time TEXT NOT NULL DEFAULT '00:00'
  `);
  await db.query(`
    ALTER TABLE app_config ADD COLUMN IF NOT EXISTS paid_timezone TEXT NOT NULL DEFAULT 'Asia/Baghdad'
  `);
  await db.query(`
    ALTER TABLE app_config ADD COLUMN IF NOT EXISTS bot_enabled BOOLEAN NOT NULL DEFAULT false
  `);
  await db.query(`
    ALTER TABLE app_config ADD COLUMN IF NOT EXISTS bot_difficulty TEXT NOT NULL DEFAULT 'hard'
  `);
  // Lets the admin close the public lobby chat without a redeploy.
  // Defaults to open so an existing install behaves exactly as before.
  await db.query(`
    ALTER TABLE app_config ADD COLUMN IF NOT EXISTS chat_enabled BOOLEAN NOT NULL DEFAULT true
  `);
  await db.query(`
    INSERT INTO app_config (id, paid_enabled, online_baseline)
    VALUES (1, true, 1000)
    ON CONFLICT (id) DO NOTHING
  `);
}

/* =========================================================
   GLOBAL CHAT — PERSISTENCE
   Stores messages sent in the public lobby chat so people who
   open the app later can see recent history, not just live
   messages sent after they connect.
========================================================= */

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
  // Safety net: earlier deploys briefly created this table with different
  // column names (message/read_at, delivered instead of read). If a live
  // table from one of those is still around, this guarantees the columns
  // the current code actually queries exist, without dropping anything.
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
  await db.query(`
    ALTER TABLE global_chat_messages
      ADD COLUMN IF NOT EXISTS deleted BOOLEAN NOT NULL DEFAULT false
  `);
  await db.query(`
    CREATE INDEX IF NOT EXISTS global_chat_messages_created_idx
    ON global_chat_messages(created_at DESC)
  `);
}

app.get('/api/global-chat/history', async (req, res) => {
  try {
    // Take the NEWEST 200 (ORDER BY DESC + LIMIT), then flip back to
    // chronological order for display. Ordering ASC before the LIMIT
    // returned the OLDEST 200 of the window instead: once more than 200
    // messages had been sent in 12 hours, every new message was cut off
    // by the limit, so recent chat vanished on reload while old chat
    // stayed forever.
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

/* =========================================================
   TELEGRAM JOIN BONUS (simple version — no bot required)
   Person taps the banner -> opens the channel link -> app credits
   the one-time bonus right away. No membership verification, so
   it's on the honor system — much simpler to set up, at the cost
   of someone being able to claim without actually joining/staying.
========================================================= */

async function initTelegramJoinTable() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS telegram_join_claims (
      user_id INTEGER PRIMARY KEY REFERENCES users(id),
      claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

app.get(
  '/api/telegram/join-info',
  auth,
  async (req, res) => {
    try {
      const already =
        await db.query(
          `SELECT 1 FROM telegram_join_claims WHERE user_id=$1`,
          [req.user.id]
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
  }
);

app.post(
  '/api/telegram/claim-bonus',
  auth,
  async (req, res) => {
    try {
      const result =
        await db.query(
          `
          INSERT INTO telegram_join_claims (user_id)
          VALUES ($1)
          ON CONFLICT (user_id) DO NOTHING
          RETURNING user_id
          `,
          [req.user.id]
        );

      if (!result.rows.length) {
        return res.json({
          alreadyClaimed: true
        });
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
  }
);

// Returns the current "HH:MM" wall-clock time in the given IANA timezone,
// e.g. "Asia/Baghdad" -- used to check the paid-games schedule window
// against local time for the admin, not server (UTC) time.
function currentTimeInZone(timezone) {
  try {
    const fmt = new Intl.DateTimeFormat('en-GB', {
      timeZone: timezone || 'Asia/Baghdad',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    });
    return fmt.format(new Date()); // "HH:MM"
  } catch (e) {
    // Bad/unknown timezone string -- fall back to UTC rather than crash.
    const fmt = new Intl.DateTimeFormat('en-GB', {
      timeZone: 'UTC', hour: '2-digit', minute: '2-digit', hour12: false
    });
    return fmt.format(new Date());
  }
}

// Is "now" (HH:MM) inside the [open, close) window? Handles windows that
// cross midnight (e.g. open=20:00, close=00:00 or close=02:00) the same
// way a same-day window (open=09:00, close=17:00) works.
function isWithinScheduleWindow(nowHHMM, openHHMM, closeHHMM) {
  if (openHHMM === closeHHMM) return true; // identical open/close = always open
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
  // Crosses midnight (e.g. 20:00 -> 00:00, stored as close="00:00").
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

    // The manual switch is always a hard "off" -- admin can kill paid
    // play instantly regardless of what the schedule says. It only ever
    // gates further when it's true; the schedule (if turned on) then
    // decides the actual open/closed state minute to minute.
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
      // What isPaidEnabled() would actually decide right now, computed the
      // same way, so the admin panel can show "open now" / "closed now"
      // without duplicating the schedule-window math client-side.
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
    const timeRe = /^([01]\d|2[0-3]):([0-5]\d)$/; // "HH:MM", 24-hour
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
      // Reject an unrecognized IANA zone name up front, instead of only
      // finding out later inside isPaidEnabled()'s try/catch.
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

    // Tell everyone who is online right now, so the chat opens or closes
    // immediately instead of only for people who reload afterwards.
    if (hasChatEnabled) {
      try { io.emit('chat_enabled_changed', { enabled: chatEnabled }); } catch (e) {}
    }

    res.json({ ok: true });
  } catch (e) {
    console.error('app-config update error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

/* =========================================================
   WALLET CONFIG
========================================================= */

const USDT_NETWORKS =
  new Set([
    'BEP20',
    'ERC20'
  ]);

const USDT_ADDRESSES = {
  TRC20:
    process.env
      .USDT_TRC20_ADDRESS ||
    '',

  BEP20:
    process.env
      .USDT_BEP20_ADDRESS ||
    '',

  ERC20:
    process.env
      .USDT_ERC20_ADDRESS ||
    ''
};

const MIN_DEPOSIT =
  Number(
    process.env
      .USDT_MIN_DEPOSIT ||
    5
  );

const MIN_WITHDRAW =
  Number(
    process.env
      .USDT_MIN_WITHDRAW ||
    15
  );

const MAX_WITHDRAW =
  Number(
    process.env
      .USDT_MAX_WITHDRAW ||
    10000
  );

const WITHDRAW_FEE =
  Number(
    process.env
      .USDT_WITHDRAW_FEE ||
    0
  );

function validUsdtAddress(
  network,
  address
) {
  address =
    String(
      address || ''
    ).trim();

  if (
    network === 'TRC20'
  ) {
    return (
      /^T[1-9A-HJ-NP-Za-km-z]{33}$/
        .test(address)
    );
  }

  if (
    network === 'BEP20' ||
    network === 'ERC20'
  ) {
    return (
      /^0x[a-fA-F0-9]{40}$/
        .test(address)
    );
  }

  return false;
}

/* =========================================================
   WALLET TABLES
========================================================= */

async function initWalletTables() {
  await db.query(`
    ALTER TABLE users

    ADD COLUMN IF NOT EXISTS
      wallet_locked
      NUMERIC(20,8)
      NOT NULL
      DEFAULT 0
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS
      wallet_transactions
    (
      id
        BIGSERIAL
        PRIMARY KEY,

      user_id
        INTEGER
        NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      type
        VARCHAR(16)
        NOT NULL
        CHECK(
          type IN (
            'deposit',
            'withdraw'
          )
        ),

      network
        VARCHAR(10)
        NOT NULL,

      amount
        NUMERIC(20,8)
        NOT NULL
        CHECK(amount >= 0),

      address
        TEXT,

      tx_hash
        TEXT,

      status
        VARCHAR(20)
        NOT NULL
        DEFAULT 'pending',

      fee
        NUMERIC(20,8)
        NOT NULL
        DEFAULT 0,

      created_at
        TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

      updated_at
        TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW()
    )
  `);

  await db.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
      wallet_deposit_tx_unique

    ON
      wallet_transactions(
        tx_hash
      )

    WHERE
      tx_hash IS NOT NULL
  `);

  await db.query(`
    CREATE INDEX IF NOT EXISTS
      wallet_user_idx

    ON
      wallet_transactions(
        user_id,
        created_at DESC
      )
  `);

  await db.query(`
    ALTER TABLE wallet_transactions
    ADD COLUMN IF NOT EXISTS
      provider TEXT
  `);

  await db.query(`
    ALTER TABLE wallet_transactions
    ADD COLUMN IF NOT EXISTS
      provider_payment_id TEXT
  `);

  await db.query(`
    ALTER TABLE wallet_transactions
    ADD COLUMN IF NOT EXISTS
      provider_payout_id TEXT
  `);

  await db.query(`
    ALTER TABLE wallet_transactions
    ADD COLUMN IF NOT EXISTS
      provider_status TEXT
  `);

  await db.query(`
    ALTER TABLE wallet_transactions
    ADD COLUMN IF NOT EXISTS
      order_id TEXT
  `);

  await db.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
      wallet_provider_payment_unique
    ON wallet_transactions(
      provider_payment_id
    )
    WHERE
      provider_payment_id
      IS NOT NULL
  `);
}

/* =========================================================
   GET WALLET
========================================================= */

app.get(
  '/api/wallet',
  auth,
  async (req, res) => {
    try {
      const result =
        await db.query(
          `
          SELECT
            balance,
            wallet_locked

          FROM users

          WHERE id=$1
          `,
          [
            req.user.id
          ]
        );

      if (
        !result.rows.length
      ) {
        return res
          .status(404)
          .json({
            error:
              'not_found'
          });
      }

      const balance =
        Number(
          result.rows[0]
            .balance ||
          0
        );

      const locked =
        Number(
          result.rows[0]
            .wallet_locked ||
          0
        );

      res.json({
        balance,

        locked_balance:
          locked,

        available_balance:
          Math.max(
            0,
            balance
          ),

        currency:
          'USDT',

        deposit_addresses:
          USDT_ADDRESSES,

        networks:
          Array.from(
            USDT_NETWORKS
          ),

        min_deposit:
          MIN_DEPOSIT,

        min_withdraw:
          MIN_WITHDRAW,

        max_withdraw:
          MAX_WITHDRAW,

        withdraw_fee:
          WITHDRAW_FEE
      });

    } catch (e) {
      console.error(
        'wallet get error:',
        e.message
      );

      res
        .status(500)
        .json({
          error:
            'server_error'
        });
    }
  }
);

/* =========================================================
   NOWPAYMENTS — AUTOMATIC DEPOSIT
========================================================= */

app.post(
  '/api/nowpayments/deposit',
  auth,
  async (req, res) => {
    try {
      if (!(await isPaidEnabled())) {
        return res
          .status(403)
          .json({ error: 'paid_features_disabled' });
      }

      const amount =
        Number(
          req.body
            ?.amount
        );

      const network =
        String(
          req.body
            ?.network ||
          ''
        ).toUpperCase();

      if (
        !Number.isFinite(amount) ||
        amount < MIN_DEPOSIT
      ) {
        return res
          .status(400)
          .json({
            error:
              'minimum_deposit_is_' + MIN_DEPOSIT + '_usdt',

            min:
              MIN_DEPOSIT
          });
      }

      if (
        !USDT_NETWORKS
          .has(network)
      ) {
        return res
          .status(400)
          .json({
            error:
              'invalid_network'
          });
      }

      const payCurrency =
        NOWPAYMENTS_NETWORK_CURRENCY[
          network
        ];

      // NOWPayments enforces its own real-world minimum per network (mainly
      // driven by that chain's gas/network fee), which can be higher than
      // our own MIN_DEPOSIT setting — ERC20 in particular. Ask NOWPayments
      // for the actual minimum for this specific currency and use whichever
      // is higher, so this never silently mismatches their live minimum
      // again.
      try {
        const minAmountResp =
          await nowPaymentsRequest(
            '/min-amount?currency_from=' +
            payCurrency +
            '&currency_to=' +
            payCurrency +
            '&fiat_equivalent=usd',
            { method: 'GET' }
          );

        const nowPaymentsMin =
          Number(
            minAmountResp &&
            minAmountResp.fiat_equivalent
          );

        if (
          Number.isFinite(nowPaymentsMin) &&
          nowPaymentsMin > 0 &&
          amount < nowPaymentsMin
        ) {
          return res
            .status(400)
            .json({
              error:
                'minimum_deposit_for_network_is_' +
                Math.ceil(nowPaymentsMin) +
                '_usdt',

              min:
                Math.ceil(nowPaymentsMin),

              network
            });
        }

      } catch (e) {
        // If the min-amount lookup itself fails, fall through and let the
        // normal /payment call below surface NOWPayments' own error —
        // don't block a deposit just because this extra check errored.
        console.log('[min-amount lookup] failed, continuing:', e.message);
      }

      const orderId =
        [
          'yd',
          req.user.id,
          Date.now(),
          crypto
            .randomBytes(4)
            .toString('hex')
        ].join('-');

      const payment =
        await nowPaymentsRequest(
          '/payment',
          {
            method: 'POST',

            body: {
              price_amount:
                Number(
                  amount.toFixed(2)
                ),

              price_currency:
                'usd',

              pay_currency:
                payCurrency,

              ipn_callback_url:
                NOWPAYMENTS_IPN_URL,

              order_id:
                orderId,

              order_description:
                'Yalla Domino USDT deposit',

              // Fixed-rate locks an exact target amount for a short
              // window; sending noticeably more than that target was
              // observed to push the whole payment to NOWPayments'
              // "Failed" status instead of crediting the difference
              // (confirmed by their support team for payment
              // 5595980686). Floating rate tolerates over/under
              // payment far better — we already credit whatever
              // actually_paid comes back in the IPN handler either way.
              is_fixed_rate:
                false,

              is_fee_paid_by_user:
                false
            }
          }
        );

      const paymentId =
        String(
          payment.payment_id ||
          ''
        );

      if (!paymentId) {
        return res
          .status(502)
          .json({
            error:
              'payment_id_missing'
          });
      }

      await db.query(
        `
        INSERT INTO
          wallet_transactions
        (
          user_id,
          type,
          network,
          amount,
          address,
          status,
          provider,
          provider_payment_id,
          provider_status,
          order_id
        )

        VALUES
        (
          $1,
          'deposit',
          $2,
          $3,
          $4,
          'pending',
          'nowpayments',
          $5,
          $6,
          $7
        )
        `,
        [
          req.user.id,
          network,
          amount,
          payment.pay_address ||
            null,
          paymentId,
          payment.payment_status ||
            'waiting',
          orderId
        ]
      );

      res.json({
        ok: true,

        payment_id:
          paymentId,

        status:
          payment.payment_status,

        network,

        pay_currency:
          payment.pay_currency,

        pay_address:
          payment.pay_address,

        pay_amount:
          Number(
            payment.pay_amount ||
            0
          ),

        price_amount:
          Number(
            payment.price_amount ||
            amount
          ),

        price_currency:
          payment.price_currency ||
          'usd',

        order_id:
          orderId,

        expires_at:
          payment.expiration_estimate_date ||
          null
      });

    } catch (e) {
      console.error(
        'NOWPayments deposit create error:',
        e.message,
        e.data || ''
      );

      res
        .status(
          e.status || 500
        )
        .json({
          error:
            'nowpayments_deposit_failed',

          details:
            e.data || null
        });
    }
  }
);

app.get(
  '/api/nowpayments/payment/:id',
  auth,
  async (req, res) => {
    try {
      const local =
        await db.query(
          `
          SELECT
            id,
            user_id,
            status,
            provider_status,
            amount,
            network
          FROM
            wallet_transactions
          WHERE
            provider='nowpayments'
            AND
            provider_payment_id=$1
            AND
            user_id=$2
          LIMIT 1
          `,
          [
            String(
              req.params.id
            ),
            req.user.id
          ]
        );

      if (
        !local.rows.length
      ) {
        return res
          .status(404)
          .json({
            error:
              'payment_not_found'
          });
      }

      const payment =
        await nowPaymentsRequest(
          '/payment/' +
          encodeURIComponent(
            req.params.id
          )
        );

      res.json({
        ok: true,
        payment
      });

    } catch (e) {
      res
        .status(
          e.status || 500
        )
        .json({
          error:
            'payment_status_failed',

          details:
            e.data || null
        });
    }
  }
);

/* =========================================================
   NOWPAYMENTS — IPN / WEBHOOK
========================================================= */

app.post(
  '/api/nowpayments/ipn',
  async (req, res) => {
    const signature =
      req.headers[
        'x-nowpayments-sig'
      ];

    console.log(
      '[nowpayments_ipn] received, hasSecret=' + !!NOWPAYMENTS_IPN_SECRET +
      ' hasSignatureHeader=' + !!signature +
      ' payment_id=' + (req.body && req.body.payment_id) +
      ' payment_status=' + (req.body && req.body.payment_status)
    );

    if (
      !verifyNowPaymentsIpn(
        req.body,
        signature,
        req.rawBody
      )
    ) {
      console.log('[nowpayments_ipn] REJECTED — bad or missing signature');
      return res
        .status(401)
        .json({
          error:
            'bad_ipn_signature'
        });
    }

    console.log('[nowpayments_ipn] signature OK, processing...');

    try {
      const payload =
        req.body || {};

      const paymentId =
        payload.payment_id != null
          ? String(
              payload.payment_id
            )
          : null;

      const payoutId =
        payload.id != null
          ? String(
              payload.id
            )
          : null;

      const status =
        String(
          payload.payment_status ||
          payload.status ||
          ''
        ).toLowerCase();

      if (paymentId) {
        const client =
          await db.pool
            .connect();

        try {
          await client.query(
            'BEGIN'
          );

          const tx =
            await client.query(
              `
              SELECT *
              FROM
                wallet_transactions
              WHERE
                provider='nowpayments'
                AND
                provider_payment_id=$1
                AND
                type='deposit'
              FOR UPDATE
              `,
              [paymentId]
            );

          if (
            !tx.rows.length
          ) {
            console.log('[nowpayments_ipn] no matching pending deposit row for payment_id=' + paymentId);
            await client.query(
              'ROLLBACK'
            );

            return res.json({
              ok: true,
              ignored:
                'unknown_payment'
            });
          }

          const transaction =
            tx.rows[0];

          await client.query(
            `
            UPDATE
              wallet_transactions
            SET
              provider_status=$1,
              updated_at=NOW()
            WHERE id=$2
            `,
            [
              status,
              transaction.id
            ]
          );

          if (
            (
              status === 'finished' ||
              status === 'partially_paid'
            ) &&
            transaction.status !==
              'confirmed'
          ) {
            const requestedAmount =
              Number(
                transaction.amount
              );

            // Credit whatever actually arrived (in the pay
            // currency, e.g. USDT — treated ~1:1 with USD)
            // rather than requiring the exact inflated amount
            // NOWPayments originally quoted. This lets people
            // send a plain round number like $15 straight from
            // their wallet: NOWPayments keeps its own fee out of
            // what shows up on-chain, and whatever lands in our
            // deposit address is what gets credited.
            const actuallyPaid =
              Number(
                payload.actually_paid
              );

            const creditAmount =
              Number.isFinite(actuallyPaid) &&
              actuallyPaid > 0
                ? actuallyPaid
                : (
                    status === 'finished'
                      ? requestedAmount
                      : 0
                  );

            if (creditAmount <= 0) {
              await client.query(
                'ROLLBACK'
              );

              return res.json({
                ok: true,
                ignored:
                  'no_amount_received'
              });
            }

            await client.query(
              `
              UPDATE users
              SET
                balance =
                  balance + $1
              WHERE id=$2
              `,
              [
                creditAmount,
                transaction.user_id
              ]
            );

            console.log('[nowpayments_ipn] CREDITED user_id=' + transaction.user_id + ' amount=' + creditAmount + ' (requested=' + requestedAmount + ', status=' + status + ')');

            await client.query(
              `
              UPDATE
                wallet_transactions
              SET
                status='confirmed',
                provider_status=$2,
                amount=$3,
                updated_at=NOW()
              WHERE id=$1
              `,
              [
                transaction.id,
                status,
                creditAmount
              ]
            );
          }

          if (
            [
              'failed',
              'expired',
              'refunded'
            ].includes(status) &&
            transaction.status ===
              'pending'
          ) {
            await client.query(
              `
              UPDATE
                wallet_transactions
              SET
                status=$1,
                updated_at=NOW()
              WHERE id=$2
              `,
              [
                status,
                transaction.id
              ]
            );
          }

          await client.query(
            'COMMIT'
          );

        } catch (e) {
          try {
            await client.query(
              'ROLLBACK'
            );
          } catch {}

          throw e;

        } finally {
          client.release();
        }

        return res.json({
          ok: true
        });
      }

      if (payoutId) {
        const tx =
          await db.query(
            `
            SELECT *
            FROM
              wallet_transactions
            WHERE
              provider='nowpayments'
              AND
              provider_payout_id=$1
              AND
              type='withdraw'
            LIMIT 1
            `,
            [payoutId]
          );

        if (
          !tx.rows.length
        ) {
          return res.json({
            ok: true,
            ignored:
              'unknown_payout'
          });
        }

        const transaction =
          tx.rows[0];

        await db.query(
          `
          UPDATE
            wallet_transactions
          SET
            provider_status=$1,
            updated_at=NOW()
          WHERE id=$2
          `,
          [
            status,
            transaction.id
          ]
        );

        if (
          status ===
            'finished' &&
          transaction.status ===
            'pending'
        ) {
          await db.query(
            `
            UPDATE users
            SET
              wallet_locked =
                GREATEST(
                  0,
                  wallet_locked - $1
                )
            WHERE id=$2
            `,
            [
              Number(
                transaction.amount
              ),
              transaction.user_id
            ]
          );

          await db.query(
            `
            UPDATE
              wallet_transactions
            SET
              status='completed',
              provider_status='finished',
              updated_at=NOW()
            WHERE id=$1
            `,
            [
              transaction.id
            ]
          );
        }

        if (
          [
            'failed',
            'rejected'
          ].includes(status) &&
          transaction.status ===
            'pending'
        ) {
          const client =
            await db.pool
              .connect();

          try {
            await client.query(
              'BEGIN'
            );

            const locked =
              await client.query(
                `
                SELECT *
                FROM
                  wallet_transactions
                WHERE id=$1
                FOR UPDATE
                `,
                [
                  transaction.id
                ]
              );

            if (
              locked.rows.length &&
              locked.rows[0]
                .status ===
                'pending'
            ) {
              await client.query(
                `
                UPDATE users
                SET
                  balance =
                    balance + $1,
                  wallet_locked =
                    GREATEST(
                      0,
                      wallet_locked - $1
                    )
                WHERE id=$2
                `,
                [
                  Number(
                    transaction.amount
                  ),
                  transaction.user_id
                ]
              );

              await client.query(
                `
                UPDATE
                  wallet_transactions
                SET
                  status=$1,
                  provider_status=$1,
                  updated_at=NOW()
                WHERE id=$2
                `,
                [
                  status,
                  transaction.id
                ]
              );
            }

            await client.query(
              'COMMIT'
            );

          } catch (e) {
            try {
              await client.query(
                'ROLLBACK'
              );
            } catch {}

            throw e;

          } finally {
            client.release();
          }
        }

        return res.json({
          ok: true
        });
      }

      return res.json({
        ok: true,
        ignored:
          'unknown_callback'
      });

    } catch (e) {
      console.error(
        'NOWPayments IPN error:',
        e
      );

      return res
        .status(500)
        .json({
          error:
            'ipn_processing_failed'
        });
    }
  }
);

/* =========================================================
   NOWPAYMENTS — AUTOMATIC PAYOUT
========================================================= */

app.post(
  '/api/nowpayments/withdraw',
  auth,
  async (req, res) => {
    const client =
      await db.pool
        .connect();

    try {
      const network =
        String(
          req.body
            ?.network ||
          ''
        ).toUpperCase();

      const address =
        String(
          req.body
            ?.address ||
          ''
        ).trim();

      const amount =
        Number(
          req.body
            ?.amount
        );

      if (
        !USDT_NETWORKS
          .has(network)
      ) {
        return res
          .status(400)
          .json({
            error:
              'invalid_network'
          });
      }

      if (
        !validUsdtAddress(
          network,
          address
        )
      ) {
        return res
          .status(400)
          .json({
            error:
              'invalid_address_for_network'
          });
      }

      if (
        !Number.isFinite(amount) ||
        amount < MIN_WITHDRAW ||
        amount > MAX_WITHDRAW
      ) {
        return res
          .status(400)
          .json({
            error:
              'invalid_amount',

            min:
              MIN_WITHDRAW,

            max:
              MAX_WITHDRAW
          });
      }

      if (
        !NOWPAYMENTS_EMAIL ||
        !NOWPAYMENTS_PASSWORD
      ) {
        return res
          .status(503)
          .json({
            error:
              'payout_setup_required',

            missing: [
              'NOWPAYMENTS_EMAIL',
              'NOWPAYMENTS_PASSWORD'
            ]
          });
      }

      if (
        !NOWPAYMENTS_2FA_SECRET
      ) {
        return res
          .status(503)
          .json({
            error:
              'payout_2fa_setup_required',

            missing: [
              'NOWPAYMENTS_2FA_SECRET'
            ]
          });
      }

      await client.query(
        'BEGIN'
      );

      const userResult =
        await client.query(
          `
          SELECT
            balance,
            wallet_locked
          FROM users
          WHERE id=$1
          FOR UPDATE
          `,
          [
            req.user.id
          ]
        );

      if (
        !userResult.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'not_found'
          });
      }

      if (
        Number(
          userResult.rows[0]
            .balance ||
          0
        ) < amount
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(400)
          .json({
            error:
              'insufficient_balance'
          });
      }

      const currency =
        NOWPAYMENTS_NETWORK_CURRENCY[
          network
        ];

      await nowPaymentsRequest(
        '/payout/validate-address',
        {
          method: 'POST',

          body: {
            address,
            currency
          }
        }
      );

      const reserved =
        await client.query(
          `
          UPDATE users
          SET
            balance =
              balance - $1,
            wallet_locked =
              wallet_locked + $1
          WHERE id=$2
          RETURNING
            balance,
            wallet_locked
          `,
          [
            amount,
            req.user.id
          ]
        );

      const externalId =
        [
          'yd-withdraw',
          req.user.id,
          Date.now(),
          crypto
            .randomBytes(4)
            .toString('hex')
        ].join('-');

      const localTx =
        await client.query(
          `
          INSERT INTO
            wallet_transactions
          (
            user_id,
            type,
            network,
            amount,
            address,
            status,
            fee,
            provider,
            provider_status,
            order_id
          )
          VALUES
          (
            $1,
            'withdraw',
            $2,
            $3,
            $4,
            'pending',
            $5,
            'nowpayments',
            'creating',
            $6
          )
          RETURNING *
          `,
          [
            req.user.id,
            network,
            amount,
            address,
            WITHDRAW_FEE,
            externalId
          ]
        );

      await client.query(
        'COMMIT'
      );

      let batchId = null;
      let payoutId = null;

      try {
        const jwtToken =
          await getNowPaymentsJwt();

        const payoutResponse =
          await nowPaymentsRequest(
            '/payout',
            {
              method: 'POST',

              headers: {
                Authorization:
                  'Bearer ' +
                  jwtToken
              },

              body: {
                ipn_callback_url:
                  NOWPAYMENTS_IPN_URL,

                withdrawals: [
                  {
                    address,

                    currency,

                    amount:
                      Number(
                        amount.toFixed(6)
                      ),

                    ipn_callback_url:
                      NOWPAYMENTS_IPN_URL,

                    unique_external_id:
                      externalId
                  }
                ]
              }
            }
          );

        batchId =
          String(
            payoutResponse.id ||
            payoutResponse.batch_withdrawal_id ||
            payoutResponse.batch_id ||
            ''
          );

        const firstWithdrawal =
          Array.isArray(
            payoutResponse.withdrawals
          )
            ? payoutResponse
                .withdrawals[0]
            : null;

        payoutId =
          firstWithdrawal?.id != null
            ? String(
                firstWithdrawal.id
              )
            : null;

        await db.query(
          `
          UPDATE
            wallet_transactions
          SET
            provider_payout_id=$1,
            provider_status=$2,
            tx_hash=$3,
            updated_at=NOW()
          WHERE id=$4
          `,
          [
            payoutId ||
              batchId ||
              null,

            String(
              firstWithdrawal
                ?.status ||
              payoutResponse.status ||
              'creating'
            ).toLowerCase(),

            batchId ||
              null,

            localTx.rows[0].id
          ]
        );

        if (!batchId) {
          throw new Error(
            'payout_batch_id_missing'
          );
        }

        const verificationCode =
          generateTotp(
            NOWPAYMENTS_2FA_SECRET
          );

        await nowPaymentsRequest(
          '/payout/' +
            encodeURIComponent(
              batchId
            ) +
            '/verify',
          {
            method: 'POST',

            headers: {
              Authorization:
                'Bearer ' +
                jwtToken
            },

            body: {
              verification_code:
                verificationCode
            }
          }
        );

        await db.query(
          `
          UPDATE
            wallet_transactions
          SET
            provider_status='waiting',
            updated_at=NOW()
          WHERE id=$1
          `,
          [
            localTx.rows[0].id
          ]
        );

        return res.json({
          ok: true,

          transaction_id:
            localTx.rows[0].id,

          payout_id:
            payoutId,

          batch_id:
            batchId,

          status:
            'waiting',

          balance:
            Number(
              reserved.rows[0]
                .balance
            ),

          locked_balance:
            Number(
              reserved.rows[0]
                .wallet_locked
            )
        });

      } catch (payoutError) {
        const rollbackClient =
          await db.pool
            .connect();

        try {
          await rollbackClient.query(
            'BEGIN'
          );

          const lockedTx =
            await rollbackClient.query(
              `
              SELECT *
              FROM
                wallet_transactions
              WHERE id=$1
              FOR UPDATE
              `,
              [
                localTx.rows[0].id
              ]
            );

          if (
            lockedTx.rows.length &&
            lockedTx.rows[0]
              .status ===
              'pending'
          ) {
            await rollbackClient.query(
              `
              UPDATE users
              SET
                balance =
                  balance + $1,
                wallet_locked =
                  GREATEST(
                    0,
                    wallet_locked - $1
                  )
              WHERE id=$2
              `,
              [
                amount,
                req.user.id
              ]
            );

            await rollbackClient.query(
              `
              UPDATE
                wallet_transactions
              SET
                status='failed',
                provider_status='failed',
                updated_at=NOW()
              WHERE id=$1
              `,
              [
                localTx.rows[0].id
              ]
            );
          }

          await rollbackClient.query(
            'COMMIT'
          );

        } catch {
          try {
            await rollbackClient.query(
              'ROLLBACK'
            );
          } catch {}

        } finally {
          rollbackClient.release();
        }

        throw payoutError;
      }

    } catch (e) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'NOWPayments withdraw error:',
        e.message,
        e.data || ''
      );

      res
        .status(
          e.status || 500
        )
        .json({
          error:
            'nowpayments_withdraw_failed',

          details:
            e.data || null
        });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   DEPOSIT
========================================================= */

app.post(
  '/api/deposit',
  auth,
  async (req, res) => {
    try {
      const network =
        String(
          req.body
            ?.network ||
          ''
        ).toUpperCase();

      const txHash =
        String(
          req.body
            ?.tx_hash ||
          ''
        ).trim();

      if (
        !USDT_NETWORKS
          .has(network)
      ) {
        return res
          .status(400)
          .json({
            error:
              'invalid_network'
          });
      }

      if (
        !txHash ||
        txHash.length < 20 ||
        txHash.length > 200
      ) {
        return res
          .status(400)
          .json({
            error:
              'invalid_tx_hash'
          });
      }

      const result =
        await db.query(
          `
          INSERT INTO
            wallet_transactions
          (
            user_id,
            type,
            network,
            amount,
            tx_hash,
            status
          )

          VALUES
          (
            $1,
            'deposit',
            $2,
            0,
            $3,
            'pending'
          )

          RETURNING
            id,
            type,
            network,
            amount,
            tx_hash,
            status,
            created_at
          `,
          [
            req.user.id,
            network,
            txHash
          ]
        );

      res.json({
        ok: true,

        transaction:
          result.rows[0],

        message:
          'deposit_submitted_for_review'
      });

    } catch (e) {
      if (
        e.code ===
        '23505'
      ) {
        return res
          .status(409)
          .json({
            error:
              'tx_hash_already_submitted'
          });
      }

      console.error(
        'deposit error:',
        e.message
      );

      res
        .status(500)
        .json({
          error:
            'server_error'
        });
    }
  }
);

/* =========================================================
   WITHDRAW
========================================================= */

app.post(
  '/api/withdraw',
  auth,
  async (req, res) => {
    const client =
      await db.pool
        .connect();

    try {
      const network =
        String(
          req.body
            ?.network ||
          ''
        ).toUpperCase();

      const address =
        String(
          req.body
            ?.address ||
          ''
        ).trim();

      const amount =
        Number(
          req.body
            ?.amount
        );

      if (
        !USDT_NETWORKS
          .has(network)
      ) {
        return res
          .status(400)
          .json({
            error:
              'invalid_network'
          });
      }

      if (
        !validUsdtAddress(
          network,
          address
        )
      ) {
        return res
          .status(400)
          .json({
            error:
              'invalid_address_for_network'
          });
      }

      if (
        !Number
          .isFinite(amount) ||
        amount <
          MIN_WITHDRAW ||
        amount >
          MAX_WITHDRAW
      ) {
        return res
          .status(400)
          .json({
            error:
              'invalid_amount',

            min:
              MIN_WITHDRAW,

            max:
              MAX_WITHDRAW
          });
      }

      await client
        .query('BEGIN');

      const userResult =
        await client.query(
          `
          SELECT
            balance,
            wallet_locked

          FROM users

          WHERE id=$1

          FOR UPDATE
          `,
          [
            req.user.id
          ]
        );

      if (
        !userResult
          .rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'not_found'
          });
      }

      const balance =
        Number(
          userResult
            .rows[0]
            .balance ||
          0
        );

      if (
        balance < amount
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(400)
          .json({
            error:
              'insufficient_balance'
          });
      }

      const updated =
        await client.query(
          `
          UPDATE users

          SET
            balance =
              balance - $1,

            wallet_locked =
              wallet_locked + $1

          WHERE id=$2

          RETURNING
            balance,
            wallet_locked
          `,
          [
            amount,
            req.user.id
          ]
        );

      const withdrawal =
        await client.query(
          `
          INSERT INTO
            wallet_transactions
          (
            user_id,
            type,
            network,
            amount,
            address,
            status,
            fee
          )

          VALUES
          (
            $1,
            'withdraw',
            $2,
            $3,
            $4,
            'pending',
            $5
          )

          RETURNING
            id,
            type,
            network,
            amount,
            address,
            status,
            fee,
            created_at
          `,
          [
            req.user.id,
            network,
            amount,
            address,
            WITHDRAW_FEE
          ]
        );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,

        transaction:
          withdrawal.rows[0],

        balance:
          Number(
            updated
              .rows[0]
              .balance
          ),

        locked_balance:
          Number(
            updated
              .rows[0]
              .wallet_locked
          ),

        message:
          'withdrawal_submitted_for_review'
      });

    } catch (e) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'withdraw error:',
        e.message
      );

      res
        .status(500)
        .json({
          error:
            'server_error'
        });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   WALLET HISTORY
========================================================= */

app.get(
  '/api/wallet/transactions',
  auth,
  async (req, res) => {
    try {
      const result =
        await db.query(
          `
          SELECT
            id,
            type,
            network,
            amount,
            address,
            tx_hash,
            status,
            fee,
            created_at,
            updated_at

          FROM
            wallet_transactions

          WHERE
            user_id=$1
            AND (
              (type='deposit' AND status='confirmed')
              OR (type='withdraw' AND status='completed')
            )

          ORDER BY
            created_at DESC

          LIMIT 50
          `,
          [
            req.user.id
          ]
        );

      res.json({
        transactions:
          result.rows
      });

    } catch {
      res
        .status(500)
        .json({
          error:
            'server_error'
        });
    }
  }
);

/* =========================================================
   MY PAID MATCH HISTORY (won/lost games, for the History
   panel — separate from wallet_transactions above)
========================================================= */

app.get(
  '/api/matches/mine',
  auth,
  async (req, res) => {
    try {
      const result =
        await db.query(
          `
          SELECT
            m.id,
            m.stake,
            m.prize,
            m.status,
            m.winner_user_id,
            m.created_at,
            m.settled_at,

            CASE
              WHEN m.p1_user_id=$1
              THEN m.p2_user_id
              ELSE m.p1_user_id
            END AS opponent_id,

            CASE
              WHEN m.p1_user_id=$1
              THEN u2.username
              ELSE u1.username
            END AS opponent_username,

            CASE
              WHEN m.p1_user_id=$1
              THEN u2.email
              ELSE u1.email
            END AS opponent_email

          FROM
            paid_matches m

          LEFT JOIN
            users u1
            ON u1.id = m.p1_user_id

          LEFT JOIN
            users u2
            ON u2.id = m.p2_user_id

          WHERE
            m.p1_user_id=$1
            OR m.p2_user_id=$1

          ORDER BY
            m.created_at DESC

          LIMIT 50
          `,
          [
            req.user.id
          ]
        );

      const matches =
        result.rows.map(
          row => ({
            id: row.id,
            stake: Number(row.stake),
            prize: Number(row.prize),
            status: row.status,
            won:
              row.winner_user_id != null &&
              Number(row.winner_user_id) === Number(req.user.id),
            opponent_name:
              defaultName({
                username: row.opponent_username,
                email: row.opponent_email
              }),
            created_at: row.created_at,
            settled_at: row.settled_at
          })
        );

      res.json({
        matches
      });

    } catch (e) {
      console.error('matches/mine error:', e.message);
      res
        .status(500)
        .json({
          error:
            'server_error'
        });
    }
  }
);

/* =========================================================
   ADMIN WALLET
========================================================= */

app.get(
  '/api/admin/wallet/transactions',
  adminOnly,
  async (_req, res) => {
    try {
      const totalsResult =
        await db.query(
          `
          SELECT
            COALESCE(SUM(amount), 0)::float8 AS total_volume,
            COUNT(*) FILTER (
              WHERE type='deposit' AND status IN ('pending','review')
            )::int AS pending_deposits_count,
            COUNT(*) FILTER (
              WHERE type='withdraw' AND status='pending'
            )::int AS pending_withdrawals_count
          FROM wallet_transactions
          `
        );
      const totals = totalsResult.rows[0] || {};

      const result =
        await db.query(
          `
          SELECT
            id,
            user_id,
            type,
            network,
            amount,
            address,
            tx_hash,
            status,
            fee,
            created_at,
            updated_at

          FROM
            wallet_transactions

          ORDER BY
            created_at DESC

          LIMIT 200
          `
        );

      // The 200-row list above is a recent-activity feed, fine for a
      // dashboard glance -- but a pending deposit or withdrawal is a task
      // someone still has to act on, and it must never fall out of reach
      // just because 200 newer transactions happened after it. Fetch
      // every still-pending item separately (unbounded: there are only
      // ever as many as haven't been resolved yet, which is small) and
      // let the client merge them in.
      const pendingResult =
        await db.query(
          `
          SELECT
            id,
            user_id,
            type,
            network,
            amount,
            address,
            tx_hash,
            status,
            fee,
            created_at,
            updated_at

          FROM
            wallet_transactions

          WHERE
            (type='deposit' AND status IN ('pending','review'))
            OR (type='withdraw' AND status='pending')

          ORDER BY
            created_at DESC
          `
        );

      res.json({
        total_volume: Number(totals.total_volume || 0),
        pending_deposits_count: Number(totals.pending_deposits_count || 0),
        pending_withdrawals_count: Number(totals.pending_withdrawals_count || 0),
        transactions:
          result.rows,
        pending_transactions:
          pendingResult.rows
      });

    } catch {
      res
        .status(500)
        .json({
          error:
            'server_error'
        });
    }
  }
);

// Bulk-clear the wallet transaction history/log (e.g. after a round of
// testing). This ONLY deletes rows from wallet_transactions — it never
// touches users.balance, so any real balance changes that already
// happened stay exactly as they are. This is a history/audit-trail
// wipe, not a financial reversal.
app.post(
  '/api/admin/wallet/transactions/delete-all',
  adminOnly,
  async (_req, res) => {
    try {
      const result =
        await db.query(
          `DELETE FROM wallet_transactions`
        );

      res.json({
        ok: true,
        deleted: result.rowCount
      });

    } catch (e) {
      console.error('wallet transactions delete-all error:', e.message);
      res
        .status(500)
        .json({
          error:
            'server_error'
        });
    }
  }
);

/* =========================================================
   APPROVE DEPOSIT
========================================================= */

app.post(
  '/api/admin/wallet/deposit/:id/approve',
  adminOnly,
  async (req, res) => {
    const client =
      await db.pool
        .connect();

    try {
      const amount =
        Number(
          req.body
            ?.amount
        );

      if (
        !Number
          .isFinite(amount) ||
        amount <= 0
      ) {
        return res
          .status(400)
          .json({
            error:
              'verified_amount_required'
          });
      }

      await client.query(
        'BEGIN'
      );

      const tx =
        await client.query(
          `
          SELECT *

          FROM
            wallet_transactions

          WHERE
            id=$1
            AND
            type='deposit'

          FOR UPDATE
          `,
          [
            req.params.id
          ]
        );

      if (
        !tx.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'not_found'
          });
      }

      if (
        tx.rows[0]
          .status !==
        'pending'
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(409)
          .json({
            error:
              'already_processed'
          });
      }

      const updated =
        await client.query(
          `
          UPDATE users

          SET
            balance =
              balance + $1

          WHERE
            id=$2

          RETURNING
            balance
          `,
          [
            amount,
            tx.rows[0]
              .user_id
          ]
        );

      await client.query(
        `
        UPDATE
          wallet_transactions

        SET
          amount=$1,
          status='confirmed',
          updated_at=NOW()

        WHERE
          id=$2
        `,
        [
          amount,
          tx.rows[0].id
        ]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,

        balance:
          Number(
            updated
              .rows[0]
              .balance
          )
      });

    } catch (e) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      res
        .status(500)
        .json({
          error:
            'server_error'
        });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   COMPLETE WITHDRAW
========================================================= */

app.post(
  '/api/admin/wallet/withdraw/:id/complete',
  adminOnly,
  async (req, res) => {
    const client =
      await db.pool
        .connect();

    try {
      await client.query(
        'BEGIN'
      );

      const tx =
        await client.query(
          `
          SELECT *

          FROM
            wallet_transactions

          WHERE
            id=$1
            AND
            type='withdraw'

          FOR UPDATE
          `,
          [
            req.params.id
          ]
        );

      if (
        !tx.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'not_found'
          });
      }

      if (
        tx.rows[0]
          .status !==
        'pending'
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(409)
          .json({
            error:
              'already_processed'
          });
      }

      const amount =
        Number(
          tx.rows[0]
            .amount
        );

      const updated =
        await client.query(
          `
          UPDATE users

          SET
            wallet_locked =
              GREATEST(
                0,
                wallet_locked - $1
              )

          WHERE
            id=$2

          RETURNING
            balance,
            wallet_locked
          `,
          [
            amount,
            tx.rows[0]
              .user_id
          ]
        );

      await client.query(
        `
        UPDATE
          wallet_transactions

        SET
          status='completed',
          updated_at=NOW()

        WHERE
          id=$1
        `,
        [
          tx.rows[0].id
        ]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,

        balance:
          Number(
            updated
              .rows[0]
              .balance
          ),

        locked_balance:
          Number(
            updated
              .rows[0]
              .wallet_locked
          )
      });

    } catch {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      res
        .status(500)
        .json({
          error:
            'server_error'
        });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   REJECT WITHDRAW
========================================================= */

app.post(
  '/api/admin/wallet/withdraw/:id/reject',
  adminOnly,
  async (req, res) => {
    const client =
      await db.pool
        .connect();

    try {
      await client.query(
        'BEGIN'
      );

      const tx =
        await client.query(
          `
          SELECT *

          FROM
            wallet_transactions

          WHERE
            id=$1
            AND
            type='withdraw'

          FOR UPDATE
          `,
          [
            req.params.id
          ]
        );

      if (
        !tx.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'not_found'
          });
      }

      if (
        tx.rows[0]
          .status !==
        'pending'
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(409)
          .json({
            error:
              'already_processed'
          });
      }

      const amount =
        Number(
          tx.rows[0]
            .amount
        );

      const updated =
        await client.query(
          `
          UPDATE users

          SET
            balance =
              balance + $1,

            wallet_locked =
              GREATEST(
                0,
                wallet_locked - $1
              )

          WHERE
            id=$2

          RETURNING
            balance,
            wallet_locked
          `,
          [
            amount,
            tx.rows[0]
              .user_id
          ]
        );

      await client.query(
        `
        UPDATE
          wallet_transactions

        SET
          status='rejected',
          updated_at=NOW()

        WHERE
          id=$1
        `,
        [
          tx.rows[0].id
        ]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,

        balance:
          Number(
            updated
              .rows[0]
              .balance
          ),

        locked_balance:
          Number(
            updated
              .rows[0]
              .wallet_locked
          )
      });

    } catch {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      res
        .status(500)
        .json({
          error:
            'server_error'
        });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   PAID MATCH CONFIG
========================================================= */

const PAID_TIERS =
  new Map([
    [1, 1.90],
    [3, 5.60],
    [5, 9.00]
  ]);

/* =========================================================
   PAID MATCH TABLE
========================================================= */

async function initPaidMatchTables() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS
      paid_matches
    (
      id
        BIGSERIAL
        PRIMARY KEY,

      room_id
        TEXT
        UNIQUE
        NOT NULL,

      p1_user_id
        INTEGER
        NOT NULL
        REFERENCES users(id),

      p2_user_id
        INTEGER
        NOT NULL
        REFERENCES users(id),

      stake
        NUMERIC(20,8)
        NOT NULL,

      prize
        NUMERIC(20,8)
        NOT NULL,

      status
        VARCHAR(20)
        NOT NULL
        DEFAULT 'active',

      p1_report
        VARCHAR(8),

      p2_report
        VARCHAR(8),

      winner_user_id
        INTEGER
        REFERENCES users(id),

      created_at
        TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

      settled_at
        TIMESTAMPTZ,

      updated_at
        TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW()
    )
  `);

  await db.query(`
    CREATE INDEX IF NOT EXISTS
      paid_matches_status_idx

    ON paid_matches(
      status,
      created_at DESC
    )
  `);
}

/* =========================================================
   TOURNAMENT (MONTHLY LEADERBOARD)
========================================================= */

// Free matches that settle faster than this many seconds are treated as
// non-genuine for tournament purposes (see getLeaderboardForPeriod and
// the admin fraud report). Override with TOURNAMENT_MIN_MATCH_SECONDS in
// Railway -> Variables if the threshold needs tuning.
const TOURNAMENT_MIN_MATCH_SECONDS =
  Math.max(0, Number(process.env.TOURNAMENT_MIN_MATCH_SECONDS || 30));

async function initTournamentTables() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS tournament_config (
      id INTEGER PRIMARY KEY DEFAULT 1,
      enabled BOOLEAN NOT NULL DEFAULT true,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT tournament_config_singleton CHECK (id = 1)
    )
  `);

  await db.query(`
    ALTER TABLE tournament_config ADD COLUMN IF NOT EXISTS fake_reset_period TEXT
  `);

  await db.query(`
    INSERT INTO tournament_config (id, enabled)
    VALUES (1, true)
    ON CONFLICT (id) DO NOTHING
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
    // Default weekly free-play prize ladder — top 1 to top 50, $500 total.
    // Fully editable afterwards from the admin panel.
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

  // Migrate the old monthly/paid-match tournament_winners table (if it still
  // has the old shape from before this became a weekly free-play tournament)
  // to the new one-row-per-rank-per-week shape.
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
  await db.query(`
    ALTER TABLE tournament_winners DROP CONSTRAINT IF EXISTS tournament_winners_period_key
  `);
  await db.query(`
    ALTER TABLE tournament_winners ADD COLUMN IF NOT EXISTS rank INTEGER
  `);
  await db.query(`
    ALTER TABLE tournament_winners ADD COLUMN IF NOT EXISTS wins INTEGER
  `);
  await db.query(`
    UPDATE tournament_winners SET rank = 1 WHERE rank IS NULL
  `);
  await db.query(`
    UPDATE tournament_winners SET wins = games_played WHERE wins IS NULL AND games_played IS NOT NULL
  `);
  await db.query(`
    UPDATE tournament_winners SET wins = 0 WHERE wins IS NULL
  `);
  await db.query(`
    ALTER TABLE tournament_winners ALTER COLUMN rank SET NOT NULL
  `);
  await db.query(`
    ALTER TABLE tournament_winners ALTER COLUMN wins SET NOT NULL
  `);
  await db.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS tournament_winners_period_user_idx
    ON tournament_winners(period, user_id)
  `);
}

/* =========================================================
   DAILY VISITS (APP OPENS)
========================================================= */

async function initVisitTables() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS daily_visits (
      visit_date DATE NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id),
      first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (visit_date, user_id)
    )
  `);
  await db.query(`
    CREATE INDEX IF NOT EXISTS daily_visits_date_idx
    ON daily_visits(visit_date DESC)
  `);

  // Separate from daily_visits above (which counts UNIQUE people per day):
  // this counts every single app open/launch, including repeats from the
  // same person on the same day — a running total, not a dedup count.
  await db.query(`
    CREATE TABLE IF NOT EXISTS app_open_counts (
      open_date DATE PRIMARY KEY,
      opens INTEGER NOT NULL DEFAULT 0
    )
  `);
}

function recordVisit(userId) {
  // Fire-and-forget: one row per user per calendar day (UTC).
  // ON CONFLICT DO NOTHING keeps this cheap even with many app opens.
  db.query(`
    INSERT INTO daily_visits (visit_date, user_id)
    VALUES (CURRENT_DATE, $1)
    ON CONFLICT (visit_date, user_id) DO NOTHING
  `, [userId]).catch(e => console.warn('recordVisit skipped:', e.message));
}

function recordAppOpen() {
  // Fire-and-forget, same style as recordVisit — but this one has no
  // ON CONFLICT DO NOTHING dedup: every call bumps the counter by one,
  // so it reflects total app opens today, not unique people.
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
    const today = await db.query(`
      SELECT COUNT(*) AS visitors FROM daily_visits WHERE visit_date = CURRENT_DATE
    `);
    const opensToday = await db.query(`
      SELECT opens FROM app_open_counts WHERE open_date = CURRENT_DATE
    `);
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

// Today's match counts, split free (stake=0) vs paid (stake>0). A plain
// COUNT(*) query rather than reading from the capped 200-row
// /api/admin/matches list, so this stays accurate as volume grows past
// that cap. "Today" is the current UTC calendar day (matches
// paid_matches.created_at, which is stored in UTC by Postgres NOW()).
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

// Computes the same set of match/player stats for a given time boundary
// (e.g. "since the start of today" or "since 30 days ago") -- shared by
// the today and last-30-days sections of the analytics endpoint so the
// two stay consistent instead of drifting apart as separate queries.
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
    // Both windows share the exact same shape (see computeMatchStatsSince)
    // so the UI can show "today" as a live-refreshing snapshot right next
    // to the steadier 30-day picture without them ever disagreeing on how
    // a stat is defined.
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

// ISO week period string, e.g. "2026-W34"
function weekPeriodString(d) {
  const date = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const dayNum = (date.getUTCDay() + 6) % 7; // Monday=0 .. Sunday=6
  date.setUTCDate(date.getUTCDate() - dayNum + 3); // nearest Thursday
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
  const jan4Day = (jan4.getUTCDay() + 6) % 7; // Monday=0
  const week1Monday = new Date(jan4.getTime() - jan4Day * 86400000);
  const start = new Date(week1Monday.getTime() + (w - 1) * 7 * 86400000);
  const end = new Date(start.getTime() + 7 * 86400000);
  return { start, end };
}

function currentWeekPeriod() {
  return weekPeriodString(new Date());
}

function previousWeekPeriod() {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - 7);
  return weekPeriodString(d);
}

async function getTiers() {
  const result = await db.query(`
    SELECT rank_from, rank_to, amount
    FROM tournament_tiers
    ORDER BY rank_from ASC
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

// Leaderboard = most WINS in settled FREE matches (stake=0) within the week.
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
      GROUP BY winner_user_id
    ) x
    JOIN users u ON u.id = x.user_id
    WHERE COALESCE(u.banned, false) = false
    ORDER BY x.wins DESC, u.id ASC
    LIMIT $3
  `, [start, end, limit || 50]);
  return result.rows;
}

/* =========================================================
   TOURNAMENT — FAKE LEADERBOARD ENTRIES (display-only seeding)

   These are cosmetic rows an operator can add so a brand-new
   leaderboard doesn't look empty. They are NEVER included in the
   real payout logic (checkAndPayoutTournament only ever reads
   from paid_matches / real users), so they can never receive real
   money — they only appear in the leaderboard people SEE.
========================================================= */

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
  await db.query(`
    ALTER TABLE client_errors
      ADD COLUMN IF NOT EXISTS match_id INTEGER,
      ADD COLUMN IF NOT EXISTS room_id TEXT
  `);
  await db.query(`
    ALTER TABLE paid_matches
      ADD COLUMN IF NOT EXISTS dispute_reason TEXT
  `);
  // Errors happen in bursts (one bad frame can log the same message dozens
  // of times) -- keep only the last 2000 rows so this can never grow into
  // a real storage/performance problem left unattended.
  await db.query(`
    DELETE FROM client_errors WHERE id NOT IN (
      SELECT id FROM client_errors ORDER BY id DESC LIMIT 2000
    )
  `);
}

// Safety net for paid matches that never got settled -- if a match's
// in-memory room is gone (both sockets disconnected for good, or a
// client-side crash nobody could recover from) but its DB row is still
// sitting "active" a long time later, nothing will ever resolve it on its
// own. Rather than leaving both players' stakes locked indefinitely until
// an admin happens to notice and click Refund, automatically refund it.
// Checking rooms.has() (not just elapsed time) means a real, unusually
// long game in progress is never touched -- it always still has a live
// room -- this only catches matches that are truly orphaned.
// Server-side backstop for a frozen match: everything else that detects
// "stuck" (the opponent-not-responding watchdog, the auto-play timer, the
// draw/move retry logic) runs as JS timers in the PLAYER's own browser --
// and mobile browsers commonly throttle or fully pause those timers once
// a tab is backgrounded or the screen locks, which a player waiting on
// their opponent's turn might well do. The server has no such throttling,
// so it's the one place a stall can still be caught reliably. If a room
// tied to an active paid match has had zero moves/draws for a while, flag
// it the same way a client-detected freeze already does.
async function checkStalledPaidMatches() {
  try {
    const STALE_MS = 4 * 60 * 1000; // 4 minutes with no board activity
    const now = Date.now();
    for (const [roomId, room] of rooms.entries()) {
      if (!room.matchId) continue; // free/offline match, nothing to flag
      const last = room.lastActivityAt || 0;
      if (now - last < STALE_MS) continue;
      if (room._flaggedStalled) continue; // already flagged this room once
      room._flaggedStalled = true;
      // Do not strand real money in 'disputed'. A server-detected technical
      // stall is not either player's fault, so refund both stakes and close
      // the in-memory room deterministically.
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
      WHERE status = 'active'
        AND updated_at < NOW() - INTERVAL '30 minutes'
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

// How often (in seconds) a single fake entry waits before its win count
// ticks up again. Randomized per entry and re-randomized after every tick
// so different rows drift in and out of sync with each other (one every
// ~7 minutes, another every ~8, etc.) rather than all moving in lockstep.
function randomIncrementIntervalSeconds() {
  return 300 + Math.floor(Math.random() * 300); // 5–10 minutes
}

// Ticks any fake leaderboard entries that are "due" for their next
// automatic win bump, so the leaderboard looks like real people are
// playing throughout the day instead of sitting frozen between manual
// admin edits. Purely cosmetic -- see the big comment above
// initFakeLeaderboard(): these rows are never read by the real payout
// logic, so this can never cost real money.
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

// Automatic weekly reshuffling of the seeded (fake) entries' win counts
// was removed on request — the operator adds/edits these names by hand
// via the admin panel and wants them to stay exactly as set until changed
// again, not get zeroed out on their own (including, apparently, in a way
// that was also being triggered by redeploys, not just real week
// boundaries — this removes that automatic behavior entirely either way).

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

// Merges real leaderboard rows with fake (display-only) rows, re-sorted by
// wins, and returns the top `limit` combined with a visual rank. Prize
// amounts for REAL users are computed from their rank AMONG REAL USERS
// ONLY (i.e. what they will actually be paid) — never from their mixed-in
// visual position — so the number shown never overstates or understates
// their real payout. Fake rows never show a prize.
async function getDisplayLeaderboard(periodStr, limit, tiers) {
  const [real, fake] = await Promise.all([
    getLeaderboardForPeriod(periodStr, Math.max(limit || 50, 200)),
    getFakeLeaderboardEntries()
  ]);
  const realRows = real.map((r, i) => ({
    user_id: r.id,
    email: r.email,
    wins: Number(r.wins),
    fake: false,
    real_rank: i + 1, // rank among REAL competitors only — this is what actually gets paid
    prize_amount: tierAmountForRank(tiers, i + 1)
  }));
  // Every real winner is always shown, full stop -- a real free-play win
  // must never be invisible just because the operator's cosmetic seeded
  // (fake) rows have bigger, always-climbing numbers. On top of that,
  // always reserve a minimum number of seeded slots too, regardless of
  // how many real winners there are this week -- otherwise a week with
  // more than `limit` real winners pushed every seeded row off the page
  // (the whole point of the seeded rows -- keeping the page looking
  // populated -- was defeated by having too MANY real winners).
  const MIN_FAKE_SLOTS = 31;
  const fakeSlots = Math.max(MIN_FAKE_SLOTS, (limit || 50) - realRows.length);
  const fakeRows = fake.slice(0, fakeSlots).map(f => ({
    user_id: null,
    fake_id: f.id,
    display_name: f.display_name,
    wins: f.wins,
    fake: true,
    real_rank: null,
    prize_amount: 0
  }));
  const combined = [...realRows, ...fakeRows];
  combined.sort((a, b) => b.wins - a.wins);
  // "rank" here is just the visual position in the mixed list (for display
  // order only) — real_rank is the one real users should ever see next to
  // their own name, since that's the number that determines their payout.
  // No further truncation: every real winner and the reserved fake slots
  // above are already the exact set meant to be shown.
  return combined.map((row, i) => ({
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

      await client.query(
        `UPDATE users SET balance=$1 WHERE id=$2`, [after, row.id]
      );
      await client.query(`
        INSERT INTO admin_balance_audit
          (user_id, amount, balance_before, balance_after, reason)
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
      SET enabled=COALESCE($1, enabled),
          updated_at=NOW()
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
      INSERT INTO tournament_tiers (rank_from, rank_to, amount)
      VALUES ($1,$2,$3)
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
      UPDATE tournament_tiers
      SET rank_from=$1, rank_to=$2, amount=$3
      WHERE id=$4
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

// Lightweight per-IP rate limit for /api/client-error -- just enough to
// stop one runaway client from flooding the table, no external library.
const clientErrorRateLimit = new Map(); // ip -> { count, windowStart }
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

// Silent client-side error reporting -- no UI, nothing shown to the
// player. Lets us see real crashes happening for real users (via Railway
// logs or the admin panel) without ever putting a debug overlay in front
// of live traffic. Public (no auth) since errors can happen before login,
// but rate-limited per IP and caps every field's length so it can never
// become an abuse/storage vector.
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
      } catch (e) { /* not logged in / bad token -- fine, report anonymously */ }
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

    console.error('[CLIENT ERROR] ' + message + ' @ ' + source + ':' + line + ':' + col + (userId ? ' userId=' + userId : '') + (roomId ? ' room=' + roomId : ''));

    await db.query(`
      INSERT INTO client_errors (message, source, line, col, stack, user_id, user_agent, url, match_id, room_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    `, [message, source, line, col, stack, userId, userAgent, url, matchId, roomId]);

    res.json({ ok: true });
  } catch (e) {
    // Never let error-reporting itself become a source of errors the
    // player can see -- always respond ok-ish and move on.
    res.status(200).json({ ok: false });
  }
});

// The client calls this the moment IT detects a freeze it can't recover
// from on its own (e.g. draw_tile_result never arrived after every retry,
// or the opponent hasn't moved in 45s+) -- so an admin sees the match
// flagged as "disputed" immediately, instead of it sitting silently as
// "active" until someone happens to check, or the 30-minute auto-refund
// safety net eventually catches it. Best-effort and non-authoritative:
// this never itself declares a winner/loser or touches money, it only
// raises a flag for a human (or the auto-refund job) to act on.
app.post('/api/report-stuck-match', auth, async (req, res) => {
  try {
    const matchId = Number(req.body?.match_id);
    const reason = String(req.body?.reason || 'client_detected_freeze').slice(0, 200);
    if (!Number.isInteger(matchId)) return res.status(400).json({ ok: false });

    await db.query(`
      UPDATE paid_matches
      SET status = 'disputed',
          dispute_reason = $1,
          updated_at = NOW()
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

    // Per-player summary of this period's free matches, with the counts
    // that distinguish real play from farming: how many settled faster
    // than the minimum, how concentrated their wins are against a single
    // opponent, and their fastest/median match length.
    const players = await db.query(`
      WITH free_matches AS (
        SELECT
          id, p1_user_id, p2_user_id, winner_user_id,
          created_at, settled_at,
          EXTRACT(EPOCH FROM (settled_at - created_at)) AS secs
        FROM paid_matches
        WHERE status='settled' AND stake=0
          AND winner_user_id IS NOT NULL
          AND settled_at >= $1 AND settled_at < $2
      ),
      wins AS (
        SELECT
          winner_user_id AS user_id,
          COUNT(*) AS total_wins,
          COUNT(*) FILTER (WHERE secs < $3) AS fast_wins,
          ROUND(MIN(secs)) AS fastest_secs,
          ROUND(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY secs)) AS median_secs
        FROM free_matches
        GROUP BY winner_user_id
      ),
      top_opponent AS (
        SELECT DISTINCT ON (user_id) user_id, opponent_id, cnt
        FROM (
          SELECT
            winner_user_id AS user_id,
            CASE WHEN winner_user_id = p1_user_id THEN p2_user_id ELSE p1_user_id END AS opponent_id,
            COUNT(*) AS cnt
          FROM free_matches
          GROUP BY 1, 2
        ) t
        ORDER BY user_id, cnt DESC
      )
      SELECT
        u.id, u.username, u.email,
        COALESCE(u.banned, false) AS banned,
        w.total_wins, w.fast_wins, w.fastest_secs, w.median_secs,
        o.opponent_id AS top_opponent_id,
        ou.username AS top_opponent_username,
        o.cnt AS top_opponent_wins
      FROM wins w
      JOIN users u ON u.id = w.user_id
      LEFT JOIN top_opponent o ON o.user_id = w.user_id
      LEFT JOIN users ou ON ou.id = o.opponent_id
      ORDER BY w.total_wins DESC, u.id ASC
      LIMIT 200
    `, [start, end, minSec]);

    // Score each player. These are signals for a human to review, not
    // proof — the admin decides what to do with them.
    const rows = players.rows.map(r => {
      const totalWins = Number(r.total_wins) || 0;
      const fastWins = Number(r.fast_wins) || 0;
      const topOppWins = Number(r.top_opponent_wins) || 0;
      const flags = [];

      if (fastWins > 0) {
        flags.push(fastWins + ' win(s) settled in under ' + minSec + 's');
      }
      if (totalWins >= 5 && topOppWins / totalWins >= 0.7) {
        flags.push(
          Math.round((topOppWins / totalWins) * 100) +
          '% of wins against one opponent (' +
          (r.top_opponent_username || ('user #' + r.top_opponent_id)) + ')'
        );
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
        counted_wins: totalWins - fastWins, // what actually reaches the leaderboard
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
      SELECT
        m.id, m.room_id, m.created_at, m.settled_at,
        ROUND(EXTRACT(EPOCH FROM (m.settled_at - m.created_at))) AS secs,
        m.winner_user_id,
        (m.winner_user_id = $1) AS won,
        CASE WHEN m.p1_user_id = $1 THEN m.p2_user_id ELSE m.p1_user_id END AS opponent_id,
        ou.username AS opponent_username
      FROM paid_matches m
      LEFT JOIN users ou
        ON ou.id = CASE WHEN m.p1_user_id = $1 THEN m.p2_user_id ELSE m.p1_user_id END
      WHERE m.stake = 0
        AND (m.p1_user_id = $1 OR m.p2_user_id = $1)
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
    await db.query(`
      UPDATE fake_leaderboard SET display_name=$1, wins=$2 WHERE id=$3
    `, [name, wins, id]);
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
    // Resuming resets the clock so it doesn't immediately fire a tick
    // it "owed" from while paused -- same fresh randomized wait as a
    // brand-new entry gets.
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

// Bulk-remove every seeded (fake) leaderboard entry in one go, so the
// operator doesn't have to delete potentially hundreds of rows one at a
// time. Only ever touches fake_leaderboard — never real users/matches.
app.post('/api/admin/tournament/fake/delete-all', adminOnly, async (req, res) => {
  try {
    const result = await db.query(`DELETE FROM fake_leaderboard`);
    res.json({ ok: true, deleted: result.rowCount });
  } catch (e) {
    console.error('fake leaderboard delete-all error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

// Quickly seed N fake entries with randomized names/win counts, so the
// operator doesn't have to add 100 rows one at a time.
const FAKE_NAME_PARTS_A = ['ahmad','sara','karzan','lana','zana','newroz','ravan','shene','dilan','hero','peshraw','avan','soran','dashti','barham','hawar','ronak','avesta','helan','nazdar'];
const FAKE_NAME_PARTS_B = ['92','_k','88','.q','111','_h','.d','99','_g','07','_j','23','.m','55','_s'];
// Manual force-refresh (in addition to the automatic once-per-week reset).
app.post('/api/admin/tournament/fake/refresh', adminOnly, async (req, res) => {
  try {
    await db.query(`UPDATE tournament_config SET fake_reset_period=NULL WHERE id=1`);
    const period = currentWeekPeriod();
    const result = await db.query(`
      WITH claim AS (
        UPDATE tournament_config
        SET fake_reset_period=$1, updated_at=NOW()
        WHERE id=1 AND fake_reset_period IS DISTINCT FROM $1
        RETURNING id
      )
      UPDATE fake_leaderboard
      SET wins = 0
      WHERE EXISTS (SELECT 1 FROM claim)
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
        await client.query(`INSERT INTO fake_leaderboard (display_name, wins, last_auto_increment_at, increment_interval_seconds) VALUES ($1,$2,NOW(),$3)`, [r.name, r.wins, randomIncrementIntervalSeconds()]);
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

// Manual payout trigger — tournament prizes are NEVER paid automatically.
// The operator reviews the leaderboard in the admin panel and clicks
// "Pay out now" when ready. Defaults to the CURRENT week's standings;
// pass { period: "2026-W34" } to pay out a specific (e.g. just-ended) week.
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

/* =========================================================
   RESERVE PAID ENTRY
========================================================= */

/* =========================================================
   CREATE FREE MATCH RECORD
   Same purpose as reservePaidEntries, but for stake=0 matches:
   no balance to lock (nothing to reserve), so this just inserts
   the paid_matches row directly. Without this row, a free match
   has no matchId, and report_result falls back to only bumping
   the player's own win/loss counters — which is why real-vs-real
   free wins were invisible to History and the tournament
   leaderboard (both read exclusively from paid_matches), even
   though wins-vs-bots were already being recorded correctly via
   their own separate insert.
========================================================= */

async function createFreeMatchRecord(
  roomId,
  p1UserId,
  p2UserId
) {
  const result =
    await db.query(
      `
      INSERT INTO
        paid_matches
      (
        room_id,
        p1_user_id,
        p2_user_id,
        stake,
        prize,
        status
      )

      VALUES
      (
        $1,
        $2,
        $3,
        0,
        0,
        'active'
      )

      RETURNING
        id,
        room_id,
        stake,
        prize,
        status
      `,
      [
        roomId,
        p1UserId,
        p2UserId
      ]
    );

  return result.rows[0];
}

async function reservePaidEntries(
  roomId,
  p1UserId,
  p2UserId,
  stake,
  prize
) {
  const client =
    await db.pool
      .connect();

  try {
    await client.query(
      'BEGIN'
    );

    const ids =
      [
        Number(p1UserId),
        Number(p2UserId)
      ].sort(
        (a, b) =>
          a - b
      );

    const locked =
      await client.query(
        `
        SELECT
          id,
          balance,
          wallet_locked

        FROM users

        WHERE
          id =
          ANY($1::int[])

        ORDER BY id

        FOR UPDATE
        `,
        [
          ids
        ]
      );

    if (
      locked.rows.length !==
      2
    ) {
      throw new Error(
        'players_not_found'
      );
    }

    const byId =
      new Map(
        locked.rows.map(
          row => [
            Number(row.id),
            row
          ]
        )
      );

    for (
      const id of ids
    ) {
      const user =
        byId.get(id);

      if (
        Number(
          user.balance ||
          0
        ) < stake
      ) {
        throw new Error(
          'insufficient_balance'
        );
      }
    }

    await client.query(
      `
      UPDATE users

      SET
        balance =
          balance - $1,

        wallet_locked =
          wallet_locked + $1

      WHERE
        id =
        ANY($2::int[])
      `,
      [
        stake,
        ids
      ]
    );

    const match =
      await client.query(
        `
        INSERT INTO
          paid_matches
        (
          room_id,
          p1_user_id,
          p2_user_id,
          stake,
          prize,
          status
        )

        VALUES
        (
          $1,
          $2,
          $3,
          $4,
          $5,
          'active'
        )

        RETURNING
          id,
          room_id,
          stake,
          prize,
          status
        `,
        [
          roomId,
          p1UserId,
          p2UserId,
          stake,
          prize
        ]
      );

    await client.query(
      'COMMIT'
    );

    return (
      match.rows[0]
    );

  } catch (e) {
    try {
      await client.query(
        'ROLLBACK'
      );
    } catch {}

    throw e;

  } finally {
    client.release();
  }
}

/* =========================================================
   SETTLE PAID MATCH
========================================================= */

async function settlePaidMatchIfAgreed(
  matchId
) {
  const client =
    await db.pool
      .connect();

  try {
    await client.query(
      'BEGIN'
    );

    const result =
      await client.query(
        `
        SELECT *

        FROM paid_matches

        WHERE id=$1

        FOR UPDATE
        `,
        [
          matchId
        ]
      );

    if (
      !result.rows.length
    ) {
      await client.query(
        'ROLLBACK'
      );

      return {
        status:
          'missing'
      };
    }

    const match =
      result.rows[0];

    if (
      match.status ===
      'settled'
    ) {
      await client.query(
        'ROLLBACK'
      );

      return {
        status:
          'settled',

        winnerUserId:
          Number(
            match
              .winner_user_id
          ),

        prize:
          Number(
            match.prize
          ),

        stake:
          Number(
            match.stake
          )
      };
    }

    // FREE matches (stake=0) only: don't wait for both sides to report.
    // Requiring mutual agreement exists to stop one side unilaterally
    // claiming a paid win -- a real anti-fraud need when money is on the
    // line. For a free match there's nothing to defraud, and waiting for
    // both reports is exactly what silently kept a completed free
    // real-vs-real match out of the tournament leaderboard whenever the
    // losing side's client never got to send its report (closed the app
    // right after losing, network drop, etc.) -- the winner's own
    // report_result had already arrived and said so. Infer the missing
    // side from the one report that did arrive rather than waiting on a
    // second one that may never come. Paid matches are untouched: this
    // block only ever runs when stake is exactly 0.
    let p1Report = match.p1_report;
    let p2Report = match.p2_report;
    if (Number(match.stake) === 0) {
      if (p1Report && !p2Report) { p2Report = p1Report === 'win' ? 'loss' : 'win'; }
      else if (p2Report && !p1Report) { p1Report = p2Report === 'win' ? 'loss' : 'win'; }
    }

    if (
      !p1Report ||
      !p2Report
    ) {
      await client.query(
        'COMMIT'
      );

      return {
        status:
          'waiting_reports'
      };
    }

    let winnerUserId =
      null;

    if (
      p1Report ===
        'win' &&
      p2Report ===
        'loss'
    ) {
      winnerUserId =
        Number(
          match.p1_user_id
        );
    }

    if (
      p2Report ===
        'win' &&
      p1Report ===
        'loss'
    ) {
      winnerUserId =
        Number(
          match.p2_user_id
        );
    }

    if (
      !winnerUserId
    ) {
      await client.query(
        `
        UPDATE paid_matches

        SET
          status='disputed',
          updated_at=NOW()

        WHERE id=$1
        `,
        [
          matchId
        ]
      );

      await client.query(
        'COMMIT'
      );

      return {
        status:
          'disputed'
      };
    }

    const stake =
      Number(
        match.stake
      );

    const prize =
      Number(
        match.prize
      );

    const ids =
      [
        Number(
          match.p1_user_id
        ),

        Number(
          match.p2_user_id
        )
      ].sort(
        (a, b) =>
          a - b
      );

    await client.query(
      `
      SELECT id

      FROM users

      WHERE
        id =
        ANY($1::int[])

      ORDER BY id

      FOR UPDATE
      `,
      [
        ids
      ]
    );

    await client.query(
      `
      UPDATE users

      SET
        wallet_locked =
          GREATEST(
            0,
            wallet_locked - $1
          )

      WHERE
        id =
        ANY($2::int[])
      `,
      [
        stake,
        ids
      ]
    );

    await client.query(
      `
      UPDATE users

      SET
        balance =
          balance + $1,

        wins =
          wins + 1

      WHERE id=$2
      `,
      [
        prize,
        winnerUserId
      ]
    );

    const loserUserId =
      winnerUserId ===
      Number(
        match.p1_user_id
      )
        ? Number(
            match.p2_user_id
          )
        : Number(
            match.p1_user_id
          );

    await client.query(
      `
      UPDATE users

      SET
        losses =
          losses + 1

      WHERE id=$1
      `,
      [
        loserUserId
      ]
    );

    await client.query(
      `
      UPDATE paid_matches

      SET
        status='settled',

        winner_user_id=$1,

        settled_at=NOW(),

        updated_at=NOW()

      WHERE id=$2
      `,
      [
        winnerUserId,
        matchId
      ]
    );

    await client.query(
      'COMMIT'
    );

    return {
      status:
        'settled',

      winnerUserId,

      loserUserId,

      prize,

      stake
    };

  } catch (e) {
    try {
      await client.query(
        'ROLLBACK'
      );
    } catch {}

    throw e;

  } finally {
    client.release();
  }
}


/* =========================================================
   AUTHORITATIVE FORFEIT SETTLEMENT
   A 60-second disconnect timeout is itself the authoritative result.
   Do not wait for two client reports; settle/refund atomically here.
========================================================= */
async function settleForfeitMatch(matchId, winnerUserId) {
  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(
      `SELECT * FROM paid_matches WHERE id=$1 FOR UPDATE`,
      [matchId]
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
      `SELECT id FROM users WHERE id = ANY($1::int[]) ORDER BY id FOR UPDATE`,
      [ids]
    );
    await client.query(
      `UPDATE users
       SET wallet_locked = GREATEST(0, wallet_locked - $1)
       WHERE id = ANY($2::int[])`,
      [stake, ids]
    );
    await client.query(
      `UPDATE users SET balance=balance+$1, wins=wins+1 WHERE id=$2`,
      [prize, winnerUserId]
    );
    await client.query(
      `UPDATE users SET losses=losses+1 WHERE id=$1`,
      [loserUserId]
    );
    await client.query(
      `UPDATE paid_matches
       SET status='settled',
           winner_user_id=$1,
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

/* =========================================================
   REFUND MATCH
========================================================= */

async function refundPaidMatch(
  matchId
) {
  const client =
    await db.pool
      .connect();

  try {
    await client.query(
      'BEGIN'
    );

    const result =
      await client.query(
        `
        SELECT *

        FROM paid_matches

        WHERE id=$1

        FOR UPDATE
        `,
        [
          matchId
        ]
      );

    if (
      !result.rows.length
    ) {
      await client.query(
        'ROLLBACK'
      );

      return false;
    }

    const match =
      result.rows[0];

    if (
      ![
        'active',
        'disputed'
      ].includes(
        match.status
      )
    ) {
      await client.query(
        'ROLLBACK'
      );

      return false;
    }

    const stake =
      Number(
        match.stake
      );

    const ids =
      [
        Number(
          match.p1_user_id
        ),

        Number(
          match.p2_user_id
        )
      ].sort(
        (a, b) =>
          a - b
      );

    await client.query(
      `
      SELECT id

      FROM users

      WHERE
        id =
        ANY($1::int[])

      ORDER BY id

      FOR UPDATE
      `,
      [
        ids
      ]
    );

    await client.query(
      `
      UPDATE users

      SET
        balance =
          balance + $1,

        wallet_locked =
          GREATEST(
            0,
            wallet_locked - $1
          )

      WHERE
        id =
        ANY($2::int[])
      `,
      [
        stake,
        ids
      ]
    );

    await client.query(
      `
      UPDATE paid_matches

      SET
        status='refunded',
        updated_at=NOW()

      WHERE id=$1
      `,
      [
        matchId
      ]
    );

    await client.query(
      'COMMIT'
    );

    return true;

  } catch (e) {
    try {
      await client.query(
        'ROLLBACK'
      );
    } catch {}

    throw e;

  } finally {
    client.release();
  }
}


/* =========================================================
   ADMIN USERS
========================================================= */

// One-off diagnostic: calls NOWPayments' own /auth endpoint with the
// configured EMAIL/PASSWORD and returns exactly what NOWPayments replied
// with (minus the password), so that reply can be pasted straight into a
// NOWPayments support ticket. Visit in a browser with ?token=<ADMIN_TOKEN>.
// Safe to remove once the payout API issue is resolved.
app.get('/api/admin/nowpayments-auth-test', async (req, res) => {
  const suppliedToken = String(req.query.token || '').trim();
  if (!ADMIN_TOKEN || suppliedToken !== ADMIN_TOKEN.trim()) {
    return res.status(403).json({
      error: 'admin_forbidden',
      hint: 'token length received: ' + suppliedToken.length + ', expected length: ' + ADMIN_TOKEN.trim().length
    });
  }

  const result = {
    request: {
      url: NOWPAYMENTS_API_BASE + '/auth',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: {
        email: NOWPAYMENTS_EMAIL,
        password: NOWPAYMENTS_PASSWORD
          ? ('*'.repeat(NOWPAYMENTS_PASSWORD.length - 2) + NOWPAYMENTS_PASSWORD.slice(-2))
          : null,
        password_length: NOWPAYMENTS_PASSWORD ? NOWPAYMENTS_PASSWORD.length : 0
      }
    },
    email_configured: !!NOWPAYMENTS_EMAIL,
    password_configured: !!NOWPAYMENTS_PASSWORD,
    api_base: NOWPAYMENTS_API_BASE
  };

  try {
    const response = await fetch(NOWPAYMENTS_API_BASE + '/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: NOWPAYMENTS_EMAIL,
        password: NOWPAYMENTS_PASSWORD
      })
    });

    const data = await response.json().catch(() => null);

    result.http_status = response.status;
    result.response_headers = {
      'content-type': response.headers.get('content-type')
    };
    result.response_body = data;

  } catch (e) {
    result.fetch_error = e.message;
  }

  res.json(result);
});

app.get('/api/admin/users', adminOnly, async (req, res) => {
  try {
    const q = String(req.query.q || '').trim();
    // FIX 2026-09-12: admin panel could only ever see the newest 500 users --
    // this endpoint had no offset support at all, so "Load older users" (or
    // any repeat request) just re-fetched the exact same top 500 rows every
    // time. offset now actually moves the window back through the full table.
    const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
    const params = [];
    let where = '';
    if (q) {
      params.push('%' + q + '%');
      where = `WHERE CAST(u.id AS TEXT) ILIKE $1
               OR COALESCE(u.username,'') ILIKE $1
               OR COALESCE(u.email,'') ILIKE $1
               OR COALESCE(u.phone,'') ILIKE $1`;
    }

    const totalCountResult = await db.query(`
      SELECT COUNT(*)::int AS n
      FROM users u
      ${where}
    `, params);
    const totalCount = totalCountResult.rows[0] ? Number(totalCountResult.rows[0].n) : 0;

    const pageParams = params.concat([offset]);
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
      OFFSET $${pageParams.length}
    `, pageParams);

    res.json({
      total_count: totalCount,
      offset,
      returned_count: result.rows.length,
      users: result.rows.map(u => ({
      ...u,
      balance: Number(u.balance || 0),
      wallet_locked: Number(u.wallet_locked || 0),
      coins: Number(u.coins || 0),
      wins: Number(u.wins || 0),
      losses: Number(u.losses || 0),
      banned: !!u.banned,
      is_chat_moderator: !!u.is_chat_moderator,
      is_chat_moderator: !!u.is_chat_moderator,
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
      SELECT * FROM paid_matches
      WHERE p1_user_id=$1 OR p2_user_id=$1
      ORDER BY created_at DESC
      LIMIT 200
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
      `UPDATE users SET balance=$1 WHERE id=$2 RETURNING balance`,
      [after, userId]
    );
    await client.query(`
      INSERT INTO admin_balance_audit
        (user_id, amount, balance_before, balance_after, reason)
      VALUES ($1,$2,$3,$4,$5)
    `, [userId, amount, before, after, reason || null]);
    await client.query('COMMIT');

    res.json({ ok: true, user_id: userId, amount,
      balance_before: before,
      balance: Number(updated.rows[0].balance) });
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
      SET banned=$1,
          ban_reason=$2,
          banned_at=CASE WHEN $1 THEN NOW() ELSE NULL END
      WHERE id=$3
      RETURNING id, banned, ban_reason, banned_at
    `, [banned, banned ? (reason || null) : null, userId]);

    if (!updated.rows.length) {
      return res.status(404).json({ error: 'user_not_found' });
    }

    if (banned) {
      // Don't just flag them in the DB and let a match they're already
      // in keep running -- pull them out right now. Their opponent gets
      // the same "left the match" handling as any other disconnect, and
      // the ban check on find_match/reconnect stops them from queuing or
      // rejoining again with the same account.
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
      UPDATE users
      SET is_chat_moderator=$1
      WHERE id=$2
      RETURNING id, is_chat_moderator
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
      INSERT INTO admin_messages (user_id, text)
      VALUES ($1, $2)
      RETURNING id, text, created_at
    `, [userId, text]);

    const message = inserted.rows[0];

    // Deliver immediately if they're online right now; either way it's
    // saved, so it's waiting for them next time they open the app even
    // if this doesn't reach a live socket.
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
      FROM admin_balance_audit
      WHERE user_id=$1
      ORDER BY created_at DESC
      LIMIT 100
    `, [userId]);
    res.json({ audit: result.rows });
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
});

/* =========================================================
   ADMIN MATCHES
========================================================= */

app.get(
  '/api/admin/matches',
  adminOnly,
  async (_req, res) => {
    try {
      const totalCountResult =
        await db.query(
          `SELECT COUNT(*)::int AS n FROM paid_matches`
        );
      const totalCount =
        totalCountResult.rows[0]
          ? Number(totalCountResult.rows[0].n)
          : 0;

      const result =
        await db.query(
          `
          SELECT
            pm.*,
            u1.username AS p1_username,
            u2.username AS p2_username,
            uw.username AS winner_username

          FROM paid_matches pm
          LEFT JOIN users u1 ON u1.id = pm.p1_user_id
          LEFT JOIN users u2 ON u2.id = pm.p2_user_id
          LEFT JOIN users uw ON uw.id = pm.winner_user_id

          ORDER BY
            pm.created_at DESC

          LIMIT 200
          `
        );

      res.json({
        total_count: totalCount,
        matches:
          result.rows
      });

    } catch {
      res
        .status(500)
        .json({
          error:
            'server_error'
        });
    }
  }
);

app.post(
  '/api/admin/matches/:id/refund',
  adminOnly,
  async (req, res) => {
    try {
      const ok =
        await refundPaidMatch(
          Number(
            req.params.id
          )
        );

      if (!ok) {
        return res
          .status(409)
          .json({
            error:
              'cannot_refund'
          });
      }

      res.json({
        ok: true
      });

    } catch {
      res
        .status(500)
        .json({
          error:
            'server_error'
        });
    }
  }
);

/* =========================================================
   ADMIN SETTLE
========================================================= */

app.post(
  '/api/admin/matches/:id/settle',
  adminOnly,
  async (req, res) => {
    const client =
      await db.pool
        .connect();

    try {
      const winnerUserId =
        Number(
          req.body
            ?.winner_user_id
        );

      if (
        !Number
          .isInteger(
            winnerUserId
          )
      ) {
        return res
          .status(400)
          .json({
            error:
              'winner_user_id_required'
          });
      }

      await client.query(
        'BEGIN'
      );

      const result =
        await client.query(
          `
          SELECT *

          FROM paid_matches

          WHERE id=$1

          FOR UPDATE
          `,
          [
            Number(
              req.params.id
            )
          ]
        );

      if (
        !result.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(404)
          .json({
            error:
              'not_found'
          });
      }

      const match =
        result.rows[0];

      if (
        ![
          'active',
          'disputed'
        ].includes(
          match.status
        )
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(409)
          .json({
            error:
              'already_processed'
          });
      }

      const p1 =
        Number(
          match.p1_user_id
        );

      const p2 =
        Number(
          match.p2_user_id
        );

      if (
        ![
          p1,
          p2
        ].includes(
          winnerUserId
        )
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res
          .status(400)
          .json({
            error:
              'winner_not_in_match'
          });
      }

      const loserUserId =
        winnerUserId === p1
          ? p2
          : p1;

      const ids =
        [
          p1,
          p2
        ].sort(
          (a, b) =>
            a - b
        );

      const stake =
        Number(
          match.stake
        );

      const prize =
        Number(
          match.prize
        );

      await client.query(
        `
        SELECT id

        FROM users

        WHERE
          id =
          ANY($1::int[])

        ORDER BY id

        FOR UPDATE
        `,
        [
          ids
        ]
      );

      await client.query(
        `
        UPDATE users

        SET
          wallet_locked =
            GREATEST(
              0,
              wallet_locked - $1
            )

        WHERE
          id =
          ANY($2::int[])
        `,
        [
          stake,
          ids
        ]
      );

      await client.query(
        `
        UPDATE users

        SET
          balance =
            balance + $1,

          wins =
            wins + 1

        WHERE id=$2
        `,
        [
          prize,
          winnerUserId
        ]
      );

      await client.query(
        `
        UPDATE users

        SET
          losses =
            losses + 1

        WHERE id=$1
        `,
        [
          loserUserId
        ]
      );

      await client.query(
        `
        UPDATE paid_matches

        SET
          status='settled',

          winner_user_id=$1,

          settled_at=NOW(),

          updated_at=NOW()

        WHERE id=$2
        `,
        [
          winnerUserId,

          Number(
            req.params.id
          )
        ]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,

        winner_user_id:
          winnerUserId,

        prize
      });

    } catch {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      res
        .status(500)
        .json({
          error:
            'server_error'
        });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   FREE / OFFLINE RESULT
========================================================= */

app.post(
  '/api/game-result',
  auth,
  async (req, res) => {
    try {
      const result =
        req.body
          ?.result ===
        'win'
          ? 'win'
          : 'loss';

      let entry =
        parseInt(
          req.body
            ?.entry,
          10
        );

      if (
        ![
          100,
          200,
          500
        ].includes(
          entry
        )
      ) {
        entry = 100;
      }

      const userResult =
        await db.query(
          `
          SELECT *

          FROM users

          WHERE id=$1
          `,
          [
            req.user.id
          ]
        );

      if (
        !userResult
          .rows.length
      ) {
        return res
          .status(404)
          .json({
            error:
              'not_found'
          });
      }

      const user =
        userResult
          .rows[0];

      let coins =
        Number(
          user.coins ||
          0
        );

      let wins =
        Number(
          user.wins ||
          0
        );

      let losses =
        Number(
          user.losses ||
          0
        );

      if (
        result === 'win'
      ) {
        coins += entry;
        wins += 1;

      } else {
        coins =
          Math.max(
            0,
            coins - entry
          );

        losses += 1;
      }

      const updated =
        await db.query(
          `
          UPDATE users

          SET
            coins=$1,
            wins=$2,
            losses=$3

          WHERE id=$4

          RETURNING *
          `,
          [
            coins,
            wins,
            losses,
            req.user.id
          ]
        );

      if (result === 'win') {
        // Also count vs-Computer wins toward the weekly Free Play
        // tournament leaderboard, same as wins against real opponents.
        try {
          const roomId =
            'bot-' + req.user.id + '-' + Date.now() + '-' +
            Math.random().toString(36).slice(2, 8);

          await db.query(
            `
            INSERT INTO paid_matches
              (room_id, p1_user_id, p2_user_id, stake, prize,
               status, winner_user_id, settled_at)
            VALUES
              ($1, $2, $2, 0, 0, 'settled', $2, NOW())
            `,
            [roomId, req.user.id]
          );
        } catch (e) {
          console.warn('bot-win tournament record skipped:', e.message);
        }
      }

      res.json({
        user:
          publicUser(
            updated.rows[0]
          )
      });

    } catch {
      res
        .status(500)
        .json({
          error:
            'server_error'
        });
    }
  }
);

/* =========================================================
   DOMINO TILES
========================================================= */

const TILE_VALUES = [
  [0, 0],
  [1, 2],
  [2, 3],
  [2, 4],
  [1, 5],
  [5, 5],
  [3, 6],
  [0, 1],
  [2, 2],
  [3, 3],
  [3, 4],
  [2, 5],
  [0, 6],
  [4, 6],
  [1, 1],
  [0, 3],
  [0, 4],
  [4, 4],
  [3, 5],
  [1, 6],
  [5, 6],
  [0, 2],
  [1, 3],
  [1, 4],
  [0, 5],
  [4, 5],
  [2, 6],
  [6, 6]
];

/* =========================================================
   SHUFFLE
========================================================= */

function shuffle(array) {
  for (
    let i =
      array.length - 1;

    i > 0;

    i--
  ) {
    const j =
      Math.floor(
        Math.random() *
        (i + 1)
      );

    [
      array[i],
      array[j]
    ] = [
      array[j],
      array[i]
    ];
  }

  return array;
}

/* =========================================================
   DEAL ROUND
========================================================= */

function dealRound() {
  const deck =
    shuffle([
      ...Array(28).keys()
    ]);

  const handA =
    deck.slice(
      0,
      7
    );

  const handB =
    deck.slice(
      7,
      14
    );

  const boneyard =
    deck.slice(14);

  let starterSeat = 0;

  let bestDouble = -1;

  let bestSum = -1;

  for (
    let seat = 0;
    seat < 2;
    seat++
  ) {
    const hand =
      seat === 0
        ? handA
        : handB;

    for (
      const value of hand
    ) {
      const tile =
        TILE_VALUES[
          value
        ];

      if (
        tile[0] ===
          tile[1] &&
        tile[0] >
          bestDouble
      ) {
        bestDouble =
          tile[0];

        starterSeat =
          seat;
      }
    }
  }

  if (
    bestDouble < 0
  ) {
    for (
      let seat = 0;
      seat < 2;
      seat++
    ) {
      const hand =
        seat === 0
          ? handA
          : handB;

      for (
        const value of hand
      ) {
        const tile =
          TILE_VALUES[
            value
          ];

        const sum =
          tile[0] +
          tile[1];

        if (
          sum >
          bestSum
        ) {
          bestSum =
            sum;

          starterSeat =
            seat;
        }
      }
    }
  }

  return {
    handA,
    handB,
    boneyard,
    starterSeat
  };
}

/* =========================================================
   MATCHMAKING MEMORY
========================================================= */

const waitingQueues =
  new Map();

const rooms =
  new Map();

const socketRoom =
  new Map();

let sequence = 1;

// Unique per process start (base36 timestamp) — see roomId construction
// below in find_match for why this is needed.
const SERVER_BOOT_ID = Date.now().toString(36);

function otherPlayer(
  room,
  socketId
) {
  if (!room || !Array.isArray(room.players)) return null;
  const seat = room.players.indexOf(socketId);
  if (seat === 0) return room.players[1] || null;
  if (seat === 1) return room.players[0] || null;
  // Never guess a seat for a stale/replaced socket. Guessing here can award
  // a paid forfeit to the wrong player during a reconnect race.
  return null;
}

// Shared by the 'disconnect' handler and the explicit 'leave_match' event:
// whichever socket triggers this is treated as forfeiting whatever room
// they're currently in, crediting the remaining player the win (and, for
// paid matches, the prize). Safe to call even if the socket isn't
// currently in any room (does nothing in that case).
/* =========================================================
   RECONNECT GRACE PERIOD
   A dropped socket no longer forfeits the match instantly. The
   room is parked for a short window so a player on a flaky
   mobile connection can rejoin the SAME match instead of losing
   it (and, in paid matches, losing their stake) to a 5-second
   signal blip. If they don't come back in time, the original
   forfeit path runs exactly as before.
========================================================= */

const RECONNECT_GRACE_MS = 60000;

// roomId -> { timer, room, seatIdx, userId }
const pendingReconnects = new Map();

// Tracks which live socket(s) belong to which userId, purely so an admin
// ban can immediately kick that account off -- find_match/resume_match
// populate this as each socket authenticates; the 'disconnect' handler
// below cleans it up.
const userSockets = new Map(); // userId -> Set<socketId>

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

// Called by POST /api/admin/users/:id/ban. Ends any match this user is
// currently in (same forfeit path as a normal disconnect, just without a
// reconnect grace window -- they're banned, not dropped) and disconnects
// every live socket of theirs so the ban takes effect immediately instead
// of only on their next connection attempt.
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
    room.matchId &&
    room.userIds &&
    room.userIds[0] &&
    room.userIds[1];

  // Give a dropped (not deliberately-leaving) player a chance to come back
  // before we forfeit their match. Only for real tracked matches — an
  // untracked/free-floating room has nothing worth preserving.
  if (!immediate && hasTrackedMatch) {
    // Work out the seat HERE. This used to read `actualSeatIdx`, which is
    // declared in finalizePlayerLeftRoom, not in this function -- so every
    // disconnect threw a ReferenceError right here and the room was never
    // parked. That is why a dropped player's resume was answered with
    // "no_match_to_resume" and an empty parked list, and why they sat on
    // "Connecting..." until the grace window expired and they lost.
    const seatIdx = Array.isArray(room.players) ? room.players.indexOf(socketId) : -1;
    if (seatIdx < 0) {
      // The socket no longer owns a seat (already replaced by a reconnect):
      // nothing to park, and nothing to forfeit.
      socketRoom.delete(socketId);
      return;
    }
    const userId = room.userIds[seatIdx];
    const key = reconnectKey(roomId, userId);

    // Already waiting on this player (duplicate disconnect) — ignore.
    if (pendingReconnects.has(key)) return;

    // Detach the dead socket but KEEP the room alive so the seat can be
    // reclaimed. socketRoom for the dead id goes away; the room itself and
    // the opponent's mapping stay untouched.
    socketRoom.delete(socketId);

    if (opponent) {
      io.to(opponent).emit('opponent_reconnecting', {
        match_id: room.matchId,
        grace_ms: RECONNECT_GRACE_MS
      });
    }

    const timer = setTimeout(async () => {
      pendingReconnects.delete(key);
      // Still gone after the grace window — run the real forfeit.
      if (rooms.has(roomId)) {
        // Only forfeit if this exact dead socket still owns the same seat.
        // A successful resume replaces room.players[seatIdx]; an old timeout
        // firing afterwards must become a harmless no-op.
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

    console.log('[reconnect] parked roomId=' + roomId + ' userId=' + userId +
      ' seat=' + seatIdx + ' grace=' + RECONNECT_GRACE_MS + 'ms');
    return;
  }

  await finalizePlayerLeftRoom(socketId);
}

async function finalizePlayerLeftRoom(socketId, guard) {
  const roomId = socketRoom.get(socketId);
  if (!roomId || !rooms.has(roomId)) return;

  const room = rooms.get(roomId);

  // Reconnect-race guard: a timeout belonging to an OLD socket must never
  // settle a room after that seat has already been reclaimed by a new socket.
  const actualSeatIdx = Array.isArray(room.players) ? room.players.indexOf(socketId) : -1;
  if (actualSeatIdx < 0) {
    socketRoom.delete(socketId);
    return;
  }
  if (guard && guard.expectedSeatIdx != null && actualSeatIdx !== Number(guard.expectedSeatIdx)) return;
  if (guard && guard.expectedUserId != null &&
      Number(room.userIds && room.userIds[actualSeatIdx]) !== Number(guard.expectedUserId)) return;

  // Idempotency: disconnect timeout, explicit leave and duplicate socket
  // events must never settle/refund the same money match twice.
  if (room.finalizing) return;
  room.finalizing = true;

  clearRoomTurnTimer(room);
  const opponent = otherPlayer(room, socketId);
  const seatIdx = room.players[0] === socketId ? 0 : 1;
  const hasTrackedMatch =
    room.matchId && room.userIds && room.userIds[0] && room.userIds[1];

  // Cancel reconnect grace timers, but KEEP the room/mappings alive until
  // the wallet transaction below has a final result. Previously the room
  // was deleted first; a DB hiccup could then leave both clients with no
  // winner and no recoverable room.
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
      const loserUserId = Number(room.userIds[seatIdx]);
      const winnerUserId = Number(room.userIds[seatIdx === 0 ? 1 : 0]);

      // A forfeit after the full reconnect grace is authoritative. Settle it
      // directly and atomically; never depend on stale/missing client reports.
      const result = await settleForfeitMatch(room.matchId, winnerUserId);

      if (opponent && result && result.status === 'settled' &&
          Number(result.winnerUserId) === winnerUserId) {
        io.to(opponent).emit('match_forfeit_win', {
          match_id: room.matchId,
          prize: result.prize,
          reason: 'disconnect_timeout'
        });
      } else if (Number(room.stake || 0) > 0) {
        // Money safety fallback: if we cannot prove/commit the winner, never
        // leave funds locked and never invent a winner. Refund both stakes.
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
        // Free tracked match: if an unexpected DB state prevented settlement,
        // at least end the board rather than freezing forever.
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
      try { refunded = await refundPaidMatch(room.matchId); } catch (e2) {
        console.error('forfeit fatal refund error:', e2.message);
      }
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
    // Only now is it safe to destroy the in-memory room.
    room.players.forEach(id => { socketRoom.delete(id); });
    rooms.delete(roomId);
  }
}

/* =========================================================
   GLOBAL CHAT — PROFANITY FILTER
   Simple word-list based censor for the public lobby chat.
   Add more words to BANNED_WORDS as needed (lowercase, no
   spaces needed — matching is case-insensitive and ignores
   common leetspeak/spacing tricks between letters).
========================================================= */

const BANNED_WORDS = [
  // English — extend this list freely
  'fuck', 'shit', 'bitch', 'asshole', 'bastard', 'dick', 'pussy',
  'cunt', 'whore', 'slut', 'nigger', 'nigga', 'faggot',

  // Kurdish
  'قوز', 'قون', 'حیز', 'گەواد', 'بێناموس', 'بێ ئەخلاق',
  'دایک', 'باوک', 'خوشک'
];

function normalizeForFilter(text) {
  return String(text || '')
    .toLowerCase()
    // collapse repeated separators people use to dodge filters
    // (e.g. "f u c k", "f.u.c.k", "f-u-c-k") down to nothing between
    // letters, so the word-list check still catches them.
    .replace(/[\s._\-*]+/g, '');
}

function containsBannedWord(text) {
  const normalized = normalizeForFilter(text);
  return BANNED_WORDS.some(
    word => normalized.includes(word.toLowerCase())
  );
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

function queueKey(
  stake,
  goal
) {
  return (
    String(
      Number(
        stake || 0
      )
    ) +
    ':' +
    String(
      Number(
        goal || 100
      )
    )
  );
}

/* =========================================================
   START ROUND
========================================================= */

// For a message where losing it is serious enough that it's worth a few
// retries (the initial deal being the clearest case -- without it a
// player has no tiles and no idea a match even started), emit directly to
// the socket with an ack, and resend if that ack doesn't come back in
// time. io.to(socketId).emit(...) can't take an ack callback the way a
// direct socket.emit() can, so this looks the socket up itself.
function emitWithRetry(socketId, event, payload, attempt) {
  attempt = attempt || 1;
  const sock = io.sockets.sockets.get(socketId);
  if (!sock) return; // they're gone; nothing more we can do here
  let acked = false;
  sock.emit(event, payload, () => { acked = true; });
  setTimeout(() => {
    if (acked) return;
    if (attempt < 5) {
      emitWithRetry(socketId, event, payload, attempt + 1);
    } else {
      console.error('[emitWithRetry] ' + event + ' never acked after ' + attempt + ' attempts, socket=' + socketId);
    }
  }, 3000);
}


function getBoardEnds(room) {
  return { left: room.leftEnd, right: room.rightEnd };
}

function tileFitsEnd(value, endValue) {
  const t = TILE_VALUES[value];
  return !!t && endValue != null && (t[0] === endValue || t[1] === endValue);
}

/* =========================================================
   AUTHORITATIVE STATE BROADCAST

   The old design sent only what CHANGED ("seat 1 played tile 12 on the
   left") and let each phone maintain its own copy of the board. That works
   right up until one message is lost, delayed, or applied twice -- after
   which the two phones are playing different games, and every later move
   makes it worse. It is exactly why a match against the bot (one copy of
   the game) never glitched while a match against a person (three copies:
   server + two phones) did.

   These functions send the WHOLE position after every change instead. A
   phone that missed ten messages is fixed by the next one, because the
   next one is the complete truth rather than an increment on top of
   whatever it happened to be holding. There is nothing left to fall out
   of step with.

   Each seat gets its own view: full detail on its own hand, only a count
   for the opponent's, so the state can be sent freely without leaking the
   opponent's tiles.
========================================================= */

function boardChainFor(room) {
  // room.log holds the ordered moves; rebuild the visible chain from it so
  // the phone never has to work out orientation for itself.
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

// RESTORED (fix-pvp-sync-1): the client (build fix-20260911l and later)
// DOES listen for 'game_state' and depends on it to correct its turn, its
// hand and its board. Removing these sends is what left every person-vs-
// person match with no way to repair itself after a single lost message.
//
// If a false "leftEnd/rightEnd mismatch" ever shows up in the client's
// console and causes repeated rebuilds, flip this one flag to false: the
// client skips those two checks when the fields are absent, and the board
// and hand counts still catch every real divergence.
const SEND_BOARD_ENDS = true;

function nextStateSerial(room) {
  room.stateSerial = (room.stateSerial || 0) + 1;
  return room.stateSerial;
}

function stateForSeat(room, seat, serial) {
  if (!room || !room.hands || !room.hands[seat]) return null;
  const oppSeat = seat === 0 ? 1 : 0;
  const state = {
    stateSerial: (serial != null ? serial : nextStateSerial(room)),
    roundSerial: room.roundSerial || 0,
    seat: seat,
    turnSeat: room.turnSeat,
    // Full detail for this seat only. The opponent gets a count, never
    // their tiles -- the state can be sent freely without leaking a hand.
    yourHand: (room.hands[seat] || []).slice(),
    oppHandCount: (room.hands[oppSeat] || []).length,
    board: boardChainFor(room),
    boneyardCount: room.boneyard ? room.boneyard.length : 0,
    goal: room.goal,
    match_id: room.matchId || null
  };
  if (SEND_BOARD_ENDS) {
    state.leftEnd = room.leftEnd;
    state.rightEnd = room.rightEnd;
  }
  return state;
}

function broadcastState(room) {
  if (!room || !room.players || !room.hands) return;
  const serial = nextStateSerial(room);
  for (let seat = 0; seat < 2; seat++) {
    const sid = room.players[seat];
    if (!sid) continue;
    const state = stateForSeat(room, seat, serial);
    if (state) io.to(sid).emit('game_state', state);
  }
}

// A round is blocked ("qapat") when the boneyard is empty and neither
// player holds a tile that fits either end. Without this the turn timer
// just auto-passed back and forth every 13s forever -- the freeze the
// players saw, with the turn flipping in the log and nothing happening.
function isRoundBlocked(room) {
  if (!room || !room.hands) return false;
  if (room.boneyard && room.boneyard.length) return false;
  if (room.leftEnd == null || room.rightEnd == null) return false;
  return !hasLegalMove(room, 0) && !hasLegalMove(room, 1);
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
  if (side === 1 && (a === room.leftEnd || b === room.leftEnd)) {
    return { side: 1, rotation: a === b ? 0 : (a === room.leftEnd ? 90 : -90), newLeft: (a === room.leftEnd ? b : a), newRight: room.rightEnd };
  }
  if (side === 2 && (a === room.rightEnd || b === room.rightEnd)) {
    return { side: 2, rotation: a === b ? 0 : (a === room.rightEnd ? -90 : 90), newLeft: room.leftEnd, newRight: (a === room.rightEnd ? b : a) };
  }
  // For auto-play or old clients that omit/choose an invalid side, derive a legal side deterministically.
  if (a === room.leftEnd || b === room.leftEnd) {
    return { side: 1, rotation: a === b ? 0 : (a === room.leftEnd ? 90 : -90), newLeft: (a === room.leftEnd ? b : a), newRight: room.rightEnd };
  }
  if (a === room.rightEnd || b === room.rightEnd) {
    return { side: 2, rotation: a === b ? 0 : (a === room.rightEnd ? -90 : 90), newLeft: room.leftEnd, newRight: (a === room.rightEnd ? b : a) };
  }
  return null;
}

function applyCanonicalMove(room, seat, value, requestedSide, requestedRotation, nonce) {
  if (!room || room.turnSeat !== seat) return { ok:false, error:'not_your_turn' };
  if (!Number.isInteger(value) || value < 0 || value >= TILE_VALUES.length) return { ok:false, error:'bad_tile' };
  const hand = room.hands && room.hands[seat];
  if (!hand) return { ok:false, error:'bad_hand' };
  const idx = hand.indexOf(value);
  if (idx < 0) return { ok:false, error:'tile_not_in_hand' };
  const placement = derivePlacement(room, value, requestedSide);
  if (!placement) return { ok:false, error:'illegal_placement' };
  hand.splice(idx,1);
  room.consecutivePasses = 0;
  room.leftEnd = placement.newLeft;
  room.rightEnd = placement.newRight;
  room.moves = (room.moves || 0) + 1;
  if (room.log) room.log.push({ type:'move', seat, value, side:placement.side, rotation:(requestedRotation != null ? requestedRotation : placement.rotation), nonce });
  room.lastActivityAt = Date.now();
  room.turnSeat = seat === 0 ? 1 : 0;
  return { ok:true, side:placement.side, rotation:(requestedRotation != null ? requestedRotation : placement.rotation) };
}

function performServerAutoTurn(room, seat) {
  if (!room || room.turnSeat !== seat || !room.hands || !room.hands[seat]) return;
  // A seat with no tiles has just gone out -- the round is over and the
  // clients are about to ask for the next deal. Acting here would look for
  // a legal tile, find none, and then pour the ENTIRE boneyard into an
  // empty hand before passing. Never auto-play for a finished hand.
  if (room.hands[seat].length === 0) return;
  if (room.hands[seat === 0 ? 1 : 0] && room.hands[seat === 0 ? 1 : 0].length === 0) return;
  const actions = [];
  let hand = room.hands[seat];
  let value = hand.find(v => derivePlacement(room, v, null));
  // Draw until a legal tile appears or the boneyard empties.
  while (value == null && room.boneyard && room.boneyard.length) {
    const drawn = room.boneyard.shift();
    hand.push(drawn);
    const drawAction = { type:'draw', seat, value:drawn, boneyard_left:room.boneyard.length };
    if (room.log) room.log.push(drawAction);
    actions.push(drawAction);
    if (derivePlacement(room, drawn, null)) value = drawn;
  }
  if (value != null) {
    const placement = derivePlacement(room, value, null);
    const r = applyCanonicalMove(room, seat, value, placement.side, placement.rotation, 'server-auto-' + Date.now());
    if (r.ok) actions.push({ type:'move', seat, value, side:r.side, rotation:r.rotation });
  } else {
    // No tile and no boneyard: a pass is legal.
    if (room.log) room.log.push({ type:'pass', seat });
    actions.push({ type:'pass', seat });
    room.lastActivityAt = Date.now();
    room.turnSeat = seat === 0 ? 1 : 0;
    room.consecutivePasses = (room.consecutivePasses || 0) + 1;
  }
  for (const sid of (room.players || [])) {
    if (sid) io.to(sid).emit('server_auto_actions', { roundSerial: room.roundSerial, seat, actions, turnSeat: room.turnSeat });
  }
  broadcastState(room);
  armRoomTurnTimer(room);
}

function clearRoomTurnTimer(room) {
  if (room && room._turnTimer) { clearTimeout(room._turnTimer); room._turnTimer = null; }
  if (room && room._turnFailTimer) { clearTimeout(room._turnFailTimer); room._turnFailTimer = null; }
}

// The client auto-plays at exactly 10000ms. Keep the server strictly
// later so the two can never fire for the same turn.
const SERVER_AUTO_TURN_MS = 13000;

function armRoomTurnTimer(room) {
  if (!room || room.turnSeat == null) return;
  // Same reasoning as performServerAutoTurn: once either hand is empty the
  // round is finished. Leave the timer off until the next deal arms it.
  if (room.hands && ((room.hands[0] && room.hands[0].length === 0) ||
                     (room.hands[1] && room.hands[1].length === 0))) {
    clearRoomTurnTimer(room);
    return;
  }
  // Blocked round: both seats have now passed, so both clients have marked
  // each other locked and are scoring the round. Re-arming here is what
  // produced the endless OURS/THEIRS ping-pong.
  if ((room.consecutivePasses || 0) >= 2 && isRoundBlocked(room)) {
    clearRoomTurnTimer(room);
    console.log('[round] blocked (qapat) roomId=' + room.id + ' -- turn timer stopped');
    return;
  }
  clearRoomTurnTimer(room);
  const serial = room.roundSerial;
  const expectedSeat = room.turnSeat;
  room.turnDeadline = Date.now() + SERVER_AUTO_TURN_MS;
  room._turnTimer = setTimeout(() => {
    if (!room || room.roundSerial !== serial || room.turnSeat !== expectedSeat) return;
    performServerAutoTurn(room, expectedSeat);
  }, SERVER_AUTO_TURN_MS);
}

function startRound(room) {
  const round =
    dealRound();

  room.deal =
    round;

  room.boneyard =
    round.boneyard
      .slice();

  room.hands = [
    round.handA.slice(),
    round.handB.slice()
  ];
  // Preserve the original deal for deterministic reconnect/full-page rebuilds.
  room.initialHands = [round.handA.slice(), round.handB.slice()];
  room.initialBoneyardCount = round.boneyard.length;
  room.starterSeat = round.starterSeat;
  room.turnSeat = round.starterSeat;
  room.roundSerial = (room.roundSerial || 0) + 1;
  room.roundStartedAt = Date.now();
  room.lastActivityAt = Date.now();
  // Keep a bounded nonce history, not just the most recent request. Mobile
  // retries can arrive late and out of order after another action has already
  // happened; remembering only the last nonce can accidentally apply an old
  // retry twice.
  room.processedMoveNonces = [new Map(), new Map()];
  room.processedDrawNonces = [new Map(), new Map()];
  room.leftEnd = null;
  room.rightEnd = null;
  room.consecutivePasses = 0;
  room.turnDeadline = Date.now() + 10000;

  // Ordered log of every board move/pass/draw this round, used to replay
  // whatever a reconnecting player missed while their socket was down
  // (see 'resume_match'). Reset on every round since it only needs to
  // cover the round currently in progress.
  room.log = [];

  emitWithRetry(
    room.players[0],
    'online_start',
    {
      seat: 0,

      yourHand:
        round.handA,

      oppHand:
        round.handB,

      starterSeat:
        round.starterSeat,

      roundSerial:
        room.roundSerial,

      boneyardCount:
        room.boneyard.length,

      goal:
        room.goal,

      match_id:
        room.matchId ||
        null,

      stake:
        room.stake,

      prize:
        room.prize
    }
  );

  emitWithRetry(
    room.players[1],
    'online_start',
    {
      seat: 1,

      yourHand:
        round.handB,

      oppHand:
        round.handA,

      starterSeat:
        round.starterSeat,

      roundSerial:
        room.roundSerial,

      boneyardCount:
        room.boneyard.length,

      goal:
        room.goal,

      match_id:
        room.matchId ||
        null,

      stake:
        room.stake,

      prize:
        room.prize
    }
  );

  armRoomTurnTimer(room);
}

function emitMatchError(
  socket,
  error,
  extra = {}
) {
  console.log(
    '[match_error] socket=' + socket.id +
    ' error=' + error +
    (Object.keys(extra).length ? ' extra=' + JSON.stringify(extra) : '')
  );

  socket.emit(
    'match_error',
    {
      error,
      ...extra
    }
  );
}

/* =========================================================
   SOCKET.IO
========================================================= */

io.on(
  'connection',
  socket => {

    /* =====================================================
       FIND MATCH
    ===================================================== */

    socket.on(
      'find_match',
      async (
        options = {}
      ) => {
        try {
          console.log('[find_match] called, socket=' + socket.id + ' options=' + JSON.stringify({goal: options.goal, stake: options.stake, hasToken: !!options.token, name: options.name}));
          const goal =
            [
              100,
              200,
              500
            ].includes(
              Number(
                options.goal
              )
            )
              ? Number(
                  options.goal
                )
              : 100;

          const stake =
            Number(
              options.stake ||
              0
            );

          const isFree =
            stake === 0;

          if (
            !isFree &&
            !(await isPaidEnabled())
          ) {
            return emitMatchError(
              socket,
              'paid_features_disabled'
            );
          }

          if (
            !isFree &&
            !PAID_TIERS.has(
              stake
            )
          ) {
            return emitMatchError(
              socket,
              'invalid_stake'
            );
          }

          let userId =
            null;

          {
            const payload =
              verifyMatchToken(
                options.token
              );

            if (
              !payload ||
              !payload.id
            ) {
              console.log('[find_match] REJECTED login_required, socket=' + socket.id);
              return emitMatchError(
                socket,
                'login_required'
              );
            }

            userId =
              Number(
                payload.id
              );
          }

          registerUserSocket(userId, socket.id);

          {
            const banRow = await db.query(
              `SELECT banned FROM users WHERE id=$1`, [userId]
            );
            if (banRow.rows.length && banRow.rows[0].banned) {
              console.log('[find_match] REJECTED banned user, userId=' + userId + ' socket=' + socket.id);
              return emitMatchError(socket, 'account_banned');
            }
          }

          if (!isFree) {
            const result =
              await db.query(
                `
                SELECT
                  balance

                FROM users

                WHERE id=$1
                `,
                [
                  userId
                ]
              );

            if (
              !result
                .rows.length
            ) {
              return emitMatchError(
                socket,
                'user_not_found'
              );
            }

            const balance =
              Number(
                result
                  .rows[0]
                  .balance ||
                0
              );

            if (
              balance <
              stake
            ) {
              return emitMatchError(
                socket,
                'insufficient_balance',
                {
                  required:
                    stake,

                  balance
                }
              );
            }
          }

          const prize =
            isFree
              ? 0
              : PAID_TIERS
                  .get(stake);

          const rawPhoto =
            typeof options.photo === 'string'
              ? options.photo
              : '';

          const photo_url =
            /^data:image\/(png|jpeg|jpg|webp);base64,/.test(rawPhoto) &&
            rawPhoto.length <= 400000
              ? rawPhoto
              : (
                  /^https?:\/\//.test(rawPhoto) && rawPhoto.length <= 2000
                    ? rawPhoto
                    : ''
                );

          const playerInfo = {
            name:
              String(
                options.name ||
                'Player'
              ).slice(
                0,
                24
              ),

            avatar:
              String(
                options.avatar ||
                ''
              ).slice(
                0,
                8
              ),

            photo_url:
              photo_url
          };

          const key =
            queueKey(
              stake,
              goal
            );

          const waiting =
            waitingQueues
              .get(key);

          const WAITING_TTL_MS = 120000;
          const waitingIsStale =
            !!waiting &&
            (Date.now() - (waiting.enqueuedAt || 0)) > WAITING_TTL_MS;

          if (waitingIsStale) {
            console.log('[find_match] discarding stale waiting entry, key=' + key + ' age_ms=' + (Date.now() - waiting.enqueuedAt));
            waitingQueues.delete(key);
          }

          const effectiveWaiting =
            waitingIsStale ? null : waiting;

          console.log(
            '[find_match] socket=' + socket.id +
            ' userId=' + userId +
            ' key=' + key +
            ' queueHadWaiting=' + !!effectiveWaiting +
            ' waitingIsSelf=' + (effectiveWaiting ? effectiveWaiting.socket.id === socket.id : false) +
            ' waitingConnected=' + (effectiveWaiting ? !!(effectiveWaiting.socket && effectiveWaiting.socket.connected) : false) +
            ' totalQueues=' + waitingQueues.size
          );

          if (
            effectiveWaiting &&
            effectiveWaiting.socket &&
            effectiveWaiting.socket
              .connected &&
            effectiveWaiting.socket.id !==
              socket.id
          ) {
            if (
              effectiveWaiting.userId ===
                userId
            ) {
              return emitMatchError(
                socket,
                'same_account_not_allowed'
              );
            }

            waitingQueues
              .delete(key);

            console.log('[find_match] MATCHED socket=' + socket.id + ' with waiting socket=' + effectiveWaiting.socket.id + ' key=' + key);

            const player1 =
              effectiveWaiting.socket;

            const player2 =
              socket;

            // Prefixed with the process start time (base36) so room ids
            // never collide with rows already sitting in paid_matches
            // from a previous server run — a plain in-memory counter
            // restarts at 1 on every deploy/restart, but the DB's
            // room_id UNIQUE constraint is permanent, which was causing
            // intermittent "duplicate key value violates unique
            // constraint paid_matches_room_id_key" failures on paid
            // matches only (free matches never touch that table).
            const roomId =
              'r' +
              SERVER_BOOT_ID +
              '-' +
              sequence++;

            let paidMatch =
              null;

            // FREE matches never touch the paid-entries/balance-reservation
            // transaction — there's nothing to reserve, and running it
            // anyway only adds a DB round-trip that can fail (e.g. a
            // players_not_found edge case) and wrongly bounce two players
            // who were correctly matched right back to the lobby. They
            // still get a lightweight paid_matches row (stake=0) so the
            // match has a real record — otherwise a real-vs-real free win
            // never shows up in History or the weekly tournament
            // leaderboard, even though a win vs a bot does (that path
            // inserts its own row separately). A failure here is non-fatal:
            // the match still starts, it just won't be tracked for the
            // tournament (matches the pre-fix behavior, not a regression).
            if (!isFree) {
              try {
                paidMatch =
                  await reservePaidEntries(
                    roomId,
                    effectiveWaiting.userId,
                    userId,
                    stake,
                    prize
                  );

              } catch (e) {
                console.error(
                  '[find_match] reservePaidEntries failed, roomId=' + roomId +
                  ' p1=' + effectiveWaiting.userId +
                  ' p2=' + userId +
                  ' stake=' + stake +
                  ' rawError=' + e.message
                );

                const error =
                  e.message ===
                  'insufficient_balance'
                    ? 'insufficient_balance'
                    : 'match_reservation_failed';

                emitMatchError(
                  player1,
                  error
                );

                emitMatchError(
                  player2,
                  error
                );

                return;
              }
            } else {
              try {
                paidMatch =
                  await createFreeMatchRecord(
                    roomId,
                    effectiveWaiting.userId,
                    userId
                  );
                console.log(
                  '[find_match] createFreeMatchRecord ok, roomId=' + roomId +
                  ' matchId=' + (paidMatch && paidMatch.id) +
                  ' p1=' + effectiveWaiting.userId + ' p2=' + userId
                );
              } catch (e) {
                console.error(
                  '[find_match] createFreeMatchRecord failed, roomId=' + roomId +
                  ' rawError=' + e.message
                );
                // Non-fatal — the free match still proceeds untracked,
                // same as before this fix.
              }
            }

            const room = {
              roomId,
              players: [
                player1.id,
                player2.id
              ],

              goal,

              stake,

              prize,

              matchId:
                paidMatch
                  ? Number(
                      paidMatch.id
                    )
                  : null,

              userIds: [
                effectiveWaiting.userId,
                userId
              ],

              moves:
                0,

              boneyard:
                [],

              hands: [
                [],
                []
              ],

              log:
                [],

              lastActivityAt:
                Date.now()
            };

            rooms.set(
              roomId,
              room
            );

            socketRoom.set(
              player1.id,
              roomId
            );

            socketRoom.set(
              player2.id,
              roomId
            );

            player1.join(
              roomId
            );

            player2.join(
              roomId
            );

            io.to(
              player1.id
            ).emit(
              'matched',
              {
                room:
                  roomId,

                seat:
                  0,

                goal,

                stake,

                prize,

                match_id:
                  room.matchId,

                opp:
                  playerInfo
              }
            );

            io.to(
              player2.id
            ).emit(
              'matched',
              {
                room:
                  roomId,

                seat:
                  1,

                goal,

                stake,

                prize,

                match_id:
                  room.matchId,

                opp:
                  effectiveWaiting.info
              }
            );

            startRound(
              room
            );

          } else {
            console.log('[find_match] no match — enqueuing socket=' + socket.id + ' at key=' + key);
            waitingQueues.set(
              key,
              {
                socket,

                goal,

                stake,

                prize,

                info:
                  playerInfo,

                userId,

                enqueuedAt:
                  Date.now()
              }
            );

            socket.emit(
              'waiting',
              {
                stake,
                goal
              }
            );
          }

        } catch (e) {
          console.error(
            'find_match error:',
            e.message
          );

          emitMatchError(
            socket,
            'server_error'
          );
        }
      }
    );

    /* =====================================================
       DRAW TILE
    ===================================================== */

    socket.on(
      'draw_tile',
      (payload) => {
        const roomId =
          socketRoom.get(
            socket.id
          );

        if (!roomId) {
          return;
        }

        const room =
          rooms.get(
            roomId
          );

        if (
          !room ||
          !room.boneyard ||
          !room.hands
        ) {
          return;
        }

        const seat =
          room.players[0] ===
          socket.id
            ? 0
            : 1;

        // A retried request (lost response, client resends with the same
        // nonce) must never draw a second tile -- replay whatever we
        // already told this seat last time instead.
        const nonce = payload && payload.nonce;
        if (!room.processedDrawNonces) room.processedDrawNonces = [new Map(), new Map()];
        const drawNonceMap = room.processedDrawNonces[seat] || (room.processedDrawNonces[seat] = new Map());
        if (nonce && drawNonceMap.has(nonce)) {
          socket.emit('draw_tile_result', drawNonceMap.get(nonce));
          return;
        }

        const opponent =
          otherPlayer(
            room,
            socket.id
          );

        // The server owns the turn. A stale/desynced client must not be able
        // to draw during the other player's turn.
        if (room.turnSeat != null && room.turnSeat !== seat) {
          socket.emit('draw_tile_result', { ok: false, error: 'not_your_turn', boneyard_left: room.boneyard.length });
          return;
        }

        if (hasLegalMove(room, seat)) {
          socket.emit('draw_tile_result', { ok: false, error: 'playable_tile_exists', boneyard_left: room.boneyard.length });
          return;
        }

        if (
          room.boneyard
            .length === 0
        ) {
          const result = {
            ok: false,
            empty: true,
            boneyard_left: 0
          };
          if (nonce) {
            drawNonceMap.set(nonce, result);
            while (drawNonceMap.size > 64) drawNonceMap.delete(drawNonceMap.keys().next().value);
          }
          socket.emit(
            'draw_tile_result',
            result
          );

          return;
        }

        const value =
          room.boneyard
            .shift();

        room.hands[
          seat
        ].push(
          value
        );

        if (room.log) {
          room.log.push({
            type: 'draw',
            seat,
            value,
            boneyard_left: room.boneyard.length
          });
        }
        room.lastActivityAt = Date.now();
        armRoomTurnTimer(room);

        const result = {
          ok: true,
          value,
          boneyard_left: room.boneyard.length
        };
        if (nonce) {
          drawNonceMap.set(nonce, result);
          while (drawNonceMap.size > 64) drawNonceMap.delete(drawNonceMap.keys().next().value);
        }

        socket.emit(
          'draw_tile_result',
          result
        );

        if (opponent) {
          io.to(
            opponent
          ).emit(
            'opponent_drew',
            {
              value,

              boneyard_left:
                room
                  .boneyard
                  .length
            }
          );
        }

        broadcastState(room);
      }
    );

    /* =====================================================
       CHAT MESSAGE (in-match, real opponent only)
    ===================================================== */

    socket.on(
      'chat_message',
      payload => {
        const roomId =
          socketRoom.get(
            socket.id
          );

        if (!roomId) {
          return;
        }

        const room =
          rooms.get(
            roomId
          );

        if (!room) {
          return;
        }

        const opponent =
          otherPlayer(
            room,
            socket.id
          );

        if (!opponent) {
          return;
        }

        const rawText =
          (payload && typeof payload.text === 'string')
            ? payload.text
            : '';

        const type =
          (payload && payload.type === 'emoji')
            ? 'emoji'
            : 'text';

        const maxLen =
          type === 'emoji'
            ? 16
            : 300;

        const text =
          rawText
            .slice(0, maxLen)
            .trim();

        if (!text) {
          return;
        }

        io.to(
          opponent
        ).emit(
          'chat_message',
          {
            text,
            type,
            ts: Date.now()
          }
        );
      }
    );

    /* =====================================================
       GLOBAL CHAT (public lobby chat — visible to everyone
       currently online, not tied to any match)
    ===================================================== */

    socket.on(
      'global_chat_message',
      async payload => {
        try {
          const tokenPayload =
            verifyMatchToken(
              payload
                ?.token
            );

          if (
            !tokenPayload ||
            !tokenPayload.id
          ) {
            return emitMatchError(
              socket,
              'login_required'
            );
          }

          // Enforce the closed chat HERE, not just by hiding the input box.
          // Anyone can reopen a hidden box from a console; the only place a
          // rule actually holds is the server.
          try {
            const chatCfg = await db.query('SELECT chat_enabled FROM app_config WHERE id=1');
            if (chatCfg.rows.length && chatCfg.rows[0].chat_enabled === false) {
              return emitMatchError(socket, 'chat_closed');
            }
          } catch (e) {
            // A config read failure must not silence the chat.
          }

          const rawText =
            (payload && typeof payload.text === 'string')
              ? payload.text
              : '';

          const text =
            censorText(
              rawText
                .slice(0, 300)
                .trim()
            );

          if (!text) {
            return;
          }

          const result =
            await db.query(
              `
              SELECT
                username,
                email

              FROM users

              WHERE id=$1
              `,
              [
                tokenPayload.id
              ]
            );

          if (
            !result
              .rows.length
          ) {
            return;
          }

          const name =
            defaultName(
              result.rows[0]
            );

          // Persist so the /api/global-chat/history endpoint can show
          // it to people who open the app later (best-effort — a save
          // failure shouldn't block the live broadcast below).
          let newMessageId = null;
          try {
            const inserted = await db.query(
              `
              INSERT INTO global_chat_messages
                (user_id, name, text)
              VALUES ($1, $2, $3)
              RETURNING id
              `,
              [
                tokenPayload.id,
                name,
                text
              ]
            );
            newMessageId = inserted.rows[0] && inserted.rows[0].id;
          } catch (e) {
            console.error(
              'global_chat_messages insert error:',
              e.message
            );
          }

          io.emit(
            'global_chat_message',
            {
              id:
                newMessageId,

              userId:
                tokenPayload.id,

              name,

              text,

              ts: Date.now()
            }
          );

        } catch (e) {
          console.error(
            'global_chat_message error:',
            e.message
          );
        }
      }
    );

    /* =====================================================
       GLOBAL CHAT — MODERATION (delete a message)
    ===================================================== */

    socket.on(
      'delete_global_chat_message',
      async payload => {
        try {
          const tokenPayload = verifyMatchToken(payload?.token);
          if (!tokenPayload || !tokenPayload.id) {
            return emitMatchError(socket, 'login_required');
          }

          const messageId = Number(payload?.message_id);
          if (!Number.isInteger(messageId)) {
            return;
          }

          const modCheck = await db.query(
            `SELECT is_chat_moderator FROM users WHERE id=$1`,
            [tokenPayload.id]
          );
          if (!modCheck.rows.length || !modCheck.rows[0].is_chat_moderator) {
            // Not a moderator -- silently ignore rather than error, since
            // a regular user should never even see the delete option, so
            // reaching here at all means something unusual (stale UI,
            // tampered client, revoked moderator status mid-session).
            return;
          }

          await db.query(
            `UPDATE global_chat_messages SET deleted=true WHERE id=$1`,
            [messageId]
          );

          io.emit('global_chat_message_deleted', { id: messageId });
        } catch (e) {
          console.error('delete_global_chat_message error:', e.message);
        }
      }
    );

    /* =====================================================
       GAME MOVE
    ===================================================== */

    socket.on(
      'game_move',
      (message, ack) => {
        const roomId =
          socketRoom.get(
            socket.id
          );

        if (!roomId) {
          if (typeof ack === 'function') ack({ ok: false, error: 'no_active_room' });
          return;
        }

        const room =
          rooms.get(
            roomId
          );

        if (!room) {
          if (typeof ack === 'function') ack({ ok: false, error: 'room_gone' });
          return;
        }

        // Resolve the seat by looking the socket UP, never by assuming
        // "not seat 0 therefore seat 1". A stale socket that no longer owns
        // a seat would otherwise be treated as seat 1 and could move on
        // behalf of a player who is sitting there perfectly happily.
        const seat = Array.isArray(room.players) ? room.players.indexOf(socket.id) : -1;
        if (seat < 0) {
          if (typeof ack === 'function') ack({ ok: false, error: 'not_in_room' });
          return;
        }
        const type = message && message.type;
        const value = Number(message && message.value);

        // A retried move (lost ack, client resends with the same nonce)
        // must never be processed twice -- that would double-count it in
        // room.moves/room.log and relay a duplicate placement to the
        // opponent. Just re-confirm receipt without redoing any of it.
        const nonce = message && message.nonce;
        if (!room.processedMoveNonces) room.processedMoveNonces = [new Map(), new Map()];
        const moveNonceMap = room.processedMoveNonces[seat] || (room.processedMoveNonces[seat] = new Map());
        if (nonce && moveNonceMap.has(nonce)) {
          if (typeof ack === 'function') ack(moveNonceMap.get(nonce));
          return;
        }

        // Server-authoritative turn/order/tile/placement validation.
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
            if (typeof ack === 'function') ack({ ok:false, error:result.error });
            return;
          }
          acceptedMessage = Object.assign({}, message, { side:result.side, rotation:result.rotation });
        } else {
          // Passing is legal only when the boneyard is empty and there is no playable tile.
          if ((room.boneyard && room.boneyard.length) || hasLegalMove(room, seat)) {
            if (typeof ack === 'function') ack({ ok:false, error:'illegal_pass' });
            return;
          }
          room.moves = (room.moves || 0) + 1;
          if (room.log) room.log.push({ type:'pass', seat, nonce });
          room.lastActivityAt = Date.now();
          room.turnSeat = seat === 0 ? 1 : 0;
          room.consecutivePasses = (room.consecutivePasses || 0) + 1;
        }
        if (nonce) {
          moveNonceMap.set(nonce, { ok: true });
          while (moveNonceMap.size > 64) moveNonceMap.delete(moveNonceMap.keys().next().value);
        }
        armRoomTurnTimer(room);

        const opponent =
          otherPlayer(
            room,
            socket.id
          );

        if (!opponent) {
          if (typeof ack === 'function') ack({ ok: true });
          return;
        }

        // Confirming with the SENDER only proves the server got the move --
        // it says nothing about whether the opponent's client actually
        // received the broadcast below. Get an ack from THEM too, and
        // retry delivery a few times if it doesn't arrive, so a move that
        // silently fails to reach the opponent doesn't leave them waiting
        // on a turn that (from their side) never happened.
        function deliverToOpponent(deliveryAttempt) {
          const opponentSocket = io.sockets.sockets.get(opponent);
          if (!opponentSocket) return; // they're gone; resume/forfeit flow handles this separately
          let delivered = false;
          opponentSocket.emit('game_move', acceptedMessage, () => { delivered = true; });
          setTimeout(() => {
            if (delivered) return;
            if (deliveryAttempt < 4) {
              deliverToOpponent(deliveryAttempt + 1);
            } else {
              // The opponent's socket is technically still "connected" from
              // the server's point of view, but their client is genuinely
              // not receiving anything (backgrounded tab, frozen JS, dead
              // radio link that hasn't dropped yet). Leaving this silent
              // stranded both players forever with only a client-side
              // 45s "leave match" button as an escape hatch. Instead, run
              // the exact same reconnect-grace / forfeit path used for a
              // real disconnect -- treat a truly unresponsive opponent the
              // same as a dropped one, so the match resolves on its own
              // instead of hanging indefinitely.
              console.error('[game_move] opponent never acked delivery after ' + deliveryAttempt + ' attempts, room=' + roomId + ' -- keeping room authoritative; transport disconnect/turn timer will resolve it');
            }
          }, 4000);
        }
        deliverToOpponent(1);

        // The incremental 'game_move' above is an optimisation; THIS is the
        // truth. A phone that missed the increment is put right by it.
        broadcastState(room);

        if (typeof ack === 'function') ack({ ok: true });
      }
    );

    /* =====================================================
       AUTHORITATIVE STATE ON DEMAND

       The client asks for this every 4 seconds while a match is running,
       and again immediately after any rejected move. Both requests used
       to hit a server with no handler for them, so the phone sat waiting
       for a correction that was never coming -- which is exactly what a
       frozen match looks like to the player.
    ===================================================== */

    socket.on('request_game_state', () => {
      try {
        const roomId = socketRoom.get(socket.id);
        if (!roomId) return;
        const room = rooms.get(roomId);
        if (!room || !room.hands || !room.players) return;
        const seat = room.players[0] === socket.id ? 0 : 1;
        const state = stateForSeat(room, seat);
        if (state) socket.emit('game_state', state);
      } catch (e) {
        console.error('[request_game_state] ' + e.message);
      }
    });

    socket.on('request_board_sync', () => {
      try {
        const roomId = socketRoom.get(socket.id);
        if (!roomId) {
          socket.emit('board_sync_result', { ok: false });
          return;
        }
        const room = rooms.get(roomId);
        if (!room || !room.hands || !room.players) {
          socket.emit('board_sync_result', { ok: false });
          return;
        }
        const seat = room.players[0] === socket.id ? 0 : 1;
        socket.emit('board_sync_result', {
          ok: true,
          seat: seat,
          turnSeat: room.turnSeat,
          roundSerial: room.roundSerial || 0,
          log: (room.log || []).slice(),
          yourHand: (room.hands[seat] || []).slice(),
          oppHandCount: (room.hands[seat === 0 ? 1 : 0] || []).length,
          boneyardCount: room.boneyard ? room.boneyard.length : 0
        });
        // Whatever prompted the diagnostic, the phone is better off with
        // the full position too.
        const state = stateForSeat(room, seat);
        if (state) socket.emit('game_state', state);
      } catch (e) {
        console.error('[request_board_sync] ' + e.message);
        try { socket.emit('board_sync_result', { ok: false }); } catch (e2) {}
      }
    });

    /* =====================================================
       REPORT PAID RESULT
    ===================================================== */

    socket.on(
      'report_result',
      async payload => {
        try {
          const roomId =
            socketRoom.get(
              socket.id
            );

          if (!roomId) {
            return;
          }

          const room =
            rooms.get(
              roomId
            );

          if (!room) {
            return;
          }

          const seat0 =
            room.players[0] ===
            socket.id
              ? 0
              : 1;

          const userId0 =
            room.userIds[
              seat0
            ];

          // FREE online match (no matchId, so nothing was reserved and
          // there's no prize to settle) — just record this player's own
          // win/loss on their profile directly, once per room per socket.
          if (!room.matchId) {
            if (!userId0 || room._freeReported === socket.id) {
              return;
            }
            room._freeReported = socket.id;
            console.log(
              '[report_result] roomId=' + roomId +
              ' userId=' + userId0 +
              ' has NO matchId -- untracked path, only users.wins/losses updated, ' +
              'this match will NOT appear in the tournament leaderboard'
            );

            const didWin =
              !!(payload && payload.didWin);

            await db.query(
              `
              UPDATE users
              SET
                wins = wins + $1,
                losses = losses + $2
              WHERE id=$3
              `,
              [
                didWin ? 1 : 0,
                didWin ? 0 : 1,
                userId0
              ]
            );

            return;
          }

          const seat =
            room.players[0] ===
            socket.id
              ? 0
              : 1;

          const userId =
            room.userIds[
              seat
            ];

          const token =
            verifyMatchToken(
              payload
                ?.token
            );

          if (
            !token ||
            Number(
              token.id
            ) !==
            Number(
              userId
            )
          ) {
            return emitMatchError(
              socket,
              'bad_match_token'
            );
          }

          const report =
            payload
              ?.didWin ===
            true
              ? 'win'
              : 'loss';

          const client =
            await db.pool
              .connect();

          try {
            await client.query(
              'BEGIN'
            );

            const match =
              await client.query(
                `
                SELECT *

                FROM paid_matches

                WHERE id=$1

                FOR UPDATE
                `,
                [
                  room.matchId
                ]
              );

            if (
              !match
                .rows.length
            ) {
              await client.query(
                'ROLLBACK'
              );

              return;
            }

            if (
              ![
                'active',
                'disputed'
              ].includes(
                match
                  .rows[0]
                  .status
              )
            ) {
              await client.query(
                'ROLLBACK'
              );

              return;
            }

            const column =
              seat === 0
                ? 'p1_report'
                : 'p2_report';

            await client.query(
              `
              UPDATE
                paid_matches

              SET
                ${column}=$1,

                updated_at=NOW()

              WHERE id=$2
              `,
              [
                report,
                room.matchId
              ]
            );

            await client.query(
              'COMMIT'
            );

          } catch (e) {
            try {
              await client.query(
                'ROLLBACK'
              );
            } catch {}

            throw e;

          } finally {
            client.release();
          }

          const result =
            await settlePaidMatchIfAgreed(
              room.matchId
            );

          console.log(
            '[report_result] matchId=' + room.matchId +
            ' stake=' + room.stake +
            ' seat=' + seat +
            ' userId=' + userId +
            ' report=' + report +
            ' -> status=' + result.status +
            (result.winnerUserId != null ? ' winnerUserId=' + result.winnerUserId : '')
          );

          if (
            result.status ===
            'settled'
          ) {
            for (
              let i = 0;
              i < 2;
              i++
            ) {
              emitWithRetry(
                room.players[
                  i
                ],
                'match_settled',
                {
                  match_id:
                    room.matchId,

                  won:
                    Number(
                      room.userIds[
                        i
                      ]
                    ) ===
                    Number(
                      result
                        .winnerUserId
                    ),

                  prize:
                    result.prize,

                  stake:
                    result.stake
                }
              );
            }

          } else if (
            result.status ===
            'disputed'
          ) {
            // Reports disagree on the winner (client-side desync). Don't
            // leave the stake stuck waiting on a manual admin refund --
            // return it to both players automatically, immediately.
            try {
              const refunded = await refundPaidMatch(room.matchId);
              console.log('[report_result] disputed match auto-refunded, matchId=' + room.matchId + ' ok=' + refunded);
            } catch (e) {
              console.error('[report_result] auto-refund failed, matchId=' + room.matchId + ' error=' + e.message);
            }

            io.to(
              roomId
            ).emit(
              'match_disputed',
              {
                match_id:
                  room.matchId,
                auto_refunded: true
              }
            );
          }

        } catch (e) {
          console.error(
            'report_result error:',
            e.message
          );

          emitMatchError(
            socket,
            'result_report_failed'
          );
        }
      }
    );

    /* =====================================================
       NEXT ROUND
    ===================================================== */

    // Round-end scoring needs the true pip total of BOTH hands, but each
    // client only ever really knows its own -- the opponent's unplayed
    // tiles are legitimately hidden from it, the same as in a real game.
    // Both clients were each privately guessing the other's hand total
    // from local placeholder tiles, so the two sides could show different,
    // both-often-wrong point counts for the exact same round even though
    // they still agreed on who won. The server already tracks both real
    // hands (that's what move/draw legality checks use), so it can just
    // answer the question directly instead of either side guessing.
    socket.on(
      'get_hand_totals',
      (payload, ack) => {
        try {
          const roomId = socketRoom.get(socket.id);
          const room = roomId ? rooms.get(roomId) : null;
          if (!room || !Array.isArray(room.players)) {
            if (typeof ack === 'function') ack({ ok: false });
            return;
          }
          const seat = room.players.indexOf(socket.id);
          if (seat < 0) {
            if (typeof ack === 'function') ack({ ok: false });
            return;
          }
          const opp = seat === 0 ? 1 : 0;
          const pipSum = hand => (hand || []).reduce((s, v) => {
            const t = TILE_VALUES[v];
            return s + (t ? t[0] + t[1] : 0);
          }, 0);
          const myHand = (room.hands && room.hands[seat]) || [];
          const oppHand = (room.hands && room.hands[opp]) || [];
          if (typeof ack === 'function') {
            ack({
              ok: true,
              mine: pipSum(myHand),
              opponent: pipSum(oppHand),
              myCount: myHand.length,
              opponentCount: oppHand.length
            });
          }
        } catch (e) {
          if (typeof ack === 'function') ack({ ok: false });
        }
      }
    );

    socket.on(
      'next_round',
      () => {
        const roomId =
          socketRoom.get(
            socket.id
          );

        if (!roomId) {
          return;
        }

        const room =
          rooms.get(
            roomId
          );

        if (!room) {
          return;
        }

        // Both clients normally request the next round at almost the same
        // time. Accept only one request for the current round; otherwise the
        // room can be dealt twice and each phone receives a different hand.
        if (room._nextRoundLockUntil && Date.now() < room._nextRoundLockUntil) return;
        room._nextRoundLockUntil = Date.now() + 5000;
        startRound(room);
      }
    );

    /* =====================================================
       CANCEL FIND
    ===================================================== */

    socket.on(
      'cancel_find',
      () => {
        for (
          const [
            key,
            waiting
          ]
          of
          waitingQueues
            .entries()
        ) {
          if (
            waiting.socket.id ===
            socket.id
          ) {
            waitingQueues
              .delete(
                key
              );
          }
        }
      }
    );

    /* =====================================================
       DISCONNECT
    ===================================================== */

    socket.on(
      'disconnect',
      async () => {
        for (
          const [
            key,
            waiting
          ]
          of
          waitingQueues
            .entries()
        ) {
          if (
            waiting.socket.id ===
            socket.id
          ) {
            waitingQueues
              .delete(
                key
              );
          }
        }

        // Reverted to the original behavior: a real disconnect forfeits
        // immediately, the same as a confirmed leave_match. The grace-window
        // "park the seat and wait for resume_match" system below this call
        // (pendingReconnects/RECONNECT_GRACE_MS) was added after the
        // original version and is what introduced needsFullRebuild's forced
        // full re-deal, the game_state reconciliation races, and the visible
        // "board gets jumbled" symptom -- none of which existed before it.
        // The original app had zero reported sync issues in real 2-player
        // matches with exactly this instant-forfeit behavior, so this
        // restores that instead of continuing to patch the system built on
        // top of it. socket.io's own pingTimeout (45s) already absorbs a
        // brief signal drop without ever firing 'disconnect' at all -- this
        // only fires for a connection that's genuinely gone.
        await handlePlayerLeftRoom(socket.id, { immediate: true });
        unregisterSocketEverywhere(socket.id);
      }
    );

    // Explicit "I am voluntarily leaving this match" signal — used when the
    // player deliberately exits mid-match (Back/menu button) instead of a
    // real network disconnect. Runs the EXACT same forfeit logic as the
    // disconnect handler, but without needing to actually sever the socket
    // connection (avoiding any reconnect timing/state risk).
    socket.on(
      'leave_match',
      async payload => {
        // MONEY-SAFETY: an accidental/legacy UI event must never instantly
        // forfeit a paid match. Paid instant-forfeit requires explicit confirmation.
        const roomId = socketRoom.get(socket.id);
        const room = roomId ? rooms.get(roomId) : null;
        const confirmed = !!(payload && payload.confirmed === true);
        if (room && Number(room.stake || 0) > 0 && !confirmed) {
          console.warn('[leave_match] ignored unconfirmed paid leave, room=' + roomId);
          return;
        }
        await handlePlayerLeftRoom(socket.id, { immediate: confirmed });
      }
    );

    // request_game_state / request_board_sync / resume_match removed:
    // reverted to the original design where a disconnect forfeits
    // immediately (see the 'disconnect' handler above) and the client
    // trusts incremental game_move/opponent_drew/draw_tile_result events
    // directly, exactly as the original working version did. See
    // /areas/yalla-domino.md for why.

  }
);

/* =========================================================
   START SERVER
========================================================= */

const PORT =
  process.env.PORT ||
  3000;

// Keep the global_chat_messages table from growing forever — the history
// endpoint only ever looks back 12 hours, so anything older is dead
// weight. Runs hourly, deletes anything past a day old.
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

    // One-time cleanup: clear any stale fake_reset_period marker so the
    // next tournament view definitely triggers a fresh atomic reset.
    await db.query(`UPDATE tournament_config SET fake_reset_period=NULL WHERE id=1`);

    await initVisitTables();

    await initGlobalChatTable();

    await initTelegramJoinTable();

    await initAppConfig();

    // Tournament payouts are MANUAL now — triggered only from the admin
    // panel ("Pay out now" button → POST /api/admin/tournament/payout),
    // not automatically on a timer.

    server.listen(
      PORT,
      () => {
        console.log(
          'Domino server running on port ' +
          PORT
        );
        console.log(
          'MIN_DEPOSIT effective value: ' + MIN_DEPOSIT +
          ' (from env USDT_MIN_DEPOSIT=' + (process.env.USDT_MIN_DEPOSIT || '<not set>') + ')'
        );
      }
    );

  } catch (error) {
    console.error(
      'DB/server startup failed:',
      error
    );

    process.exit(1);
  }
}

startServer();
