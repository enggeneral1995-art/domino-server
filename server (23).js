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

function verifyNowPaymentsIpn(body, receivedSig) {
  if (
    !NOWPAYMENTS_IPN_SECRET ||
    !receivedSig
  ) {
    return false;
  }

  const sorted =
    sortObjectDeep(body || {});

  const expected =
    crypto
      .createHmac(
        'sha512',
        NOWPAYMENTS_IPN_SECRET
      )
      .update(
        JSON.stringify(sorted)
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

  return (
    a.length === b.length &&
    crypto.timingSafeEqual(a, b)
  );
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
    limit: '1mb'
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
    }
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
      null
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
      ADD COLUMN IF NOT EXISTS photo_url TEXT
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
            hashPassword(
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

app.post(
  '/api/login',
  async (req, res) => {
    try {
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
        !verifyPassword(
          password,
          user.password_hash
        )
      ) {
        return res
          .status(401)
          .json({
            error:
              'invalid_credentials'
          });
      }

      await updateUserLocation(user.id, req);
      recordVisit(user.id);

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
        !verifyPassword(
          currentPassword,
          user.password_hash
        )
      ) {
        return res
          .status(401)
          .json({
            error:
              'incorrect_current_password'
          });
      }

      const newHash =
        hashPassword(newPassword);

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
    INSERT INTO app_config (id, paid_enabled, online_baseline)
    VALUES (1, true, 1000)
    ON CONFLICT (id) DO NOTHING
  `);
}

async function isPaidEnabled() {
  try {
    const result = await db.query(`SELECT paid_enabled FROM app_config WHERE id=1`);
    return result.rows.length ? !!result.rows[0].paid_enabled : true;
  } catch (e) {
    return true;
  }
}

app.get('/api/app-config', async (req, res) => {
  try {
    const cfg = await db.query(`SELECT paid_enabled, online_baseline FROM app_config WHERE id=1`);
    const row = cfg.rows[0] || {};
    res.json({
      paid_enabled: row.paid_enabled !== false,
      online_baseline: row.online_baseline != null ? Number(row.online_baseline) : 1000
    });
  } catch (e) {
    res.json({ paid_enabled: true, online_baseline: 1000 });
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

    const hasPaid = typeof paidEnabled === 'boolean';
    const hasBaseline = onlineBaseline !== undefined && onlineBaseline !== null;

    if (!hasPaid && !hasBaseline) {
      return res.status(400).json({ error: 'nothing_to_update' });
    }
    if (hasBaseline && (!Number.isInteger(onlineBaseline) || onlineBaseline < 0)) {
      return res.status(400).json({ error: 'invalid_online_baseline' });
    }

    await db.query(`
      UPDATE app_config
      SET paid_enabled=COALESCE($1, paid_enabled),
          online_baseline=COALESCE($2, online_baseline),
          updated_at=NOW()
      WHERE id=1
    `, [hasPaid ? paidEnabled : null, hasBaseline ? onlineBaseline : null]);

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
    'TRC20',
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
    15
  );

const MIN_WITHDRAW =
  Number(
    process.env
      .USDT_MIN_WITHDRAW ||
    10
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
              'minimum_deposit_is_15_usdt',

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

              is_fixed_rate:
                true,

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

    if (
      !verifyNowPaymentsIpn(
        req.body,
        signature
      )
    ) {
      return res
        .status(401)
        .json({
          error:
            'bad_ipn_signature'
        });
    }

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
            status ===
              'finished' &&
            transaction.status !==
              'confirmed'
          ) {
            const requestedAmount =
              Number(
                transaction.amount
              );

            const callbackPrice =
              Number(
                payload.price_amount
              );

            if (
              Number.isFinite(
                callbackPrice
              ) &&
              Math.abs(
                callbackPrice -
                requestedAmount
              ) > 0.01
            ) {
              await client.query(
                `
                UPDATE
                  wallet_transactions
                SET
                  status='review',
                  updated_at=NOW()
                WHERE id=$1
                `,
                [
                  transaction.id
                ]
              );

              await client.query(
                'COMMIT'
              );

              return res.json({
                ok: true,
                review:
                  'amount_mismatch'
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
                requestedAmount,
                transaction.user_id
              ]
            );

            await client.query(
              `
              UPDATE
                wallet_transactions
              SET
                status='confirmed',
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
                payout_description:
                  'Yalla Domino withdrawal',

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
   ADMIN WALLET
========================================================= */

app.get(
  '/api/admin/wallet/transactions',
  adminOnly,
  async (_req, res) => {
    try {
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
    res.json({
      today: Number(today.rows[0]?.visitors || 0),
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

async function initFakeLeaderboard() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS fake_leaderboard (
      id BIGSERIAL PRIMARY KEY,
      display_name TEXT NOT NULL,
      wins INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

async function getFakeLeaderboardEntries() {
  const result = await db.query(`
    SELECT id, display_name, wins FROM fake_leaderboard ORDER BY wins DESC, id ASC
  `);
  return result.rows.map(r => ({
    id: r.id,
    fake: true,
    display_name: r.display_name,
    wins: Number(r.wins)
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
  const combined = [
    ...real.map((r, i) => ({
      user_id: r.id,
      email: r.email,
      wins: Number(r.wins),
      fake: false,
      prize_amount: tierAmountForRank(tiers, i + 1) // real rank, not visual rank
    })),
    ...fake.map(f => ({
      user_id: null,
      fake_id: f.id,
      display_name: f.display_name,
      wins: f.wins,
      fake: true,
      prize_amount: 0
    }))
  ];
  combined.sort((a, b) => b.wins - a.wins);
  return combined.slice(0, limit || 50).map((row, i) => ({
    ...row,
    rank: i + 1
  }));
}

async function checkAndPayoutTournament() {
  try {
    const cfg = await db.query(`SELECT * FROM tournament_config WHERE id=1`);
    if (!cfg.rows.length || !cfg.rows[0].enabled) return;

    const period = previousWeekPeriod();

    const already = await db.query(
      `SELECT id FROM tournament_winners WHERE period=$1 LIMIT 1`, [period]
    );
    if (already.rows.length) return;

    const tiers = await getTiers();
    if (!tiers.length) return;

    const maxRank = Math.max(...tiers.map(t => t.rank_to));
    const leaderboard = await getLeaderboardForPeriod(period, maxRank);
    if (!leaderboard.length) return;

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
      }

      await client.query('COMMIT');
      console.log('Weekly tournament paid out for ' + period);
    } catch (e) {
      try { await client.query('ROLLBACK'); } catch {}
      console.error('tournament payout error:', e.message);
    } finally {
      client.release();
    }
  } catch (e) {
    console.error('checkAndPayoutTournament error:', e.message);
  }
}

app.get('/api/tournament/leaderboard', async (req, res) => {
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

app.post('/api/admin/tournament/fake', adminOnly, async (req, res) => {
  try {
    const name = String(req.body?.display_name || '').trim().slice(0, 40);
    const wins = Number(req.body?.wins);
    if (!name) return res.status(400).json({ error: 'display_name_required' });
    if (!Number.isInteger(wins) || wins < 0) return res.status(400).json({ error: 'invalid_wins' });
    const result = await db.query(`
      INSERT INTO fake_leaderboard (display_name, wins)
      VALUES ($1, $2)
      RETURNING id, display_name, wins
    `, [name, wins]);
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

// Quickly seed N fake entries with randomized names/win counts, so the
// operator doesn't have to add 100 rows one at a time.
const FAKE_NAME_PARTS_A = ['ahmad','sara','karzan','lana','zana','newroz','ravan','shene','dilan','hero','peshraw','avan','soran','dashti','barham','hawar','ronak','avesta','helan','nazdar'];
const FAKE_NAME_PARTS_B = ['92','_k','88','.q','111','_h','.d','99','_g','07','_j','23','.m','55','_s'];
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
        await client.query(`INSERT INTO fake_leaderboard (display_name, wins) VALUES ($1,$2)`, [r.name, r.wins]);
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

/* =========================================================
   RESERVE PAID ENTRY
========================================================= */

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

    if (
      !match.p1_report ||
      !match.p2_report
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
      match.p1_report ===
        'win' &&
      match.p2_report ===
        'loss'
    ) {
      winnerUserId =
        Number(
          match.p1_user_id
        );
    }

    if (
      match.p2_report ===
        'win' &&
      match.p1_report ===
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
      losses: Number(u.losses || 0)
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
      const result =
        await db.query(
          `
          SELECT *

          FROM paid_matches

          ORDER BY
            created_at DESC

          LIMIT 200
          `
        );

      res.json({
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

function otherPlayer(
  room,
  socketId
) {
  return (
    room.players[0] ===
    socketId
  )
    ? room.players[1]
    : room.players[0];
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

  io.to(
    room.players[0]
  ).emit(
    'online_start',
    {
      seat: 0,

      yourHand:
        round.handA,

      oppHand:
        round.handB,

      starterSeat:
        round.starterSeat,

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

  io.to(
    room.players[1]
  ).emit(
    'online_start',
    {
      seat: 1,

      yourHand:
        round.handB,

      oppHand:
        round.handA,

      starterSeat:
        round.starterSeat,

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
}

function emitMatchError(
  socket,
  error,
  extra = {}
) {
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
              )
          };

          const key =
            queueKey(
              stake,
              goal
            );

          const waiting =
            waitingQueues
              .get(key);

          if (
            waiting &&
            waiting.socket &&
            waiting.socket
              .connected &&
            waiting.socket.id !==
              socket.id
          ) {
            if (
              !isFree &&
              waiting.userId ===
                userId
            ) {
              return emitMatchError(
                socket,
                'same_account_not_allowed'
              );
            }

            waitingQueues
              .delete(key);

            const player1 =
              waiting.socket;

            const player2 =
              socket;

            const roomId =
              'r' +
              sequence++;

            let paidMatch =
              null;

            try {
              paidMatch =
                await reservePaidEntries(
                  roomId,
                  waiting.userId,
                  userId,
                  stake,
                  prize
                );

            } catch (e) {
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

            const room = {
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
                waiting.userId,
                userId
              ],

              moves:
                0,

              boneyard:
                [],

              hands: [
                [],
                []
              ]
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
                  waiting.info
              }
            );

            startRound(
              room
            );

          } else {
            waitingQueues.set(
              key,
              {
                socket,

                goal,

                stake,

                prize,

                info:
                  playerInfo,

                userId
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

        const opponent =
          otherPlayer(
            room,
            socket.id
          );

        if (
          room.boneyard
            .length === 0
        ) {
          socket.emit(
            'draw_tile_result',
            {
              ok:
                false,

              empty:
                true,

              boneyard_left:
                0
            }
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

        socket.emit(
          'draw_tile_result',
          {
            ok:
              true,

            value,

            boneyard_left:
              room
                .boneyard
                .length
          }
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
      }
    );

    /* =====================================================
       GAME MOVE
    ===================================================== */

    socket.on(
      'game_move',
      message => {
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

        room.moves++;

        const opponent =
          otherPlayer(
            room,
            socket.id
          );

        if (!opponent) {
          return;
        }

        io.to(
          opponent
        ).emit(
          'game_move',
          message
        );
      }
    );

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

          if (
            !room ||
            !room.matchId
          ) {
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

          if (
            result.status ===
            'settled'
          ) {
            for (
              let i = 0;
              i < 2;
              i++
            ) {
              io.to(
                room.players[
                  i
                ]
              ).emit(
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
            io.to(
              roomId
            ).emit(
              'match_disputed',
              {
                match_id:
                  room.matchId
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

        startRound(
          room
        );
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

        const roomId =
          socketRoom.get(
            socket.id
          );

        if (
          roomId &&
          rooms.has(
            roomId
          )
        ) {
          const room =
            rooms.get(
              roomId
            );

          const opponent =
            otherPlayer(
              room,
              socket.id
            );

          room.players
            .forEach(
              id => {
                socketRoom
                  .delete(id);
              }
            );

          rooms.delete(
            roomId
          );

          const hasTrackedMatch =
            room.matchId &&
            room.userIds &&
            room.userIds[0] &&
            room.userIds[1];

          if (hasTrackedMatch) {
            // The disconnecting player forfeits this match (win/loss and,
            // for paid matches, the prize too); the remaining player is
            // credited automatically instead of the board just sitting
            // frozen forever or the innocent player being kicked to the
            // lobby with nothing. Applies to both paid and free matches now
            // that free matches also get a real match record.
            const seatIdx =
              room.players[0] === socket.id ? 0 : 1;
            const loserUserId = room.userIds[seatIdx];
            const winnerUserId = room.userIds[seatIdx === 0 ? 1 : 0];

            try {
              await db.query(
                `
                UPDATE paid_matches
                SET
                  p1_report = CASE
                    WHEN p1_user_id=$1 THEN 'loss'
                    WHEN p1_user_id=$2 THEN 'win'
                    ELSE p1_report
                  END,
                  p2_report = CASE
                    WHEN p2_user_id=$1 THEN 'loss'
                    WHEN p2_user_id=$2 THEN 'win'
                    ELSE p2_report
                  END,
                  updated_at = NOW()
                WHERE id=$3 AND status='active'
                `,
                [loserUserId, winnerUserId, room.matchId]
              );

              const result = await settlePaidMatchIfAgreed(room.matchId);

              if (opponent && result && result.status === 'settled') {
                io.to(opponent).emit('match_forfeit_win', {
                  match_id: room.matchId,
                  prize: result.prize
                });
              } else if (opponent) {
                io.to(opponent).emit('opponent_left', {
                  paid: true,
                  match_id: room.matchId
                });
              }
            } catch (e) {
              console.error('forfeit settle error:', e.message);
              if (opponent) {
                io.to(opponent).emit('opponent_left', {
                  paid: true,
                  match_id: room.matchId
                });
              }
            }
          } else if (opponent) {
            // Free match: nothing to settle financially, just let them know.
            io.to(opponent).emit('opponent_left', {
              paid: room.stake > 0,
              match_id: room.matchId
            });
          }
        }
      }
    );
  }
);

/* =========================================================
   START SERVER
========================================================= */

const PORT =
  process.env.PORT ||
  3000;

async function startServer() {
  try {
    await db.init();

    await initWalletTables();

    await initPaidMatchTables();

    await initAdminUserTools();

    await initTournamentTables();

    await initFakeLeaderboard();

    await initVisitTables();

    await initAppConfig();

    await checkAndPayoutTournament();
    setInterval(checkAndPayoutTournament, 60 * 60 * 1000);

    server.listen(
      PORT,
      () => {
        console.log(
          'Domino server running on port ' +
          PORT
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
