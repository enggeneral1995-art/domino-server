/*
 * Domino Block Online Server
 * Auth + Profile + USDT Wallet + Free/Paid 1v1 matchmaking
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('./db');

const JWT_SECRET =
  process.env.JWT_SECRET || 'change_this_secret_in_railway';

const ADMIN_TOKEN =
  process.env.ADMIN_TOKEN || '';

const app = express();

app.use(express.json({ limit: '1mb' }));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
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

const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: '*' }
});

/* =========================================================
   PASSWORD / AUTH
========================================================= */

function hashPassword(password) {
  const salt =
    crypto.randomBytes(16).toString('hex');

  const derived =
    crypto
      .scryptSync(password, salt, 64)
      .toString('hex');

  return salt + ':' + derived;
}

function verifyPassword(password, stored) {
  try {
    const [salt, key] =
      String(stored).split(':');

    const derived =
      crypto
        .scryptSync(password, salt, 64)
        .toString('hex');

    const a = Buffer.from(key, 'hex');
    const b = Buffer.from(derived, 'hex');

    return (
      a.length === b.length &&
      crypto.timingSafeEqual(a, b)
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
  if (!token) return null;

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
    String(user.email || 'player')
      .split('@')[0]
  );
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    phone: user.phone || null,

    balance:
      Number(user.balance || 0),

    coins:
      Number(
        user.coins != null
          ? user.coins
          : 500
      ),

    username:
      defaultName(user),

    wins:
      Number(user.wins || 0),

    losses:
      Number(user.losses || 0),

    avatar:
      user.avatar || null
  };
}

function auth(req, res, next) {
  const header =
    req.headers.authorization || '';

  const token =
    header.startsWith('Bearer ')
      ? header.slice(7)
      : null;

  if (!token) {
    return res.status(401).json({
      error: 'no_token'
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
    return res.status(401).json({
      error: 'bad_token'
    });
  }
}

function adminOnly(req, res, next) {
  if (
    !ADMIN_TOKEN ||
    req.headers['x-admin-token'] !==
      ADMIN_TOKEN
  ) {
    return res.status(403).json({
      error: 'admin_forbidden'
    });
  }

  next();
}

/* =========================================================
   HEALTH
========================================================= */

app.get('/', (_req, res) => {
  res.json({
    ok: true,
    service: 'Domino Block',
    version: 'v7-paid-match-escrow'
  });
});

/* =========================================================
   REGISTER
========================================================= */

app.post('/api/register', async (req, res) => {
  try {
    let {
      email,
      phone,
      password
    } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({
        error:
          'email_and_password_required'
      });
    }

    email =
      String(email)
        .trim()
        .toLowerCase();

    if (
      String(password).length < 6
    ) {
      return res.status(400).json({
        error:
          'password_too_short'
      });
    }

    const exists =
      await db.query(
        'SELECT id FROM users WHERE email=$1',
        [email]
      );

    if (exists.rows.length) {
      return res.status(409).json({
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
          hashPassword(password)
        ]
      );

    res.json({
      token:
        makeToken(result.rows[0]),

      user:
        publicUser(result.rows[0])
    });

  } catch (e) {
    console.error(
      'register error:',
      e.message
    );

    res.status(500).json({
      error: 'server_error'
    });
  }
});

/* =========================================================
   LOGIN
========================================================= */

app.post('/api/login', async (req, res) => {
  try {
    let {
      email,
      password
    } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({
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
        'SELECT * FROM users WHERE email=$1',
        [email]
      );

    if (
      !result.rows.length ||
      !verifyPassword(
        password,
        result.rows[0].password_hash
      )
    ) {
      return res.status(401).json({
        error:
          'invalid_credentials'
      });
    }

    res.json({
      token:
        makeToken(result.rows[0]),

      user:
        publicUser(result.rows[0])
    });

  } catch (e) {
    console.error(
      'login error:',
      e.message
    );

    res.status(500).json({
      error: 'server_error'
    });
  }
});

/* =========================================================
   ME / PROFILE
========================================================= */

app.get('/api/me', auth, async (req, res) => {
  try {
    const result =
      await db.query(
        'SELECT * FROM users WHERE id=$1',
        [req.user.id]
      );

    if (!result.rows.length) {
      return res.status(404).json({
        error: 'not_found'
      });
    }

    res.json({
      user:
        publicUser(result.rows[0])
    });

  } catch {
    res.status(500).json({
      error: 'server_error'
    });
  }
});

app.get(
  '/api/profile',
  auth,
  async (req, res) => {
    try {
      const result =
        await db.query(
          'SELECT * FROM users WHERE id=$1',
          [req.user.id]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error: 'not_found'
        });
      }

      res.json({
        user:
          publicUser(result.rows[0])
      });

    } catch {
      res.status(500).json({
        error: 'server_error'
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
      } = req.body || {};

      const sets = [];
      const values = [];

      let index = 1;

      if (
        username !== undefined &&
        username !== null
      ) {
        username =
          String(username).trim();

        if (
          username.length < 2 ||
          username.length > 20
        ) {
          return res.status(400).json({
            error:
              'username_length'
          });
        }

        sets.push(
          `username=$${index++}`
        );

        values.push(username);
      }

      if (
        avatar !== undefined &&
        avatar !== null
      ) {
        avatar =
          String(avatar).trim();

        if (avatar.length > 40) {
          return res.status(400).json({
            error:
              'avatar_invalid'
          });
        }

        sets.push(
          `avatar=$${index++}`
        );

        values.push(avatar);
      }

      if (!sets.length) {
        return res.status(400).json({
          error:
            'nothing_to_update'
        });
      }

      values.push(req.user.id);

      const result =
        await db.query(
          `
          UPDATE users
          SET ${sets.join(', ')}
          WHERE id=$${index}
          RETURNING *
          `,
          values
        );

      res.json({
        user:
          publicUser(result.rows[0])
      });

    } catch (e) {
      console.error(
        'profile update error:',
        e.message
      );

      res.status(500).json({
        error: 'server_error'
      });
    }
  }
);

/* =========================================================
   USDT WALLET
========================================================= */

const USDT_NETWORKS =
  new Set([
    'TRC20',
    'BEP20',
    'ERC20'
  ]);

const USDT_ADDRESSES = {
  TRC20:
    process.env.USDT_TRC20_ADDRESS || '',

  BEP20:
    process.env.USDT_BEP20_ADDRESS || '',

  ERC20:
    process.env.USDT_ERC20_ADDRESS || ''
};

const MIN_WITHDRAW =
  Number(
    process.env.USDT_MIN_WITHDRAW || 10
  );

const MAX_WITHDRAW =
  Number(
    process.env.USDT_MAX_WITHDRAW || 10000
  );

const WITHDRAW_FEE =
  Number(
    process.env.USDT_WITHDRAW_FEE || 0
  );

function validUsdtAddress(
  network,
  address
) {
  address =
    String(address || '').trim();

  if (network === 'TRC20') {
    return /^T[1-9A-HJ-NP-Za-km-z]{33}$/
      .test(address);
  }

  if (
    network === 'BEP20' ||
    network === 'ERC20'
  ) {
    return /^0x[a-fA-F0-9]{40}$/
      .test(address);
  }

  return false;
}

/* =========================================================
   DATABASE TABLES
========================================================= */

async function initWalletTables() {
  await db.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
      wallet_locked NUMERIC(20,8)
      NOT NULL
      DEFAULT 0
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS
      wallet_transactions
    (
      id BIGSERIAL PRIMARY KEY,

      user_id INTEGER NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      type VARCHAR(16) NOT NULL
        CHECK(
          type IN (
            'deposit',
            'withdraw'
          )
        ),

      network VARCHAR(10) NOT NULL,

      amount NUMERIC(20,8)
        NOT NULL
        CHECK(amount >= 0),

      address TEXT,

      tx_hash TEXT,

      status VARCHAR(20)
        NOT NULL
        DEFAULT 'pending',

      fee NUMERIC(20,8)
        NOT NULL
        DEFAULT 0,

      created_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

      updated_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW()
    )
  `);

  await db.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
      wallet_deposit_tx_unique

    ON wallet_transactions(tx_hash)

    WHERE tx_hash IS NOT NULL
  `);

  await db.query(`
    CREATE INDEX IF NOT EXISTS
      wallet_user_idx

    ON wallet_transactions(
      user_id,
      created_at DESC
    )
  `);
}

/* =========================================================
   WALLET
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
          [req.user.id]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error: 'not_found'
        });
      }

      const balance =
        Number(
          result.rows[0].balance || 0
        );

      const locked =
        Number(
          result.rows[0]
            .wallet_locked || 0
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

      res.status(500).json({
        error: 'server_error'
      });
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
          req.body?.network || ''
        ).toUpperCase();

      const txHash =
        String(
          req.body?.tx_hash || ''
        ).trim();

      if (
        !USDT_NETWORKS.has(network)
      ) {
        return res.status(400).json({
          error:
            'invalid_network'
        });
      }

      if (
        !txHash ||
        txHash.length < 20 ||
        txHash.length > 200
      ) {
        return res.status(400).json({
          error:
            'invalid_tx_hash'
        });
      }

      const result =
        await db.query(
          `
          INSERT INTO wallet_transactions
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
      if (e.code === '23505') {
        return res.status(409).json({
          error:
            'tx_hash_already_submitted'
        });
      }

      console.error(
        'deposit error:',
        e.message
      );

      res.status(500).json({
        error: 'server_error'
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
      await db.pool.connect();

    try {
      const network =
        String(
          req.body?.network || ''
        ).toUpperCase();

      const address =
        String(
          req.body?.address || ''
        ).trim();

      const amount =
        Number(
          req.body?.amount
        );

      if (
        !USDT_NETWORKS.has(network)
      ) {
        return res.status(400).json({
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
        return res.status(400).json({
          error:
            'invalid_address_for_network'
        });
      }

      if (
        !Number.isFinite(amount) ||
        amount < MIN_WITHDRAW ||
        amount > MAX_WITHDRAW
      ) {
        return res.status(400).json({
          error:
            'invalid_amount',

          min:
            MIN_WITHDRAW,

          max:
            MAX_WITHDRAW
        });
      }

      await client.query('BEGIN');

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
          [req.user.id]
        );

      if (!userResult.rows.length) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          error: 'not_found'
        });
      }

      if (
        Number(
          userResult.rows[0]
            .balance || 0
        ) < amount
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(400).json({
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
          INSERT INTO wallet_transactions
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
            updated.rows[0].balance
          ),

        locked_balance:
          Number(
            updated.rows[0]
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

      res.status(500).json({
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

          FROM wallet_transactions

          WHERE user_id=$1

          ORDER BY
            created_at DESC

          LIMIT 50
          `,
          [req.user.id]
        );

      res.json({
        transactions:
          result.rows
      });

    } catch {
      res.status(500).json({
        error:
          'server_error'
      });
    }
  }
);

/* =========================================================
   WALLET ADMIN
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

          FROM wallet_transactions

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
      res.status(500).json({
        error:
          'server_error'
      });
    }
  }
);

app.post(
  '/api/admin/wallet/deposit/:id/approve',
  adminOnly,
  async (req, res) => {
    const client =
      await db.pool.connect();

    try {
      const amount =
        Number(
          req.body?.amount
        );

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
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

          FROM wallet_transactions

          WHERE
            id=$1
            AND type='deposit'

          FOR UPDATE
          `,
          [req.params.id]
        );

      if (!tx.rows.length) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          error: 'not_found'
        });
      }

      if (
        tx.rows[0].status !==
        'pending'
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(409).json({
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

          WHERE id=$2

          RETURNING balance
          `,
          [
            amount,
            tx.rows[0].user_id
          ]
        );

      await client.query(
        `
        UPDATE wallet_transactions

        SET
          amount=$1,
          status='confirmed',
          updated_at=NOW()

        WHERE id=$2
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
            updated.rows[0].balance
          )
      });

    } catch (e) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      res.status(500).json({
        error:
          'server_error'
      });

    } finally {
      client.release();
    }
  }
);

app.post(
  '/api/admin/wallet/withdraw/:id/complete',
  adminOnly,
  async (req, res) => {
    const client =
      await db.pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const tx =
        await client.query(
          `
          SELECT *

          FROM wallet_transactions

          WHERE
            id=$1
            AND type='withdraw'

          FOR UPDATE
          `,
          [req.params.id]
        );

      if (!tx.rows.length) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          error: 'not_found'
        });
      }

      if (
        tx.rows[0].status !==
        'pending'
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(409).json({
          error:
            'already_processed'
        });
      }

      const amount =
        Number(
          tx.rows[0].amount
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

          WHERE id=$2

          RETURNING
            balance,
            wallet_locked
          `,
          [
            amount,
            tx.rows[0].user_id
          ]
        );

      await client.query(
        `
        UPDATE wallet_transactions

        SET
          status='completed',
          updated_at=NOW()

        WHERE id=$1
        `,
        [tx.rows[0].id]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,

        balance:
          Number(
            updated.rows[0].balance
          ),

        locked_balance:
          Number(
            updated.rows[0]
              .wallet_locked
          )
      });

    } catch {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      res.status(500).json({
        error:
          'server_error'
      });

    } finally {
      client.release();
    }
  }
);

app.post(
  '/api/admin/wallet/withdraw/:id/reject',
  adminOnly,
  async (req, res) => {
    const client =
      await db.pool.connect();

    try {
      await client.query(
        'BEGIN'
      );

      const tx =
        await client.query(
          `
          SELECT *

          FROM wallet_transactions

          WHERE
            id=$1
            AND type='withdraw'

          FOR UPDATE
          `,
          [req.params.id]
        );

      if (!tx.rows.length) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          error: 'not_found'
        });
      }

      if (
        tx.rows[0].status !==
        'pending'
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(409).json({
          error:
            'already_processed'
        });
      }

      const amount =
        Number(
          tx.rows[0].amount
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

          WHERE id=$2

          RETURNING
            balance,
            wallet_locked
          `,
          [
            amount,
            tx.rows[0].user_id
          ]
        );

      await client.query(
        `
        UPDATE wallet_transactions

        SET
          status='rejected',
          updated_at=NOW()

        WHERE id=$1
        `,
        [tx.rows[0].id]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,

        balance:
          Number(
            updated.rows[0].balance
          ),

        locked_balance:
          Number(
            updated.rows[0]
              .wallet_locked
          )
      });

    } catch {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      res.status(500).json({
        error:
          'server_error'
      });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   PAID MATCH
========================================================= */

const PAID_TIERS =
  new Map([
    [1, 1.90],
    [3, 5.60],
    [5, 9.00]
  ]);

async function initPaidMatchTables() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS
      paid_matches
    (
      id BIGSERIAL PRIMARY KEY,

      room_id TEXT
        UNIQUE
        NOT NULL,

      p1_user_id INTEGER
        NOT NULL
        REFERENCES users(id),

      p2_user_id INTEGER
        NOT NULL
        REFERENCES users(id),

      stake NUMERIC(20,8)
        NOT NULL,

      prize NUMERIC(20,8)
        NOT NULL,

      status VARCHAR(20)
        NOT NULL
        DEFAULT 'active',

      p1_report VARCHAR(8),

      p2_report VARCHAR(8),

      winner_user_id INTEGER
        REFERENCES users(id),

      created_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW(),

      settled_at TIMESTAMPTZ,

      updated_at TIMESTAMPTZ
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

async function reservePaidEntries(
  roomId,
  p1UserId,
  p2UserId,
  stake,
  prize
) {
  const client =
    await db.pool.connect();

  try {
    await client.query(
      'BEGIN'
    );

    const ids =
      [
        Number(p1UserId),
        Number(p2UserId)
      ].sort(
        (a, b) => a - b
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
          id = ANY($1::int[])

        ORDER BY id

        FOR UPDATE
        `,
        [ids]
      );

    if (
      locked.rows.length !== 2
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

    for (const id of ids) {
      if (
        Number(
          byId.get(id).balance || 0
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
        id = ANY($2::int[])
      `,
      [
        stake,
        ids
      ]
    );

    const match =
      await client.query(
        `
        INSERT INTO paid_matches
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

    return match.rows[0];

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

async function settlePaidMatchIfAgreed(
  matchId
) {
  const client =
    await db.pool.connect();

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
        [matchId]
      );

    if (!result.rows.length) {
      await client.query(
        'ROLLBACK'
      );

      return {
        status: 'missing'
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
        status: 'settled',

        winnerUserId:
          Number(
            match.winner_user_id
          ),

        prize:
          Number(match.prize),

        stake:
          Number(match.stake)
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

    let winnerUserId = null;

    if (
      match.p1_report === 'win' &&
      match.p2_report === 'loss'
    ) {
      winnerUserId =
        Number(
          match.p1_user_id
        );
    }

    if (
      match.p2_report === 'win' &&
      match.p1_report === 'loss'
    ) {
      winnerUserId =
        Number(
          match.p2_user_id
        );
    }

    if (!winnerUserId) {
      await client.query(
        `
        UPDATE paid_matches

        SET
          status='disputed',
          updated_at=NOW()

        WHERE id=$1
        `,
        [matchId]
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
      Number(match.stake);

    const prize =
      Number(match.prize);

    const ids =
      [
        Number(
          match.p1_user_id
        ),

        Number(
          match.p2_user_id
        )
      ].sort(
        (a, b) => a - b
      );

    await client.query(
      `
      SELECT id

      FROM users

      WHERE
        id = ANY($1::int[])

      ORDER BY id

      FOR UPDATE
      `,
      [ids]
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
        id = ANY($2::int[])
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
      [loserUserId]
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

async function refundPaidMatch(
  matchId
) {
  const client =
    await db.pool.connect();

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
        [matchId]
      );

    if (!result.rows.length) {
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
        (a, b) => a - b
      );

    await client.query(
      `
      SELECT id

      FROM users

      WHERE
        id = ANY($1::int[])

      ORDER BY id

      FOR UPDATE
      `,
      [ids]
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
        id = ANY($2::int[])
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
      [matchId]
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
   MATCH ADMIN
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
      res.status(500).json({
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
          Number(req.params.id)
        );

      if (!ok) {
        return res.status(409).json({
          error:
            'cannot_refund'
        });
      }

      res.json({
        ok: true
      });

    } catch {
      res.status(500).json({
        error:
          'server_error'
      });
    }
  }
);

app.post(
  '/api/admin/matches/:id/settle',
  adminOnly,
  async (req, res) => {
    const client =
      await db.pool.connect();

    try {
      const winnerUserId =
        Number(
          req.body
            ?.winner_user_id
        );

      if (
        !Number.isInteger(
          winnerUserId
        )
      ) {
        return res.status(400).json({
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

      if (!result.rows.length) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
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

        return res.status(409).json({
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
        ![p1, p2].includes(
          winnerUserId
        )
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(400).json({
          error:
            'winner_not_in_match'
        });
      }

      const loserUserId =
        winnerUserId === p1
          ? p2
          : p1;

      const ids =
        [p1, p2].sort(
          (a, b) => a - b
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
          id = ANY($1::int[])

        ORDER BY id

        FOR UPDATE
        `,
        [ids]
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
          id = ANY($2::int[])
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
        [loserUserId]
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

      res.status(500).json({
        error:
          'server_error'
      });

    } finally {
      client.release();
    }
  }
);

/* =========================================================
   LEGACY FREE COIN RESULT
========================================================= */

app.post(
  '/api/game-result',
  auth,
  async (req, res) => {
    try {
      const result =
        req.body?.result === 'win'
          ? 'win'
          : 'loss';

      let entry =
        parseInt(
          req.body?.entry,
          10
        );

      if (
        ![
          100,
          200,
          500
        ].includes(entry)
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
          [req.user.id]
        );

      if (
        !userResult.rows.length
      ) {
        return res.status(404).json({
          error:
            'not_found'
        });
      }

      const user =
        userResult.rows[0];

      let coins =
        Number(
          user.coins || 0
        );

      let wins =
        Number(
          user.wins || 0
        );

      let losses =
        Number(
          user.losses || 0
        );

      if (result === 'win') {
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

      res.json({
        user:
          publicUser(
            updated.rows[0]
          )
      });

    } catch {
      res.status(500).json({
        error:
          'server_error'
      });
    }
  }
);

/* =========================================================
   ONLINE DOMINO
========================================================= */

const TILE_VALUES = [
  [0,0],
  [1,2],
  [2,3],
  [2,4],
  [1,5],
  [5,5],
  [3,6],
  [0,1],
  [2,2],
  [3,3],
  [3,4],
  [2,5],
  [0,6],
  [4,6],
  [1,1],
  [0,3],
  [0,4],
  [4,4],
  [3,5],
  [1,6],
  [5,6],
  [0,2],
  [1,3],
  [1,4],
  [0,5],
  [4,5],
  [2,6],
  [6,6]
];

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

function dealRound() {
  const deck =
    shuffle([
      ...Array(28).keys()
    ]);

  const handA =
    deck.slice(0, 7);

  const handB =
    deck.slice(7, 14);

  let starterSeat = 0;

  let bestDbl = -1;

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
        TILE_VALUES[value];

      if (
        tile[0] === tile[1] &&
        tile[0] > bestDbl
      ) {
        bestDbl =
          tile[0];

        starterSeat =
          seat;
      }
    }
  }

  if (bestDbl < 0) {
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
          TILE_VALUES[value];

        const sum =
          tile[0] +
          tile[1];

        if (
          sum > bestSum
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
    starterSeat
  };
}

/* =========================================================
   MATCHMAKING
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
    `${Number(stake || 0)}:` +
    `${Number(goal || 100)}`
  );
}

function startRound(room) {
  const round =
    dealRound();

  room.deal =
    round;

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

      goal:
        room.goal,

      match_id:
        room.matchId || null,

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

      goal:
        room.goal,

      match_id:
        room.matchId || null,

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
   SOCKET
========================================================= */

io.on(
  'connection',
  socket => {

    socket.on(
      'find_match',
      async (options = {}) => {
        try {
          const goal =
            [
              100,
              200,
              500
            ].includes(
              Number(options.goal)
            )
              ? Number(options.goal)
              : 100;

          const stake =
            Number(
              options.stake || 0
            );

          const isFree =
            stake === 0;

          if (
            !isFree &&
            !PAID_TIERS.has(stake)
          ) {
            return emitMatchError(
              socket,
              'invalid_stake'
            );
          }

          let userId = null;

          if (!isFree) {
            const payload =
              verifyMatchToken(
                options.token
              );

            if (!payload?.id) {
              return emitMatchError(
                socket,
                'login_required'
              );
            }

            userId =
              Number(payload.id);

            const balanceResult =
              await db.query(
                `
                SELECT balance

                FROM users

                WHERE id=$1
                `,
                [userId]
              );

            if (
              !balanceResult.rows.length
            ) {
              return emitMatchError(
                socket,
                'user_not_found'
              );
            }

            const balance =
              Number(
                balanceResult
                  .rows[0]
                  .balance || 0
              );

            if (
              balance < stake
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
              : PAID_TIERS.get(
                  stake
                );

          const info = {
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
            waitingQueues.get(
              key
            );

          if (
            waiting &&
            waiting.socket.connected &&
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

            waitingQueues.delete(
              key
            );

            const player1 =
              waiting.socket;

            const player2 =
              socket;

            const roomId =
              'r' +
              sequence++;

            let paidMatch =
              null;

            if (!isFree) {
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

              userIds:
                isFree
                  ? [
                      null,
                      null
                    ]
                  : [
                      waiting.userId,
                      userId
                    ],

              moves: 0
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
                  info
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

                info,

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

        io.to(
          otherPlayer(
            room,
            socket.id
          )
        ).emit(
          'game_move',
          message
        );
      }
    );

    /* =====================================================
       REPORT RESULT
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
            !room.matchId ||
            room.stake <= 0
          ) {
            return;
          }

          const seat =
            room.players[0] ===
            socket.id
              ? 0
              : 1;

          const userId =
            room.userIds[seat];

          const token =
            verifyMatchToken(
              payload?.token
            );

          if (
            !token ||
            Number(token.id) !==
              Number(userId)
          ) {
            return emitMatchError(
              socket,
              'bad_match_token'
            );
          }

          const report =
            payload?.didWin === true
              ? 'win'
              : 'loss';

          const client =
            await db.pool.connect();

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
                [room.matchId]
              );

            if (
              !match.rows.length
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
                match.rows[0]
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
              UPDATE paid_matches

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
                room.players[i]
              ).emit(
                'match_settled',
                {
                  match_id:
                    room.matchId,

                  won:
                    Number(
                      room.userIds[i]
                    ) ===
                    Number(
                      result.winnerUserId
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
       CANCEL SEARCH
    ===================================================== */

    socket.on(
      'cancel_find',
      () => {
        for (
          const [
            key,
            waiting
          ]
          of waitingQueues.entries()
        ) {
          if (
            waiting.socket.id ===
            socket.id
          ) {
            waitingQueues.delete(
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
      () => {
        for (
          const [
            key,
            waiting
          ]
          of waitingQueues.entries()
        ) {
          if (
            waiting.socket.id ===
            socket.id
          ) {
            waitingQueues.delete(
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
          rooms.has(roomId)
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

          if (opponent) {
            io.to(
              opponent
            ).emit(
              'opponent_left',
              {
                paid:
                  room.stake > 0,

                match_id:
                  room.matchId
              }
            );
          }

          room.players.forEach(
            id => {
              socketRoom.delete(
                id
              );
            }
          );

          /*
           * Paid balance stays locked
           * if a player disconnects.
           *
           * Admin can later settle
           * or refund the match.
           */

          rooms.delete(
            roomId
          );
        }
      }
    );
  }
);

/* =========================================================
   START SERVER
========================================================= */

const PORT =
  process.env.PORT || 3000;

async function startServer() {
  try {
    await db.init();

    await initWalletTables();

    await initPaidMatchTables();

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
