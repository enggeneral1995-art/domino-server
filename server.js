/*
 * server.js — Domino Block Online Server
 * Auth + Profile + Online 1v1 + USDT Wallet
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('./db');

const JWT_SECRET =
  process.env.JWT_SECRET || 'change_this_secret_in_railway';

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
  cors: {
    origin: '*'
  }
});

/* =========================================================
   PASSWORD
========================================================= */

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');

  const derived = crypto
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

/* =========================================================
   HELPERS
========================================================= */

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

function defaultName(user) {
  if (user.username) {
    return user.username;
  }

  return String(
    user.email || 'player'
  ).split('@')[0];
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

/* =========================================================
   HEALTH
========================================================= */

app.get('/', (_req, res) => {
  res.json({
    ok: true,
    service: 'Domino Block',
    version: 'v6-wallet-safe'
  });
});

/* =========================================================
   AUTH
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

    const passwordHash =
      hashPassword(password);

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
          ($1, $2, $3)
        RETURNING *
        `,
        [
          email,
          phone || null,
          passwordHash
        ]
      );

    const user =
      result.rows[0];

    res.json({
      token:
        makeToken(user),

      user:
        publicUser(user)
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

    if (!result.rows.length) {
      return res.status(401).json({
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
      return res.status(401).json({
        error:
          'invalid_credentials'
      });
    }

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

    res.status(500).json({
      error: 'server_error'
    });
  }
});

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
        publicUser(
          result.rows[0]
        )
    });

  } catch {
    res.status(500).json({
      error: 'server_error'
    });
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
          publicUser(
            result.rows[0]
          )
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
      }

      const sets = [];
      const values = [];
      let index = 1;

      if (
        username !== undefined &&
        username !== null
      ) {
        sets.push(
          `username=$${index++}`
        );
        values.push(username);
      }

      if (
        avatar !== undefined &&
        avatar !== null
      ) {
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
          publicUser(
            result.rows[0]
          )
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

const ADMIN_TOKEN =
  process.env.ADMIN_TOKEN || '';

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
   WALLET TABLES
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
      wallet_transactions (

        id BIGSERIAL PRIMARY KEY,

        user_id INTEGER NOT NULL
          REFERENCES users(id)
          ON DELETE CASCADE,

        type VARCHAR(16) NOT NULL
          CHECK (
            type IN (
              'deposit',
              'withdraw'
            )
          ),

        network VARCHAR(10) NOT NULL,

        amount NUMERIC(20,8)
          NOT NULL
          CHECK (amount >= 0),

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

      const user =
        result.rows[0];

      const balance =
        Number(user.balance || 0);

      const locked =
        Number(
          user.wallet_locked || 0
        );

      res.json({
        balance,
        locked_balance: locked,

        available_balance:
          Math.max(
            0,
            balance
          ),

        currency: 'USDT',

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
   DEPOSIT SUBMISSION
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

      const exists =
        await db.query(
          `
          SELECT id
          FROM wallet_transactions
          WHERE tx_hash=$1
          `,
          [txHash]
        );

      if (exists.rows.length) {
        return res.status(409).json({
          error:
            'tx_hash_already_submitted'
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
      console.error(
        'deposit error:',
        e.message
      );

      if (e.code === '23505') {
        return res.status(409).json({
          error:
            'tx_hash_already_submitted'
        });
      }

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

      await client.query(
        'BEGIN'
      );

      /*
       * Lock this user's row.
       * This prevents two simultaneous
       * withdrawals from spending the
       * same balance.
       */

      const userResult =
        await client.query(
          `
          SELECT
            id,
            balance,
            wallet_locked

          FROM users

          WHERE id=$1

          FOR UPDATE
          `,
          [req.user.id]
        );

      if (
        !userResult.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          error:
            'not_found'
        });
      }

      const balance =
        Number(
          userResult.rows[0]
            .balance || 0
        );

      if (balance < amount) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(400).json({
          error:
            'insufficient_balance'
        });
      }

      /*
       * Reserve balance.
       */

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
            updated.rows[0]
              .balance
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
        error: 'server_error'
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

    } catch (e) {
      console.error(
        'wallet history error:',
        e.message
      );

      res.status(500).json({
        error: 'server_error'
      });
    }
  }
);

/* =========================================================
   ADMIN
========================================================= */

function adminOnly(
  req,
  res,
  next
) {
  if (
    !ADMIN_TOKEN ||
    req.headers['x-admin-token'] !==
      ADMIN_TOKEN
  ) {
    return res.status(403).json({
      error:
        'admin_forbidden'
    });
  }

  next();
}

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

/* =========================================================
   ADMIN — APPROVE DEPOSIT
========================================================= */

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

      /*
       * Lock transaction row.
       */

      const txResult =
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

      if (
        !txResult.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          error:
            'not_found'
        });
      }

      const transaction =
        txResult.rows[0];

      if (
        transaction.status !==
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

      /*
       * Lock user row.
       */

      const userResult =
        await client.query(
          `
          SELECT
            balance

          FROM users

          WHERE id=$1

          FOR UPDATE
          `,
          [
            transaction.user_id
          ]
        );

      if (
        !userResult.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          error:
            'user_not_found'
        });
      }

      /*
       * Credit verified deposit.
       */

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
            transaction.user_id
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
          transaction.id
        ]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,

        balance:
          Number(
            updated.rows[0]
              .balance
          )
      });

    } catch (e) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'deposit approve error:',
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
   ADMIN — COMPLETE WITHDRAW
========================================================= */

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

      const txResult =
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

      if (
        !txResult.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          error:
            'not_found'
        });
      }

      const transaction =
        txResult.rows[0];

      if (
        transaction.status !==
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
          transaction.amount
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
            transaction.user_id
          ]
        );

      if (
        !updated.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          error:
            'user_not_found'
        });
      }

      await client.query(
        `
        UPDATE wallet_transactions

        SET
          status='completed',
          updated_at=NOW()

        WHERE id=$1
        `,
        [transaction.id]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,

        balance:
          Number(
            updated.rows[0]
              .balance
          ),

        locked_balance:
          Number(
            updated.rows[0]
              .wallet_locked
          )
      });

    } catch (e) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'withdraw complete error:',
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
   ADMIN — REJECT WITHDRAW
========================================================= */

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

      const txResult =
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

      if (
        !txResult.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          error:
            'not_found'
        });
      }

      const transaction =
        txResult.rows[0];

      if (
        transaction.status !==
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
          transaction.amount
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
            transaction.user_id
          ]
        );

      if (
        !updated.rows.length
      ) {
        await client.query(
          'ROLLBACK'
        );

        return res.status(404).json({
          error:
            'user_not_found'
        });
      }

      await client.query(
        `
        UPDATE wallet_transactions

        SET
          status='rejected',
          updated_at=NOW()

        WHERE id=$1
        `,
        [transaction.id]
      );

      await client.query(
        'COMMIT'
      );

      res.json({
        ok: true,

        balance:
          Number(
            updated.rows[0]
              .balance
          ),

        locked_balance:
          Number(
            updated.rows[0]
              .wallet_locked
          )
      });

    } catch (e) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      console.error(
        'withdraw reject error:',
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
   GAME RESULT
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

      const resultUser =
        await db.query(
          'SELECT * FROM users WHERE id=$1',
          [req.user.id]
        );

      if (
        !resultUser.rows.length
      ) {
        return res.status(404).json({
          error:
            'not_found'
        });
      }

      const user =
        resultUser.rows[0];

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

      res.json({
        user:
          publicUser(
            updated.rows[0]
          )
      });

    } catch (e) {
      console.error(
        'game-result error:',
        e.message
      );

      res.status(500).json({
        error:
          'server_error'
      });
    }
  }
);

/* =========================================================
   ONLINE DOMINO GAME
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
    let i = array.length - 1;
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

  const scan =
    (hand, seat) => {
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
    };

  scan(handA, 0);
  scan(handB, 1);

  if (
    bestDbl < 0
  ) {
    const scanSum =
      (hand, seat) => {
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
            bestSum = sum;
            starterSeat = seat;
          }
        }
      };

    scanSum(handA, 0);
    scanSum(handB, 1);
  }

  return {
    handA,
    handB,
    starterSeat
  };
}

let waiting = null;
const rooms = new Map();
const socketRoom = new Map();
let sequence = 1;

function otherPlayer(
  room,
  socketId
) {
  return room.players[0] === socketId
    ? room.players[1]
    : room.players[0];
}

function startRound(room) {
  const round =
    dealRound();

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
        room.goal
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
        room.goal
    }
  );
}

io.on(
  'connection',
  socket => {

    socket.on(
      'find_match',
      (options = {}) => {
        const goal =
          [
            100,
            200,
            500
          ].includes(
            options.goal
          )
            ? options.goal
            : 100;

        const player = {
          name:
            String(
              options.name ||
              'Player'
            ).slice(0, 24),

          avatar:
            String(
              options.avatar ||
              ''
            ).slice(0, 8)
        };

        if (
          waiting &&
          waiting.socket.connected &&
          waiting.socket.id !==
            socket.id
        ) {
          const p1 =
            waiting.socket;

          const p1info =
            waiting.info || {
              name:
                'Player',
              avatar:
                ''
            };

          const p2 =
            socket;

          waiting = null;

          const roomId =
            'r' +
            sequence++;

          const room = {
            players: [
              p1.id,
              p2.id
            ],
            goal
          };

          rooms.set(
            roomId,
            room
          );

          socketRoom.set(
            p1.id,
            roomId
          );

          socketRoom.set(
            p2.id,
            roomId
          );

          p1.join(roomId);
          p2.join(roomId);

          io.to(
            p1.id
          ).emit(
            'matched',
            {
              seat: 0,
              goal,
              opp: player
            }
          );

          io.to(
            p2.id
          ).emit(
            'matched',
            {
              seat: 1,
              goal,
              opp: p1info
            }
          );

          startRound(room);

        } else {
          waiting = {
            socket,
            goal,
            info: player
          };

          socket.emit(
            'waiting'
          );
        }
      }
    );

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
          rooms.get(roomId);

        if (!room) {
          return;
        }

        const opponent =
          otherPlayer(
            room,
            socket.id
          );

        io.to(
          opponent
        ).emit(
          'game_move',
          message
        );
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
          rooms.get(roomId);

        if (!room) {
          return;
        }

        startRound(room);
      }
    );

    socket.on(
      'cancel_find',
      () => {
        if (
          waiting &&
          waiting.socket.id ===
            socket.id
        ) {
          waiting = null;
        }
      }
    );

    socket.on(
      'disconnect',
      () => {
        if (
          waiting &&
          waiting.socket.id ===
            socket.id
        ) {
          waiting = null;
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
            rooms.get(roomId);

          const opponent =
            otherPlayer(
              room,
              socket.id
            );

          if (opponent) {
            io.to(
              opponent
            ).emit(
              'opponent_left'
            );
          }

          room.players.forEach(
            id => {
              socketRoom.delete(id);
            }
          );

          rooms.delete(
            roomId
          );
        }
      }
    );
  }
);

/* =========================================================
   START
========================================================= */

const PORT =
  process.env.PORT || 3000;

async function startServer() {
  try {
    await db.init();

    await initWalletTables();

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
