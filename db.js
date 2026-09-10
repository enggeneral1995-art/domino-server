// db.js — PostgreSQL connection + table setup
// Railway-ready

const { Pool } = require('pg');

const connectionString =
  process.env.DATABASE_URL;

const isInternal =
  !connectionString ||
  connectionString.includes('railway.internal');

const pool = new Pool({
  connectionString,

  ssl: isInternal
    ? false
    : {
        rejectUnauthorized: false
      },

  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

async function init() {
  const maxTries = 10;
  const delayMs = 3000;

  for (
    let attempt = 1;
    attempt <= maxTries;
    attempt++
  ) {
    try {
      await pool.query('SELECT 1');

      /*
       * USERS
       */

      await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,

          email TEXT UNIQUE NOT NULL,

          phone TEXT,

          password_hash TEXT NOT NULL,

          balance NUMERIC(20,8)
            NOT NULL
            DEFAULT 0,

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT now()
        );
      `);

      /*
       * PROFILE
       */

      await pool.query(`
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS
          username TEXT;
      `);

      await pool.query(`
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS
          wins INTEGER
          NOT NULL
          DEFAULT 0;
      `);

      await pool.query(`
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS
          losses INTEGER
          NOT NULL
          DEFAULT 0;
      `);

      await pool.query(`
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS
          avatar TEXT;
      `);

      await pool.query(`
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS
          coins INTEGER
          NOT NULL
          DEFAULT 500;
      `);

      /*
       * WALLET
       */

      await pool.query(`
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS
          wallet_locked NUMERIC(20,8)
          NOT NULL
          DEFAULT 0;
      `);

      /*
       * WALLET TRANSACTIONS
       */

      await pool.query(`
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

          created_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW(),

          updated_at
            TIMESTAMPTZ
            NOT NULL
            DEFAULT NOW()
        );
      `);

      /*
       * Prevent the same blockchain
       * transaction from being submitted
       * twice.
       */

      await pool.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS
          wallet_deposit_tx_unique
        ON wallet_transactions(tx_hash)
        WHERE tx_hash IS NOT NULL;
      `);

      /*
       * Faster transaction history.
       */

      await pool.query(`
        CREATE INDEX IF NOT EXISTS
          wallet_user_idx
        ON wallet_transactions(
          user_id,
          created_at DESC
        );
      `);

      console.log(
        'DB ready: users + profile + coins + wallet'
      );

      return;

    } catch (err) {

      console.log(
        `DB not ready ` +
        `(attempt ${attempt}/${maxTries}):`,
        err.code || err.message
      );

      if (
        attempt === maxTries
      ) {
        console.error(
          'DB connection failed after all retries.'
        );

        throw err;
      }

      await new Promise(
        resolve =>
          setTimeout(
            resolve,
            delayMs
          )
      );
    }
  }
}

function query(
  text,
  params
) {
  return pool.query(
    text,
    params
  );
}

module.exports = {
  pool,
  init,
  query
};
