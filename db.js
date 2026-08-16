// db.js — PostgreSQL connection + table setup (Railway-ready, with retry)
const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL;
const isInternal =
  !connectionString || connectionString.includes('railway.internal');

const pool = new Pool({
  connectionString,
  ssl: isInternal ? false : { rejectUnauthorized: false },
});

async function init() {
  const maxTries = 10;
  const delayMs = 3000;

  for (let attempt = 1; attempt <= maxTries; attempt++) {
    try {
      await pool.query('SELECT 1');

      // base table
      await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          phone TEXT,
          password_hash TEXT NOT NULL,
          balance NUMERIC(18,2) NOT NULL DEFAULT 0,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
      `);

      // profile columns (added safely if table already exists)
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS username TEXT;`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS wins INTEGER NOT NULL DEFAULT 0;`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS losses INTEGER NOT NULL DEFAULT 0;`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT;`);
      await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS coins INTEGER NOT NULL DEFAULT 500;`);

      console.log('DB ready: users table + profile + coins ok');
      return;
    } catch (err) {
      console.log(`DB not ready (attempt ${attempt}/${maxTries}): ${err.code || err.message}`);
      if (attempt === maxTries) { console.error('DB connection failed after all retries.'); throw err; }
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
}

function query(text, params) { return pool.query(text, params); }

module.exports = { pool, init, query };
