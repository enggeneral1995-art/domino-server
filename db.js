// db.js — PostgreSQL connection + table setup (Railway-ready, with retry)
const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL;

// Railway's internal host (postgres.railway.internal) does NOT use SSL.
// The public host (rlwy.net / proxy) DOES need SSL.
// We detect automatically so it works either way.
const isInternal =
  !connectionString || connectionString.includes('railway.internal');

const pool = new Pool({
  connectionString,
  ssl: isInternal ? false : { rejectUnauthorized: false },
});

// Wait until the database is actually reachable, then create the table.
// On Railway the private network can take a few seconds to be ready at boot,
// which is the usual cause of ECONNREFUSED. We retry a few times.
async function init() {
  const maxTries = 10;
  const delayMs = 3000;

  for (let attempt = 1; attempt <= maxTries; attempt++) {
    try {
      await pool.query('SELECT 1'); // test the connection first
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
      console.log('DB ready: users table ok');
      return; // success — stop retrying
    } catch (err) {
      console.log(
        `DB not ready (attempt ${attempt}/${maxTries}): ${err.code || err.message}. Retrying in ${delayMs / 1000}s...`
      );
      if (attempt === maxTries) {
        console.error('DB connection failed after all retries.');
        throw err;
      }
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
}

module.exports = { pool, init };
