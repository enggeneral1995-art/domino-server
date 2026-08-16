// db.js — PostgreSQL connection + table setup (Railway-ready, with diagnostics)
const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL;

// --- Diagnostics: show WHERE we are trying to connect (password hidden) ---
try {
  if (!connectionString) {
    console.log('DIAG: DATABASE_URL is EMPTY -> pg will try localhost:5432');
  } else {
    const u = new URL(connectionString);
    console.log(`DIAG: connecting to host=${u.hostname} port=${u.port} db=${u.pathname.replace('/', '')} ssl=${u.hostname.includes('railway.internal') ? 'off' : 'on'}`);
  }
} catch (e) {
  console.log('DIAG: could not parse DATABASE_URL:', e.message);
}

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
      return;
    } catch (err) {
      // Print the FULL error target so we can see exactly what's refused
      console.log(
        `DB not ready (attempt ${attempt}/${maxTries}): code=${err.code} address=${err.address || '?'} port=${err.port || '?'} msg=${err.message}`
      );
      if (attempt === maxTries) {
        console.error('DB connection failed after all retries.');
        throw err;
      }
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
}

function query(text, params) {
  return pool.query(text, params);
}

module.exports = { pool, init, query };
