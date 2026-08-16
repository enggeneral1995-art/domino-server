// db.js — PostgreSQL connection + table setup (lazy, build-safe)
const { Pool } = require('pg');

let pool = null;
function getPool() {
  if (!pool) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: false
    });
  }
  return pool;
}

async function init() {
  if (!process.env.DATABASE_URL) {
    console.warn('DATABASE_URL not set yet — skipping table init');
    return;
  }
  await getPool().query(`
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
}

// export a proxy-like object so `pool.query(...)` works via getPool()
module.exports = {
  init,
  query: (...args) => getPool().query(...args),
  get pool(){ return getPool(); }
};
