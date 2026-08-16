// db.js — PostgreSQL connection + table setup (lazy, build-safe, self-healing)
const { Pool } = require('pg');

let pool = null;
function getPool() {
  if (!pool) {
    var url = process.env.DATABASE_URL || '';
    // internal Railway host needs no SSL; public proxy host does
    var needSSL = url.indexOf('railway.internal') === -1;
    pool = new Pool({
      connectionString: url,
      ssl: needSSL ? { rejectUnauthorized: false } : false
    });
  }
  return pool;
}

const CREATE_SQL = `
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    phone TEXT,
    password_hash TEXT NOT NULL,
    balance NUMERIC(18,2) NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  );
`;

let ready = false;
async function ensure() {
  if (ready) return;
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL missing');
  await getPool().query(CREATE_SQL);
  ready = true;
  console.log('DB ready: users table ok');
}

// try a few times at startup (DATABASE_URL may appear a moment after boot)
async function init() {
  for (let i = 0; i < 10; i++) {
    try { await ensure(); return; }
    catch (e) {
      console.warn('DB init attempt ' + (i+1) + ' failed: ' + e.message);
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  console.warn('DB init: giving up for now; will retry on first request');
}

// query that makes sure the table exists first (self-heals if startup missed it)
async function query(text, params) {
  if (!ready) { try { await ensure(); } catch (e) { /* will throw below if truly broken */ } }
  return getPool().query(text, params);
}

module.exports = { init, ensure, query, get pool(){ return getPool(); } };
