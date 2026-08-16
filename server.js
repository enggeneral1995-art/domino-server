/*
 * server.js — Domino Block online server (v4)
 * - Auth API (register / login / me) backed by PostgreSQL
 * - Profile API (get / update: username, avatar, wins, losses)
 * - Online 1v1 game via lockstep relay (matchmaking + shared deck + move relay)
 */
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_in_railway';

// password hashing using Node's built-in crypto (no external deps)
function hashPassword(password){
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + derived;
}
function verifyPassword(password, stored){
  try {
    const [salt, key] = String(stored).split(':');
    const derived = crypto.scryptSync(password, salt, 64).toString('hex');
    const a = Buffer.from(key, 'hex');
    const b = Buffer.from(derived, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch(e){ return false; }
}

const app = express();
app.use(express.json());

// allow the game (on Netlify) to call this API from another domain
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.get('/', (_req, res) => res.send('Domino Block server is running (v4 auth + profile + game)'));

/* ---------------- AUTH ---------------- */
function makeToken(user){ return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' }); }

// default username from the email (before the @), used only if none set yet
function defaultName(u){
  if (u.username) return u.username;
  return String(u.email || 'player').split('@')[0];
}
function publicUser(u){
  return {
    id: u.id,
    email: u.email,
    phone: u.phone,
    balance: Number(u.balance),
    coins: Number(u.coins != null ? u.coins : 500),
    username: defaultName(u),
    wins: Number(u.wins || 0),
    losses: Number(u.losses || 0),
    avatar: u.avatar || null
  };
}

app.post('/api/register', async (req, res) => {
  try {
    let { email, phone, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email_and_password_required' });
    email = String(email).trim().toLowerCase();
    if (password.length < 6) return res.status(400).json({ error: 'password_too_short' });

    const exists = await db.query('SELECT id FROM users WHERE email=$1', [email]);
    if (exists.rows.length) return res.status(409).json({ error: 'email_already_used' });

    const hash = hashPassword(password);
    const r = await db.query(
      'INSERT INTO users (email, phone, password_hash) VALUES ($1,$2,$3) RETURNING *',
      [email, phone || null, hash]
    );
    const user = r.rows[0];
    res.json({ token: makeToken(user), user: publicUser(user) });
  } catch (e) {
    console.error('register error:', e.message, e.code||'');
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    let { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email_and_password_required' });
    email = String(email).trim().toLowerCase();

    const r = await db.query('SELECT * FROM users WHERE email=$1', [email]);
    if (!r.rows.length) return res.status(401).json({ error: 'invalid_credentials' });
    const user = r.rows[0];
    const ok = verifyPassword(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid_credentials' });

    res.json({ token: makeToken(user), user: publicUser(user) });
  } catch (e) {
    console.error('login error:', e.message, e.code||'');
    res.status(500).json({ error: 'server_error' });
  }
});

function auth(req, res, next){
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: 'no_token' });
  try { req.user = jwt.verify(t, JWT_SECRET); next(); }
  catch(e){ res.status(401).json({ error: 'bad_token' }); }
}

app.get('/api/me', auth, async (req, res) => {
  try {
    const r = await db.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'not_found' });
    res.json({ user: publicUser(r.rows[0]) });
  } catch(e){ res.status(500).json({ error: 'server_error' }); }
});

/* ---------------- PROFILE ---------------- */

// get my full profile
app.get('/api/profile', auth, async (req, res) => {
  try {
    const r = await db.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'not_found' });
    res.json({ user: publicUser(r.rows[0]) });
  } catch(e){
    console.error('profile get error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

// update username and/or avatar
app.post('/api/profile', auth, async (req, res) => {
  try {
    let { username, avatar } = req.body || {};

    // validate username (optional)
    if (username !== undefined && username !== null) {
      username = String(username).trim();
      if (username.length < 2 || username.length > 20) {
        return res.status(400).json({ error: 'username_length' });
      }
    }
    // validate avatar (optional): accept a short id/name like "a1".."a12" or a small string
    if (avatar !== undefined && avatar !== null) {
      avatar = String(avatar).trim();
      if (avatar.length > 40) return res.status(400).json({ error: 'avatar_invalid' });
    }

    // build a dynamic update only for the fields provided
    const sets = [];
    const vals = [];
    let i = 1;
    if (username !== undefined && username !== null) { sets.push(`username=$${i++}`); vals.push(username); }
    if (avatar !== undefined && avatar !== null)     { sets.push(`avatar=$${i++}`);   vals.push(avatar); }

    if (!sets.length) return res.status(400).json({ error: 'nothing_to_update' });

    vals.push(req.user.id);
    const r = await db.query(
      `UPDATE users SET ${sets.join(', ')} WHERE id=$${i} RETURNING *`,
      vals
    );
    res.json({ user: publicUser(r.rows[0]) });
  } catch(e){
    console.error('profile update error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

/* ---------------- GAME RESULT (offline vs computer) ---------------- */
// Awards/deducts FREE coins and updates wins/losses. Coins have no cash value.
app.post('/api/game-result', auth, async (req, res) => {
  try {
    const result = (req.body && req.body.result) === 'win' ? 'win' : 'loss';
    let entry = parseInt(req.body && req.body.entry, 10);
    if (![100, 200, 500].includes(entry)) entry = 100;

    const r = await db.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'not_found' });
    const u = r.rows[0];

    let coins = Number(u.coins || 0);
    let wins = Number(u.wins || 0);
    let losses = Number(u.losses || 0);

    if (result === 'win') { coins += entry; wins += 1; }          // winner takes the pot (no fee)
    else { coins = Math.max(0, coins - entry); losses += 1; }

    const up = await db.query(
      'UPDATE users SET coins=$1, wins=$2, losses=$3 WHERE id=$4 RETURNING *',
      [coins, wins, losses, req.user.id]
    );
    res.json({ user: publicUser(up.rows[0]) });
  } catch (e) {
    console.error('game-result error:', e.message);
    res.status(500).json({ error: 'server_error' });
  }
});

/* ---------------- GAME (lockstep relay) ---------------- */
const TILE_VALUES = [[0,0],[1,2],[2,3],[2,4],[1,5],[5,5],[3,6],[0,1],[2,2],[3,3],
  [3,4],[2,5],[0,6],[4,6],[1,1],[0,3],[0,4],[4,4],[3,5],[1,6],
  [5,6],[0,2],[1,3],[1,4],[0,5],[4,5],[2,6],[6,6]];
function shuffle(a){ for(let i=a.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[a[i],a[j]]=[a[j],a[i]];} return a; }
function dealRound(){
  const deck = shuffle([...Array(28).keys()]);
  const handA = deck.slice(0,7), handB = deck.slice(7,14);
  let starterSeat=0,bestDbl=-1,bestSum=-1;
  const scan=(h,s)=>{for(const v of h){const t=TILE_VALUES[v];if(t[0]===t[1]&&t[0]>bestDbl){bestDbl=t[0];starterSeat=s;}}};
  scan(handA,0);scan(handB,1);
  if(bestDbl<0){const s2=(h,s)=>{for(const v of h){const t=TILE_VALUES[v];if(t[0]+t[1]>bestSum){bestSum=t[0]+t[1];starterSeat=s;}}};s2(handA,0);s2(handB,1);}
  return { handA, handB, starterSeat };
}
let waiting=null; const rooms=new Map(); const socketRoom=new Map(); let seq=1;
const other=(room,sid)=> room.players[0]===sid ? room.players[1] : room.players[0];
function startRound(room){
  const d=dealRound();
  io.to(room.players[0]).emit('online_start',{seat:0,yourHand:d.handA,oppHand:d.handB,starterSeat:d.starterSeat,goal:room.goal});
  io.to(room.players[1]).emit('online_start',{seat:1,yourHand:d.handB,oppHand:d.handA,starterSeat:d.starterSeat,goal:room.goal});
}
io.on('connection', socket => {
  socket.on('find_match', (opts={}) => {
    const goal=[100,200,500].includes(opts.goal)?opts.goal:100;
    if (waiting && waiting.socket.connected && waiting.socket.id!==socket.id){
      const p1=waiting.socket,p2=socket; waiting=null;
      const roomId='r'+(seq++); const room={players:[p1.id,p2.id],goal};
      rooms.set(roomId,room); socketRoom.set(p1.id,roomId); socketRoom.set(p2.id,roomId);
      p1.join(roomId); p2.join(roomId);
      io.to(p1.id).emit('matched',{seat:0,goal}); io.to(p2.id).emit('matched',{seat:1,goal});
      startRound(room);
    } else { waiting={socket,goal}; socket.emit('waiting'); }
  });
  socket.on('game_move', (msg) => { const r=socketRoom.get(socket.id); if(!r)return; const room=rooms.get(r); if(!room)return; io.to(other(room,socket.id)).emit('game_move',msg); });
  socket.on('next_round', () => { const r=socketRoom.get(socket.id); if(!r)return; const room=rooms.get(r); if(!room)return; startRound(room); });
  socket.on('cancel_find', () => { if(waiting && waiting.socket.id===socket.id) waiting=null; });
  socket.on('disconnect', () => {
    if (waiting && waiting.socket.id===socket.id) waiting=null;
    const r=socketRoom.get(socket.id);
    if (r && rooms.has(r)){ const room=rooms.get(r); const o=other(room,socket.id); if(o) io.to(o).emit('opponent_left'); room.players.forEach(s=>socketRoom.delete(s)); rooms.delete(r); }
  });
});

const PORT = process.env.PORT || 3000;
db.init().catch(e => console.error('DB init failed:', e.message)).finally(() => {
  server.listen(PORT, () => console.log('Domino server (v4) on port ' + PORT));
});
