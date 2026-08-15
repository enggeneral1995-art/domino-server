/*
 * server.js — Online 1v1 Domino Block backend
 * - Simple matchmaking queue (pairs two waiting players)
 * - Authoritative game: server owns the deck & rules
 * - Each player only receives their own hand + opponent tile COUNT
 *
 * This is STEP 1: no money, no login yet. Those come later.
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { DominoGame } = require('./domino');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*' } // tighten this later to your app's domain
});

// tiny health page so you can confirm the server is alive in a browser
app.get('/', (_req, res) => res.send('Domino Block server is running ✅'));

// ---- in-memory state (later: move to a database) ----
let waiting = null;                 // a socket waiting for an opponent {socket, goal}
const rooms = new Map();            // roomId -> { game, players:[socketId,socketId] }
const socketRoom = new Map();       // socketId -> roomId

let roomSeq = 1;

function pushState(room) {
  const { game, players } = room;
  players.forEach((sid, idx) => {
    io.to(sid).emit('state', game.stateFor(idx));
  });
}

// after a move, if the now-current player has no legal move, auto-pass for them
function resolveForcedPasses(room) {
  const { game } = room;
  let guard = 0;
  while (!game.roundOver && !game.matchOver && !game.hasMove(game.current) && guard < 4) {
    const forced = game.current;
    const r = game.pass(forced);
    io.to(room.players[forced]).emit('info', { type: 'you_locked' });
    io.to(room.players[1 - forced]).emit('info', { type: 'opp_locked' });
    if (!r.ok) break;
    if (r.event === 'blocked') break;
    guard++;
  }
}

function startRoundBroadcast(room, note) {
  pushState(room);
  if (note) room.players.forEach(sid => io.to(sid).emit('info', note));
  // starter might be locked immediately (rare) — resolve
  resolveForcedPasses(room);
  pushState(room);
}

io.on('connection', (socket) => {
  console.log('connected:', socket.id);

  // ---- matchmaking ----
  socket.on('find_match', (opts = {}) => {
    const goal = [100, 150, 200].includes(opts.goal) ? opts.goal : 100;

    if (waiting && waiting.socket.connected && waiting.socket.id !== socket.id) {
      // pair them
      const p1 = waiting.socket;
      const p2 = socket;
      waiting = null;

      const roomId = 'r' + (roomSeq++);
      const game = new DominoGame([p1.id, p2.id], goal);
      const room = { game, players: [p1.id, p2.id], goal };
      rooms.set(roomId, room);
      socketRoom.set(p1.id, roomId);
      socketRoom.set(p2.id, roomId);
      p1.join(roomId);
      p2.join(roomId);

      io.to(p1.id).emit('matched', { room: roomId, seat: 0, goal });
      io.to(p2.id).emit('matched', { room: roomId, seat: 1, goal });

      startRoundBroadcast(room, { type: 'round_start' });
    } else {
      waiting = { socket, goal };
      socket.emit('waiting');
    }
  });

  socket.on('cancel_find', () => {
    if (waiting && waiting.socket.id === socket.id) waiting = null;
    socket.emit('cancelled');
  });

  // ---- gameplay ----
  socket.on('play_tile', ({ id, end } = {}) => {
    const roomId = socketRoom.get(socket.id);
    if (!roomId) return;
    const room = rooms.get(roomId);
    if (!room) return;
    const seat = room.players.indexOf(socket.id);
    if (seat === -1) return;

    const res = room.game.play(seat, id, end);
    if (!res.ok) { socket.emit('reject', { reason: res.error }); return; }

    if (res.event === 'domino') {
      room.players.forEach(sid => io.to(sid).emit('info', { type: 'domino', winner: room.game.roundWinner, points: room.game.lastRoundPoints }));
    }
    resolveForcedPasses(room);
    pushState(room);
    maybeNextRound(room, roomId);
  });

  socket.on('pass_turn', () => {
    const roomId = socketRoom.get(socket.id);
    if (!roomId) return;
    const room = rooms.get(roomId);
    if (!room) return;
    const seat = room.players.indexOf(socket.id);
    if (seat === -1) return;

    const res = room.game.pass(seat);
    if (!res.ok) { socket.emit('reject', { reason: res.error }); return; }
    resolveForcedPasses(room);
    pushState(room);
    maybeNextRound(room, roomId);
  });

  // start the next round after a short delay, if match not over
  function maybeNextRound(room, roomId) {
    const g = room.game;
    if (g.matchOver) {
      room.players.forEach((sid, idx) => io.to(sid).emit('match_over', {
        youWon: g.winner === idx, scores: g.scores, goal: g.goal
      }));
      // clean up room shortly after
      setTimeout(() => {
        room.players.forEach(sid => socketRoom.delete(sid));
        rooms.delete(roomId);
      }, 1000);
      return;
    }
    if (g.roundOver) {
      setTimeout(() => {
        if (!rooms.has(roomId)) return;
        g.startRound(g.roundWinner >= 0 ? g.roundWinner : null);
        startRoundBroadcast(room, { type: 'round_start' });
      }, 2500);
    }
  }

  // ---- disconnect ----
  socket.on('disconnect', () => {
    console.log('disconnected:', socket.id);
    if (waiting && waiting.socket.id === socket.id) waiting = null;

    const roomId = socketRoom.get(socket.id);
    if (roomId && rooms.has(roomId)) {
      const room = rooms.get(roomId);
      const other = room.players.find(sid => sid !== socket.id);
      if (other) io.to(other).emit('opponent_left');
      room.players.forEach(sid => socketRoom.delete(sid));
      rooms.delete(roomId);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('Domino server listening on port ' + PORT));
