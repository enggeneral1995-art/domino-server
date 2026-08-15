/*
 * server.js — Domino Block online server (v2, lockstep relay)
 * matchmaking + shared deck deal + move relay for the purchased game.
 */
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.get('/', (_req, res) => res.send('Domino Block server is running (v2 lockstep)'));

// tile index -> [a,b]  (MUST match the game's TILE_VALUES order)
const TILE_VALUES = [[0,0],[1,2],[2,3],[2,4],[1,5],[5,5],[3,6],[0,1],[2,2],[3,3],
  [3,4],[2,5],[0,6],[4,6],[1,1],[0,3],[0,4],[4,4],[3,5],[1,6],
  [5,6],[0,2],[1,3],[1,4],[0,5],[4,5],[2,6],[6,6]];

function shuffle(a){ for(let i=a.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[a[i],a[j]]=[a[j],a[i]];} return a; }

function dealRound(){
  const deck = shuffle([...Array(28).keys()]);
  const handA = deck.slice(0,7);
  const handB = deck.slice(7,14);
  let starterSeat = 0, bestDbl = -1, bestSum = -1;
  const scan = (hand,seat)=>{ for(const v of hand){ const t=TILE_VALUES[v]; if(t[0]===t[1] && t[0]>bestDbl){ bestDbl=t[0]; starterSeat=seat; } } };
  scan(handA,0); scan(handB,1);
  if(bestDbl<0){
    const scan2 = (hand,seat)=>{ for(const v of hand){ const t=TILE_VALUES[v]; if(t[0]+t[1]>bestSum){bestSum=t[0]+t[1];starterSeat=seat;} } };
    scan2(handA,0); scan2(handB,1);
  }
  return { handA, handB, starterSeat };
}

let waiting = null;
const rooms = new Map();
const socketRoom = new Map();
let seq = 1;
const other = (room,sid)=> room.players[0]===sid ? room.players[1] : room.players[0];

function startRound(room){
  const d = dealRound();
  io.to(room.players[0]).emit('online_start', { seat:0, yourHand:d.handA, oppHand:d.handB, starterSeat:d.starterSeat, goal:room.goal });
  io.to(room.players[1]).emit('online_start', { seat:1, yourHand:d.handB, oppHand:d.handA, starterSeat:d.starterSeat, goal:room.goal });
}

io.on('connection', socket => {
  socket.on('find_match', (opts={}) => {
    const goal = [100,150,200].includes(opts.goal) ? opts.goal : 100;
    if (waiting && waiting.socket.connected && waiting.socket.id !== socket.id){
      const p1 = waiting.socket, p2 = socket; waiting = null;
      const roomId = 'r'+(seq++);
      const room = { players:[p1.id,p2.id], goal };
      rooms.set(roomId, room);
      socketRoom.set(p1.id, roomId); socketRoom.set(p2.id, roomId);
      p1.join(roomId); p2.join(roomId);
      io.to(p1.id).emit('matched', { seat:0, goal });
      io.to(p2.id).emit('matched', { seat:1, goal });
      startRound(room);
    } else {
      waiting = { socket, goal };
      socket.emit('waiting');
    }
  });

  socket.on('game_move', (msg) => {
    const roomId = socketRoom.get(socket.id); if(!roomId) return;
    const room = rooms.get(roomId); if(!room) return;
    io.to(other(room, socket.id)).emit('game_move', msg);
  });

  socket.on('next_round', () => {
    const roomId = socketRoom.get(socket.id); if(!roomId) return;
    const room = rooms.get(roomId); if(!room) return;
    startRound(room);
  });

  socket.on('cancel_find', () => { if(waiting && waiting.socket.id===socket.id) waiting=null; });

  socket.on('disconnect', () => {
    if (waiting && waiting.socket.id === socket.id) waiting = null;
    const roomId = socketRoom.get(socket.id);
    if (roomId && rooms.has(roomId)){
      const room = rooms.get(roomId);
      const o = other(room, socket.id);
      if(o) io.to(o).emit('opponent_left');
      room.players.forEach(sid => socketRoom.delete(sid));
      rooms.delete(roomId);
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('Domino server (v2 lockstep) on port ' + PORT));
