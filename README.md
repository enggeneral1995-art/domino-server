# Domino Block — Online 1v1 Server (Step 1)

Authoritative Socket.io backend. The SERVER owns the deck and rules, so clients cannot cheat.

## What this step includes
- Matchmaking queue (pairs two waiting players)
- Full 2-player Block Domino, played on the server
- Each player only receives their own hand + opponent's tile count
- Cheat protection (turn / tile / legal-move validation)

## Not yet (later steps)
- Login / accounts
- Wallet / USDT / real money
- Connecting the mobile front-end graphics

## Run locally
1. Install Node.js 18+
2. In this folder:
   npm install
   npm start
3. Open http://localhost:3000 — you should see "Domino Block server is running".

## Deploy on Railway (same as your other projects)
1. Push this folder to a GitHub repo.
2. On Railway: New Project -> Deploy from GitHub -> pick the repo.
3. Railway auto-runs `npm install` then `npm start`.
4. It gives you a public URL like https://your-app.up.railway.app
   The mobile client will connect to that URL.

## Socket events (for the client later)
Client -> server:
  find_match { goal }        join matchmaking
  play_tile  { id, end }     play a tile ("id" like "3-5", end "left"|"right"|"first")
  pass_turn                  pass (only if no legal move)

Server -> client:
  waiting                    you are in the queue
  matched { room, seat, goal }
  state  {...}               full view for THIS player (your hand, opp count, chain, whose turn)
  info   { type }            round_start / domino / you_locked / opp_locked
  reject { reason }          your action was invalid
  match_over { youWon, scores, goal }
  opponent_left
