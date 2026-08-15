/*
 * domino.js — Authoritative 2-player Block Domino engine.
 * All game logic lives on the SERVER so clients can't cheat.
 * A client only sends "I want to play tile X on end Y"; the server validates.
 */

function makeSet() {
  const t = [];
  for (let a = 0; a <= 6; a++) for (let b = a; b <= 6; b++) t.push({ a, b });
  return t;
}
function shuffle(a) {
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}
function tileId(t) { return t.a + '-' + t.b; } // canonical id (a<=b)

class DominoGame {
  /**
   * @param {string[]} playerIds  two socket/player ids, index 0 and 1
   * @param {number} goal         match target score (100/150/200)
   */
  constructor(playerIds, goal = 100) {
    this.playerIds = playerIds.slice(0, 2);
    this.goal = goal;
    this.scores = [0, 0];
    this.matchOver = false;
    this.winner = null;
    this.startRound();
  }

  startRound(starterHint = null) {
    const set = shuffle(makeSet());
    this.hands = [set.slice(0, 7), set.slice(7, 14)];
    this.chain = [];         // ordered left->right: {a,b} already oriented (chain[i].b === chain[i+1].a)
    this.leftEnd = null;
    this.rightEnd = null;
    this.passStreak = 0;
    this.roundOver = false;
    this.roundWinner = null;
    this.lastRoundPoints = 0;

    // starter: highest double, else highest pip sum; tie/none -> hint or player 0
    let starter = -1, bestDbl = -1, bestSum = -1;
    for (let i = 0; i < 2; i++) {
      for (const t of this.hands[i]) {
        if (t.a === t.b && t.a > bestDbl) { bestDbl = t.a; starter = i; }
      }
    }
    if (starter === -1) {
      for (let i = 0; i < 2; i++) {
        for (const t of this.hands[i]) {
          if (t.a + t.b > bestSum) { bestSum = t.a + t.b; starter = i; }
        }
      }
    }
    if (starterHint !== null) starter = starterHint;
    this.current = starter < 0 ? 0 : starter;
  }

  // ---- helpers ----
  _fits(t, end) { return t.a === end || t.b === end; }

  playableEnds(t) {
    if (this.chain.length === 0) return ['first'];
    const e = [];
    if (this._fits(t, this.leftEnd)) e.push('left');
    if (this._fits(t, this.rightEnd)) e.push('right');
    return e;
  }

  hasMove(playerIdx) {
    const hand = this.hands[playerIdx];
    if (this.chain.length === 0) return true;
    return hand.some(t => this._fits(t, this.leftEnd) || this._fits(t, this.rightEnd));
  }

  handSum(playerIdx) {
    return this.hands[playerIdx].reduce((s, t) => s + t.a + t.b, 0);
  }

  /**
   * Attempt a move. Returns {ok:true, ...} or {ok:false, error}.
   * @param {number} playerIdx  0 or 1
   * @param {string} id         tile id "a-b"
   * @param {string} end        'left' | 'right' | 'first'
   */
  play(playerIdx, id, end) {
    if (this.roundOver || this.matchOver) return { ok: false, error: 'round_over' };
    if (playerIdx !== this.current) return { ok: false, error: 'not_your_turn' };

    const hand = this.hands[playerIdx];
    const idx = hand.findIndex(t => tileId(t) === id);
    if (idx === -1) return { ok: false, error: 'no_such_tile' };
    const t = hand[idx];

    const ends = this.playableEnds(t);
    if (ends.length === 0) return { ok: false, error: 'illegal_move' };

    // decide end
    let useEnd = end;
    if (this.chain.length === 0) useEnd = 'first';
    else if (!ends.includes(end)) {
      if (ends.length === 1) useEnd = ends[0];   // auto-correct to the only legal end
      else return { ok: false, error: 'bad_end' };
    }

    // remove from hand & place
    hand.splice(idx, 1);
    if (this.chain.length === 0) {
      this.chain.push({ a: t.a, b: t.b });
      this.leftEnd = t.a; this.rightEnd = t.b;
    } else if (useEnd === 'left') {
      let l, r;
      if (t.b === this.leftEnd) { l = t.a; r = t.b; } else { l = t.b; r = t.a; }
      this.chain.unshift({ a: l, b: r }); this.leftEnd = l;
    } else {
      let l, r;
      if (t.a === this.rightEnd) { l = t.a; r = t.b; } else { l = t.b; r = t.a; }
      this.chain.push({ a: l, b: r }); this.rightEnd = r;
    }
    this.passStreak = 0;

    // win by emptying hand?
    if (hand.length === 0) { this._endRound(playerIdx); return { ok: true, event: 'domino' }; }

    this.current = 1 - this.current;
    // if next player cannot move at all, they will auto-pass (handled by caller loop / pass())
    return { ok: true, event: 'placed' };
  }

  /** current player passes (only valid if they truly have no move) */
  pass(playerIdx) {
    if (this.roundOver || this.matchOver) return { ok: false, error: 'round_over' };
    if (playerIdx !== this.current) return { ok: false, error: 'not_your_turn' };
    if (this.hasMove(playerIdx)) return { ok: false, error: 'you_have_a_move' };

    this.passStreak++;
    if (this.passStreak >= 2) { this._endBlocked(); return { ok: true, event: 'blocked' }; }
    this.current = 1 - this.current;
    return { ok: true, event: 'passed' };
  }

  _endRound(winnerIdx) {
    this.roundOver = true;
    this.roundWinner = winnerIdx;
    const pts = this.handSum(1 - winnerIdx);
    this.lastRoundPoints = pts;
    this.scores[winnerIdx] += pts;
    this._checkMatch(winnerIdx);
  }

  _endBlocked() {
    this.roundOver = true;
    const s0 = this.handSum(0), s1 = this.handSum(1);
    let winnerIdx;
    if (s0 < s1) winnerIdx = 0;
    else if (s1 < s0) winnerIdx = 1;
    else winnerIdx = -1; // tie -> no points this round
    this.roundWinner = winnerIdx;
    if (winnerIdx === -1) { this.lastRoundPoints = 0; return; }
    const pts = this.handSum(1 - winnerIdx);
    this.lastRoundPoints = pts;
    this.scores[winnerIdx] += pts;
    this._checkMatch(winnerIdx);
  }

  _checkMatch(winnerIdx) {
    if (this.scores[winnerIdx] >= this.goal) {
      this.matchOver = true;
      this.winner = winnerIdx;
    }
  }

  /**
   * Build the view a specific player is allowed to see.
   * They see their OWN hand fully, but only the COUNT of the opponent's hand.
   */
  stateFor(playerIdx) {
    const opp = 1 - playerIdx;
    return {
      you: playerIdx,
      goal: this.goal,
      scores: this.scores,
      chain: this.chain,
      leftEnd: this.leftEnd,
      rightEnd: this.rightEnd,
      current: this.current,
      yourTurn: this.current === playerIdx && !this.roundOver && !this.matchOver,
      yourHand: this.hands[playerIdx].map(t => ({ a: t.a, b: t.b, id: tileId(t) })),
      yourPlayable: this.hands[playerIdx]
        .filter(t => this.playableEnds(t).length)
        .map(t => tileId(t)),
      oppTileCount: this.hands[opp].length,
      roundOver: this.roundOver,
      roundWinner: this.roundWinner,
      lastRoundPoints: this.lastRoundPoints,
      matchOver: this.matchOver,
      winner: this.winner
    };
  }
}

module.exports = { DominoGame, tileId };
