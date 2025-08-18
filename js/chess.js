import { hash } from './malicious-secure-ot.js';
import { click } from './client.js'
import { Move, State } from './enums.js';
export const SIZE = 8


function cell(t, f = 0) {
	return { t: t, f: f }
}

export function idx(x, y) {
	if (x >= 0 && x < SIZE && y >= 0 && y < SIZE) {
		return x + (y * SIZE)
	}
}

export function white(p) {
	return /^[A-Z]$/.test(p.t)
}

// XOR two SHA-256 digests (hex) and return hex
const toHex = bytes => [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
const fromHex = hex => new Uint8Array(hex.match(/../g).map(h => parseInt(h, 16)));
export const xorHex = (hexA, hexB) => {
	const a = fromHex(hexA);
	const b = fromHex(hexB);
	if (a.length !== b.length) throw new Error("length mismatch");
	const out = new Uint8Array(a.length);
	for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
	return toHex(out);
};

export function my_board(IS_HOST) {
	let board = Array(SIZE * SIZE).fill(null).map((_) => cell(' '));
	for (let i = 0; i < SIZE; i++) {
		board[idx(i, IS_HOST ? 1 : SIZE - 2)] = cell(IS_HOST ? 'P' : 'p')
	}
	let y = IS_HOST ? 0 : SIZE - 1;
	board[(idx(0, y))] = cell(IS_HOST ? 'R' : 'r')
	board[(idx(1, y))] = cell(IS_HOST ? 'N' : 'n')
	board[(idx(2, y))] = cell(IS_HOST ? 'B' : 'b')
	board[(idx(3, y))] = cell(IS_HOST ? 'K' : 'k')
	board[(idx(4, y))] = cell(IS_HOST ? 'Q' : 'q')
	board[(idx(5, y))] = cell(IS_HOST ? 'B' : 'b')
	board[(idx(6, y))] = cell(IS_HOST ? 'N' : 'n')
	board[(idx(7, y))] = cell(IS_HOST ? 'R' : 'r')
	return board
}

export function known_board(state, first) {
	let board = Array(SIZE * SIZE).fill(null).map(_ => { return cell('~') })
	if (first) {
		for (let i = (state.IS_HOST ? 0 : (SIZE - 4)) * SIZE; i < (state.IS_HOST ? 4 : SIZE) * SIZE; i++) {
			board[i].t = ' '
		}
	}
	for (let i = 0; i < SIZE * SIZE; i++) {
		if (state.my_board[i].t != ' ') {
			board[i] = state.my_board[i]
		}
	}
	return board
}

export function update_board(state, result) {
	state.rays.forEach(r => {
		let i = idx(r[0], r[1])
		if (state.known_board[i].t == '~') {
			if('prnbkq '.includes(result?.[i]?.t?.toLowerCase()) && typeof result?.[i]?.f == 'number'){
				state.known_board[i] = cell(result[i].t, result[i].f)
			}else{
				document.getElementById('message').innerText = 'Game is invalid'
				state.state = State.GameOver
				return
			}
			
		}
	});
	for (let d = 0; d < state.choices.length; d++) {
		if (state.choices[d] == 0) {
			if(typeof result[d] != 'string' && result[d].length != state.proof.length){
				document.getElementById('message').innerText = 'Game is invalid'
				state.state = State.GameOver
				return
			}
			state.proof = xorHex(state.proof, result[d])
		}
	}
	state.rays = state.rays.filter(r => {
		return state.known_board[idx(r[0], r[1])].t == ' '
	})
}

export function check_captured(state, result) {
	state.capture = null
	for (let d = 0; d < state.choices.length; d++) {
		if (state.choices[d] == 0) {
			state.proof = xorHex(state.proof, result[d])
		} else if (result?.[d]?.t != ' ') {
			state.my_board[d] = cell(' ')
			state.capture = d
		}
	}
}

export function rays(board, IS_HOST) {
	let rays = []
	for (let x = 0; x < SIZE; x++) {
		for (let y = 0; y < SIZE; y++) {
			let l = board[idx(x, y)]
			if((IS_HOST && !white(l))|| (!IS_HOST && white(l))){
				continue
			}
			switch (l.t.toLowerCase()) {
				case 'p':
					let dir = white(l) ? 1 : -1
					rays.push([x, y, 0, dir, 2 - l.f], [x, y, 1, dir, 1], [x, y, -1, dir, 1])
					break;
				case 'k':
					rays.push([x, y, 1, 0, 1], [x, y, 1, 1, 1], [x, y, 0, 1, 1], [x, y, -1, 1, 1], [x, y, -1, 0, 1], [x, y, -1, -1, 1], [x, y, 0, -1, 1], [x, y, 1, -1, 1])
					break;
				case 'q':
					rays.push([x, y, 1, 0, SIZE], [x, y, 1, 1, SIZE], [x, y, 0, 1, SIZE], [x, y, -1, 1, SIZE], [x, y, -1, 0, SIZE], [x, y, -1, -1, SIZE], [x, y, 0, -1, SIZE], [x, y, 1, -1, SIZE])
					break;
				case 'r':
					rays.push([x, y, 1, 0, SIZE], [x, y, 0, 1, SIZE], [x, y, -1, 0, SIZE], [x, y, 0, -1, SIZE])
					break;
				case 'b':
					rays.push([x, y, 1, 1, SIZE], [x, y, -1, 1, SIZE], [x, y, -1, -1, SIZE], [x, y, 1, -1, SIZE])
					break;
				case 'n':
					rays.push([x, y, 2, 1, 1], [x, y, 1, 2, 1], [x, y, -1, 2, 1], [x, y, -2, 1, 1], [x, y, -2, -1, 1], [x, y, -1, -2, 1], [x, y, 1, -2, 1], [x, y, 2, -1, 1])
				default:
					break;
			}
		}
	}
	return rays
}

export function no_read_proofs(challenge, turn, iter) {
	let proofs = []
	for (let i = 0; i < SIZE * SIZE; i++) {
		proofs.push(no_read_proof(challenge, turn, iter, i))
	}
	return proofs
}
function no_read_proof(challenge, turn, iter, idx) {
	return hash(`${challenge}_${turn}_${iter}_${idx}`)
}


export function choices(rays) {
	rays = rays.map(r => {
		r[0] += r[2]
		r[1] += r[3]
		r[4] -= 1
		return r
	}).filter(r => {
		return r[0] >= 0 && r[0] < SIZE && r[1] >= 0 && r[1] < SIZE && r[4] >= 0
	})
	let choices = Array(SIZE * SIZE).fill(0);
	rays.forEach(r => {
		choices[idx(r[0], r[1])] = 1
	});
	return { rays: rays, choices: choices}
}

function empty_or_enemy(board, x, y, is_white) {
	return empty(board, x, y) || enemy(board, x, y, is_white)
}

function enemy(board, x, y, is_white) {
	return board[idx(x, y)]?.t && (board[idx(x, y)].t != ' ' && white(board[idx(x, y)]) != is_white)
}

function empty(board, x, y) {
	return board[idx(x, y)]?.t == ' '
}

function valid_moves_(board, x, y, dx, dy, is_white) {
	let results = []
	for (let d = 1; d < SIZE; d++) {
		if (empty(board, x + (d * dx), y + (d * dy))) {
			results.push({ type: Move.Normal, loc: idx(x + (d * dx), y + (d * dy)) })
		} else {
			if (enemy(board, x + (d * dx), y + (d * dy), is_white)) {
				results.push({ type: Move.Normal, loc: idx(x + (d * dx), y + (d * dy)) })
			}
			break
		}
	}
	return results
}

export function valid_moves(board, i) {
	// todo en pasant
	let x = i % SIZE
	let y = (i - x) / SIZE
	let results = []
	let is_white = white(board[i])
	let dir = is_white ? 1 : -1
	switch (board[i].t.toLowerCase()) {
		case 'p':
			if (board[idx(x, y + dir)]?.t == ' ') {
				results.push({ type: y + dir == SIZE - 1 || y + dir == 0 ? Move.Promote : Move.Normal, loc: idx(x, y + dir) })
				if (board[i].f == 0) {
					if (board[idx(x, y + 2 * dir)]?.t == ' ') {
						results.push({ type: Move.Normal, loc: idx(x, y + dir * 2) })
					}
				}
			}
			if (board[idx(x + 1, y + dir)]?.t && board[idx(x + 1, y + dir)]?.t != ' ' && white(board[idx(x + 1, y + dir)]) != is_white) {
				results.push({ type: y + dir == SIZE - 1 || y + dir == 0 ? Move.Promote : Move.Normal, loc: idx(x + 1, y + dir) })
			}
			if (board[idx(x - 1, y + dir)]?.t && board[idx(x - 1, y + dir)]?.t != ' ' && white(board[idx(x - 1, y + dir)]) != is_white) {
				results.push({ type: y + dir == SIZE - 1 || y + dir == 0 ? Move.Promote : Move.Normal, loc: idx(x - 1, y + dir) })
			}
			break;
		case 'k':
			if (empty_or_enemy(board, x + 1, y, is_white)) { results.push({ type: Move.Normal, loc: idx(x + 1, y) }) }
			if (empty_or_enemy(board, x + 1, y + 1, is_white)) { results.push({ type: Move.Normal, loc: idx(x + 1, y + 1) }) }
			if (empty_or_enemy(board, x, y + 1, is_white)) { results.push({ type: Move.Normal, loc: idx(x, y + 1) }) }
			if (empty_or_enemy(board,x - 1, y + 1, is_white)) { results.push({ type: Move.Normal, loc: idx(x - 1, y + 1) }) }
			if (empty_or_enemy(board,x - 1, y, is_white)) { results.push({ type: Move.Normal, loc: idx(x - 1, y) }) }
			if (empty_or_enemy(board,x - 1, y - 1, is_white)) { results.push({ type: Move.Normal, loc: idx(x - 1, y - 1) }) }
			if (empty_or_enemy(board,x, y - 1, is_white)) { results.push({ type: Move.Normal, loc: idx(x, y - 1) }) }
			if (empty_or_enemy(board,x + 1, y - 1, is_white)) { results.push({ type: Move.Normal, loc: idx(x + 1, y - 1) }) }

			if (board[i].f == 0) {
				if (empty(board, x - (1 * dir), y) && empty(board, x - (2 * dir), y) &&
					board[idx(x - (3 * dir), y)].t.toLowerCase() == 'r' &&
					board[idx(x - (3 * dir), y)].f == 0) {
					results.push({ type: Move.Castle, loc: idx(x - (2 * dir), y), rook_from: idx(x - (3 * dir), y), rook_to: idx(x - (1 * dir), y) })
				}

				if (empty(board, x + (1 * dir), y) && empty(board, x + (2 * dir), y) && empty(board, x + (3 * dir), y) &&
					board[idx(x + (4 * dir), y)].t.toLowerCase() == 'r' && board[idx(x + (4 * dir), y)].f == 0) {
					results.push({ type: Move.Castle, loc: idx(x + (2 * dir), y), rook_from: idx(x + (4 * dir), y), rook_to: idx(x + (1 * dir), y) })
				}
			}
			break;
		case 'q':
			results.push(...valid_moves_(board, x, y, 1, 0, is_white))
			results.push(...valid_moves_(board, x, y, 1, 1, is_white))
			results.push(...valid_moves_(board, x, y, 0, 1, is_white))
			results.push(...valid_moves_(board, x, y, -1, 1, is_white))
			results.push(...valid_moves_(board, x, y, -1, 0, is_white))
			results.push(...valid_moves_(board, x, y, -1, -1, is_white))
			results.push(...valid_moves_(board, x, y, 0, -1, is_white))
			results.push(...valid_moves_(board, x, y, 1, -1, is_white))
			break;
		case 'r':
			results.push(...valid_moves_(board, x, y, 1, 0, is_white))
			results.push(...valid_moves_(board, x, y, 0, 1, is_white))
			results.push(...valid_moves_(board, x, y, -1, 0, is_white))
			results.push(...valid_moves_(board, x, y, 0, -1, is_white))
			break;
		case 'b':
			results.push(...valid_moves_(board, x, y, 1, 1, is_white))
			results.push(...valid_moves_(board, x, y, -1, 1, is_white))
			results.push(...valid_moves_(board, x, y, -1, -1, is_white))
			results.push(...valid_moves_(board, x, y, 1, -1, is_white))
			break;
		case 'n':
			if (empty_or_enemy(board, x + 2, y + 1, is_white)) { results.push({ type: Move.Normal, loc: idx(x + 2, y + 1) }) }
			if (empty_or_enemy(board,x + 1, y + 2, is_white)) { results.push({ type: Move.Normal, loc: idx(x + 1, y + 2) }) }
			if (empty_or_enemy(board,x - 1, y + 2, is_white)) { results.push({ type: Move.Normal, loc: idx(x - 1, y + 2) }) }
			if (empty_or_enemy(board,x - 2, y + 1, is_white)) { results.push({ type: Move.Normal, loc: idx(x - 2, y + 1) }) }
			if (empty_or_enemy(board,x - 2, y - 1, is_white)) { results.push({ type: Move.Normal, loc: idx(x - 2, y - 1) }) }
			if (empty_or_enemy(board,x - 1, y - 2, is_white)) { results.push({ type: Move.Normal, loc: idx(x - 1, y - 2) }) }
			if (empty_or_enemy(board,x + 1, y - 2, is_white)) { results.push({ type: Move.Normal, loc: idx(x + 1, y - 2) }) }
			if (empty_or_enemy(board,x + 2, y - 1, is_white)) { results.push({ type: Move.Normal, loc: idx(x + 2, y - 1) }) }
		default:
			break;
	}
	return results
}

export function board_after_move(board, move) {
	board[move.move.loc] = board[move.loc]
	board[move.move.loc].f = 1
	board[move.loc] = cell(' ')
	if (move.type == Move.Promote) {
		board[move.move.loc].t = white(board[move.move.loc]) ? 'Q' : 'q'
	} else if (move.type == Move.Castle) {
		board[move.rook_to] = board[move.rook_from]
		board[move.rook_from] = cell(' ')
	}
	return board
}

export function move(state, move) {
	let win = state.known_board[move.move.loc].t.toLowerCase() == 'k'
	state.my_board = board_after_move(state.my_board, move)
	state.known_board = board_after_move(state.known_board, move)
	return win
}

const PIECE = {
	'K': '\u2654', 'Q': '\u2655', 'R': '\u2656', 'B': '\u2657', 'N': '\u2658', 'P': '\u2659',
	'k': '\u265A', 'q': '\u265B', 'r': '\u265C', 'b': '\u265D', 'n': '\u265E', 'p': '\u265F'
};

export function renderChessboard(state, progress = 0) {
	let arr = state.known_board
	if (arr.length !== 64) throw new Error("array length must be 64");
	arr = arr.map(d => d?.t || ' ')
	let container = document.getElementById("board")
	container.innerHTML = "";
	let counter = 56
	for (let i = state.IS_HOST ? 63 : 0; state.IS_HOST ? i >= 0 : i < 64; state.IS_HOST ? i-- : i++) {
		counter--
		const ch = arr[i];
		const row = Math.floor(i / 8), col = i % 8;
		const cell = document.createElement("div");
		cell.className = "cell ";
		if (i == state.capture) {
			cell.className += "captured";
		} else if (ch == '~') {
			cell.className += ((row + col) % 2 ? "dark-gray" : "light-gray");
		} else {
			cell.className += ((row + col) % 2 ? "dark" : "light");
		}

		if (counter < 0 && counter >= -progress) {
			cell.className += " progress"
		}
		cell.onclick = () => click(i)
		cell.id = i
		cell.textContent = ch === ' ' ? '' : (PIECE[ch] || ch);
		container.appendChild(cell);
	}
}