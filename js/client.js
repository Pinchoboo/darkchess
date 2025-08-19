import { MessageType, State } from './enums.js'
import * as messages from './messages.js'
import * as chess from './chess.js'
import { host } from './host.js'
import { join } from './join.js'
import * as ot from './ot_api.js'
import { hash } from './malicious-secure-ot.js'
const urlParams = new URLSearchParams(window.location.search);
const IS_HOST = urlParams.get('id') === null;

let state = null
function resetState() {
	state = {
		state: State.Preinit,
		oponent: null,
		turn: 0,
		my_board: chess.my_board(IS_HOST),
		IS_HOST: IS_HOST,
		ot: {},
		secret: window.crypto.randomUUID(),
		commit_prefix: window.crypto.randomUUID(),
		proof: hash(''),
		waiting: !IS_HOST,
		selected: null,
		capture: null,
		moves: [],
		commits: [],
		known_boards: []
	};
}

export function handleData(conn, type, data) {
	console.log(`[${conn.label}]${type}: ${data?.stage ? data.stage : JSON.stringify(data)}`)

	if (state.oponent != conn.label) {
		if (!state.oponent && type == MessageType.ClientHello && state.state == State.Preinit) {
			state.oponent = conn.label
			if (IS_HOST) {
				state.state = State.Init
				conn.send(messages.ClientHello())
				document.getElementById('message').innerText = 'Your turn'
			} else {
				state.state = State.OpponentsTurn
				state.known_board = chess.known_board(state, true)
				chess.renderChessboard(state)
				conn.send(messages.Setup())
				document.getElementById('message').innerText = 'Opponents turn'
			}
		} else {
			return conn.close()
		}
	}
	update(type, data, conn)
}

function update(type, data, conn) {
	state.conn = conn
	switch (type) {
		case MessageType.Close:
			document.getElementById('message').innerText = 'Opponent has disconnected'
			resetState()
			break;
		case MessageType.Setup:
			if(state.state != State.Init) { return }
			state.state = State.MyTurn
			// assert turn == 0 && state.ot.count != 1 && IS_HOST && setup not done
			state.known_board = chess.known_board(state, true)
			chess.renderChessboard(state)
			break;
		case MessageType.Ot:
			// assert correct stage
			switch (data.stage) {
				case 'rsetup':
					if(state.state != State.SendingOT) { return }

					state.ot.Rs_bytes = data.data.map(d => new Uint8Array(d))
					state.ot.count = (state.ot.count || 0) + 1
					if (state.ot.count == 1) {
						state.ot.resp = ot.srespond(state.ot.ssetup, state.ot.Rs_bytes, chess.no_read_proofs(state.secret, state.turn, state.ot.count), state.my_board.map(c => {
							return c.t == ' ' ? c : { c: '!', f: 0 }
						}))
					} else {
						state.ot.resp = ot.srespond(state.ot.ssetup, state.ot.Rs_bytes, chess.no_read_proofs(state.secret, state.turn, state.ot.count), state.my_board)
					}

					if (state.ot.count < chess.SIZE) {
						state.ot.ssetup = ot.ssetup()
						conn.send(messages.Ot('srespond', { srespond: state.ot.resp, S_bytes: state.ot.ssetup.S_bytes }))
					} else {
						state.state = State.OpponentsTurn
						conn.send(messages.Ot('srespond', { srespond: state.ot.resp }))
						state.ot = {}
					}
					break;
				case 'srespond':
					if(state.state != State.ReceivingOT) { return }

					let result = ot.rresult(state.ot.S_bytes, state.ot.rsetup, data.data.srespond.map(d => {
						return {
							e0: { nonce: new Uint8Array(d.e0.nonce), ct: new Uint8Array(d.e0.ct), tag: new Uint8Array(d.e0.tag) },
							e1: { nonce: new Uint8Array(d.e1.nonce), ct: new Uint8Array(d.e1.ct), tag: new Uint8Array(d.e1.tag) }
						}
					}))
					// first one checks captures
					if (state.ot.count == 1) {
						chess.check_captured(state, result)
						state.known_board = chess.known_board(state)
						state.rays = chess.rays(state.my_board, state.IS_HOST)
					} else {
						chess.update_board(state, result)
					}
					chess.renderChessboard(state, state.ot.count)
					if (state.ot.count < chess.SIZE) {
						state.ot.S_bytes = new Uint8Array(data.data.S_bytes)
						let { rays, choices } = chess.choices(state.rays)
						state.rays = rays
						state.choices = choices
						state.ot.rsetup = ot.rsetup(state.ot.S_bytes, choices)
						state.ot.count += 1
						conn.send(messages.Ot('rsetup', state.ot.rsetup.Rs_bytes))
					} else {
						state.ot = {}
						state.waiting = false
						state.state = State.MyTurn
						// todo: make more efficient
						state.known_boards.push(JSON.parse(JSON.stringify(state.known_board)))
					}
					break;
			}
			break;
		case MessageType.Commit:
			if(state.state != State.OpponentsTurn){ return }
			state.state = State.ReceivingOT
			// assert valid
			state.turn++
			state.commits.push(data.commit)
			state.ot.S_bytes = new Uint8Array(data.S_bytes)
			state.choices = state.my_board.map((c) => c.t != ' ' ? 1 : 0)
			state.ot.rsetup = ot.rsetup(state.ot.S_bytes, state.choices)
			state.ot.count = 1
			conn.send(messages.Ot('rsetup', state.ot.rsetup.Rs_bytes))
			state.known_board = chess.known_board(state)
			chess.renderChessboard(state, 1)
			document.getElementById('message').innerText = 'Your turn'
			break;
		case MessageType.EndGame:
			if (!state.ended) {
				// render board
				state.ended = true
				if (data.commit) {
					state.commits.push(data.commit)
				}
				state.conn.send(messages.EndGame({ proof: state.proof, moves: state.moves, commit_prefix: state.commit_prefix }))
			}
			check_game(data)
			break;
	}
	window.state = state
}


export function click(i) {
	// todo remove conditions
	if (state.turn % 2 == state.IS_HOST ? 0 : 1 && !state.waiting && !state.ended && state.state == State.MyTurn) {
		let s = state.my_board[i];
		if (state.selected != null) {
			let move = state.valid_moves.find(m => m.loc == i)
			if (move) {
				move = { loc: state.selected, move: move }
				let win = chess.move(state, move)
				chess.renderChessboard(state, 0)
				state.turn++
				state.waiting = true
				state.ot.ssetup = ot.ssetup()

				state.moves.push(move)
				if (win) {
					state.state = State.GameOver
					state.ended = true;
					state.conn.send(messages.EndGame({ proof: state.proof, moves: state.moves, commit_prefix: state.commit_prefix, commit: hash(state.commit_prefix + JSON.stringify(move)) }))
				} else {
					state.state = State.SendingOT
					state.conn.send(messages.Commit({ commit: hash(state.commit_prefix + JSON.stringify(move)), S_bytes: state.ot.ssetup.S_bytes }))
					document.getElementById('message').innerText = 'Opponents turn'
				}
			}
			document.getElementById(state.selected).classList.remove('selected')
			state.selected = null;
			[...document.getElementsByClassName('target')].forEach(element => {
				element.classList.remove('target')
			});
		} else if (s.t != ' ') {
			state.valid_moves = chess.valid_moves(state.known_board, i)
			if (state.valid_moves.length > 0) {
				state.selected = i
				document.getElementById(i).classList.add('selected')
				for (let m = 0; m < state.valid_moves.length; m++) {
					document.getElementById(state.valid_moves[m].loc)?.classList?.add('target')
				}
			}
		}
	}
}

function check_game(data) {
	document.getElementById('message').innerText = 'Checking validity of game...'
	let check_game_timeout = setTimeout(() => {
		console.log('check game timeout', data)
		document.getElementById('message').innerText = 'Game is invalid'
	}, 5000 + state.moves.length * 500)

	{ // Check commits 
		let calculated_commits = data.moves.map(m => hash(data.commit_prefix + JSON.stringify(m)))
		if (calculated_commits.length != data.moves.length) {
			console.log('COULD NOT PROVE: wrong number of commits/moves!')
			console.log(calculated_commits, state.commits)
			document.getElementById('message').innerText = 'Game is invalid'
			return false
		}
		for (let i = 0; i < calculated_commits.length; i++) {
			if (calculated_commits[i] != state.commits[i]) {
				console.log('COULD NOT PROVE: wrong commits!')
				console.log(calculated_commits, state.commits)
				document.getElementById('message').innerText = 'Game is invalid'
				return false
			}
		}
	}


	//verify data.moves are valid, proof
	// todo check incomming OT data 
	let board = chess.my_board(true)
	{
		let board2 = chess.my_board(false)
		for (let i = 0; i < board.length; i++) {
			if (board2[i].t != ' ') { board[i] = board2[i] }
		}
	}
	let proof_check = hash('')
	for (let i = 0; i < state.moves.length + data.moves.length; i++) {
		let move = (i % 2 == state.IS_HOST ? 0 : 1) ? state.moves[(i - i % 2) / 2] : data.moves[(i - i % 2) / 2]
		if (!chess.valid_moves(board, move.loc)
			.find(v => v.loc == move.move.loc && JSON.stringify(v) == JSON.stringify(move.move))) {
			console.log('Invalid move', board, move)
			document.getElementById('message').innerText = 'Game is invalid'
			return false
		}

		// check proof
		let choices = board.map((c) => (c.t == ' ' || chess.white(c) == state.IS_HOST) ? 0 : 1)
		// choices for capture check are made without knowledge of update
		board = chess.board_after_move(board, move)
		if ((i + 1) < state.moves.length + data.moves.length) {
			if ((i + 1) % 2 == (!state.IS_HOST ? 0 : 1)) { // check their no_read_proofs
				let count = 1
				let no_read_proofs = chess.no_read_proofs(state.secret, i + 1, count)
				for (let j = 0; j < board.length; j++) {
					if (choices[j] == 0) {
						proof_check = chess.xorHex(proof_check, no_read_proofs[j])
					}
				}
				let rays_ = chess.rays(board, !state.IS_HOST)
				while (count < chess.SIZE) {
					count++
					let { rays, choices } = chess.choices(rays_)
					no_read_proofs = chess.no_read_proofs(state.secret, i + 1, count)
					for (let j = 0; j < board.length; j++) {
						if (choices[j] == 0) {
							proof_check = chess.xorHex(proof_check, no_read_proofs[j])
						}
					}
					rays_ = rays.filter(r => {
						return board[chess.idx(r[0], r[1])].t == ' '
					})

				}
			} else {
				for(let b = 0; b < board.length; b++){
					if(state.known_boards[(i - (i % 2))/2][b].t != '~' && state.known_boards[(i - (i % 2))/2][b].t != board[b].t){
						console.log('known board check failed:', i, b)
						console.log(state.known_boards[(i - (i % 2))/2])
						console.log(board)
						document.getElementById('message').innerText = 'Game is invalid'
						return false
					}
				}
			}
		}
	}
	if (data.proof != proof_check) {
		console.log('proof check failed')
		console.log(data.proof)
		console.log(proof_check)
		document.getElementById('message').innerText = 'Game is invalid'
		return false
	}

	state.known_board = board
	chess.renderChessboard(state)
	// todo: set attacked square if any, allow resign, improve join, host replay workflow 
	clearTimeout(check_game_timeout)
	document.getElementById('message').innerText = 'Game finnished'
	return true
}


// START
resetState();
(() => {
	if (IS_HOST) {
		host()
	} else {
		join()
	}
})()
