import './peerjs.min.js';
import { ClientHello } from './messages.js';
import { handleData } from './client.js';

export async function join() {
	console.log('joining')
	let peer = new Peer();
	const urlParams = new URLSearchParams(window.location.search);

	let unable_to_connect = setTimeout(() => {
		document.getElementById('message').innerHTML = "<h1>Opponent has disconnected</h1><h2><a href='./.'>Host a game yourself?<a></h2>"
	}, 5000)
	peer.on('open', (id) => {
		onbeforeunload = (_) => { peer.destroy() }

		peer.on('close', () => {
			peer.destroy()
			document.getElementById('message').innerHTML = "<h1>Opponent has disconnected</h1><h2><a href='./.'>Host a game yourself?<a></h2>"
		})

		peer.on('disconnected', () => { document.getElementsByTagName('body')[0].innerHTML = "<h1>Opponent has disconnected</h1><h2><a href='./.'>Host a game yourself?<a></h2>" })
		peer.on('error', (err) => { console.log(err) })
		let conn = peer.connect(urlParams.get('id'), { reliable: true })
		conn.on('data', (data) => handleData(conn, data.type, data.data));
		conn.on('open', () => {
			clearTimeout(unable_to_connect)
			conn.send(ClientHello())
		})
		conn.on('close', () => {
			document.getElementById('message').innerHTML = "<h1>Opponent has disconnected</h1><h2><a href='./.'>Host a game yourself?<a></h2>"
		})
		conn.on('error', () => { console.log('error') })
	})
}