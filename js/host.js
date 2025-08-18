import './peerjs.min.js';
import { handleData } from './client.js';
import { MessageType } from './enums.js';
const BasePath = location.protocol + '//' + location.host + location.pathname.replaceAll(/index\.html/g, '');


export async function host() {
	console.log('hosting')
	let peer = new Peer();
	peer.on('open', (id) => {
		onbeforeunload = (_) => { peer.destroy() }
		// display join url
		document.getElementsByTagName('body')[0].innerHTML += `<h3 onclick="copy('${BasePath}?id=${id}')" href="#">&#128279;Click to copy challenge link</h3> `

		peer.on('connection', function (conn) {
			conn.on('data', (data) => handleData(conn, data.type, data.data));
			conn.on('close', () => handleData(conn, MessageType.Close, null))
			conn.on('error', (err) => { console.log(err) })
		});

		peer.on('close', () => { peer.destroy() })
		peer.on('disconnected', () => { peer.reconnect() })
		peer.on('error', (err) => { console.log(err) })
	})
}

window.copy = (s) => {
	navigator.clipboard.writeText(s).then(() => {
		const popup = document.getElementById("popup");
		popup.classList.add("show");
		setTimeout(() => {
			popup.classList.remove("show");
		}, 3000);
	});
}