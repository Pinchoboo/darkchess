// Clean toy demo for malicious-secure OT functions
// Import functions from core file
import {
  co15_sender_setup,
  co15_receiver_choose,
  co15_sender_respond,
  co15_receiver_output,
  hash
} from './malicious-secure-ot.js'; // core implementation file

function encTxt(s) {
	s = JSON.stringify(s).padEnd(66, " ").slice(0, 66)
	return new TextEncoder().encode(s);
}

export function ssetup() {
	//{ y, S_bytes, T_bytes }
	return co15_sender_setup()
} 
export function rsetup(S_bytes, choice_bits){
   choice_bits = Uint8Array.from(choice_bits);
   //{ xs, Rs_bytes }
   return {choice_bits: choice_bits, ...co15_receiver_choose(S_bytes, choice_bits)};
}

export function srespond(ssetup, Rs_bytes, messages0, messages1){
   return co15_sender_respond(ssetup.y, ssetup.S_bytes, ssetup.T_bytes, Rs_bytes, { messages0: messages0.map(encTxt), messages1: messages1.map(encTxt) });
}

export function rresult(S_bytes, rsetup, data){
	let td = new TextDecoder()
	return co15_receiver_output(S_bytes, rsetup.Rs_bytes, rsetup.xs, rsetup.choice_bits, data).map(d => JSON.parse(td.decode(d)));
}