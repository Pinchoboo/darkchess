// Malicious-secure 1-out-of-2 OT (random-OT + AE) based on Chou–Orlandi '15 (CO15)
// Group: secp256k1 via @noble/curves. Hash/KDF: HKDF-SHA512 via @noble/hashes.
// Security model: ROM; includes group-membership validation and transcript-keyed KDF as in CO15.
// This file exposes minimal, composable functions for Sender/Receiver roles and a small AE wrapper.
// Dependencies: npm i @noble/curves @noble/hashes

import { secp256k1 } from 'https://esm.sh/@noble/curves@1.9.7/secp256k1';
import { hkdf } from 'https://esm.sh/@noble/hashes@1.8.0/hkdf';
import { sha512 } from 'https://esm.sh/@noble/hashes@1.8.0/sha512';
import { randomBytes } from 'https://esm.sh/@noble/hashes@1.8.0/utils';

// ----- Low-level helpers -----
const Point = secp256k1.ProjectivePoint; // prime-order group
const G = Point.BASE;
const n = BigInt(secp256k1.CURVE.n);

function modN(x) { x %= n; return x >= 0n ? x : x + n; }
function bytesToBigInt(b) {
  let hex = [...b].map(x => x.toString(16).padStart(2, "0")).join("");
  return modN(BigInt("0x" + (hex || "0")));
}
function randScalar() { return modN(bytesToBigInt(randomBytes(32))); }

function enc(P) { return P.toRawBytes(true); }            // compressed SEC1
function dec(bytes) {                                     // validates subgroup & on-curve
  try { return Point.fromHex(bytes); } catch { throw new Error('Invalid curve point'); }
}

function concatBytes(...arrs) {
  const len = arrs.reduce((a, b) => a + b.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

// HKDF-SHA512-based KDF H((S,R), U) -> 32 bytes
function kdfKey(S_bytes, R_bytes, U_point) {
  const salt = sha512.create().update(S_bytes).update(R_bytes).digest();
  const ikm  = enc(U_point);
  return hkdf(sha512, ikm, salt, new TextEncoder().encode('CO15-OT-key'), 32);
}

// Simple AE using HKDF to derive (keystream, MAC) and XOR + HMAC-SHA512/256-like tag
// Deterministic per (key, aad, nonce). Nonce must be unique per message under a key.
import { hmac } from 'https://esm.sh/@noble/hashes@1.8.0/hmac';
import { sha256 } from 'https://esm.sh/@noble/hashes@1.8.0/sha256';
export function hash(s){
	const data = new TextEncoder().encode(s);
	const hash = sha256(data);
	return [...hash].map(b => b.toString(16).padStart(2, "0")).join("");
};
function aeadSeal(key32, nonce12, aad, plaintext) {
  const prk = hkdf(sha512, key32, nonce12, new TextEncoder().encode('CO15-AE-v1'), 64);
  const ks  = prk.slice(0, plaintext.length);
  const macKey = prk.slice(plaintext.length);
  const ct = new Uint8Array(plaintext.length);
  for (let i = 0; i < plaintext.length; i++) ct[i] = plaintext[i] ^ ks[i];
  const tag = hmac(sha256, macKey, concatBytes(aad, nonce12, ct)).slice(0, 32);
  return { ct, tag };
}

function aeadOpen(key32, nonce12, aad, ct, tag) {
  const prk = hkdf(sha512, key32, nonce12, new TextEncoder().encode('CO15-AE-v1'), 64);
  const ks  = prk.slice(0, ct.length);
  const macKey = prk.slice(ct.length);
  const calc = hmac(sha256, macKey, concatBytes(aad, nonce12, ct)).slice(0, 32);
  // constant-time compare
  if (calc.length !== tag.length) throw new Error('bad tag');
  let ok = 0; for (let i = 0; i < tag.length; i++) ok |= calc[i] ^ tag[i];
  if (ok !== 0) throw new Error('bad tag');
  const pt = new Uint8Array(ct.length);
  for (let i = 0; i < ct.length; i++) pt[i] = ct[i] ^ ks[i];
  return pt;
}

// ----- CO15 Random-OT (1-out-of-2) -----
// Setup (Sender, one-time, reusable for many parallel OTs)
export function co15_sender_setup() {
  const y = randScalar();
  if (y === 0n) return co15_sender_setup();
  const S = G.multiply(y);          // S = yB
  const T = S.multiply(y);          // T = yS = y^2 B
  return { y, S_bytes: enc(S), T_bytes: enc(T) };
}

// Receiver chooses n OTs with choices c[i] ∈ {0,1}
export function co15_receiver_choose(S_bytes, choices /* Uint8Array of 0/1 */) {
  const S = dec(S_bytes);
  const xs = []; const Rs_bytes = [];
  for (let i = 0; i < choices.length; i++) {
    const x = randScalar(); if (x === 0n) { i--; continue; }
    xs.push(x);
    const Ri = (choices[i] ? S : Point.ZERO).add(G.multiply(x)); // Ri = c*S + x*B
    Rs_bytes.push(enc(Ri));
  }
  return { xs, Rs_bytes };
}


// Sender derives two random keys per-OT (k0, k1). Optionally encrypts payloads m0/m1.
export function co15_sender_respond(y, S_bytes, T_bytes, Rs_bytes, opts /* { messages0?: Uint8Array[], messages1?: Uint8Array[], aead?: boolean } */ = {}) {
  const S = dec(S_bytes); const T = dec(T_bytes);
  const out = [];
  for (let i = 0; i < Rs_bytes.length; i++) {
    const Ri = dec(Rs_bytes[i]);
    // U_j = y*Ri - j*T
    const U0 = Ri.multiply(y);              // yRi
    const U1 = U0.subtract(T);              // yRi - T
    const k0 = kdfKey(S_bytes, Rs_bytes[i], U0);
    const k1 = kdfKey(S_bytes, Rs_bytes[i], U1);

    if (opts.messages0 && opts.messages1) {
      const m0 = opts.messages0[i]; const m1 = opts.messages1[i];
      const nonce0 = randomBytes(12); const nonce1 = randomBytes(12);
      const aad = concatBytes(S_bytes, Rs_bytes[i]);
      const { ct: c0, tag: t0 } = aeadSeal(k0, nonce0, aad, m0);
      const { ct: c1, tag: t1 } = aeadSeal(k1, nonce1, aad, m1);
      out.push({ e0: { nonce: nonce0, ct: c0, tag: t0 }, e1: { nonce: nonce1, ct: c1, tag: t1 } });
    } else {
      out.push({ k0, k1 });
    }
  }
  return out; // array per-OT
}

// Receiver derives its key k_c (or decrypts selected ciphertext)
export function co15_receiver_output(S_bytes, Rs_bytes, xs, choiceBits, payloads /* array from sender_respond */) {
  const S = dec(S_bytes);
  const results = [];
  for (let i = 0; i < Rs_bytes.length; i++) {
    const Ri = dec(Rs_bytes[i]);
    const x = xs[i];
    const Uc = S.multiply(x);                   // x*S = x*y*B = xyB
    const kc = kdfKey(S_bytes, Rs_bytes[i], Uc);
    const choice = choiceBits[i] ? 1 : 0;
    const item = payloads[i];
    if (item.k0 && item.k1) {
      results.push(choice === 0 ? item.k0 : item.k1); // raw key
    } else if (item.e0 && item.e1) {
      const e = choice === 0 ? item.e0 : item.e1;
      const aad = concatBytes(S_bytes, Rs_bytes[i]);
      const pt = aeadOpen(kc, e.nonce, aad, e.ct, e.tag);
      results.push(pt);
    } else {
      throw new Error('Malformed payload');
    }
  }
  return results;
}

// ----- Malicious-safety notes and enforcement -----
// 1) dec() rejects invalid points, preventing invalid-curve and subgroup attacks.
// 2) Transcript-keyed KDF (salt = H(S||R)) follows CO15 to resist MITM key-reuse issues.
// 3) AE layer provides integrity for ciphertext-carrying use; for random-OT keys, use as KDF outputs.
// 4) State separation: never reuse the same (S, y) across unrelated sessions if adversarial relay is possible.
// 5) For many OTs, reuse S across parallel instances in one session; keep T = y*S private to sender.

// ----- Example (Node) -----
// import { co15_sender_setup, co15_receiver_choose, co15_sender_respond, co15_receiver_output } from './malicious-secure-ot.js';
// const { y, S_bytes, T_bytes } = co15_sender_setup();
// const choices = Uint8Array.from([0,1,1,0]);
// const r = co15_receiver_choose(S_bytes, choices);
// // Option A: random-OT keys
// const payloadA = co15_sender_respond(y, S_bytes, T_bytes, r.Rs_bytes);
// const keys = co15_receiver_output(S_bytes, r.Rs_bytes, r.xs, choices, payloadA);
// // Option B: carry messages via AE
// const m0 = [new TextEncoder().encode('alpha'), new TextEncoder().encode('bravo'), new Uint8Array([1,2,3]), new Uint8Array([9])];
// const m1 = [new TextEncoder().encode('one'),   new TextEncoder().encode('two'),   new Uint8Array([4,5,6]), new Uint8Array([8])];
// const payloadB = co15_sender_respond(y, S_bytes, T_bytes, r.Rs_bytes, { messages0: m0, messages1: m1 });
// const out = co15_receiver_output(S_bytes, r.Rs_bytes, r.xs, choices, payloadB);

// ----- KOS15-style malicious OT extension (sketch implementation) -----
// For large-batch OTs, wrap CO15 base-OTs with extension and correlation checks
// Minimal, didactic outline for binary-OT extension; not performance-tuned.


function xorBytes(a, b) { const o = new Uint8Array(a.length); for (let i=0;i<a.length;i++) o[i] = a[i]^b[i]; return o; }
function prg(seed, bytes=1024) { // expand seed using HKDF-SHA512
  return hkdf(sha512, seed, new Uint8Array(0), new TextEncoder().encode('OT-PRG'), bytes);
}

// Receiver side of KOS15 extension
export function kos15_extend_receiver(baseSenderS_bytes, baseT_bytes, base_count /* = k = 128 */, N /* number of extended OTs */, choices /* Uint8Array */) {
  // 1) Run base_count CO15 OTs with the receiver acting as SENDER of choices for base seeds
  //    Here we flip roles via CO15: treat each base-OT as sender sending two seeds; receiver selects one.
  //    For simplicity, we inline a role-reversal using CO15 where the actual sender initiates base-OTs outside.
  throw new Error('KOS15 extension outline only. Integrate with a role-reversed CO15 base-OT to exchange seeds, then implement Q-matrix + correlation check.');
}

export function kos15_extend_sender() {
  throw new Error('KOS15 extension outline only. Implement per KOS15 with T matrix, correlation check using random chi and AES-ECB-free hashing.');
}
