// FallMail · P2P encrypted messaging · DID-addressed
// ECDH(x25519) + AES-GCM + Ed25519 signatures
// Uses FallID (identity) + FallLink (transport) + FallPod (persistence) + FallStore (attachments)
// AI-Native Solutions · MIT · 2026
//
// Wire format (one message):
//   { id, fromDid, toDid, subject, encryptedBody, attachments[], timestamp, signature, ephPub }
// - `encryptedBody` = base64(AES-GCM(body-json, K)) where K = HKDF(x25519(a, B))
// - `ephPub`        = base64 raw x25519 32-byte ephemeral public key (sender side)
// - `signature`     = base58btc(Ed25519(sig over id))
// - `id`            = sha256hex of encryptedBody + toDid
//
// Storage paths (via FallPod):
//   /mail/inbox/<id>.json     — received (kept encrypted at rest; decrypted on read)
//   /mail/outbox/<id>.json    — sent   (kept locally with plaintext + wire copy)
//   /mail/read/<id>           — read tombstone
//   /mail/trash/<id>          — deleted tombstone
//   /mail/drafts/<id>.json    — drafts

// ─── base58btc ────────────────────────────────────────────────────
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58encode(bytes) {
  if (!bytes.length) return '';
  let zeros = 0; while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits = [0];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) { carry += digits[j] << 8; digits[j] = carry % 58; carry = (carry / 58) | 0; }
    while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = '';
  for (let i = 0; i < zeros; i++) out += '1';
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out;
}
function b58decode(str) {
  if (!str) return new Uint8Array(0);
  const bytes = [0];
  for (const c of str) {
    const v = B58.indexOf(c); if (v < 0) throw new Error('bad b58 char: ' + c);
    let carry = v;
    for (let j = 0; j < bytes.length; j++) { carry += bytes[j] * 58; bytes[j] = carry & 0xff; carry >>>= 8; }
    while (carry) { bytes.push(carry & 0xff); carry >>>= 8; }
  }
  let zeros = 0; for (const c of str) { if (c === '1') zeros++; else break; }
  const out = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[zeros + i] = bytes[bytes.length - 1 - i];
  return out;
}

// ─── base64 ───────────────────────────────────────────────────────
function b64(bytes) { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s); }
function unb64(str) { const s = atob(str); const out = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i); return out; }

// ─── hex ──────────────────────────────────────────────────────────
function hex(bytes) { return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''); }

// ─── did:key (Ed25519) parsing ────────────────────────────────────
// FallID emits: 'did:key:z' + b58btc(0xed 0x01 || pubkey32)
function didToEdPub(did) {
  if (!did || !did.startsWith('did:key:z')) throw new Error('bad DID: ' + did);
  const raw = b58decode(did.slice('did:key:z'.length));
  if (raw.length < 34 || raw[0] !== 0xed || raw[1] !== 0x01) throw new Error('not an Ed25519 did:key');
  return raw.slice(2); // 32-byte Ed25519 public key
}

// ─── curve25519 (X25519) — RFC 7748 scalar mult, BigInt ───────────
const P25519 = (1n << 255n) - 19n;
const A24 = 121665n;
function decodeScalar(k) {
  const s = k.slice(); s[0] &= 248; s[31] &= 127; s[31] |= 64;
  let n = 0n; for (let i = 31; i >= 0; i--) n = (n << 8n) | BigInt(s[i]); return n;
}
function decodeU(u) {
  const s = u.slice(); s[31] &= 127;
  let n = 0n; for (let i = 31; i >= 0; i--) n = (n << 8n) | BigInt(s[i]); return n % P25519;
}
function encodeU(u) {
  const out = new Uint8Array(32); let n = ((u % P25519) + P25519) % P25519;
  for (let i = 0; i < 32; i++) { out[i] = Number(n & 0xffn); n >>= 8n; } return out;
}
function powMod(base, exp, m) {
  let r = 1n, b = base % m;
  while (exp > 0n) { if (exp & 1n) r = (r * b) % m; b = (b * b) % m; exp >>= 1n; }
  return r;
}
function inv(x) { return powMod(x, P25519 - 2n, P25519); }
function cswap(a, b, swap) { const d = (0n - swap) & ((1n << 256n) - 1n) & (a ^ b); return [a ^ d, b ^ d]; }
function x25519_scalarMult(kBytes, uBytes) {
  const k = decodeScalar(kBytes);
  const u = decodeU(uBytes);
  let x1 = u, x2 = 1n, z2 = 0n, x3 = u, z3 = 1n, swap = 0n;
  for (let t = 254; t >= 0; t--) {
    const kt = (k >> BigInt(t)) & 1n;
    swap ^= kt;
    [x2, x3] = cswap(x2, x3, swap);
    [z2, z3] = cswap(z2, z3, swap);
    swap = kt;
    const A = (x2 + z2) % P25519, AA = (A * A) % P25519;
    const B = (x2 - z2 + P25519) % P25519, BB = (B * B) % P25519;
    const E = (AA - BB + P25519) % P25519;
    const C = (x3 + z3) % P25519, D = (x3 - z3 + P25519) % P25519;
    const DA = (D * A) % P25519, CB = (C * B) % P25519;
    x3 = powMod((DA + CB) % P25519, 2n, P25519);
    z3 = (x1 * powMod((DA - CB + P25519) % P25519, 2n, P25519)) % P25519;
    x2 = (AA * BB) % P25519;
    z2 = (E * ((AA + (A24 * E) % P25519) % P25519)) % P25519;
  }
  [x2, x3] = cswap(x2, x3, swap);
  [z2, z3] = cswap(z2, z3, swap);
  return encodeU((x2 * inv(z2)) % P25519);
}
const X25519_BASE = (() => { const b = new Uint8Array(32); b[0] = 9; return b; })();
function x25519_publicKey(sk) { return x25519_scalarMult(sk, X25519_BASE); }

// ─── Ed25519 pubkey (Edwards y) → X25519 pubkey (Montgomery u) ────
// u = (1 + y) / (1 - y)  mod p
function edPubToXPub(edPub32) {
  const y = decodeU(edPub32); // note: strips sign bit which lives in bit 255
  const num = (1n + y) % P25519;
  const den = (1n - y + P25519) % P25519;
  const u = (num * inv(den)) % P25519;
  return encodeU(u);
}

// ─── AES-GCM + HKDF wrapper ───────────────────────────────────────
async function hkdfKey(shared, info) {
  const salt = new TextEncoder().encode('fallmail-v1');
  const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(info) },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
async function aesEncrypt(key, plain) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));
  const out = new Uint8Array(iv.length + ct.length); out.set(iv, 0); out.set(ct, iv.length); return out;
}
async function aesDecrypt(key, blob) {
  const iv = blob.slice(0, 12), ct = blob.slice(12);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
}
async function sha256hex(bytes) {
  const buf = await crypto.subtle.digest('SHA-256', bytes); return hex(new Uint8Array(buf));
}

// ─── FallMail class ───────────────────────────────────────────────
export class FallMail extends EventTarget {
  constructor({ fallid, falllink, fallpod, fallstore } = {}) {
    super();
    if (!fallid) throw new Error('FallMail requires { fallid }');
    if (!fallpod) throw new Error('FallMail requires { fallpod }');
    this.fallid = fallid;
    this.falllink = falllink || null;
    this.fallpod = fallpod;
    this.fallstore = fallstore || null;
    this._callbacks = new Set();
    this._wired = false;
    this._did = null;
  }

  async ready() {
    this._did = await this.fallid.getDID();
    if (this.falllink && !this._wired) {
      this.falllink.on('message', (d) => this._onWire(d));
      this._wired = true;
    }
    // ensure mail dirs exist by writing a keeper marker (idempotent)
    try { await this.fallpod.put('/mail/.keep', { init: Date.now() }); } catch {}
    return this;
  }

  onMessage(fn) { this._callbacks.add(fn); return () => this._callbacks.delete(fn); }
  _emit(msg) { for (const fn of this._callbacks) try { fn(msg); } catch {} }

  // ─── send ───
  async send(toDid, subject, body, attachments = []) {
    await this.ready();
    if (!toDid || !toDid.startsWith('did:key:z')) throw new Error('toDid must be did:key:z…');
    const bodyObj = { subject: subject || '', body: body || '', attachments: attachments || [] };
    const bodyBytes = new TextEncoder().encode(JSON.stringify(bodyObj));

    // ephemeral X25519 keypair
    const ephSk = crypto.getRandomValues(new Uint8Array(32));
    const ephPk = x25519_publicKey(ephSk);

    // recipient X25519 pubkey (derived from their Ed25519 did:key)
    const recipEd = didToEdPub(toDid);
    const recipXPub = edPubToXPub(recipEd);
    const shared = x25519_scalarMult(ephSk, recipXPub);

    const key = await hkdfKey(shared, 'fallmail-msg:' + toDid);
    const ct = await aesEncrypt(key, bodyBytes);
    const encryptedBody = b64(ct);
    const idBytes = new TextEncoder().encode(encryptedBody + toDid);
    const id = await sha256hex(idBytes);

    const sig = await this.fallid.sign(new TextEncoder().encode(id));
    const signature = b58encode(sig);
    const timestamp = new Date().toISOString();

    const wire = {
      id, fromDid: this._did, toDid,
      subject: subject || '',
      encryptedBody,
      ephPub: b64(ephPk),
      attachments: attachments || [],
      timestamp,
      signature,
      v: 1
    };

    // local outbox mirror (plaintext) — sovereign, local only
    await this.fallpod.put('/mail/outbox/' + id + '.json', {
      wire, plain: bodyObj, sentAt: timestamp, toDid, fromDid: this._did, subject
    });

    // transmit via FallLink (broadcast to all connected peers; recipient filters)
    let delivered = false;
    if (this.falllink) {
      try {
        const sent = this.falllink.broadcast({ __fm: 'mail', wire });
        delivered = sent > 0;
      } catch (e) { /* offline is fine — outbox retains it */ }
    }
    this.dispatchEvent(new CustomEvent('sent', { detail: { id, delivered } }));
    return { id, delivered, wire };
  }

  // ─── inbox / outbox ───
  async inbox() {
    const paths = await this.fallpod.list('/mail/inbox/');
    const trashKeys = new Set((await this.fallpod.list('/mail/trash/')).map(p => p.split('/').pop()));
    const readKeys = new Set((await this.fallpod.list('/mail/read/')).map(p => p.split('/').pop()));
    const out = [];
    for (const p of paths) {
      const rec = await this.fallpod.get(p);
      if (!rec) continue;
      const id = rec.wire?.id || p.split('/').pop().replace(/\.json$/, '');
      if (trashKeys.has(id)) continue;
      try {
        const decrypted = await this._decrypt(rec.wire);
        out.push({
          id, fromDid: rec.wire.fromDid, toDid: rec.wire.toDid,
          subject: decrypted.subject || rec.wire.subject || '(no subject)',
          body: decrypted.body || '',
          attachments: decrypted.attachments || [],
          timestamp: rec.wire.timestamp,
          verified: decrypted.verified === true,
          read: readKeys.has(id)
        });
      } catch (e) {
        out.push({ id, fromDid: rec.wire.fromDid, toDid: rec.wire.toDid, subject: rec.wire.subject, body: '(decryption failed: ' + e.message + ')', attachments: [], timestamp: rec.wire.timestamp, verified: false, read: readKeys.has(id), error: true });
      }
    }
    out.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
    return out;
  }

  async outbox() {
    const paths = await this.fallpod.list('/mail/outbox/');
    const trashKeys = new Set((await this.fallpod.list('/mail/trash/')).map(p => p.split('/').pop()));
    const out = [];
    for (const p of paths) {
      const rec = await this.fallpod.get(p);
      if (!rec) continue;
      const id = rec.wire?.id || p.split('/').pop().replace(/\.json$/, '');
      if (trashKeys.has(id)) continue;
      out.push({
        id, fromDid: rec.fromDid, toDid: rec.toDid,
        subject: rec.subject || rec.plain?.subject || '(no subject)',
        body: rec.plain?.body || '', attachments: rec.plain?.attachments || [],
        timestamp: rec.sentAt, verified: true, read: true
      });
    }
    out.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
    return out;
  }

  async drafts() {
    const paths = await this.fallpod.list('/mail/drafts/');
    const out = [];
    for (const p of paths) {
      const rec = await this.fallpod.get(p); if (!rec) continue;
      out.push({ ...rec, id: rec.id || p.split('/').pop().replace(/\.json$/, '') });
    }
    out.sort((a, b) => (b.savedAt || '').localeCompare(a.savedAt || ''));
    return out;
  }

  async saveDraft(draft) {
    const id = draft.id || 'draft-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    const rec = { id, toDid: draft.toDid || '', subject: draft.subject || '', body: draft.body || '', attachments: draft.attachments || [], savedAt: new Date().toISOString() };
    await this.fallpod.put('/mail/drafts/' + id + '.json', rec);
    return rec;
  }

  async deleteDraft(id) { await this.fallpod.delete('/mail/drafts/' + id + '.json'); }

  async trash() {
    const paths = await this.fallpod.list('/mail/trash/');
    const out = [];
    for (const p of paths) {
      const id = p.split('/').pop();
      const inRec = await this.fallpod.get('/mail/inbox/' + id + '.json');
      const outRec = await this.fallpod.get('/mail/outbox/' + id + '.json');
      const rec = inRec || outRec; if (!rec) continue;
      try {
        const dec = inRec ? await this._decrypt(rec.wire) : rec.plain;
        out.push({ id, fromDid: rec.wire?.fromDid || rec.fromDid, toDid: rec.wire?.toDid || rec.toDid, subject: dec?.subject || rec.subject || '(no subject)', body: dec?.body || '', timestamp: rec.wire?.timestamp || rec.sentAt, attachments: dec?.attachments || [] });
      } catch {}
    }
    return out;
  }

  async read(id) { await this.fallpod.put('/mail/read/' + id, { at: new Date().toISOString() }); }
  async unread(id) { try { await this.fallpod.delete('/mail/read/' + id); } catch {} }
  async delete(id) { await this.fallpod.put('/mail/trash/' + id, { at: new Date().toISOString() }); }
  async restore(id) { try { await this.fallpod.delete('/mail/trash/' + id); } catch {} }

  async reply(messageId, body) {
    const all = [...(await this.inbox()), ...(await this.outbox())];
    const original = all.find(m => m.id === messageId);
    if (!original) throw new Error('original message not found: ' + messageId);
    const target = original.fromDid === this._did ? original.toDid : original.fromDid;
    const subj = original.subject.startsWith('Re: ') ? original.subject : 'Re: ' + original.subject;
    return this.send(target, subj, body);
  }

  async attach(fileBlob) {
    if (!this.fallstore) throw new Error('FallMail: no fallstore configured');
    const name = fileBlob.name || 'attachment';
    const type = fileBlob.type || 'application/octet-stream';
    const cid = await this.fallstore.store(fileBlob);
    return { cid, name, type, size: fileBlob.size || 0 };
  }

  async fetchAttachment(cid) {
    if (!this.fallstore) throw new Error('FallMail: no fallstore configured');
    return this.fallstore.retrieve(cid);
  }

  // ─── decrypt (recipient side) ───
  async _decrypt(wire) {
    // We are the recipient. Compute X25519 shared = scalarMult(ourXSk, ephPub)
    const ourXSk = await this._ourXSk();
    const eph = unb64(wire.ephPub);
    const shared = x25519_scalarMult(ourXSk, eph);
    const key = await hkdfKey(shared, 'fallmail-msg:' + wire.toDid);
    const plain = await aesDecrypt(key, unb64(wire.encryptedBody));
    const obj = JSON.parse(new TextDecoder().decode(plain));

    // verify signature over id (with sender's DID)
    let verified = false;
    try {
      const sig = b58decode(wire.signature);
      verified = await this.fallid.verify(new TextEncoder().encode(wire.id), sig, wire.fromDid);
    } catch { verified = false; }
    return { ...obj, verified };
  }

  // Derive our X25519 secret key from the Ed25519 identity via JWK 'd' seed
  // (SHA-512 of seed, clamp lower half — canonical Ed25519→X25519 map)
  async _ourXSk() {
    if (this._xSk) return this._xSk;
    // Access private JWK via FallID's internal cache. FallID stores JWK in IDB;
    // we open the same DB to read the seed. Sovereign, same origin, no key export.
    const seed = await this._readEdSeed();
    const h = new Uint8Array(await crypto.subtle.digest('SHA-512', seed));
    const sk = h.slice(0, 32);
    sk[0] &= 248; sk[31] &= 127; sk[31] |= 64;
    this._xSk = sk;
    return sk;
  }

  async _readEdSeed() {
    // FallID DB: name 'fallid', store 'identity', key 'primary' → { privkeyJwk: { d: base64url(seed) } }
    const db = await new Promise((res, rej) => { const r = indexedDB.open('fallid', 1); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
    const rec = await new Promise((res, rej) => { const t = db.transaction('identity', 'readonly').objectStore('identity').get('primary'); t.onsuccess = () => res(t.result); t.onerror = () => rej(t.error); });
    if (!rec || !rec.privkeyJwk || !rec.privkeyJwk.d) throw new Error('FallID identity not initialised');
    const b64u = rec.privkeyJwk.d.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64u + '==='.slice((b64u.length + 3) % 4);
    const bin = atob(pad); const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.slice(0, 32);
  }

  // ─── wire ingress ───
  async _onWire(payload) {
    // FallLink emits raw string or object depending on how peer sends. Normalize.
    let obj = payload;
    if (typeof payload === 'string') { try { obj = JSON.parse(payload); } catch { return; } }
    if (obj && obj.data && typeof obj.data === 'string') { try { obj = JSON.parse(obj.data); } catch {} }
    else if (obj && obj.data) obj = obj.data;
    if (!obj || obj.__fm !== 'mail' || !obj.wire) return;
    const wire = obj.wire;
    if (wire.toDid !== this._did) return; // not for us
    // dedupe: skip if already stored
    const path = '/mail/inbox/' + wire.id + '.json';
    if (await this.fallpod.exists(path)) return;
    await this.fallpod.put(path, { wire, receivedAt: new Date().toISOString() });
    let preview = { subject: wire.subject };
    try { preview = await this._decrypt(wire); } catch {}
    const msg = { id: wire.id, fromDid: wire.fromDid, subject: preview.subject || wire.subject, verified: preview.verified === true, timestamp: wire.timestamp };
    this._emit(msg);
    this.dispatchEvent(new CustomEvent('message', { detail: msg }));
  }

  // ─── local injection (for testing/loopback) ───
  async _inject(wire) { return this._onWire({ __fm: 'mail', wire }); }
}

export default FallMail;
