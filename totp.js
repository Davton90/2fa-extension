// totp.js — TOTP (RFC 6238 / RFC 4226) murni JS, tanpa dependensi.
// SHA-1 + HMAC-SHA1 ditulis manual agar generate kode bisa sinkron
// (dipanggil tiap detik untuk countdown tanpa async jank).

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Decode base32 (RFC 4648, tanpa padding wajib) -> Uint8Array */
export function base32Decode(input) {
  const s = String(input || '').toUpperCase().replace(/[\s-=]/g, '');
  if (!s) throw new Error('Secret kosong');
  if (!/^[A-Z2-7]+$/.test(s)) throw new Error('Secret bukan base32 valid (A-Z, 2-7)');
  let bits = 0, value = 0;
  const out = [];
  for (const ch of s) {
    value = (value << 5) | B32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
      value &= bits > 0 ? (1 << bits) - 1 : 0;
    }
  }
  return new Uint8Array(out);
}

function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) | 0; }

/** SHA-1 murni JS. Input Uint8Array -> Uint8Array(20). */
export function sha1(msg) {
  const ml = msg.length;
  const bitLenHi = Math.floor((ml * 8) / 0x100000000);
  const bitLenLo = (ml * 8) >>> 0;
  // padding: 0x80 + nol + 8 byte panjang
  const padLen = (64 - ((ml + 1 + 8) % 64)) % 64;
  const total = ml + 1 + padLen + 8;
  const buf = new Uint8Array(total);
  buf.set(msg, 0);
  buf[ml] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(total - 8, bitLenHi);
  dv.setUint32(total - 4, bitLenLo);

  let h0 = 0x67452301 | 0, h1 = 0xefcdab89 | 0, h2 = 0x98badcfe | 0;
  let h3 = 0x10325476 | 0, h4 = 0xc3d2e1f0 | 0;
  const w = new Int32Array(80);

  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getInt32(off + i * 4);
    for (let i = 16; i < 80; i++) {
      w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4;
    for (let i = 0; i < 80; i++) {
      let f, k;
      if (i < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
      else { f = b ^ c ^ d; k = 0xca62c1d6; }
      const t = (rotl(a, 5) + f + e + k + w[i]) | 0;
      e = d; d = c; c = rotl(b, 30); b = a; a = t;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0;
    h3 = (h3 + d) | 0; h4 = (h4 + e) | 0;
  }
  const out = new Uint8Array(20);
  const odv = new DataView(out.buffer);
  odv.setInt32(0, h0); odv.setInt32(4, h1); odv.setInt32(8, h2);
  odv.setInt32(12, h3); odv.setInt32(16, h4);
  return out;
}

/** HMAC-SHA1 sinkron. key/msg Uint8Array -> Uint8Array(20) */
export function hmacSha1(key, msg) {
  const BLOCK = 64;
  let k = key;
  if (k.length > BLOCK) k = sha1(k);
  const kp = new Uint8Array(BLOCK);
  kp.set(k, 0);
  const ipad = new Uint8Array(BLOCK), opad = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) {
    ipad[i] = kp[i] ^ 0x36;
    opad[i] = kp[i] ^ 0x5c;
  }
  const inner = new Uint8Array(BLOCK + msg.length);
  inner.set(ipad, 0); inner.set(msg, BLOCK);
  const innerHash = sha1(inner);
  const outer = new Uint8Array(BLOCK + 20);
  outer.set(opad, 0); outer.set(innerHash, BLOCK);
  return sha1(outer);
}

const POW10 = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000];

/**
 * Generate kode TOTP.
 * @param {string} secretBase32
 * @param {object} opts {digits=6, period=30, time=Date.now()}
 */
export function generateTOTP(secretBase32, opts = {}) {
  const digits = opts.digits || 6;
  const period = opts.period || 30;
  const time = opts.time ?? Date.now();
  if (!POW10[digits]) throw new Error('Digits harus 1-8');
  const key = base32Decode(secretBase32);
  if (key.length === 0) throw new Error('Secret kosong setelah decode');

  const counter = Math.floor(Math.floor(time / 1000) / period);
  const msg = new Uint8Array(8);
  // 64-bit big-endian counter (hi selalu 0 untuk praktisnya)
  const dv = new DataView(msg.buffer);
  dv.setUint32(0, Math.floor(counter / 0x100000000));
  dv.setUint32(4, counter >>> 0);

  const h = hmacSha1(key, msg);
  const offset = h[h.length - 1] & 0x0f;
  const code =
    (((h[offset] & 0x7f) << 24) |
      ((h[offset + 1] & 0xff) << 16) |
      ((h[offset + 2] & 0xff) << 8) |
      (h[offset + 3] & 0xff)) % POW10[digits];

  return String(code).padStart(digits, '0');
}

/** Sisa detik sampai kode berikutnya berganti. */
export function secondsRemaining(period = 30, time = Date.now()) {
  return period - (Math.floor(time / 1000) % period);
}

/** Format "123 456" agar mudah dibaca. */
export function formatCode(code) {
  if (code.length === 6) return code.slice(0, 3) + ' ' + code.slice(3);
  if (code.length === 8) return code.slice(0, 4) + ' ' + code.slice(4);
  return code;
}

/**
 * Parse otpauth://totp/... URI dari QR Google Authenticator dkk.
 * -> { issuer, account, secret, digits, period }
 */
export function parseOtpauthUri(uri) {
  const s = String(uri || '').trim();
  if (!/^otpauth:\/\/totp\//i.test(s)) {
    throw new Error('URI harus diawali otpauth://totp/');
  }
  const u = new URL(s);
  if ((u.searchParams.get('algorithm') || 'SHA1').toUpperCase() !== 'SHA1') {
    throw new Error('Hanya algoritma SHA1 yang didukung (layanan ini pakai ' +
      u.searchParams.get('algorithm') + ')');
  }
  const secret = (u.searchParams.get('secret') || '').replace(/[\s-]/g, '').toUpperCase();
  if (!secret) throw new Error('URI tidak berisi secret');
  base32Decode(secret); // validasi

  const rawLabel = decodeURIComponent(u.pathname.replace(/^\/+/, ''));
  let issuer = u.searchParams.get('issuer') || '';
  let account = rawLabel;
  if (rawLabel.includes(':')) {
    const idx = rawLabel.indexOf(':');
    if (!issuer) issuer = rawLabel.slice(0, idx).trim();
    account = rawLabel.slice(idx + 1).trim();
  }
  return {
    issuer: issuer.trim(),
    account: (account || '').trim() || 'Tanpa nama',
    secret,
    digits: Math.min(8, Math.max(6, parseInt(u.searchParams.get('digits') || '6', 10) || 6)),
    period: Math.min(120, Math.max(15, parseInt(u.searchParams.get('period') || '30', 10) || 30)),
  };
}
