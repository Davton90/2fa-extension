// crypto-vault.js — enkripsi AES-GCM 256 + PBKDF2-SHA256 untuk vault TOTP.
// Vault tersimpan di chrome.storage.local (terenkripsi).
// Kunci sesi disimpan di chrome.storage.session (hilang saat browser ditutup).

const VAULT_KEY = '2fa_vault';
const SESSION_KEY = '2fa_session';
const SETTINGS_KEY = '2fa_settings';
const KDF_ITER = 120000;

const te = new TextEncoder();
const td = new TextDecoder();

function b64encode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function b64decode(b64) {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

async function deriveKey(password, saltB64, iter = KDF_ITER) {
  const salt = typeof saltB64 === 'string' ? b64decode(saltB64) : saltB64;
  const base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/** Enkripsi array akun -> objek vault siap simpan. */
export async function encryptAccounts(accounts, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    te.encode(JSON.stringify(accounts))
  );
  const rawKey = b64encode(new Uint8Array(await crypto.subtle.exportKey('raw', key)));
  return {
    vault: {
      v: 1, iter: KDF_ITER,
      salt: b64encode(salt), iv: b64encode(iv),
      data: b64encode(new Uint8Array(ct)),
    },
    rawKey,
  };
}

/** Dekripsi vault dengan password -> array akun. */
export async function decryptWithPassword(vault, password) {
  const key = await deriveKey(password, vault.salt, vault.iter || KDF_ITER);
  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64decode(vault.iv) },
      key,
      b64decode(vault.data)
    );
  } catch {
    throw new Error('Password salah');
  }
  const rawKey = b64encode(new Uint8Array(await crypto.subtle.exportKey('raw', key)));
  return { accounts: JSON.parse(td.decode(plain)), rawKey };
}

/** Dekripsi vault dengan rawKey dari sesi (tanpa password). */
export async function decryptWithRawKey(vault, rawKeyB64) {
  const key = await crypto.subtle.importKey(
    'raw', b64decode(rawKeyB64), { name: 'AES-GCM' }, false, ['decrypt']
  );
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64decode(vault.iv) },
    key,
    b64decode(vault.data)
  );
  return JSON.parse(td.decode(plain));
}

// ---- storage helpers ----

export async function getVault() {
  const r = await chrome.storage.local.get(VAULT_KEY);
  return r[VAULT_KEY] || null;
}
export async function setVault(vault) {
  await chrome.storage.local.set({ [VAULT_KEY]: vault });
}
export async function hasVault() {
  return !!(await getVault());
}

export async function getSettings() {
  const r = await chrome.storage.local.get(SETTINGS_KEY);
  return { autolockMin: 10, ...(r[SETTINGS_KEY] || {}) };
}
export async function setSettings(s) {
  await chrome.storage.local.set({ [SETTINGS_KEY]: s });
}

async function sessionStore() {
  try {
    if (chrome.storage.session) {
      return {
        get: async () => (await chrome.storage.session.get(SESSION_KEY))[SESSION_KEY] || null,
        set: async (v) => chrome.storage.session.set({ [SESSION_KEY]: v }),
        clear: async () => chrome.storage.session.remove(SESSION_KEY),
      };
    }
  } catch { /* fallback memori */ }
  let mem = null;
  return {
    get: async () => mem,
    set: async (v) => { mem = v; },
    clear: async () => { mem = null; },
  };
}

/** Simpan sesi unlock (kunci + expiry). */
export async function saveSession(rawKeyB64, autolockMin) {
  const store = await sessionStore();
  const unlockUntil = autolockMin > 0 ? Date.now() + autolockMin * 60 * 1000 : Number.MAX_SAFE_INTEGER;
  await store.set({ rawKey: rawKeyB64, unlockUntil });
}

/** Ambil akun terdekripsi dari sesi aktif, atau null bila terkunci. */
export async function loadFromSession() {
  const vault = await getVault();
  if (!vault) return { state: 'empty' };
  const store = await sessionStore();
  const sess = await store.get();
  if (!sess || Date.now() > (sess.unlockUntil || 0)) {
    await store.clear();
    return { state: 'locked' };
  }
  try {
    const accounts = await decryptWithRawKey(vault, sess.rawKey);
    return { state: 'unlocked', accounts, rawKey: sess.rawKey };
  } catch {
    await store.clear();
    return { state: 'locked' };
  }
}

export async function lockVault() {
  const store = await sessionStore();
  await store.clear();
}

/** Tulis ulang vault terenkripsi memakai rawKey sesi (tanpa minta password lagi). */
export async function persistWithSessionKey(accounts, rawKeyB64) {
  const vault = await getVault();
  if (!vault) throw new Error('Vault belum ada');
  const key = await crypto.subtle.importKey(
    'raw', b64decode(rawKeyB64), { name: 'AES-GCM' }, false, ['encrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(accounts)));
  await setVault({ ...vault, iv: b64encode(iv), data: b64encode(new Uint8Array(ct)) });
}
