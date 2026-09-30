// popup.js — UI Authenticator TOTP + vault AES-GCM.
import { generateTOTP, secondsRemaining, formatCode, base32Decode, parseOtpauthUri } from './totp.js';
import {
  getVault, setVault, hasVault, getSettings, setSettings,
  encryptAccounts, decryptWithPassword, loadFromSession,
  saveSession, lockVault, persistWithSessionKey,
} from './crypto-vault.js';

const $ = (id) => document.getElementById(id);
const lockScreen = $('screen-lock'), mainScreen = $('screen-main');
const masterPass = $('masterPass'), masterPass2 = $('masterPass2');
const masterPass2Wrap = $('masterPass2Wrap'), lockDesc = $('lockDesc');
const lockError = $('lockError'), btnUnlock = $('btnUnlock'), btnWipe = $('btnWipe');
const accountList = $('accountList'), emptyState = $('emptyState');
const searchInput = $('searchInput');
const addForm = $('addForm');

let accounts = [];
let sessionKey = null;
let isSetupMode = false;
let timer = null;

function toast(msg) {
  const t = $('toast');
  t.textContent = msg; t.hidden = false;
  clearTimeout(t._h);
  t._h = setTimeout(() => { t.hidden = true; }, 2200);
}

// ---------- lock / unlock ----------

async function init() {
  const empty = !(await hasVault());
  isSetupMode = empty;
  if (empty) {
    lockDesc.textContent = 'Belum ada vault. Buat master password baru (min. 8 karakter).';
    masterPass2Wrap.hidden = false;
    btnUnlock.textContent = 'Buat vault';
    btnWipe.hidden = true;
  } else {
    const sess = await loadFromSession();
    if (sess.state === 'unlocked') {
      enterMain(sess.accounts, sess.rawKey);
      return;
    }
    lockDesc.textContent = 'Masukkan master password untuk membuka vault.';
    masterPass2Wrap.hidden = true;
    btnUnlock.textContent = 'Buka';
    btnWipe.hidden = false;
  }
  lockScreen.hidden = false;
  mainScreen.hidden = true;
  masterPass.focus();
}

btnUnlock.onclick = async () => {
  lockError.textContent = '';
  const pw = masterPass.value;
  try {
    if (isSetupMode) {
      if (pw.length < 8) throw new Error('Password min. 8 karakter');
      if (pw !== masterPass2.value) throw new Error('Konfirmasi password tidak cocok');
      const { vault, rawKey } = await encryptAccounts([], pw);
      await setVault(vault);
      const st = await getSettings();
      await saveSession(rawKey, st.autolockMin);
      enterMain([], rawKey);
    } else {
      if (!pw) throw new Error('Isi password dulu');
      const vault = await getVault();
      btnUnlock.disabled = true;
      try {
        const { accounts: acc, rawKey } = await decryptWithPassword(vault, pw);
        const st = await getSettings();
        await saveSession(rawKey, st.autolockMin);
        enterMain(acc, rawKey);
      } finally {
        btnUnlock.disabled = false;
      }
    }
  } catch (e) {
    lockError.textContent = e.message || String(e);
  }
};
masterPass.addEventListener('keydown', (e) => { if (e.key === 'Enter') btnUnlock.click(); });

btnWipe.onclick = async () => {
  if (!confirm('Hapus SEMUA akun 2FA dan buat vault baru? Tindakan ini tidak bisa dibatalkan.')) return;
  await chrome.storage.local.clear();
  await lockVault();
  masterPass.value = ''; masterPass2.value = '';
  init();
};

$('btnLock').onclick = async () => {
  await lockVault();
  stopTicker();
  accounts = []; sessionKey = null;
  masterPass.value = ''; masterPass2.value = '';
  init();
};

// ---------- main ----------

async function enterMain(acc, rawKey) {
  accounts = Array.isArray(acc) ? acc : [];
  sessionKey = rawKey;
  lockScreen.hidden = true;
  mainScreen.hidden = false;
  masterPass.value = ''; masterPass2.value = '';
  const st = await getSettings();
  $('autolockSel').value = String(st.autolockMin ?? 10);
  startTicker();
}

function filteredAccounts() {
  const q = (searchInput.value || '').toLowerCase().trim();
  if (!q) return accounts.map((a, i) => ({ a, i }));
  return accounts
    .map((a, i) => ({ a, i }))
    .filter(({ a }) => ((a.issuer || '') + ' ' + (a.account || '')).toLowerCase().includes(q));
}

function render() {
  const now = Date.now();
  const items = filteredAccounts();
  emptyState.hidden = items.length > 0;
  accountList.innerHTML = '';
  for (const { a, i } of items) {
    const period = a.period || 30;
    let code = '······', err = null;
    try {
      code = generateTOTP(a.secret, { digits: a.digits || 6, period, time: now });
    } catch (e) { err = e.message; }
    const remain = secondsRemaining(period, now);
    const div = document.createElement('div');
    div.className = 'acct' + (remain <= 5 ? ' low' : '');
    div.innerHTML =
      `<button class="del" title="Hapus">✕</button>` +
      `<div class="top"><span class="name"></span><span class="timer">${remain} dtk</span></div>` +
      `<div class="code"></div><div class="bar"><i style="width:${(remain / period) * 100}%"></i></div>`;
    div.querySelector('.name').textContent =
      (a.issuer ? a.issuer + ' · ' : '') + (a.account || 'Tanpa nama');
    div.querySelector('.code').textContent = err ? '— error —' : formatCode(code);
    if (err) div.title = err;
    div.onclick = async (ev) => {
      if (ev.target.classList.contains('del')) return;
      if (err) { toast(err); return; }
      try {
        await navigator.clipboard.writeText(code);
        toast('Kode disalin: ' + formatCode(code));
      } catch { toast(formatCode(code)); }
    };
    div.querySelector('.del').onclick = async () => {
      const label = (a.issuer ? a.issuer + ' ' : '') + (a.account || '');
      if (!confirm(`Hapus "${label}"?`)) return;
      accounts.splice(i, 1);
      await persistWithSessionKey(accounts, sessionKey);
      render();
    };
    accountList.appendChild(div);
  }
}

function startTicker() {
  stopTicker();
  render();
  timer = setInterval(render, 500);
}
function stopTicker() {
  if (timer) clearInterval(timer);
  timer = null;
}

searchInput.oninput = render;

// ---------- tambah akun ----------

$('btnShowAdd').onclick = () => {
  addForm.hidden = !addForm.hidden;
};
$('btnCancelAdd').onclick = () => { addForm.hidden = true; };

$('fUri').oninput = () => {
  const v = $('fUri').value.trim();
  if (!v) return;
  try {
    const p = parseOtpauthUri(v);
    $('fIssuer').value = p.issuer;
    $('fAccount').value = p.account;
    $('fSecret').value = p.secret;
    $('fDigits').value = String(p.digits);
    $('fPeriod').value = String(p.period);
    $('addError').textContent = '';
  } catch { /* biarkan user isi manual */ }
};

function fillUri(raw) {
  $('fUri').value = raw;
  $('fUri').dispatchEvent(new Event('input'));
}

async function detectQR(source) {
  if (!('BarcodeDetector' in window)) {
    throw new Error('Browser tidak mendukung BarcodeDetector — tempel otpauth:// URI manual');
  }
  const det = new BarcodeDetector({ formats: ['qr_code'] });
  const found = await det.detect(source);
  if (!found.length) throw new Error('QR tidak terbaca — pastikan gambar tajam & cukup besar');
  return found[0].rawValue;
}

$('qrFile').onchange = async () => {
  const f = $('qrFile').files[0];
  if (!f) return;
  try {
    const bmp = await createImageBitmap(f);
    const raw = await detectQR(bmp);
    fillUri(raw);
    toast('QR terbaca ✓');
  } catch (e) {
    $('addError').textContent = e.message || String(e);
  }
};

// ---------- scan dari layar (screenshot tab aktif) ----------
// Screenshot penuh sering gagal kalau QR-nya kecil — jadi coba
// beberapa varian: penuh, setengah atas/bawah, dan downscale.
async function detectQRRobust(img) {
  if (!('BarcodeDetector' in window)) {
    throw new Error('Browser tidak mendukung BarcodeDetector — tempel otpauth:// URI manual');
  }
  const det = new BarcodeDetector({ formats: ['qr_code'] });
  const W = img.width, H = img.height;
  const regions = [
    [0, 0, W, H],                 // penuh
    [0, 0, W, Math.floor(H / 2)], // paruh atas
    [0, Math.floor(H / 2), W, Math.ceil(H / 2)], // paruh bawah
  ];
  const canvas = $('camCanvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  for (const [sx, sy, sw, sh] of regions) {
    if (sw < 40 || sh < 40) continue;
    // skala penuh + downscale 0.5 (screenshot HiDPI besar kadang gagal detect)
    for (const scale of [1, 0.5]) {
      const dw = Math.max(1, Math.floor(sw * scale));
      const dh = Math.max(1, Math.floor(sh * scale));
      canvas.width = dw; canvas.height = dh;
      ctx.drawImage(img, sx, sy, sw, sh, 0, 0, dw, dh);
      const bmp = await createImageBitmap(canvas);
      const found = await det.detect(bmp);
      if (found.length) return found[0].rawValue;
    }
  }
  throw new Error('QR tidak terbaca dari layar — perbesar/zoom QR lalu coba lagi');
}

$('btnTabScan').onclick = async () => {
  $('addError').textContent = '';
  try {
    $('camStatus').textContent = 'Mengambil screenshot tab…';
    const dataUrl = await chrome.tabs.captureVisibleTab({ format: 'png' });
    const img = new Image();
    await new Promise((res, rej) => { img.onload = res; img.onerror = rej; img.src = dataUrl; });
    const raw = await detectQRRobust(img);
    fillUri(raw);
    $('camStatus').textContent = 'QR terbaca ✓';
    toast('QR terbaca ✓');
  } catch (e) {
    $('camStatus').textContent = '';
    $('addError').textContent = e.message || String(e) ||
      'Gagal screenshot — buka tab situsnya dulu lalu coba lagi';
  }
};

$('btnAdd').onclick = async () => {
  $('addError').textContent = '';
  try {
    let issuer = $('fIssuer').value.trim();
    let account = $('fAccount').value.trim() || 'Tanpa nama';
    let secret = $('fSecret').value.replace(/[\s-]/g, '').toUpperCase();
    const digits = parseInt($('fDigits').value, 10) || 6;
    const period = parseInt($('fPeriod').value, 10) || 30;
    if (!secret) throw new Error('Secret wajib diisi');
    base32Decode(secret); // validasi
    // cegah duplikat secret
    if (accounts.some((a) => a.secret.replace(/[\s-]/g, '').toUpperCase() === secret)) {
      throw new Error('Secret ini sudah ada di vault');
    }
    // uji generate sekali
    generateTOTP(secret, { digits, period });
    accounts.push({ id: crypto.randomUUID(), issuer, account, secret, digits, period });
    await persistWithSessionKey(accounts, sessionKey);
    $('fUri').value = ''; $('fIssuer').value = ''; $('fAccount').value = ''; $('fSecret').value = '';
    $('qrFile').value = '';
    addForm.hidden = true;
    render();
    toast('Akun ditambahkan ✓');
  } catch (e) {
    $('addError').textContent = e.message || String(e);
  }
};

// ---------- export / import / settings ----------

$('btnExport').onclick = () => {
  const blob = new Blob([JSON.stringify(accounts, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = '2fa-backup.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
};

$('btnImport').onclick = () => $('importFile').click();
$('importFile').onchange = async () => {
  const f = $('importFile').files[0];
  if (!f) return;
  try {
    const arr = JSON.parse(await f.text());
    if (!Array.isArray(arr)) throw new Error('Format JSON harus array akun');
    let n = 0;
    for (const it of arr) {
      if (!it || !it.secret) continue;
      const secret = String(it.secret).replace(/[\s-]/g, '').toUpperCase();
      base32Decode(secret);
      generateTOTP(secret, { digits: it.digits || 6, period: it.period || 30 });
      accounts.push({
        id: crypto.randomUUID(),
        issuer: String(it.issuer || ''),
        account: String(it.account || it.label || 'Impor'),
        secret,
        digits: it.digits === 8 ? 8 : 6,
        period: [15, 30, 60].includes(it.period) ? it.period : 30,
      });
      n++;
    }
    await persistWithSessionKey(accounts, sessionKey);
    render();
    toast(`${n} akun diimpor ✓`);
  } catch (e) {
    toast('Import gagal: ' + (e.message || e));
  }
  $('importFile').value = '';
};

$('btnChangePw').onclick = async () => {
  const p1 = prompt('Master password baru (min. 8 karakter):');
  if (!p1) return;
  if (p1.length < 8) { toast('Password min. 8 karakter'); return; }
  const p2 = prompt('Konfirmasi password baru:');
  if (p1 !== p2) { toast('Konfirmasi tidak cocok'); return; }
  const { vault, rawKey } = await encryptAccounts(accounts, p1);
  await setVault(vault);
  sessionKey = rawKey;
  const st = await getSettings();
  await saveSession(rawKey, st.autolockMin);
  toast('Password diganti ✓');
};

$('autolockSel').onchange = async () => {
  const v = parseInt($('autolockSel').value, 10);
  const st = await getSettings();
  st.autolockMin = v;
  await setSettings(st);
  if (sessionKey) await saveSession(sessionKey, v);
  toast('Auto-kunci: ' + (v === 0 ? 'saat browser ditutup' : v + ' mnt'));
};

init();
