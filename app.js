// =============================================
//   TRIPLE DES SECURITY — app.js
// =============================================

// NAVIGATION
function showPage(pageId, el) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const page = document.getElementById('page-' + pageId);
  if (page) page.classList.add('active');
  if (el) el.classList.add('active');
  else document.querySelectorAll('.nav-item').forEach(n => { if (n.getAttribute('onclick') && n.getAttribute('onclick').includes("'" + pageId + "'")) n.classList.add('active'); });
  updateStats();
  if (pageId === 'riwayat') renderHistory();
}

// CLOCK
function updateClock() {
  const now = new Date();
  const days = ['Minggu','Senin','Selasa','Rabu','Kamis','Jumat','Sabtu'];
  const months = ['Jan','Feb','Mar','Apr','Mei','Jun','Jul','Ags','Sep','Okt','Nov','Des'];
  const dayName = days[now.getDay()];
  const timeStr = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')} WIB`;
  const dateStr = `${now.getDate()} ${months[now.getMonth()]} ${now.getFullYear()}`;

  const hTime = document.getElementById('headerTime');
  if (hTime) hTime.innerHTML = `<i class="fas fa-calendar"></i>${dayName}, ${dateStr}&nbsp;&nbsp;<i class="fas fa-clock"></i>${timeStr}`;

  ['enc','dec'].forEach(t => {
    const d = document.getElementById(t + 'Date');
    const ti = document.getElementById(t + 'Time');
    if (d) d.textContent = `${dateStr} - ${dayName}`;
    if (ti) ti.textContent = timeStr;
  });

  const rl = document.getElementById('dateRangeLabel');
  if (rl) rl.textContent = `01 ${months[now.getMonth()]} ${now.getFullYear()} - ${String(now.getDate()).padStart(2,'0')} ${months[now.getMonth()]} ${now.getFullYear()}`;
}
setInterval(updateClock, 1000);
updateClock();

// CHAR COUNT
function updateCount(el, id) { document.getElementById(id).textContent = el.value.length; }

// EYE TOGGLE
function toggleEye(icon) {
  const input = icon.previousElementSibling;
  if (input.type === 'password') { input.type = 'text'; icon.classList.replace('fa-eye','fa-eye-slash'); }
  else { input.type = 'password'; icon.classList.replace('fa-eye-slash','fa-eye'); }
}

// =============================================
// TRIPLE DES — Manual Feistel Implementation
// =============================================

function padKey(key) {
  const k = (key + '00000000').slice(0, 8);
  return Array.from(k).map(c => c.charCodeAt(0));
}

function keySchedule(keyBytes) {
  const subkeys = [];
  let state = keyBytes.slice();
  for (let r = 0; r < 16; r++) {
    const sk = state.map((b, i) => ((b ^ state[(i+3)%8] ^ (r*37 + i*17)) & 0xFF));
    subkeys.push(sk);
    state = sk.slice();
  }
  return subkeys;
}

function f(half, subkey, pos) {
  let v = 0;
  for (let i = 0; i < 4; i++) v ^= (half[i] * (subkey[(pos+i)%8] | 1)) & 0xFF;
  return v & 0xFF;
}

function feistelEnc(block8, subkeys) {
  let L = block8.slice(0,4), R = block8.slice(4,8);
  for (let r = 0; r < 16; r++) {
    const newR = L.map((b,i) => (b ^ f(R, subkeys[r], i)) & 0xFF);
    L = R; R = newR;
  }
  return [...R, ...L];
}

function feistelDec(block8, subkeys) {
  let L = block8.slice(0,4), R = block8.slice(4,8);
  for (let r = 15; r >= 0; r--) {
    const newR = L.map((b,i) => (b ^ f(R, subkeys[r], i)) & 0xFF);
    L = R; R = newR;
  }
  return [...R, ...L];
}

function desEnc(bytes, keyBytes) {
  const sk = keySchedule(keyBytes);
  const out = [];
  for (let i = 0; i < bytes.length; i += 8) {
    const block = Array.from({length:8}, (_,j) => bytes[i+j] || 0);
    out.push(...feistelEnc(block, sk));
  }
  return out;
}

function desDec(bytes, keyBytes) {
  const sk = keySchedule(keyBytes);
  const out = [];
  for (let i = 0; i < bytes.length; i += 8) {
    const block = Array.from({length:8}, (_,j) => bytes[i+j] || 0);
    out.push(...feistelDec(block, sk));
  }
  return out;
}

function addPadding(bytes) {
  const p = 8 - (bytes.length % 8);
  return [...bytes, ...Array(p).fill(p)];
}

function removePadding(bytes) {
  if (!bytes.length) return bytes;
  const p = bytes[bytes.length - 1];
  return (p >= 1 && p <= 8) ? bytes.slice(0, -p) : bytes;
}

function strToBytes(str) {
  return Array.from(new TextEncoder().encode(str));
}

function bytesToStr(bytes) {
  try { return new TextDecoder().decode(new Uint8Array(bytes)); }
  catch { return bytes.map(b => String.fromCharCode(b)).join(''); }
}

function bytesToHex(bytes) {
  return bytes.map(b => b.toString(16).padStart(2,'0').toUpperCase()).join('');
}

function hexToBytes(hex) {
  const h = hex.replace(/\s/g,'');
  return Array.from({length: h.length/2}, (_,i) => parseInt(h.slice(i*2,i*2+2),16));
}

function tripleDesEncrypt(plaintext, k1, k2, k3) {
  let bytes = addPadding(strToBytes(plaintext));
  bytes = desEnc(bytes, padKey(k1));
  bytes = desDec(bytes, padKey(k2));
  bytes = desEnc(bytes, padKey(k3));
  return bytesToHex(bytes);
}

function tripleDesDecrypt(cipherHex, k1, k2, k3) {
  let bytes = hexToBytes(cipherHex);
  bytes = desDec(bytes, padKey(k3));
  bytes = desEnc(bytes, padKey(k2));
  bytes = desDec(bytes, padKey(k1));
  return bytesToStr(removePadding(bytes));
}

// =============================================
// HISTORY
// =============================================
const HISTORY_KEY = 'tripleDES_history';
function getHistory() { try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; } catch { return []; } }
function saveHistory(h) { localStorage.setItem(HISTORY_KEY, JSON.stringify(h)); }

function addHistory(type, input, output) {
  const now = new Date();
  const months = ['Jan','Feb','Mar','Apr','Mei','Jun','Jul','Ags','Sep','Okt','Nov','Des'];
  const hist = getHistory();
  hist.unshift({
    id: Date.now(), type, input, output,
    datetime: `${now.getDate()} ${months[now.getMonth()]} ${now.getFullYear()} - ${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')} WIB`,
    ts: now.getTime()
  });
  saveHistory(hist);
  updateStats();
  updateRecentActivity();
}

function updateStats() {
  const hist = getHistory();
  const enc = hist.filter(h => h.type==='Enkripsi').length;
  const dec = hist.filter(h => h.type==='Dekripsi').length;
  const total = hist.length;
  let avg = 0;
  if (hist.length > 0) {
    const days = Math.max(1, Math.ceil((hist[0].ts - hist[hist.length-1].ts) / 86400000) + 1);
    avg = (total / days).toFixed(1);
  }
  ['statTotal','rTotal'].forEach(id => setEl(id, total));
  ['statEnc','rEnc'].forEach(id => setEl(id, enc));
  ['statDec','rDec'].forEach(id => setEl(id, dec));
  ['statAvg','rAvg'].forEach(id => setEl(id, avg));
}

function setEl(id, val) { const e = document.getElementById(id); if(e) e.textContent = val; }

function updateRecentActivity() {
  const hist = getHistory().slice(0,3);
  const el = document.getElementById('recentList');
  if (!el) return;
  if (!hist.length) { el.innerHTML = '<p class="empty-msg">Belum ada aktivitas.</p>'; return; }
  el.innerHTML = hist.map(h => `
    <div class="recent-item">
      <span class="tag-${h.type==='Enkripsi'?'enc':'dec'}">${h.type}</span>
      <div class="recent-info"><span>${h.input.slice(0,30)}${h.input.length>30?'...':''}</span></div>
      <i class="fas fa-eye" style="color:var(--blue);cursor:pointer;font-size:13px" onclick="openModal(${h.id})"></i>
    </div>`).join('');
}

// =============================================
// ENCRYPT / DECRYPT ACTIONS
// =============================================
function doEncrypt() {
  const plaintext = document.getElementById('encPlaintext').value.trim();
  const k1 = document.getElementById('encKey1').value;
  const k2 = document.getElementById('encKey2').value;
  const k3 = document.getElementById('encKey3').value;
  if (!plaintext) { showToast('⚠️ Masukkan teks yang akan dienkripsi!','error'); return; }
  if (!k1||!k2||!k3) { showToast('⚠️ Masukkan semua 3 kunci!','error'); return; }
  try {
    const result = tripleDesEncrypt(plaintext, k1, k2, k3);
    document.getElementById('encResultEmpty').style.display = 'none';
    const out = document.getElementById('encResult');
    out.style.display = 'block'; out.textContent = result;
    addHistory('Enkripsi', plaintext, result);
    showToast('✅ Enkripsi berhasil!','success');
  } catch(e) { showToast('❌ Gagal enkripsi: '+e.message,'error'); }
}

function doDecrypt() {
  const cipher = document.getElementById('decCiphertext').value.trim();
  const k1 = document.getElementById('decKey1').value;
  const k2 = document.getElementById('decKey2').value;
  const k3 = document.getElementById('decKey3').value;
  if (!cipher) { showToast('⚠️ Masukkan ciphertext!','error'); return; }
  if (!k1||!k2||!k3) { showToast('⚠️ Masukkan semua 3 kunci!','error'); return; }
  if (!/^[0-9A-Fa-f\s]+$/.test(cipher)) { showToast('⚠️ Format ciphertext tidak valid! Gunakan hex.','error'); return; }
  try {
    const result = tripleDesDecrypt(cipher, k1, k2, k3);
    document.getElementById('decResultEmpty').style.display = 'none';
    const out = document.getElementById('decResult');
    out.style.display = 'block'; out.textContent = result; out.style.color = 'var(--text)';
    addHistory('Dekripsi', cipher, result);
    showToast('✅ Dekripsi berhasil!','success');
  } catch(e) { showToast('❌ Gagal dekripsi. Periksa kunci Anda.','error'); }
}

function quickEncrypt() {
  const text = document.getElementById('homeEncInput').value.trim();
  const k1 = document.getElementById('hek1').value;
  const k2 = document.getElementById('hek2').value;
  const k3 = document.getElementById('hek3').value;
  if (!text||!k1||!k2||!k3) { showToast('⚠️ Lengkapi semua field!','error'); return; }
  try {
    const result = tripleDesEncrypt(text, k1, k2, k3);
    addHistory('Enkripsi', text, result);
    showPage('enkripsi', null);
    document.getElementById('encPlaintext').value = text;
    document.getElementById('encKey1').value = k1;
    document.getElementById('encKey2').value = k2;
    document.getElementById('encKey3').value = k3;
    document.getElementById('encResultEmpty').style.display = 'none';
    const out = document.getElementById('encResult');
    out.style.display = 'block'; out.textContent = result;
    showToast('✅ Enkripsi berhasil!','success');
  } catch(e) { showToast('❌ Gagal enkripsi','error'); }
}

function quickDecrypt() {
  const cipher = document.getElementById('homeDecInput').value.trim();
  const k1 = document.getElementById('hdk1').value;
  const k2 = document.getElementById('hdk2').value;
  const k3 = document.getElementById('hdk3').value;
  if (!cipher||!k1||!k2||!k3) { showToast('⚠️ Lengkapi semua field!','error'); return; }
  try {
    const result = tripleDesDecrypt(cipher, k1, k2, k3);
    addHistory('Dekripsi', cipher, result);
    showPage('dekripsi', null);
    document.getElementById('decCiphertext').value = cipher;
    document.getElementById('decKey1').value = k1;
    document.getElementById('decKey2').value = k2;
    document.getElementById('decKey3').value = k3;
    document.getElementById('decResultEmpty').style.display = 'none';
    const out = document.getElementById('decResult');
    out.style.display = 'block'; out.textContent = result; out.style.color = 'var(--text)';
    showToast('✅ Dekripsi berhasil!','success');
  } catch(e) { showToast('❌ Gagal dekripsi. Periksa kunci.','error'); }
}

function copyResult(id) {
  const el = document.getElementById(id);
  if (!el||!el.textContent.trim()) { showToast('⚠️ Tidak ada hasil.','error'); return; }
  navigator.clipboard.writeText(el.textContent).then(() => showToast('📋 Disalin!','success')).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = el.textContent; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
    showToast('📋 Disalin!','success');
  });
}

// =============================================
// HISTORY PAGE
// =============================================
let currentPage = 1;
const PER_PAGE = 10;

function renderHistory() {
  const hist = getHistory();
  const ft = document.getElementById('filterType')?.value || 'all';
  const search = (document.getElementById('searchInput')?.value || '').toLowerCase();

  const filtered = hist.filter(h =>
    (ft==='all' || h.type===ft) &&
    (!search || h.input.toLowerCase().includes(search) || h.output.toLowerCase().includes(search))
  );

  const totalPages = Math.max(1, Math.ceil(filtered.length / PER_PAGE));
  if (currentPage > totalPages) currentPage = 1;
  const slice = filtered.slice((currentPage-1)*PER_PAGE, currentPage*PER_PAGE);

  const tbody = document.getElementById('historyBody');
  const empty = document.getElementById('historyEmpty');
  const table = document.getElementById('historyTable');

  if (!filtered.length) {
    tbody.innerHTML = '';
    empty.style.display = 'block';
    table.style.display = 'none';
  } else {
    empty.style.display = 'none';
    table.style.display = 'table';
    tbody.innerHTML = slice.map((h, i) => `
      <tr>
        <td>${(currentPage-1)*PER_PAGE+i+1}</td>
        <td><span class="tag-${h.type==='Enkripsi'?'enc':'dec'}">${h.type}</span></td>
        <td style="font-size:12px;color:var(--text3)">${h.datetime}</td>
        <td><span class="truncate">${escHtml(h.input)}</span></td>
        <td><span class="truncate" style="font-family:'Space Mono',monospace;font-size:11px;color:var(--green)">${escHtml(h.output)}</span></td>
        <td><div class="action-btns">
          <button class="action-btn act-view" onclick="openModal(${h.id})"><i class="fas fa-eye"></i></button>
          <button class="action-btn act-copy" onclick="copyText('${escAttr(h.output)}')"><i class="fas fa-copy"></i></button>
          <button class="action-btn act-del" onclick="deleteItem(${h.id})"><i class="fas fa-trash"></i></button>
        </div></td>
      </tr>`).join('');
  }
  renderPagination(totalPages);
  updateStats();
}

function renderPagination(total) {
  const c = document.getElementById('pagination');
  if (!c || total <= 1) { if(c) c.innerHTML=''; return; }
  let html = `<button class="page-btn nav-p" onclick="goPage(${currentPage-1})" ${currentPage===1?'disabled':''}>‹</button>`;
  for (let i=1; i<=total; i++) {
    if (i===1||i===total||(i>=currentPage-1&&i<=currentPage+1))
      html += `<button class="page-btn ${i===currentPage?'active':''}" onclick="goPage(${i})">${i}</button>`;
    else if (i===currentPage-2||i===currentPage+2)
      html += `<button class="page-btn" disabled>…</button>`;
  }
  html += `<button class="page-btn nav-p" onclick="goPage(${currentPage+1})" ${currentPage===total?'disabled':''}>›</button>`;
  c.innerHTML = html;
}

function goPage(p) {
  const total = Math.ceil(getHistory().length / PER_PAGE);
  if (p<1||p>total) return;
  currentPage = p; renderHistory();
}

function clearHistory() {
  if (!confirm('Hapus semua riwayat aktivitas?')) return;
  localStorage.removeItem(HISTORY_KEY);
  updateStats(); updateRecentActivity(); renderHistory();
  showToast('🗑️ Riwayat dibersihkan.','success');
}

function deleteItem(id) {
  saveHistory(getHistory().filter(h => h.id!==id));
  updateStats(); updateRecentActivity(); renderHistory();
  showToast('🗑️ Item dihapus.','success');
}

function copyText(text) {
  navigator.clipboard.writeText(text).then(() => showToast('📋 Disalin!','success')).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
    showToast('📋 Disalin!','success');
  });
}

// MODAL
function openModal(id) {
  const item = getHistory().find(h => h.id===id);
  if (!item) return;
  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';
  overlay.innerHTML = `
    <div class="modal">
      <h3><i class="fas fa-${item.type==='Enkripsi'?'lock':'lock-open'}" style="color:var(--blue)"></i> Detail ${item.type}</h3>
      <div class="modal-row"><label>Waktu</label><div class="modal-content">${item.datetime}</div></div>
      <div class="modal-row"><label>Input</label><div class="modal-content">${escHtml(item.input)}</div></div>
      <div class="modal-row"><label>Output</label><div class="modal-content" style="color:var(--green)">${escHtml(item.output)}</div></div>
      <div class="modal-actions">
        <button class="btn-modal-close" onclick="this.closest('.modal-overlay').remove()">Tutup</button>
        <button class="btn-encrypt" style="padding:8px 18px;font-size:13px" onclick="copyText('${escAttr(item.output)}');this.closest('.modal-overlay').remove()"><i class="fas fa-copy"></i> Salin Output</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  setTimeout(() => overlay.classList.add('open'), 10);
  overlay.addEventListener('click', e => { if(e.target===overlay) overlay.remove(); });
}

// TOAST
let toastTimer;
function showToast(msg, type='') {
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = 'toast show ' + type;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3000);
}

// UTILS
function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function escAttr(s) { return String(s).replace(/'/g,"\\'").replace(/"/g,'&quot;'); }

// INIT
document.addEventListener('DOMContentLoaded', () => { updateStats(); updateRecentActivity(); });