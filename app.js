// Notes 閱讀器：在瀏覽器內解密並顯示文件。
// 主站加密格式見 _publish/lib/crypto.mjs，分享檔格式見 _publish/lib/shares.mjs；兩邊的常數與流程必須一致。
//
// 網址：
//   #/d/<文件代號>   主站文件。沒有記住金鑰時，只有入口（首頁代號）會顯示鎖定頁，其他一律 404
//   #/s/<token>      分享頁。只顯示那一份文件，不碰主站金鑰
'use strict';

(() => {
  const te = (s) => new TextEncoder().encode(s);
  const subtle = window.crypto && window.crypto.subtle;
  const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));

  function err(code, message) { return Object.assign(new Error(message || code), { code }); }

  function b64urlBytes(s) {
    const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  }

  function bytesB64url(u8) {
    let s = '';
    for (const b of u8) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function gunzip(u8) {
    const stream = new Blob([u8]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  function equal(a, b) {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }

  // ================= 加密：主站 =================

  const MAGIC = te('NTS1');
  const HEADER_LEN = 36;
  const IV_LEN = 12;
  const SALT = te('notes/v1');

  function parseKey(text) {
    const s = String(text || '').trim();
    if (!/^[A-Za-z0-9_-]{43}$/.test(s)) throw err('parse', '金鑰格式不正確：應為 43 字元（英數字、- 與 _）。');
    const raw = b64urlBytes(s);
    if (raw.length !== 32) throw err('parse', '金鑰長度不正確。');
    return raw;
  }

  // 子金鑰全部設為不可匯出：頁面上的程式只能拿來用，讀不出金鑰本身
  async function deriveKeys(raw) {
    const base = await subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
    const derive = (info, alg, usages) =>
      subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: SALT, info: te(info) }, base, alg, false, usages);
    return {
      enc: await derive('enc', { name: 'AES-GCM', length: 256 }, ['decrypt']),
      fp: await derive('fp', { name: 'HMAC', hash: 'SHA-256', length: 256 }, ['sign']),
    };
  }

  async function openBundle(keys, b) {
    if (b.length < HEADER_LEN + IV_LEN + 16 || !MAGIC.every((v, i) => b[i] === v)) throw err('format');
    const fp = new Uint8Array(await subtle.sign('HMAC', keys.fp, te('fingerprint'))).slice(0, 16);
    if (!equal(b.slice(4, 20), fp)) throw err('key');
    try {
      return new Uint8Array(await subtle.decrypt(
        { name: 'AES-GCM', iv: b.slice(HEADER_LEN, HEADER_LEN + IV_LEN), additionalData: b.slice(0, HEADER_LEN) },
        keys.enc, b.slice(HEADER_LEN + IV_LEN)));
    } catch (e) {
      throw err('auth');
    }
  }

  // ================= 加密：分享檔 =================

  const SHARE_MAGIC = te('NSH1');
  const SHARE_SALT = te('notes/share/v1');

  async function tokenKeys(token) {
    const base = await subtle.importKey('raw', token, 'HKDF', false, ['deriveKey']);
    const derive = (info, alg, usages) =>
      subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: SHARE_SALT, info: te(info) }, base, alg, false, usages);
    const fileKey = await derive('share-file', { name: 'HMAC', hash: 'SHA-256', length: 256 }, ['sign']);
    return {
      file: hex(new Uint8Array(await subtle.sign('HMAC', fileKey, te('file'))).slice(0, 16)),
      enc: await derive('share-enc', { name: 'AES-GCM', length: 256 }, ['decrypt']),
    };
  }

  async function openShare(enc, b) {
    if (b.length < 32 || !SHARE_MAGIC.every((v, i) => b[i] === v)) throw err('format');
    const plain = new Uint8Array(await subtle.decrypt(
      { name: 'AES-GCM', iv: b.slice(4, 16), additionalData: SHARE_MAGIC }, enc, b.slice(16)));
    const len = new DataView(plain.buffer).getUint32(0);
    return JSON.parse(new TextDecoder().decode(await gunzip(plain.slice(4, 4 + len))));
  }

  // 台北時間的今天；到期日當天整天有效（與 _publish/lib/shares.mjs 一致）
  const todayTaipei = () => new Date(Date.now() + 8 * 3600e3).toISOString().slice(0, 10);

  // ================= 金鑰保存（IndexedDB，存不可匯出的 CryptoKey）=================

  const DB_NAME = 'notes';
  const STORE = 'keys';

  function idb() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function idbDo(mode, fn) {
    const db = await idb();
    try {
      return await new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, mode);
        const req = fn(tx.objectStore(STORE));
        tx.oncomplete = () => resolve(req && req.result);
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    } finally {
      db.close();
    }
  }

  const loadKeys = () => idbDo('readonly', (s) => s.get('main'));
  const saveKeys = (keys) => idbDo('readwrite', (s) => s.put({ enc: keys.enc, fp: keys.fp }, 'main'));
  const forgetKeys = () => idbDo('readwrite', (s) => s.delete('main'));

  // ================= 狀態與工具 =================

  const $ = (sel, el = document) => el.querySelector(sel);
  // 鎖定頁、404、分享頁一律維持這個通用標題；只有解鎖後的主站才顯示文件檔名
  const SITE_TITLE = document.title;
  // 麵包屑每一層的行高（px）：字級沿用內文標題（app.css 的 .doc-body h1～h3 是 1.8／1.45／1.2em，基準 15px），行高 1.3 倍進位
  const CRUMB_H = { 1: 36, 2: 29, 3: 24 };

  function freshState() {
    return {
      mode: null,                 // 'app' | 'share' | 'lock' | '404'
      bundle: null, byId: new Map(), byPath: new Map(), unpublished: new Set(),
      lower: new Map(), blobUrls: new Map(), anchors: new Map(), pager: new Map(),
      shareImages: null,
      current: null, pendingAnchor: null, pendingJump: false,
      marks: [], markIdx: -1, tables: [], floatTable: null,
      headings: [], tocLinks: new Map(), tocOpen: new Set(), singleRoot: null, maxDepth: 0, crumbH: 0,
    };
  }
  let state = freshState();

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const c of children.flat()) if (c != null) el.append(c);
    return el;
  }

  // 時間：畫面上顯示短格式「10/14 17:23」，滑鼠停上去才看到「2026/10/14 17:23」
  const pad2 = (n) => String(n).padStart(2, '0');
  function fmtShort(iso) {
    const d = new Date(iso);
    return `${pad2(d.getMonth() + 1)}/${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  }
  function fmtFull(iso) {
    const d = new Date(iso);
    return `${d.getFullYear()}/${pad2(d.getMonth() + 1)}/${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  }
  const timeSpan = (iso) => h('span', { class: 'time', title: fmtFull(iso) }, fmtShort(iso));

  const basename = (p) => p.slice(p.lastIndexOf('/') + 1);
  const dirname = (p) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
  const displayName = (p) => basename(p).replace(/\.md$/i, '');

  function normalizePath(p) {
    const out = [];
    for (const seg of p.split('/')) {
      if (!seg || seg === '.') continue;
      if (seg === '..') { if (!out.length) return null; out.pop(); } else out.push(seg);
    }
    return out.join('/');
  }

  function safeDecode(s) {
    try { return decodeURIComponent(s); } catch (e) { return s; }
  }

  // 與 GitHub 產生標題錨點的規則一致，讓既有的 ](#…) 連結可以直接用
  function slugify(text) {
    return text.trim().toLowerCase().replace(/[^\p{L}\p{M}\p{N}\p{Pc}\- ]/gu, '').replace(/ /g, '-');
  }

  async function sha256hex(s) {
    return hex(new Uint8Array(await subtle.digest('SHA-256', te(s))));
  }

  // ================= 畫面切換 =================

  function showOnly(id) {
    for (const v of ['notfound', 'lock', 'app']) $('#' + v).hidden = v !== id;
    $('#capsule').hidden = id !== 'app';
    $('#jump').hidden = id !== 'app';
    if (id !== 'app') toggleMenu(false);
    setIcon(id !== 'notfound');
  }

  // 書籤圖示只在鎖定頁與閱讀頁出現。index.html 刻意不寫 <link rel="icon">：
  // 404 畫面（根網址、打錯的網址、失效的分享）要跟真正不存在的網站一樣，連圖示都不能有
  function setIcon(on) {
    let link = document.querySelector('link[rel="icon"]');
    if (!on) { if (link) link.remove(); return; }
    if (link) return;
    link = h('link', { rel: 'icon', type: 'image/svg+xml', href: 'favicon.svg' + VERSION_QUERY });
    document.head.append(link);
  }

  function showNotFound() {
    wipe();
    state.mode = '404';
    document.body.classList.remove('share-mode');
    showOnly('notfound');
  }

  function showLock(msg) {
    state.mode = 'lock';
    document.body.classList.remove('share-mode');
    showOnly('lock');
    $('#lock-msg').textContent = msg || '';
    $('#key-input').value = '';
    $('#key-input').focus();
  }

  // ================= 版面偏好（只存在這台瀏覽器）=================

  const PREF_KEY = 'notes.layout2';
  const DEFAULTS = { tree: true, recent: false, toc: true, tier: 1, cl: 60, cr: 60, lw: 280, tw: 300, ru: 'n', rv: 10, mine: false };
  const LIMITS = { lw: [200, 600], tw: [200, 600], cl: [0, 4000], cr: [0, 4000], rv: [0, 10000] };
  const RECENT_STEPS = { n: [10, 20, 30, 50, 100, 200, 500], d: [1, 3, 7, 14, 30, 90, 180, 365] };
  const prefs = { ...DEFAULTS };
  try {
    const saved = JSON.parse(localStorage.getItem(PREF_KEY));
    if (saved && typeof saved === 'object') {
      for (const k of Object.keys(DEFAULTS)) if (typeof saved[k] === typeof DEFAULTS[k]) prefs[k] = saved[k];
    }
  } catch (e) { /* 沒有或讀不到就用預設 */ }
  if (![1, 2, 3, 4].includes(prefs.tier)) prefs.tier = 1;
  if (!RECENT_STEPS[prefs.ru]) prefs.ru = DEFAULTS.ru;
  for (const [k, [lo, hi]] of Object.entries(LIMITS)) prefs[k] = clamp(Math.round(prefs[k]) || (k === 'rv' ? prefs[k] : DEFAULTS[k]), lo, hi);

  function savePrefs() {
    try { localStorage.setItem(PREF_KEY, JSON.stringify(prefs)); } catch (e) { /* 無痕視窗等情況存不了，不影響使用 */ }
  }

  const MIN_PAGE = 480;   // 自訂寬度時，內文最窄多少 px
  const TIER_LABEL = { 1: '窄', 2: '中', 3: '寬', 4: '自訂' };

  // 自訂寬度：內文左右邊界各自離內文區邊緣多遠。視窗變窄放不下時，兩邊等比例縮小（不改存檔的值）
  function customInsets() {
    const avail = Math.max(0, $('#content').clientWidth - 48);
    const maxTotal = Math.max(0, avail - MIN_PAGE);
    const total = prefs.cl + prefs.cr;
    if (total <= maxTotal || !total) return [prefs.cl, prefs.cr];
    const k = maxTotal / total;
    return [Math.floor(prefs.cl * k), Math.floor(prefs.cr * k)];
  }

  // 關掉的欄不留佔位：內文在剩下的空間裡置中。目錄與最近都關時，大綱就是最左邊那欄
  function applyLayout() {
    const app = $('#app');
    const share = state.mode === 'share';
    const searching = !!$('#search').value.trim();
    const leftOpen = !share && (prefs.tree || prefs.recent || prefs.mine || searching);   // 搜尋中一定要看得到搜尋框
    app.classList.toggle('no-left', !leftOpen);
    app.classList.toggle('no-toc', !prefs.toc);
    for (const t of [1, 2, 3, 4]) app.classList.toggle('tier-' + t, prefs.tier === t);
    app.style.setProperty('--lw', prefs.lw + 'px');
    app.style.setProperty('--tw', prefs.tw + 'px');
    const [cl, cr] = customInsets();
    app.style.setProperty('--cl', cl + 'px');
    app.style.setProperty('--cr', cr + 'px');
    $('#panel-results').hidden = !searching;
    $('#panel-tree').hidden = searching || !prefs.tree;
    $('#panel-recent').hidden = searching || !prefs.recent;
    $('#panel-mine').hidden = searching || !prefs.mine;
    $('#bm-btn').hidden = share;
    for (const b of document.querySelectorAll('#capsule [data-toggle]')) {
      b.setAttribute('aria-pressed', String(!!prefs[b.dataset.toggle]));
      b.hidden = share && b.dataset.toggle !== 'toc';
    }
    $('#tier-btn').textContent = '寬度 ' + TIER_LABEL[prefs.tier];
    $('#menu-btn').hidden = share;
    state.floatTable = null;   // 版面變了，浮動表格標頭的欄寬要重新量
    updateSpy();
    updateJump();
  }

  function setPanel(name, open) {
    prefs[name] = open;
    savePrefs();
    applyLayout();
  }

  function toggleMenu(force) {
    const open = force === undefined ? $('#menu').hidden : force;
    $('#menu').hidden = !open;
    $('#capsule').classList.toggle('open', open);
    $('#menu-btn').setAttribute('aria-expanded', String(open));
  }

  // 拖拉：pointer capture 讓滑鼠移出把手也能繼續拖
  function dragSetup(el, onMove, onEnd, onStart) {
    el.addEventListener('pointerdown', (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      if (onStart) onStart();
      el.setPointerCapture(e.pointerId);
      document.body.classList.add('dragging');
      const up = () => {
        el.removeEventListener('pointermove', onMove);
        el.removeEventListener('pointerup', up);
        el.removeEventListener('pointercancel', up);
        document.body.classList.remove('dragging');
        if (onEnd) onEnd();
      };
      el.addEventListener('pointermove', onMove);
      el.addEventListener('pointerup', up);
      el.addEventListener('pointercancel', up);
    });
  }

  function setupResizers() {
    // 欄寬：拖右邊緣；雙擊恢復預設
    for (const r of document.querySelectorAll('.resizer')) {
      const key = r.dataset.col === 'left' ? 'lw' : 'tw';
      const col = r.parentElement;
      dragSetup(r, (ev) => {
        prefs[key] = clamp(Math.round(ev.clientX - col.getBoundingClientRect().left), ...LIMITS[key]);
        applyLayout();
      }, savePrefs);
      r.addEventListener('dblclick', () => { prefs[key] = DEFAULTS[key]; savePrefs(); applyLayout(); });
    }
    // 內文寬度：左右邊界各自拖拉，互不影響。開始拖的當下，先把目前看到的左右邊界記成自訂值，畫面才不會跳
    for (const edge of document.querySelectorAll('.edge')) {
      const side = edge.classList.contains('edge-l') ? 'cl' : 'cr';
      const other = side === 'cl' ? 'cr' : 'cl';
      const box = () => {
        const r = $('#content').getBoundingClientRect();
        return [r.left + 24, r.right - 24];
      };
      dragSetup(edge, (ev) => {
        const [l0, r0] = box();
        const room = Math.max(0, r0 - l0 - MIN_PAGE - prefs[other]);
        prefs[side] = clamp(Math.round(side === 'cl' ? ev.clientX - l0 : r0 - ev.clientX), 0, room);
        applyLayout();
      }, savePrefs, () => {
        const [l0, r0] = box();
        const p = $('.page').getBoundingClientRect();
        prefs.cl = Math.max(0, Math.round(p.left - l0));
        prefs.cr = Math.max(0, Math.round(r0 - p.right));
        prefs.tier = 4;
        applyLayout();
      });
    }
  }

  // ================= 解鎖／上鎖 =================

  const MESSAGES = {
    key: '金鑰不正確。',
    stale: '這台裝置記住的金鑰已失效（金鑰可能已更換），請重新輸入。',
    auth: '內容驗證失敗：資料可能損毀或遭竄改，已拒絕顯示。',
    format: '資料格式不正確，無法解密。',
    net: '無法載入資料，請稍後再試。',
  };
  const messageFor = (e) => (e && e.code === 'parse' ? e.message : MESSAGES[e && e.code] || '發生未預期的錯誤。');

  async function fetchBytes(url) {
    let res;
    try { res = await fetch(url, { cache: 'no-store' }); } catch (e) { throw err('net'); }
    if (res.status === 404) throw err('missing');
    if (!res.ok) throw err('net');
    return new Uint8Array(await res.arrayBuffer());
  }

  async function unlock(keys) {
    const plain = await openBundle(keys, await fetchBytes('bundle.bin'));
    const bundle = JSON.parse(new TextDecoder().decode(await gunzip(plain)));
    setup(bundle);
  }

  // 入口：首頁代號的 SHA-256 與 index.html 上的比對值相同
  async function isEntry() {
    const m = location.hash.match(/^#\/d\/([0-9a-f]{16})$/);
    return !!m && (await sha256hex('notes-entry:' + m[1])) === document.body.dataset.gate;
  }

  async function onSubmit(ev) {
    ev.preventDefault();
    const input = $('#key-input');
    const remember = $('#remember').checked;
    const btn = $('#unlock-btn');
    btn.disabled = true;
    $('#lock-msg').textContent = '解密中…';
    try {
      const raw = parseKey(input.value);
      input.value = '';
      const keys = await deriveKeys(raw);
      raw.fill(0);
      await unlock(keys);
      if (remember) await saveKeys(keys).catch(() => alert('這個瀏覽器無法保存金鑰（可能是無痕視窗），下次需要重新輸入。'));
    } catch (e) {
      $('#lock-msg').textContent = messageFor(e);
    } finally {
      btn.disabled = false;
    }
  }

  async function lockAndForget() {
    if (!confirm('確定要上鎖，並從這台裝置刪除金鑰嗎？\n之後需要從入口網址重新輸入主金鑰才能閱讀。')) return;
    const home = state.bundle && state.bundle.home;
    await forgetKeys().catch(() => {});
    try { localStorage.removeItem(MINE_KEY); localStorage.removeItem(VER_KEY); } catch (e) { /* 存不了就算了 */ }
    wipe();
    // 留在入口網址，讓你可以馬上重新解鎖；用 replaceState 不觸發 hashchange
    history.replaceState(null, '', location.pathname + location.search + (home ? '#/d/' + home : ''));
    showLock('已上鎖：畫面已清除，這台裝置不再保存金鑰。');
  }

  function wipe() {
    document.title = SITE_TITLE;
    for (const url of state.blobUrls.values()) URL.revokeObjectURL(url);
    state = freshState();
    for (const id of ['#doc', '#toc', '#toc-levels', '#tree', '#recent', '#bm-list', '#seen-list', '#upd-list', '#results', '#crumb', '#share-list']) $(id).replaceChildren();
    $('#crumb').classList.remove('on');
    delete $('#crumb').dataset.key;
    $('#search').value = '';
    $('#hit-nav').hidden = true;
    $('#tfloat').hidden = true;
    $('#modal').hidden = true;
  }

  // ================= 分享頁 =================

  async function showShare(tokenText) {
    wipe();
    state.mode = 'share';
    try {
      if (!/^[A-Za-z0-9_-]{22}$/.test(tokenText)) throw err('missing');
      const token = b64urlBytes(tokenText);
      if (token.length !== 16) throw err('missing');
      // 22 個字元共 132 位元，token 只有 128 位元，最後一個字元有 4 個多餘的位元。
      // 解碼時這 4 位元會被忽略，所以最後一碼有 16 種寫法會解出同一組 token；
      // 這裡要求網址必須是標準寫法，其他寫法一律當作不存在。
      if (bytesB64url(token) !== tokenText) throw err('missing');
      const tk = await tokenKeys(token);
      const payload = await openShare(tk.enc, await fetchBytes(`s/${tk.file}.bin`));
      // 防君子的到期檢查：過期與不存在顯示一模一樣的畫面
      if (payload.expires && todayTaipei() > payload.expires) throw err('missing');
      state.shareImages = payload.images || {};
      document.body.classList.add('share-mode');
      showOnly('app');
      applyLayout();
      await showDoc({ id: 'share', path: '', kind: payload.kind, lang: payload.lang, text: payload.text,
        mime: payload.mime, b64: payload.b64, mtime: payload.mtime });
    } catch (e) {
      showNotFound();
    }
  }

  // ================= 主站版面 =================

  function setup(bundle) {
    wipe();
    state.mode = 'app';
    state.bundle = bundle;
    for (const f of bundle.files) {
      state.byId.set(f.id, f);
      state.byPath.set(f.path, f);
      if (f.text != null) state.lower.set(f.id, f.text.toLowerCase());
    }
    state.unpublished = new Set(bundle.unpublished || []);
    initVer(bundle.files);
    document.body.classList.remove('share-mode');
    renderTree();
    renderRecent();
    renderMine();
    showOnly('app');
    applyLayout();
    route();
  }

  function docLink(f, label) {
    return h('a', { href: '#/d/' + f.id, dataset: { doc: f.id }, title: f.path, class: isUpdated(f) ? 'upd' : null }, label || displayName(f.path));
  }

  // 依「第一層名稱的前綴」分組：CRT_xx、客盡_xx、新案_sql/… 各歸各組
  function renderTree() {
    const groups = new Map();
    const files = [...state.bundle.files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    for (const f of files) {
      const top = f.path.split('/')[0];
      const key = top.includes('_') ? top.split('_')[0] : top;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(f);
    }
    // 上一份／下一份：同一組內照目錄的順序（圖片不算）
    for (const list of groups.values()) {
      const docs = list.filter((f) => f.kind !== 'image');
      docs.forEach((f, i) => state.pager.set(f.id, { prev: docs[i - 1] || null, next: docs[i + 1] || null }));
    }
    const nav = $('#tree');
    for (const [key, list] of groups) {
      nav.append(h('details', { class: 'group', dataset: { group: key } },
        h('summary', null, key, h('span', { class: 'count' }, String(list.length))), buildItems(list, key)));
    }
  }

  function buildItems(list, groupKey) {
    const ul = h('ul');
    const sub = new Map();
    for (const f of list) {
      const dir = dirname(f.path);
      if (!dir) {
        const label = displayName(f.path).replace(new RegExp('^' + groupKey + '_'), '');
        ul.append(h('li', null, docLink(f, label)));
      } else {
        if (!sub.has(dir)) sub.set(dir, []);
        sub.get(dir).push(f);
      }
    }
    for (const [dir, files] of sub) {
      const inner = h('ul');
      for (const f of files) inner.append(h('li', null, docLink(f, basename(f.path))));
      ul.append(h('li', null, h('details', { class: 'folder' }, h('summary', { title: dir + '/' }, dir + '/'), inner)));
    }
    return ul;
  }

  // 最近修改：單位（筆／天）加滑桿檔位，最後一檔固定是「全部」
  function recentSteps() {
    return [...RECENT_STEPS[prefs.ru], 0];
  }

  function renderRecent() {
    const all = [...state.bundle.files].filter((f) => f.mtime)
      .sort((a, b) => (a.mtime < b.mtime ? 1 : -1));
    const steps = recentSteps();
    let idx = steps.indexOf(prefs.rv);
    if (idx < 0) idx = steps.findIndex((v) => v === 0 || v >= prefs.rv);   // 舊值不在檔位上：取最接近的較大檔
    const v = steps[idx];
    const cutoff = prefs.ru === 'd' && v ? Date.now() - v * 86400e3 : null;
    const list = !v ? all : cutoff != null ? all.filter((f) => Date.parse(f.mtime) >= cutoff) : all.slice(0, v);

    const range = $('#recent-range');
    range.max = String(steps.length - 1);
    range.value = String(idx);
    $('#recent-unit').value = prefs.ru;
    $('#recent-label').textContent = (!v ? '全部' : `最近 ${v} ${prefs.ru === 'd' ? '天' : '筆'}`) + `：${list.length} / ${all.length} 份`;
    $('#recent').replaceChildren(...list.map((f) =>
      h('li', null, docLink(f), h('span', { class: 'date', title: fmtFull(f.mtime) }, fmtShort(f.mtime)))));
    if (state.current) markCurrentInTree(state.current);
  }

  // ================= 書籤與最近閱讀（只存在這台瀏覽器，用檔案路徑記）=================

  // 更新提示：記下每份文件「讀到的修改時間」；和目前不同（或新增的文件）就標小圓點。
  // 第一次使用（沒有紀錄）把現有文件全部當已讀，免得滿畫面圓點。
  const VER_KEY = 'notes.ver';
  let ver = {};
  const isUpdated = (f) => !!f.mtime && ver[f.path] !== f.mtime;

  function saveVer() {
    try { localStorage.setItem(VER_KEY, JSON.stringify(ver)); } catch (e) { /* 存不了就算了 */ }
  }

  function initVer(files) {
    let saved = null;
    try { saved = JSON.parse(localStorage.getItem(VER_KEY)); } catch (e) { saved = null; }
    if (saved && typeof saved === 'object' && !Array.isArray(saved)) { ver = saved; return; }
    ver = Object.fromEntries(files.filter((f) => f.mtime).map((f) => [f.path, f.mtime]));
    saveVer();
  }

  function markRead(f) {
    if (!f.mtime || ver[f.path] === f.mtime) return;
    ver[f.path] = f.mtime;
    saveVer();
    for (const a of document.querySelectorAll(`a[data-doc="${f.id}"]`)) a.classList.remove('upd');
    renderMine();
  }

  const MINE_KEY = 'notes.mine';
  const SEEN_MAX = 20;
  const mine = { bm: [], seen: [] };
  try {
    const saved = JSON.parse(localStorage.getItem(MINE_KEY));
    for (const k of Object.keys(mine)) if (saved && Array.isArray(saved[k])) mine[k] = saved[k].filter((p) => typeof p === 'string');
  } catch (e) { /* 沒有或讀不到就從空的開始 */ }

  function saveMine() {
    try { localStorage.setItem(MINE_KEY, JSON.stringify(mine)); } catch (e) { /* 無痕視窗等情況存不了，不影響使用 */ }
  }

  function renderMine() {
    if (!state.bundle) return;
    const fill = (sel, paths, removable) => {
      const docs = paths.map((p) => state.byPath.get(p)).filter(Boolean);   // 已被刪除的文件直接略過
      $(sel).replaceChildren(...(docs.length ? docs.map((f) => h('li', null, docLink(f),
        removable ? h('button', { type: 'button', class: 'x', title: '移除書籤', onclick: () => toggleBookmark(f.path) }, '✕') : null))
        : [h('li', { class: 'muted' }, '（空）')]));
    };
    const upd = state.bundle.files.filter(isUpdated).sort((x, y) => (x.mtime < y.mtime ? 1 : -1));
    $('#upd-box').hidden = !upd.length;
    $('#upd-title').firstChild.textContent = `有更新（${upd.length}）`;
    $('#upd-list').replaceChildren(...upd.slice(0, 50).map((f) => h('li', null, docLink(f), h('span', { class: 'date', title: fmtFull(f.mtime) }, fmtShort(f.mtime)))));
    fill('#bm-list', mine.bm, true);
    fill('#seen-list', mine.seen, false);
    updateBmButton();
    if (state.current) markCurrentInTree(state.current);
  }

  function updateBmButton() {
    const on = !!state.current && mine.bm.includes(state.current.path);
    const b = $('#bm-btn');
    b.textContent = on ? '★' : '☆';
    b.setAttribute('aria-pressed', String(on));
    b.title = on ? '移除這份文件的書籤' : '把這份文件加入書籤';
  }

  function toggleBookmark(path) {
    if (!path) return;
    mine.bm = mine.bm.includes(path) ? mine.bm.filter((p) => p !== path) : [path, ...mine.bm];
    saveMine();
    renderMine();
  }

  function recordSeen(f) {
    mine.seen = [f.path, ...mine.seen.filter((p) => p !== f.path)].slice(0, SEEN_MAX);
    saveMine();
    renderMine();
  }

  function setRecent(ru, rv) {
    prefs.ru = ru;
    prefs.rv = rv;
    savePrefs();
    renderRecent();
  }

  // ================= 路由 =================

  async function boot() {
    const sm = location.hash.match(/^#\/s\/(.*)$/);
    if (sm) return showShare(sm[1]);
    if (state.mode === 'app' && state.bundle) return route();

    let stale = false;
    let stored = null;
    try { stored = await loadKeys(); } catch (e) { stored = null; }
    if (stored) {
      try {
        await unlock(stored);
        return;
      } catch (e) {
        if (e.code === 'key') {
          stale = true;
          await forgetKeys().catch(() => {});
        } else if (await isEntry()) {
          return showLock(messageFor(e));
        } else {
          return showNotFound();
        }
      }
    }
    if (await isEntry()) return showLock(stale ? MESSAGES.stale : '');
    showNotFound();
  }

  function route() {
    const m = location.hash.match(/^#\/d\/([0-9a-f]{16})$/);
    const f = m && state.byId.get(m[1]);
    if (f) return showDoc(f);
    const home = state.byId.get(state.bundle.home) || state.bundle.files[0];
    if (home) {
      history.replaceState(null, '', '#/d/' + home.id);
      showDoc(home);
    }
  }

  function go(id, anchor) {
    if (state.current && state.current.id === id) {
      if (anchor) { scrollToAnchor(anchor); revealCurrent(); }
      return;
    }
    state.pendingAnchor = anchor || null;
    location.hash = '#/d/' + id;
  }

  // ================= 文件顯示 =================

  async function showDoc(f) {
    state.current = f;
    document.body.classList.remove('dg-open');
    if (state.mode === 'app') { recordSeen(f); markRead(f); }
    document.title = state.mode === 'app' ? displayName(f.path) : SITE_TITLE;
    state.anchors = new Map();
    const body = h('div', { class: 'doc-body' });
    // 最下方（分隔線之後）：檔名與「(commit 前 7 碼 時間)」，懸停顯示 commit 訊息，用來確認看到的是不是最新發布的版本。
    // 分享頁不透露檔名與 commit，只在 showModified 打開時顯示該文件的修改時間
    const bd = state.bundle && state.bundle.build;
    const when = state.mode === 'share'
      ? (f.mtime ? h('span', { class: 'when' }, '(最後修改 ', timeSpan(f.mtime), ')') : null)
      : bd ? h('span', { class: 'when', title: bd.subject }, '(', h('code', null, bd.hash), ' ', fmtShort(bd.time), ')') : null;
    const foot = state.mode === 'share'
      ? (when ? h('footer', { class: 'doc-foot' }, when) : null)
      : h('footer', { class: 'doc-foot' }, h('span', { class: 'doc-path' }, f.path), when);
    $('#doc').replaceChildren(...[body, pagerFor(f), foot].filter(Boolean));

    if (f.kind === 'md') await renderMarkdown(f, body);
    else if (f.kind === 'code') renderCode(f, body);
    else if (f.kind === 'image') body.append(h('img', { src: blobUrl(f), alt: basename(f.path) || '圖片', class: 'doc-image' }));

    renderToc(body);
    markCurrentInTree(f);
    collectTables(body);
    window.scrollTo(0, 0);

    // 搜尋黃底綁搜尋框：搜尋框有字，不論怎麼進入這份文件都標黃；清空搜尋框才消失
    state.marks = [];
    state.markIdx = -1;
    const q = state.mode === 'app' ? $('#search').value.trim() : '';
    if (q) applyMarks(body, q);

    let jumped = false;
    if (state.pendingJump && state.marks.length) {
      gotoMark(0);
      jumped = true;
    } else if (state.pendingAnchor) {
      scrollToAnchor(state.pendingAnchor);
      jumped = true;
    }
    state.pendingJump = false;
    state.pendingAnchor = null;
    updateHitNav();
    if (jumped) revealCurrent();   // 從連結或搜尋跳進文件：把目標所在的大綱分支展開
    updateSpy();
  }

  function pagerFor(f) {
    const p = state.mode === 'app' && state.pager.get(f.id);
    if (!p || (!p.prev && !p.next)) return null;
    const side = (cls, arrow, g) => (g
      ? h('a', { class: cls, href: '#/d/' + g.id, dataset: { doc: g.id }, title: g.path },
        h('span', { class: 'pg-dir' }, arrow), h('span', { class: 'pg-name' }, displayName(g.path)))
      : h('span', { class: cls + ' off' }));
    return h('nav', { class: 'doc-pager', 'aria-label': '上一份與下一份' },
      side('pg-prev', '← 上一份', p.prev), side('pg-next', '下一份 →', p.next));
  }

  function renderCode(f, body) {
    const code = h('code', { class: 'language-' + (f.lang || 'plaintext') }, f.text);
    body.append(h('pre', { class: 'code-file' }, code));
    if (window.hljs && f.lang !== 'plaintext') window.hljs.highlightElement(code);
    addCopyButton(body.firstChild, code);
  }

  // 程式碼區塊右上角的複製按鈕：複製的是原始文字，不含上色標籤；文字由 CSS 畫出，搜尋黃底不會誤標到按鈕
  function addCopyButton(pre, code) {
    pre.classList.add('has-copy');
    pre.append(h('button', {
      type: 'button', class: 'copy-code', title: '複製這段程式碼', 'aria-label': '複製這段程式碼',
      onclick: async (e) => {
        const b = e.currentTarget;
        let ok = true;
        try { await navigator.clipboard.writeText(code.textContent); } catch (x) { ok = false; }
        b.dataset.state = ok ? 'done' : 'fail';
        setTimeout(() => { delete b.dataset.state; }, 1500);
      },
    }));
  }

  function bytesUrl(key, b64, mime) {
    if (!state.blobUrls.has(key)) {
      const u8 = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
      state.blobUrls.set(key, URL.createObjectURL(new Blob([u8], { type: mime })));
    }
    return state.blobUrls.get(key);
  }

  const blobUrl = (f) => bytesUrl(f.id, f.b64, f.mime);

  async function renderMarkdown(f, body) {
    if (!window.marked || !window.DOMPurify) {
      // 本機 --dev 模式尚未下載函式庫時的退路
      body.append(h('pre', { class: 'code-file' }, f.text));
      return;
    }
    const html = window.marked.parse(f.text, { gfm: true, async: false });
    const frag = window.DOMPurify.sanitize(html, {
      RETURN_DOM_FRAGMENT: true,
      FORBID_TAGS: ['style', 'form', 'button', 'textarea', 'select', 'option', 'iframe', 'object', 'embed', 'link', 'meta', 'base'],
      FORBID_ATTR: ['id', 'name'],
    });
    body.append(frag);

    // 標題錨點（不設 id，存在對照表裡）
    const seen = new Map();
    for (const el of body.querySelectorAll('h1, h2, h3, h4, h5, h6')) {
      const base = slugify(el.textContent);
      const n = seen.get(base) || 0;
      seen.set(base, n + 1);
      state.anchors.set(n ? `${base}-${n}` : base, el);
    }

    // 只允許停用的勾選框（GFM 任務清單），其他輸入框一律移除
    for (const el of body.querySelectorAll('input')) {
      if (el.type === 'checkbox') el.disabled = true; else el.remove();
    }

    for (const a of body.querySelectorAll('a[href]')) rewriteLink(f, a);
    for (const img of body.querySelectorAll('img')) rewriteImage(f, img);

    const mermaidNodes = [];
    for (const code of body.querySelectorAll('pre > code')) {
      if (code.classList.contains('language-mermaid')) {
        const div = h('div', { class: 'mermaid' }, code.textContent);
        code.parentElement.replaceWith(h('div', { class: 'dg' }, div));
        mermaidNodes.push(div);
      } else {
        if (window.hljs && /language-/.test(code.className)) window.hljs.highlightElement(code);
        addCopyButton(code.parentElement, code);
      }
    }
    if (mermaidNodes.length) {
      try {
        const pele = await loadPele();
        for (const n of mermaidNodes) {
          const text = n.textContent;
          mounts.set(n, pele.mount(n, text, { zoom: 'auto', onError: () => { n.textContent = text; n.classList.add('mermaid-failed'); } }));
          if (n.querySelector('svg')) addExpandButton(n.parentElement);
        }
      } catch (e) {
        for (const n of mermaidNodes) n.classList.add('mermaid-failed');
      }
    }
  }

  // 圖表放大：這張圖暫時鋪滿整個瀏覽器視窗（用 CSS 疊層，不用 Fullscreen API：
  // 內嵌瀏覽器與部分環境會擋掉它）。留一個等高的空位，收起來時閱讀位置不會跳。
  const mounts = new WeakMap();

  function toggleExpand(n) {   // n 是外層 .dg；按鈕放在它裡面，Pele 重畫 .mermaid 時才不會被清掉
    const open = !n.classList.contains('dg-expanded');
    if (open) {
      n.before(h('div', { class: 'dg-ph', style: `height:${n.getBoundingClientRect().height}px` }));
    } else {
      n.previousElementSibling?.classList.contains('dg-ph') && n.previousElementSibling.remove();
    }
    n.classList.toggle('dg-expanded', open);
    document.body.classList.toggle('dg-open', open);
    requestAnimationFrame(() => {   // 讓 Pele 依新的容器大小重排，縮放回到「符合視窗」
      const m = mounts.get(n.firstElementChild);
      if (m) { m.refresh(); if (m.zoom) m.zoom.reset(); }
    });
  }

  function collapseExpanded() {
    const n = document.querySelector('.dg.dg-expanded');
    if (n) toggleExpand(n);
  }

  function addExpandButton(n) {
    n.append(h('button', { type: 'button', class: 'dg-full', title: '這張圖放大到整個畫面（Esc 離開）', onclick: () => toggleExpand(n) }));
  }

  function linkOff(a, reason, detail) {
    const span = h('span', { class: 'link-off', title: detail ? `${reason}：${detail}` : reason }, ...a.childNodes);
    a.replaceWith(span);
  }

  function rewriteLink(f, a) {
    const raw = a.getAttribute('href');
    if (/^(https?:|mailto:)/i.test(raw)) {
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      return;
    }
    const hash = raw.indexOf('#');
    const pathPart = safeDecode(hash >= 0 ? raw.slice(0, hash) : raw);
    const anchor = hash >= 0 ? safeDecode(raw.slice(hash + 1)) : '';
    if (!pathPart) {
      a.setAttribute('href', '#/d/' + f.id);
      a.dataset.doc = f.id;
      a.dataset.anchor = anchor;
      return;
    }
    // 分享頁不透露其他文件的存在與名稱
    if (state.mode === 'share') return linkOff(a, '未分享');
    if (/^[a-z][a-z0-9+.-]*:/i.test(pathPart)) return linkOff(a, '不支援的連結', pathPart);
    const target = normalizePath((dirname(f.path) ? dirname(f.path) + '/' : '') + pathPart);
    if (target == null) return linkOff(a, '指向文件庫以外的路徑', pathPart);
    const doc = state.byPath.get(target);
    if (doc) {
      a.setAttribute('href', '#/d/' + doc.id);
      a.dataset.doc = doc.id;
      if (anchor) a.dataset.anchor = anchor;
      a.title = doc.path;
      return;
    }
    if (state.unpublished.has(target)) return linkOff(a, '此文件未發布', target);
    const dir = target.replace(/\/$/, '') + '/';
    if (state.bundle.files.some((x) => x.path.startsWith(dir))) return linkOff(a, '資料夾，請從左側目錄展開', target);
    if ([...state.unpublished].some((p) => p.startsWith(dir))) return linkOff(a, '此資料夾未發布', target);
    linkOff(a, '文件不存在', target);
  }

  function rewriteImage(f, img) {
    const src = safeDecode(img.getAttribute('src') || '');
    if (state.mode === 'share') {
      const pic = state.shareImages[src];
      if (pic) img.src = bytesUrl('share:' + src, pic.b64, pic.mime);
      else img.replaceWith(h('span', { class: 'link-off', title: '圖片未分享' }, `[圖片：${img.alt || '未分享'}]`));
      return;
    }
    const target = normalizePath((dirname(f.path) ? dirname(f.path) + '/' : '') + src);
    const file = target != null && state.byPath.get(target);
    if (file && file.kind === 'image') {
      img.src = blobUrl(file);
    } else {
      // 不載入外部或不存在的圖片
      img.replaceWith(h('span', { class: 'link-off', title: '圖片未發布或不在文件庫內：' + src }, `[圖片：${img.alt || src}]`));
    }
  }

  // 沿用 index.html 給 app.js 的版本參數，避免瀏覽器快取到舊版 pele
  const VERSION_QUERY = document.currentScript ? new URL(document.currentScript.src).search : '';
  let pelePromise = null;
  function loadPele() {
    if (!pelePromise) {
      pelePromise = new Promise((resolve, reject) => {
        const s = document.createElement('script');
        s.src = 'vendor/pele.min.js' + VERSION_QUERY;
        s.onload = () => resolve(window.pele);
        s.onerror = () => { pelePromise = null; reject(new Error('pele')); };
        document.head.append(s);
      });
    }
    return pelePromise;
  }

  function scrollToAnchor(anchor) {
    // GitHub 的錨點一律小寫，但文件裡的連結常寫成大小寫混用，所以再試一次小寫
    const el = state.anchors.get(anchor) || state.anchors.get(anchor.toLowerCase()) || state.anchors.get(slugify(anchor));
    if (el) el.scrollIntoView({ block: 'start' });
  }

  // ================= 大綱（可折疊的樹）=================
  // 節點：{ i, el, level, text, parent, children, depth }。depth 從 1 起算（沒有上層的標題）。
  // 預設：整份只有一個頂層標題（通常是 H1 文件標題）時，它固定展開，它底下的標題當第一層；
  //       有多個頂層標題的文件，全部收合，只列出頂層。

  function renderToc(body) {
    const nodes = [...body.querySelectorAll('h1, h2, h3')].map((el, i) =>
      ({ i, el, level: +el.tagName[1], text: el.textContent.trim(), parent: null, children: [], depth: 1 }));
    const stack = [];
    for (const n of nodes) {
      while (stack.length && stack[stack.length - 1].level >= n.level) stack.pop();
      n.parent = stack[stack.length - 1] || null;
      n.depth = n.parent ? n.parent.depth + 1 : 1;
      if (n.parent) n.parent.children.push(n);
      stack.push(n);
    }
    const roots = nodes.filter((n) => !n.parent);
    state.headings = nodes;
    state.singleRoot = roots.length === 1 ? roots[0] : null;
    state.maxDepth = nodes.reduce((m, n) => Math.max(m, n.depth), 0);
    state.tocOpen = new Set(state.singleRoot ? [state.singleRoot] : []);
    // 麵包屑最高多少：取這份文件所有標題的「從上層到自己」行高總和的最大值（單一頂層不顯示，不算）。
    // 每份文件開啟時算一次，標題跳轉的停靠位置才不會隨目前位置飄動
    let maxH = 0;
    for (const n of nodes) {
      let sum = 0;
      for (let p = n; p && p !== state.singleRoot; p = p.parent) sum += CRUMB_H[p.level];
      maxH = Math.max(maxH, sum);
    }
    state.crumbH = (maxH || CRUMB_H[3]) + 9;   // 上下內距 4＋4 與底線 1
    $('.page').style.setProperty('--crumb-h', state.crumbH + 'px');
    // 每個標題的「吸附線」：麵包屑只顯示它上層時的下緣。標題捲到這條線就換進麵包屑，
    // 這時麵包屑多出來的那一行正好蓋住原標題，畫面上不會同時出現兩個一樣的標題；
    // 跳轉（scroll-margin）也停在這條線上，跳過去的標題一落地就是吸附狀態
    for (const n of nodes) {
      let s = 0;
      for (let p = n.parent; p && p !== state.singleRoot; p = p.parent) s += CRUMB_H[p.level];
      n.dock = s ? s + 9 : 0;
      n.el.style.scrollMarginTop = (n.dock + 1) + 'px';
    }
    const crumb = $('#crumb');
    crumb.classList.remove('on');
    delete crumb.dataset.key;
    renderLevels();
    renderTocRows();
  }

  function renderLevels() {
    const box = $('#toc-levels');
    box.replaceChildren();
    if (state.maxDepth < 2) return;
    for (let n = 1; n <= state.maxDepth; n++) {
      box.append(h('button', { type: 'button', class: 'lv', title: `展開到第 ${n} 層`, onclick: () => setLevel(n) }, String(n)));
    }
  }

  // 「展開到第 N 層」：深度小於 N 的節點展開，其餘收合；一個控制同時包辦展開與收合
  function setLevel(n) {
    state.tocOpen = new Set(state.headings.filter((x) => x.children.length && x.depth < n));
    renderTocRows();
    updateSpy();
  }

  function toggleNode(n) {
    if (state.tocOpen.has(n)) state.tocOpen.delete(n); else state.tocOpen.add(n);
    renderTocRows();
    updateSpy();
  }

  const isShown = (n) => {
    for (let p = n.parent; p; p = p.parent) if (!state.tocOpen.has(p)) return false;
    return true;
  };

  function renderTocRows() {
    state.tocLinks = new Map();
    const toc = $('#toc');
    if (state.headings.length < 2) {
      toc.replaceChildren(h('p', { class: 'muted' }, '這份文件沒有大綱'));
      return;
    }
    const ul = h('ul');
    for (const n of state.headings) {
      if (!isShown(n)) continue;
      const open = state.tocOpen.has(n);
      const chev = n.children.length
        ? h('button', { type: 'button', class: 'chev', title: open ? '收合' : '展開', 'aria-expanded': String(open), onclick: () => toggleNode(n) }, open ? '▾' : '▸')
        : h('span', { class: 'chev' });
      const a = h('a', {
        href: location.hash, title: n.text,
        onclick: (e) => { e.preventDefault(); n.el.scrollIntoView({ block: 'start' }); },
      }, n.text);
      state.tocLinks.set(n, a);
      ul.append(h('li', { class: 'toc-row', style: `padding-left:${(n.depth - 1) * 14}px` }, chev, a));
    }
    toc.replaceChildren(ul);
  }

  // ================= 標題麵包屑、目前位置（scrollspy）=================

  let spyQueued = false;
  function queueSpy() {
    if (spyQueued) return;
    spyQueued = true;
    requestAnimationFrame(() => { spyQueued = false; updateSpy(); });
  }

  // 目前位置：最後一個已經捲到自己吸附線上的標題。吸附線最低不超過 state.crumbH，所以更下面的標題不用看
  function currentIndex() {
    let idx = -1;
    for (let i = 0; i < state.headings.length; i++) {
      const n = state.headings[i];
      const top = n.el.getBoundingClientRect().top;
      if (top > state.crumbH + 1) break;
      if (top <= n.dock + 2) idx = i;
    }
    return idx;
  }

  // 麵包屑裡的標題：複製原標題的內容（行內程式碼的灰底、粗體等照舊），拿掉搜尋黃底
  function crumbText(n) {
    const clone = n.el.cloneNode(true);
    for (const m of clone.querySelectorAll('mark.hit')) m.replaceWith(document.createTextNode(m.textContent));
    return clone.childNodes;
  }

  // 跳進文件之後，把目前位置所屬的大綱分支展開
  function revealCurrent() {
    const idx = currentIndex();
    if (idx < 0) return;
    for (let n = state.headings[idx].parent; n; n = n.parent) state.tocOpen.add(n);
    renderTocRows();
    updateSpy();
  }

  function updateSpy() {
    const crumb = $('#crumb');
    if (!state.headings.length || $('#app').hidden) {
      crumb.replaceChildren();
      crumb.classList.remove('on');
      delete crumb.dataset.key;
      updateTableFloat();
      return;
    }
    const idx = currentIndex();
    const cur = idx >= 0 ? state.headings[idx] : null;

    // 麵包屑：從目前標題往上收集每一層，一層一行、不縮排。單一頂層（文件標題）不重複顯示
    const chain = [];
    for (let n = cur; n; n = n.parent) chain.unshift(n);
    if (state.singleRoot && chain[0] === state.singleRoot) chain.shift();
    const key = chain.map((n) => n.i).join(',');
    if (crumb.dataset.key !== key) {
      crumb.dataset.key = key;
      crumb.replaceChildren(h('div', { class: 'box' }, chain.map((n, i) =>
        h('div', { class: 'line lv' + n.level, style: `height:${CRUMB_H[n.level]}px` },
          h('a', { href: location.hash, title: n.text, onclick: (e) => { e.preventDefault(); n.el.scrollIntoView({ block: 'start' }); } }, ...crumbText(n))))));
      crumb.classList.toggle('on', chain.length > 0);
    }

    // 大綱標亮目前位置；它如果藏在收合的分支裡，就標亮最近的可見上層
    let target = cur;
    while (target && !isShown(target)) target = target.parent;
    for (const [n, a] of state.tocLinks) {
      const on = n === target;
      if (a.classList.contains('active') !== on) {
        a.classList.toggle('active', on);
        if (on) {
          const box = a.closest('.panel-body');
          const ar = a.getBoundingClientRect();
          const br = box.getBoundingClientRect();
          if (ar.top < br.top || ar.bottom > br.bottom) box.scrollTop += ar.top - br.top - br.height / 3;
        }
      }
    }
    updateTableFloat();
  }

  const JUMP_AT = 300;   // 離頂部或底部超過這個距離才顯示對應的按鈕（px）
  function updateJump() {
    const el = document.documentElement;
    const y = window.scrollY;
    const toBottom = el.scrollHeight - (y + window.innerHeight);
    $('#jump-top').hidden = y < JUMP_AT;
    $('#jump-bottom').hidden = toBottom < JUMP_AT;
  }

  // ================= 長表格的浮動標頭 =================
  // 列數 ≥ 8 的表格：標頭捲到麵包屑下緣以上、表格還沒看完時，在麵包屑正下方浮出一份標頭的複製品。
  // 不用 CSS sticky：表格外層是可橫向捲動的容器，sticky 只會貼在那個容器裡，貼不到整個畫面。

  const TABLE_MIN_ROWS = 8;

  function collectTables(body) {
    state.tables = [...body.querySelectorAll('table')].filter((t) => t.tHead && t.rows.length >= TABLE_MIN_ROWS);
    state.floatTable = null;
    for (const t of state.tables) t.addEventListener('scroll', queueSpy, { passive: true });   // 橫向捲動時同步
    $('#tfloat').hidden = true;
  }

  // 複製標頭，並把每一格的寬度釘成原表格量到的寬度，欄位才會對齊
  function buildFloat(t) {
    const tbl = $('#tfloat table');
    tbl.replaceChildren(t.tHead.cloneNode(true));
    const src = [...t.tHead.rows[0].cells];
    const dst = [...tbl.tHead.rows[0].cells];
    src.forEach((cell, i) => {
      const w = cell.getBoundingClientRect().width + 'px';
      Object.assign(dst[i].style, { boxSizing: 'border-box', width: w, minWidth: w, maxWidth: w });
    });
    tbl.style.width = t.tHead.rows[0].getBoundingClientRect().width + 'px';
    state.floatTable = t;
  }

  function updateTableFloat() {
    const fl = $('#tfloat');
    // 隱藏時一併清空複製的標頭：下次顯示一定是重新複製，不可能殘留上一個表格的欄位
    const hide = () => {
      if (state.floatTable) $('#tfloat table').replaceChildren();
      fl.hidden = true;
      state.floatTable = null;
    };
    if (!state.tables.length || $('#app').hidden) return hide();

    // 浮動標頭的上緣＝麵包屑目前的下緣；沒有麵包屑就貼畫面頂端
    const crumb = $('#crumb');
    const top = crumb.classList.contains('on') ? $('.box', crumb).getBoundingClientRect().bottom : 0;

    let active = null, rect = null, hh = 0, hw = 0;
    for (const t of state.tables) {
      const r = t.getBoundingClientRect();
      if (r.bottom <= top || r.top >= innerHeight) continue;
      const hr = t.tHead.getBoundingClientRect();
      if (hr.top < top - 0.5) { active = t; rect = r; hh = hr.height; hw = hr.width; break; }
    }
    if (!active) return hide();
    // 換了表格、或複製的標頭與原標頭的欄數、文字對不上，就重新複製（自我修復）
    const cells = active.tHead.rows[0].cells;
    const sig = [...cells].map((c) => c.textContent).join('\u0001');
    if (state.floatTable !== active || state.floatSig !== sig || $('#tfloat th', fl) === null
        || fl.querySelectorAll('th').length !== cells.length) {
      buildFloat(active);
      state.floatSig = sig;
    }

    // 表格快看完時，標頭隨表格尾端往上滑出（滑到麵包屑底下被蓋住）
    const offset = Math.min(0, rect.bottom - top - hh);
    // 寬度＝表格本身的寬度（標頭那一列的寬度），但不超過外層容器的可視寬度。
    // 不能直接用容器寬度：表格比容器窄時（內容少的表），容器比表格寬，標頭右邊會多出一塊灰色空白。
    Object.assign(fl.style, {
      left: rect.left + 'px', width: Math.min(active.clientWidth, hw) + 'px', height: hh + 'px', top: (top + offset) + 'px',
    });
    $('.tf-inner', fl).style.transform = `translateX(${-active.scrollLeft}px)`;
    fl.hidden = false;
  }

  function markCurrentInTree(f) {
    for (const a of document.querySelectorAll('#tree a[aria-current], #recent a[aria-current], #bm-list a[aria-current], #seen-list a[aria-current], #upd-list a[aria-current]')) a.removeAttribute('aria-current');
    for (const a of document.querySelectorAll(`#tree a[data-doc="${f.id}"], #recent a[data-doc="${f.id}"], #bm-list a[data-doc="${f.id}"], #seen-list a[data-doc="${f.id}"], #upd-list a[data-doc="${f.id}"]`)) {
      a.setAttribute('aria-current', 'page');
      for (let d = a.closest('details'); d; d = d.parentElement.closest('details')) d.open = true;
    }
  }

  // ================= 搜尋 =================

  function search(q) {
    const needle = q.toLowerCase();
    const results = [];
    for (const f of state.bundle.files) {
      const text = state.lower.get(f.id);
      const inPath = f.path.toLowerCase().includes(needle);
      let count = 0, first = -1;
      if (text) {
        for (let i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + needle.length)) {
          if (first < 0) first = i;
          count++;
        }
      }
      if (count || inPath) results.push({ f, count, first, inPath });
    }
    results.sort((a, b) => (b.inPath - a.inPath) || (b.count - a.count));
    return results.slice(0, 50);
  }

  function snippet(f, first, len) {
    if (first < 0) return null;
    const start = Math.max(0, first - 30);
    const flat = (s) => s.replace(/\s+/g, ' ');
    return h('div', { class: 'snippet' },
      (start ? '…' : '') + flat(f.text.slice(start, first)),
      h('mark', null, f.text.slice(first, first + len)),
      flat(f.text.slice(first + len, first + len + 50)) + '…');
  }

  function renderResults(q) {
    if (!state.bundle) return;
    if (q) {
      const results = search(q);
      $('#results-title').textContent = `搜尋結果：${results.length}${results.length === 50 ? '+' : ''} 份`;
      $('#results').replaceChildren(h('ul', null, results.map((r) => h('li', { class: 'result' },
        h('a', {
          href: '#/d/' + r.f.id, title: r.f.path,
          onclick: (e) => { e.preventDefault(); state.pendingJump = true; if (state.current && state.current.id === r.f.id) showDoc(r.f); else go(r.f.id); },
        }, displayName(r.f.path)),
        r.count ? h('span', { class: 'count' }, String(r.count)) : null,
        snippet(r.f, r.first, q.length)))));
    }
    applyLayout();
  }

  // ---------- 搜尋黃底：生命週期綁搜尋框 ----------
  const MARK_LIMIT = 300;

  // 在畫面上的文字節點裡找出搜尋字，用 <mark class="hit"> 包起來，回傳所有 mark（最多 300 個）
  function applyMarks(root, q) {
    const needle = q.toLowerCase();
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: (n) => (n.parentElement.closest('svg, .mermaid') ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT),
    });
    const nodes = [];
    for (let n = walker.nextNode(); n; n = walker.nextNode()) if (n.data.toLowerCase().includes(needle)) nodes.push(n);
    const marks = [];
    for (const node of nodes) {
      let rest = node;
      for (let i = rest.data.toLowerCase().indexOf(needle); i >= 0 && marks.length < MARK_LIMIT; i = rest.data.toLowerCase().indexOf(needle)) {
        const hit = rest.splitText(i);
        rest = hit.splitText(needle.length);
        const mark = h('mark', { class: 'hit' }, hit.data);
        hit.replaceWith(mark);
        marks.push(mark);
      }
    }
    state.marks = marks;
    state.markIdx = -1;
    state.floatTable = null;   // 標題格裡的文字可能被切開、包上黃底，浮動標頭要重新複製
    return marks;
  }

  // 拿掉所有黃底，把被切開的文字節點接回去
  function clearMarks() {
    const parents = new Set();
    for (const m of document.querySelectorAll('#doc mark.hit')) {
      parents.add(m.parentNode);
      m.replaceWith(document.createTextNode(m.textContent));
    }
    for (const p of parents) p.normalize();
    state.marks = [];
    state.markIdx = -1;
    state.floatTable = null;
  }

  // 搜尋框的字變了：重新標記目前這份文件（不捲動，免得打字時閱讀位置被拉走）
  function refreshMarks(q) {
    if (state.mode === 'app' && state.current) {
      clearMarks();
      const body = $('.doc-body');
      if (q && body) applyMarks(body, q);
    }
    updateHitNav();
  }

  function gotoMark(i) {
    const n = state.marks.length;
    if (!n) return;
    state.markIdx = ((i % n) + n) % n;
    state.marks.forEach((el, k) => el.classList.toggle('cur', k === state.markIdx));
    state.marks[state.markIdx].scrollIntoView({ block: 'center' });
    updateHitNav();
    revealCurrent();   // 順便把目前命中所在的大綱分支展開
  }

  function updateHitNav() {
    const nav = $('#hit-nav');
    const q = $('#search').value.trim();
    nav.hidden = !q || state.mode !== 'app';
    const n = state.marks.length;
    const more = n >= MARK_LIMIT ? '+' : '';
    $('#hit-count').textContent = !n ? '這份文件沒有命中'
      : state.markIdx >= 0 ? `第 ${state.markIdx + 1} / ${n}${more} 個` : `共 ${n}${more} 個`;
    $('#hit-prev').disabled = !n;
    $('#hit-next').disabled = !n;
  }

  // ================= 分享管理 =================

  const STATE_LABEL = { active: '有效', revoked: '已撤銷', expired: '已過期' };

  function openShareList() {
    const shares = (state.bundle && state.bundle.shares) || [];
    const base = location.origin + location.pathname;
    const rows = shares.map((s) => {
      const doc = s.docId && state.byId.get(s.docId);
      const url = s.token ? `${base}#/s/${s.token}` : null;
      const copy = url ? h('button', {
        type: 'button', class: 'copy',
        onclick: async (e) => {
          try { await navigator.clipboard.writeText(url); e.target.textContent = '已複製'; } catch (x) { prompt('複製這個網址：', url); }
          setTimeout(() => { e.target.textContent = '複製連結'; }, 1500);
        },
      }, '複製連結') : null;
      return h('tr', { class: 'st-' + s.state },
        h('td', null, h('code', null, s.id), s.ver > 1 ? h('span', { class: 'muted' }, ` v${s.ver}`) : null),
        h('td', null, doc ? docLink(doc) : s.doc),
        h('td', null, STATE_LABEL[s.state] || s.state),
        h('td', null, s.expires || '—'),
        h('td', null, s.showModified ? '顯示' : '—'),
        h('td', { class: 'comment' }, s.comment || ''),
        h('td', null, copy));
    });
    $('#share-list').replaceChildren(shares.length
      ? h('table', null,
        h('thead', null, h('tr', null, ['id', '文件', '狀態', '到期', '修改時間', '註解', ''].map((t) => h('th', null, t)))),
        h('tbody', null, rows))
      : h('p', { class: 'muted' }, '目前沒有任何分享。'));
    $('#modal').hidden = false;
  }

  // ================= 啟動 =================

  function start() {
    if (!subtle || !window.DecompressionStream || !window.indexedDB) {
      showOnly('notfound');
      return;
    }
    $('#lock-form').addEventListener('submit', onSubmit);
    $('#menu-btn').addEventListener('click', () => toggleMenu());
    $('#share-btn').addEventListener('click', () => { toggleMenu(false); openShareList(); });
    $('#lock-btn').addEventListener('click', () => { toggleMenu(false); lockAndForget(); });
    document.addEventListener('click', (e) => { if (!e.target.closest('#menu, #menu-btn')) toggleMenu(false); });
    $('#modal-close').addEventListener('click', () => { $('#modal').hidden = true; });
    $('#modal').addEventListener('click', (e) => { if (e.target.id === 'modal') $('#modal').hidden = true; });
    $('#share-list').addEventListener('click', (e) => { if (e.target.closest('a[data-doc]')) $('#modal').hidden = true; });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { $('#modal').hidden = true; toggleMenu(false); collapseExpanded(); } });
    window.addEventListener('hashchange', () => { boot(); });
    // 捲動事件本來就是一個畫面最多一次，直接在事件裡更新，浮動標頭與麵包屑才不會慢一個畫面
    window.addEventListener('scroll', updateSpy, { passive: true });
    window.addEventListener('resize', () => { state.floatTable = null; if (state.mode === 'app') applyLayout(); queueSpy(); });

    for (const b of document.querySelectorAll('[data-close]')) b.addEventListener('click', () => setPanel(b.dataset.close, false));
    for (const b of document.querySelectorAll('#capsule [data-toggle]')) b.addEventListener('click', () => setPanel(b.dataset.toggle, !prefs[b.dataset.toggle]));
    $('#tier-btn').addEventListener('click', () => {
      prefs.tier = prefs.tier % 4 + 1;
      savePrefs();
      applyLayout();
    });
    setupResizers();

    // 回到頂部／跳到底部：浮在右下角，只在有地方可去時才出現；尊重「減少動態效果」設定
    const smooth = () => (window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth');
    $('#jump-top').addEventListener('click', () => window.scrollTo({ top: 0, behavior: smooth() }));
    $('#jump-bottom').addEventListener('click', () => window.scrollTo({ top: document.documentElement.scrollHeight, behavior: smooth() }));
    window.addEventListener('scroll', updateJump, { passive: true });
    window.addEventListener('resize', updateJump);

    $('#bm-btn').addEventListener('click', () => { if (state.current) toggleBookmark(state.current.path); });
    $('#upd-allread').addEventListener('click', () => { for (const f of state.bundle.files) if (f.mtime) ver[f.path] = f.mtime; saveVer(); for (const x of document.querySelectorAll('a.upd')) x.classList.remove('upd'); renderMine(); });
    $('#seen-clear').addEventListener('click', () => { mine.seen = []; saveMine(); renderMine(); });
    $('#recent-unit').addEventListener('change', (e) => setRecent(e.target.value, RECENT_STEPS[e.target.value][0]));
    $('#recent-range').addEventListener('input', (e) => setRecent(prefs.ru, recentSteps()[+e.target.value]));

    // 搜尋框：打字停 200 毫秒才搜尋；Enter／Shift+Enter 與按鈕在命中之間跳；Esc 清空
    let timer = null;
    const runSearch = () => {
      clearTimeout(timer);
      timer = null;
      const q = $('#search').value.trim();
      renderResults(q);
      refreshMarks(q);
    };
    $('#search').addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(runSearch, 200);
    });
    $('#search').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        if (timer) runSearch();   // 打完字馬上按 Enter：先把還沒執行的搜尋做完
        gotoMark(e.shiftKey ? (state.markIdx < 0 ? -1 : state.markIdx - 1) : state.markIdx + 1);
      } else if (e.key === 'Escape' && $('#search').value) {
        e.preventDefault();
        $('#search').value = '';
        runSearch();
      }
    });
    $('#hit-next').addEventListener('click', () => gotoMark(state.markIdx + 1));
    $('#hit-prev').addEventListener('click', () => gotoMark(state.markIdx < 0 ? -1 : state.markIdx - 1));

    // 文件內連結：站內跳頁與錨點都不寫進網址列（網址只放文件代號）
    $('#doc').addEventListener('click', (e) => {
      const a = e.target.closest('a[data-doc]');
      if (!a) return;
      e.preventDefault();
      go(a.dataset.doc, a.dataset.anchor);
    });

    boot();
  }

  start();
})();
