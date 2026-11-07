





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



  const MAGIC = te('NTS1');
  const HEADER_LEN = 36;
  const IV_LEN = 12;
  const SALT = te('notes/v1');

  function parseKey(text) {
    const s = String(text || '').trim();
    if (!/^[A-Za-z0-9_-]{43}$/.test(s)) throw err('parse', '\u91d1\u9470\u683c\u5f0f\u4e0d\u6b63\u78ba\uff1a\u61c9\u70ba 43 \u5b57\u5143\uff08\u82f1\u6578\u5b57\u3001- \u8207 _\uff09\u3002');
    const raw = b64urlBytes(s);
    if (raw.length !== 32) throw err('parse', '\u91d1\u9470\u9577\u5ea6\u4e0d\u6b63\u78ba\u3002');
    return raw;
  }


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


  const todayTaipei = () => new Date(Date.now() + 8 * 3600e3).toISOString().slice(0, 10);



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



  const $ = (sel, el = document) => el.querySelector(sel);

  const SITE_TITLE = document.title;

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


  const pad2 = (n) => String(n).padStart(2, '0');
  function fmtShort(iso) {
    const d = new Date(iso);
    return `${pad2(d.getMonth() + 1)}/${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  }
  function fmtFull(iso) {
    const d = new Date(iso);
    return `${d.getFullYear()}/${pad2(d.getMonth() + 1)}/${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
  }

  const WEEKDAY = '\u65e5\u4e00\u4e8c\u4e09\u56db\u4e94\u516d';
  function fmtCommit(iso) {
    const d = new Date(iso);
    return `${pad2(d.getMonth() + 1)}/${pad2(d.getDate())}(${WEEKDAY[d.getDay()]})${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
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


  function slugify(text) {
    return text.trim().toLowerCase().replace(/[^\p{L}\p{M}\p{N}\p{Pc}\- ]/gu, '').replace(/ /g, '-');
  }

  async function sha256hex(s) {
    return hex(new Uint8Array(await subtle.digest('SHA-256', te(s))));
  }



  function showOnly(id) {
    for (const v of ['notfound', 'lock', 'app']) $('#' + v).hidden = v !== id;
    $('#capsule').hidden = id !== 'app';
    $('#jump').hidden = id !== 'app';
    if (id !== 'app') toggleMenu(false);
    setIcon(id !== 'notfound');
  }



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
  } catch (e) {   }
  if (![1, 2, 3, 4].includes(prefs.tier)) prefs.tier = 1;
  if (!RECENT_STEPS[prefs.ru]) prefs.ru = DEFAULTS.ru;
  for (const [k, [lo, hi]] of Object.entries(LIMITS)) prefs[k] = clamp(Math.round(prefs[k]) || (k === 'rv' ? prefs[k] : DEFAULTS[k]), lo, hi);

  function savePrefs() {
    try { localStorage.setItem(PREF_KEY, JSON.stringify(prefs)); } catch (e) {   }
  }

  const MIN_PAGE = 480;
  const TIER_LABEL = { 1: '\u7a84', 2: '\u4e2d', 3: '\u5bec', 4: '\u81ea\u8a02' };


  function customInsets() {
    const avail = Math.max(0, $('#content').clientWidth - 48);
    const maxTotal = Math.max(0, avail - MIN_PAGE);
    const total = prefs.cl + prefs.cr;
    if (total <= maxTotal || !total) return [prefs.cl, prefs.cr];
    const k = maxTotal / total;
    return [Math.floor(prefs.cl * k), Math.floor(prefs.cr * k)];
  }


  function applyLayout() {
    const app = $('#app');
    const share = state.mode === 'share';
    const searching = !!$('#search').value.trim();
    const leftOpen = !share && (prefs.tree || prefs.recent || prefs.mine || searching);
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
    $('#tier-btn').textContent = '\u5bec\u5ea6 ' + TIER_LABEL[prefs.tier];
    $('#menu-btn').hidden = share;
    state.floatTable = null;
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

    for (const r of document.querySelectorAll('.resizer')) {
      const key = r.dataset.col === 'left' ? 'lw' : 'tw';
      const col = r.parentElement;
      dragSetup(r, (ev) => {
        prefs[key] = clamp(Math.round(ev.clientX - col.getBoundingClientRect().left), ...LIMITS[key]);
        applyLayout();
      }, savePrefs);
      r.addEventListener('dblclick', () => { prefs[key] = DEFAULTS[key]; savePrefs(); applyLayout(); });
    }

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



  const MESSAGES = {
    key: '\u91d1\u9470\u4e0d\u6b63\u78ba\u3002',
    stale: '\u9019\u53f0\u88dd\u7f6e\u8a18\u4f4f\u7684\u91d1\u9470\u5df2\u5931\u6548\uff08\u91d1\u9470\u53ef\u80fd\u5df2\u66f4\u63db\uff09\uff0c\u8acb\u91cd\u65b0\u8f38\u5165\u3002',
    auth: '\u5167\u5bb9\u9a57\u8b49\u5931\u6557\uff1a\u8cc7\u6599\u53ef\u80fd\u640d\u6bc0\u6216\u906d\u7ac4\u6539\uff0c\u5df2\u62d2\u7d55\u986f\u793a\u3002',
    format: '\u8cc7\u6599\u683c\u5f0f\u4e0d\u6b63\u78ba\uff0c\u7121\u6cd5\u89e3\u5bc6\u3002',
    net: '\u7121\u6cd5\u8f09\u5165\u8cc7\u6599\uff0c\u8acb\u7a0d\u5f8c\u518d\u8a66\u3002',
  };
  const messageFor = (e) => (e && e.code === 'parse' ? e.message : MESSAGES[e && e.code] || '\u767c\u751f\u672a\u9810\u671f\u7684\u932f\u8aa4\u3002');

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
    $('#lock-msg').textContent = '\u89e3\u5bc6\u4e2d\u2026';
    try {
      const raw = parseKey(input.value);
      input.value = '';
      const keys = await deriveKeys(raw);
      raw.fill(0);
      await unlock(keys);
      if (remember) await saveKeys(keys).catch(() => alert('\u9019\u500b\u700f\u89bd\u5668\u7121\u6cd5\u4fdd\u5b58\u91d1\u9470\uff08\u53ef\u80fd\u662f\u7121\u75d5\u8996\u7a97\uff09\uff0c\u4e0b\u6b21\u9700\u8981\u91cd\u65b0\u8f38\u5165\u3002'));
    } catch (e) {
      $('#lock-msg').textContent = messageFor(e);
    } finally {
      btn.disabled = false;
    }
  }

  async function lockAndForget() {
    if (!confirm('\u78ba\u5b9a\u8981\u4e0a\u9396\uff0c\u4e26\u5f9e\u9019\u53f0\u88dd\u7f6e\u522a\u9664\u91d1\u9470\u55ce\uff1f\n\u4e4b\u5f8c\u9700\u8981\u5f9e\u5165\u53e3\u7db2\u5740\u91cd\u65b0\u8f38\u5165\u4e3b\u91d1\u9470\u624d\u80fd\u95b1\u8b80\u3002')) return;
    const home = state.bundle && state.bundle.home;
    await forgetKeys().catch(() => {});
    try { localStorage.removeItem(MINE_KEY); localStorage.removeItem(VER_KEY); } catch (e) {   }
    wipe();

    history.replaceState(null, '', location.pathname + location.search + (home ? '#/d/' + home : ''));
    showLock('\u5df2\u4e0a\u9396\uff1a\u756b\u9762\u5df2\u6e05\u9664\uff0c\u9019\u53f0\u88dd\u7f6e\u4e0d\u518d\u4fdd\u5b58\u91d1\u9470\u3002');
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



  async function showShare(tokenText) {
    wipe();
    state.mode = 'share';
    try {
      if (!/^[A-Za-z0-9_-]{22}$/.test(tokenText)) throw err('missing');
      const token = b64urlBytes(tokenText);
      if (token.length !== 16) throw err('missing');



      if (bytesB64url(token) !== tokenText) throw err('missing');
      const tk = await tokenKeys(token);
      const payload = await openShare(tk.enc, await fetchBytes(`s/${tk.file}.bin`));

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



  function setup(bundle) {
    wipe();
    state.mode = 'app';
    state.bundle = bundle;
    for (const f of bundle.files) {
      state.byId.set(f.id, f);
      state.byPath.set(f.path, f);

      if (f.kind === 'html' && f.text != null) f.plain = f.text.replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
      if (f.text != null) state.lower.set(f.id, (f.plain ?? f.text).toLowerCase());
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


  function renderTree() {
    const groups = new Map();
    const files = [...state.bundle.files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    for (const f of files) {
      const top = f.path.split('/')[0];
      const key = top.includes('_') ? top.split('_')[0] : top;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(f);
    }

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


  function recentSteps() {
    return [...RECENT_STEPS[prefs.ru], 0];
  }

  function renderRecent() {
    const all = [...state.bundle.files].filter((f) => f.mtime)
      .sort((a, b) => (a.mtime < b.mtime ? 1 : -1));
    const steps = recentSteps();
    let idx = steps.indexOf(prefs.rv);
    if (idx < 0) idx = steps.findIndex((v) => v === 0 || v >= prefs.rv);
    const v = steps[idx];
    const cutoff = prefs.ru === 'd' && v ? Date.now() - v * 86400e3 : null;
    const list = !v ? all : cutoff != null ? all.filter((f) => Date.parse(f.mtime) >= cutoff) : all.slice(0, v);

    const range = $('#recent-range');
    range.max = String(steps.length - 1);
    range.value = String(idx);
    $('#recent-unit').value = prefs.ru;
    $('#recent-label').textContent = (!v ? '\u5168\u90e8' : `\u6700\u8fd1 ${v} ${prefs.ru === 'd' ? '\u5929' : '\u7b46'}`) + `\uff1a${list.length} / ${all.length} \u4efd`;
    $('#recent').replaceChildren(...list.map((f) =>
      h('li', null, docLink(f), h('span', { class: 'date', title: fmtFull(f.mtime) }, fmtShort(f.mtime)))));
    if (state.current) markCurrentInTree(state.current);
  }





  const VER_KEY = 'notes.ver';
  let ver = {};
  const isUpdated = (f) => !!f.mtime && ver[f.path] !== f.mtime;

  function saveVer() {
    try { localStorage.setItem(VER_KEY, JSON.stringify(ver)); } catch (e) {   }
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
  } catch (e) {   }

  function saveMine() {
    try { localStorage.setItem(MINE_KEY, JSON.stringify(mine)); } catch (e) {   }
  }

  function renderMine() {
    if (!state.bundle) return;
    const fill = (sel, paths, removable) => {
      const docs = paths.map((p) => state.byPath.get(p)).filter(Boolean);
      $(sel).replaceChildren(...(docs.length ? docs.map((f) => h('li', null, docLink(f),
        removable ? h('button', { type: 'button', class: 'x', title: '\u79fb\u9664\u66f8\u7c64', onclick: () => toggleBookmark(f.path) }, '\u2715') : null))
        : [h('li', { class: 'muted' }, '\uff08\u7a7a\uff09')]));
    };
    const upd = state.bundle.files.filter(isUpdated).sort((x, y) => (x.mtime < y.mtime ? 1 : -1));
    $('#upd-box').hidden = !upd.length;
    $('#upd-title').firstChild.textContent = `\u6709\u66f4\u65b0\uff08${upd.length}\uff09`;
    $('#upd-list').replaceChildren(...upd.slice(0, 50).map((f) => h('li', null, docLink(f), h('span', { class: 'date', title: fmtFull(f.mtime) }, fmtShort(f.mtime)))));
    fill('#bm-list', mine.bm, true);
    fill('#seen-list', mine.seen, false);
    updateBmButton();
    if (state.current) markCurrentInTree(state.current);
  }

  function updateBmButton() {
    const on = !!state.current && mine.bm.includes(state.current.path);
    const b = $('#bm-btn');
    b.textContent = on ? '\u2605' : '\u2606';
    b.setAttribute('aria-pressed', String(on));
    b.title = on ? '\u79fb\u9664\u9019\u4efd\u6587\u4ef6\u7684\u66f8\u7c64' : '\u628a\u9019\u4efd\u6587\u4ef6\u52a0\u5165\u66f8\u7c64';
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



  async function showDoc(f) {
    state.current = f;
    $('#app').classList.toggle('doc-html', f.kind === 'html');
    document.body.classList.remove('dg-open');
    if (state.mode === 'app') { recordSeen(f); markRead(f); }
    document.title = state.mode === 'app' ? displayName(f.path) : SITE_TITLE;
    state.anchors = new Map();
    const body = h('div', { class: 'doc-body' });


    const bd = state.bundle && state.bundle.build;
    const when = state.mode === 'share'
      ? (f.mtime ? h('span', { class: 'when' }, '(\u6700\u5f8c\u4fee\u6539 ', timeSpan(f.mtime), ')') : null)
      : bd ? h('div', { class: 'when' }, h('code', null, bd.hash), ' ', fmtCommit(bd.time)) : null;
    const cm = state.mode !== 'share' && bd ? h('div', { class: 'cm' }, bd.subject) : null;

    const pager = pagerFor(f);
    const foot = state.mode === 'share'
      ? (when ? h('footer', { class: 'doc-foot' }, when) : null)
      : pager
        ? h('footer', { class: 'doc-foot has-pager' }, pager.prev, h('div', { class: 'foot-mid' }, h('span', { class: 'doc-path' }, f.path), when, cm), pager.next)
        : h('footer', { class: 'doc-foot' }, h('span', { class: 'doc-path' }, f.path), when, cm);
    $('#doc').replaceChildren(...[body, foot].filter(Boolean));

    if (f.kind === 'md') await renderMarkdown(f, body);
    else if (f.kind === 'code') renderCode(f, body);
    else if (f.kind === 'html') renderHtml(f, body);
    else if (f.kind === 'image') body.append(h('img', { src: blobUrl(f), alt: basename(f.path) || '\u5716\u7247', class: 'doc-image' }));

    renderToc(body);
    markCurrentInTree(f);
    collectTables(body);
    window.scrollTo(0, 0);


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
    if (jumped) revealCurrent();
    updateSpy();
    updateJump();
  }

  function pagerFor(f) {
    const p = state.mode === 'app' && state.pager.get(f.id);
    if (!p || (!p.prev && !p.next)) return null;
    const side = (cls, g, dir, nameFirst) => {
      if (!g) return h('span', { class: cls + ' off' });
      const dirEl = h('span', { class: 'pg-dir' }, dir);
      const nameEl = h('span', { class: 'pg-name' }, displayName(g.path));
      return h('a', { class: cls, href: '#/d/' + g.id, dataset: { doc: g.id }, title: g.path }, ...(nameFirst ? [nameEl, dirEl] : [dirEl, nameEl]));
    };
    return { prev: side('pg-prev', p.prev, '\u2190 \u4e0a\u4e00\u4efd', false), next: side('pg-next', p.next, '\u4e0b\u4e00\u4efd \u2192', true) };
  }

  function renderCode(f, body) {
    const code = h('code', { class: 'language-' + (f.lang || 'plaintext') }, f.text);
    body.append(h('pre', { class: 'code-file' }, code));
    if (window.hljs && f.lang !== 'plaintext') window.hljs.highlightElement(code);
    addCopyButton(body.firstChild, code);
  }




  function renderHtml(f, body) {
    const frame = h('iframe', {
      class: 'html-frame', title: displayName(f.path), src: 'frame.html', referrerpolicy: 'no-referrer',
    });
    const send = (e) => {
      if (e.source !== frame.contentWindow || !e.data || e.data.type !== 'notes-frame-ready') return;
      frame.contentWindow.postMessage({ type: 'notes-html', html: f.text }, '*');
    };
    window.addEventListener('message', send);

    const off = new MutationObserver(() => {
      if (!frame.isConnected) { window.removeEventListener('message', send); off.disconnect(); }
    });
    off.observe($('#doc'), { childList: true });
    body.append(frame);
  }


  function addCopyButton(pre, code) {
    pre.classList.add('has-copy');
    pre.append(h('button', {
      type: 'button', class: 'copy-code', title: '\u8907\u88fd\u9019\u6bb5\u7a0b\u5f0f\u78bc', 'aria-label': '\u8907\u88fd\u9019\u6bb5\u7a0b\u5f0f\u78bc',
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


    const seen = new Map();
    for (const el of body.querySelectorAll('h1, h2, h3, h4, h5, h6')) {
      const base = slugify(el.textContent);
      const n = seen.get(base) || 0;
      seen.set(base, n + 1);
      state.anchors.set(n ? `${base}-${n}` : base, el);
    }


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



  const mounts = new WeakMap();

  function toggleExpand(n) {
    const open = !n.classList.contains('dg-expanded');
    if (open) {
      n.before(h('div', { class: 'dg-ph', style: `height:${n.getBoundingClientRect().height}px` }));
    } else {
      n.previousElementSibling?.classList.contains('dg-ph') && n.previousElementSibling.remove();
    }
    n.classList.toggle('dg-expanded', open);
    document.body.classList.toggle('dg-open', open);
    requestAnimationFrame(() => {
      const m = mounts.get(n.firstElementChild);
      if (m) { m.refresh(); if (m.zoom) m.zoom.reset(); }
    });
  }

  function collapseExpanded() {
    const n = document.querySelector('.dg.dg-expanded');
    if (n) toggleExpand(n);
  }

  function addExpandButton(n) {
    n.append(h('button', { type: 'button', class: 'dg-full', title: '\u9019\u5f35\u5716\u653e\u5927\u5230\u6574\u500b\u756b\u9762\uff08Esc \u96e2\u958b\uff09', onclick: () => toggleExpand(n) }));
  }

  function linkOff(a, reason, detail) {
    const span = h('span', { class: 'link-off', title: detail ? `${reason}\uff1a${detail}` : reason }, ...a.childNodes);
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

    if (state.mode === 'share') return linkOff(a, '\u672a\u5206\u4eab');
    if (/^[a-z][a-z0-9+.-]*:/i.test(pathPart)) return linkOff(a, '\u4e0d\u652f\u63f4\u7684\u9023\u7d50', pathPart);
    const target = normalizePath((dirname(f.path) ? dirname(f.path) + '/' : '') + pathPart);
    if (target == null) return linkOff(a, '\u6307\u5411\u6587\u4ef6\u5eab\u4ee5\u5916\u7684\u8def\u5f91', pathPart);
    const doc = state.byPath.get(target);
    if (doc) {
      a.setAttribute('href', '#/d/' + doc.id);
      a.dataset.doc = doc.id;
      if (anchor) a.dataset.anchor = anchor;
      a.title = doc.path;
      return;
    }
    if (state.unpublished.has(target)) return linkOff(a, '\u6b64\u6587\u4ef6\u672a\u767c\u5e03', target);
    const dir = target.replace(/\/$/, '') + '/';
    if (state.bundle.files.some((x) => x.path.startsWith(dir))) return linkOff(a, '\u8cc7\u6599\u593e\uff0c\u8acb\u5f9e\u5de6\u5074\u76ee\u9304\u5c55\u958b', target);
    if ([...state.unpublished].some((p) => p.startsWith(dir))) return linkOff(a, '\u6b64\u8cc7\u6599\u593e\u672a\u767c\u5e03', target);
    linkOff(a, '\u6587\u4ef6\u4e0d\u5b58\u5728', target);
  }

  function rewriteImage(f, img) {
    const src = safeDecode(img.getAttribute('src') || '');
    if (state.mode === 'share') {
      const pic = state.shareImages[src];
      if (pic) img.src = bytesUrl('share:' + src, pic.b64, pic.mime);
      else img.replaceWith(h('span', { class: 'link-off', title: '\u5716\u7247\u672a\u5206\u4eab' }, `[\u5716\u7247\uff1a${img.alt || '\u672a\u5206\u4eab'}]`));
      return;
    }
    const target = normalizePath((dirname(f.path) ? dirname(f.path) + '/' : '') + src);
    const file = target != null && state.byPath.get(target);
    if (file && file.kind === 'image') {
      img.src = blobUrl(file);
    } else {

      img.replaceWith(h('span', { class: 'link-off', title: '\u5716\u7247\u672a\u767c\u5e03\u6216\u4e0d\u5728\u6587\u4ef6\u5eab\u5167\uff1a' + src }, `[\u5716\u7247\uff1a${img.alt || src}]`));
    }
  }


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

    const el = state.anchors.get(anchor) || state.anchors.get(anchor.toLowerCase()) || state.anchors.get(slugify(anchor));
    if (el) el.scrollIntoView({ block: 'start' });
  }






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


    let maxH = 0;
    for (const n of nodes) {
      let sum = 0;
      for (let p = n; p && p !== state.singleRoot; p = p.parent) sum += CRUMB_H[p.level];
      maxH = Math.max(maxH, sum);
    }
    state.crumbH = (maxH || CRUMB_H[3]) + 9;
    $('.page').style.setProperty('--crumb-h', state.crumbH + 'px');



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
      box.append(h('button', { type: 'button', class: 'lv', title: `\u5c55\u958b\u5230\u7b2c ${n} \u5c64`, onclick: () => setLevel(n) }, String(n)));
    }
  }


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
      toc.replaceChildren(h('p', { class: 'muted' }, '\u9019\u4efd\u6587\u4ef6\u6c92\u6709\u5927\u7db1'));
      return;
    }
    const ul = h('ul');
    for (const n of state.headings) {
      if (!isShown(n)) continue;
      const open = state.tocOpen.has(n);
      const chev = n.children.length
        ? h('button', { type: 'button', class: 'chev', title: open ? '\u6536\u5408' : '\u5c55\u958b', 'aria-expanded': String(open), onclick: () => toggleNode(n) }, open ? '\u25be' : '\u25b8')
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



  let spyQueued = false;
  function queueSpy() {
    if (spyQueued) return;
    spyQueued = true;
    requestAnimationFrame(() => { spyQueued = false; updateSpy(); });
  }


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


  function crumbText(n) {
    const clone = n.el.cloneNode(true);
    for (const m of clone.querySelectorAll('mark.hit')) m.replaceWith(document.createTextNode(m.textContent));
    return clone.childNodes;
  }


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

  const JUMP_AT = 300;
  function updateJump() {
    const el = document.documentElement;
    const y = window.scrollY;
    const toBottom = el.scrollHeight - (y + window.innerHeight);
    $('#jump-top').hidden = y < JUMP_AT;
    $('#jump-bottom').hidden = toBottom < JUMP_AT;
  }





  const TABLE_MIN_ROWS = 8;

  function collectTables(body) {
    state.tables = [...body.querySelectorAll('table')].filter((t) => t.tHead && t.rows.length >= TABLE_MIN_ROWS);
    state.floatTable = null;
    for (const t of state.tables) t.addEventListener('scroll', queueSpy, { passive: true });
    $('#tfloat').hidden = true;
  }


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

    const hide = () => {
      if (state.floatTable) $('#tfloat table').replaceChildren();
      fl.hidden = true;
      state.floatTable = null;
    };
    if (!state.tables.length || $('#app').hidden) return hide();


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

    const cells = active.tHead.rows[0].cells;
    const sig = [...cells].map((c) => c.textContent).join('\u0001');
    if (state.floatTable !== active || state.floatSig !== sig || $('#tfloat th', fl) === null
        || fl.querySelectorAll('th').length !== cells.length) {
      buildFloat(active);
      state.floatSig = sig;
    }


    const offset = Math.min(0, rect.bottom - top - hh);


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
    const text = f.plain ?? f.text;
    return h('div', { class: 'snippet' },
      (start ? '\u2026' : '') + flat(text.slice(start, first)),
      h('mark', null, text.slice(first, first + len)),
      flat(text.slice(first + len, first + len + 50)) + '\u2026');
  }

  function renderResults(q) {
    if (!state.bundle) return;
    if (q) {
      const results = search(q);
      $('#results-title').textContent = `\u641c\u5c0b\u7d50\u679c\uff1a${results.length}${results.length === 50 ? '+' : ''} \u4efd`;
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


  const MARK_LIMIT = 300;


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
    state.floatTable = null;
    return marks;
  }


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
    revealCurrent();
  }

  function updateHitNav() {
    const nav = $('#hit-nav');
    const q = $('#search').value.trim();
    nav.hidden = !q || state.mode !== 'app';
    const n = state.marks.length;
    const more = n >= MARK_LIMIT ? '+' : '';
    $('#hit-count').textContent = !n ? '\u9019\u4efd\u6587\u4ef6\u6c92\u6709\u547d\u4e2d'
      : state.markIdx >= 0 ? `\u7b2c ${state.markIdx + 1} / ${n}${more} \u500b` : `\u5171 ${n}${more} \u500b`;
    $('#hit-prev').disabled = !n;
    $('#hit-next').disabled = !n;
  }



  const STATE_LABEL = { active: '\u6709\u6548', revoked: '\u5df2\u64a4\u92b7', expired: '\u5df2\u904e\u671f' };

  function openShareList() {
    const shares = (state.bundle && state.bundle.shares) || [];
    const base = location.origin + location.pathname;
    const rows = shares.map((s) => {
      const doc = s.docId && state.byId.get(s.docId);
      const url = s.token ? `${base}#/s/${s.token}` : null;
      const copy = url ? h('button', {
        type: 'button', class: 'copy',
        onclick: async (e) => {
          try { await navigator.clipboard.writeText(url); e.target.textContent = '\u5df2\u8907\u88fd'; } catch (x) { prompt('\u8907\u88fd\u9019\u500b\u7db2\u5740\uff1a', url); }
          setTimeout(() => { e.target.textContent = '\u8907\u88fd\u9023\u7d50'; }, 1500);
        },
      }, '\u8907\u88fd\u9023\u7d50') : null;
      return h('tr', { class: 'st-' + s.state },
        h('td', null, h('code', null, s.id), s.ver > 1 ? h('span', { class: 'muted' }, ` v${s.ver}`) : null),
        h('td', null, doc ? docLink(doc) : s.doc),
        h('td', null, STATE_LABEL[s.state] || s.state),
        h('td', null, s.expires || '\u2014'),
        h('td', null, s.showModified ? '\u986f\u793a' : '\u2014'),
        h('td', { class: 'comment' }, s.comment || ''),
        h('td', null, copy));
    });
    $('#share-list').replaceChildren(shares.length
      ? h('table', null,
        h('thead', null, h('tr', null, ['id', '\u6587\u4ef6', '\u72c0\u614b', '\u5230\u671f', '\u4fee\u6539\u6642\u9593', '\u8a3b\u89e3', ''].map((t) => h('th', null, t)))),
        h('tbody', null, rows))
      : h('p', { class: 'muted' }, '\u76ee\u524d\u6c92\u6709\u4efb\u4f55\u5206\u4eab\u3002'));
    $('#modal').hidden = false;
  }



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


    const smooth = () => (window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth');
    $('#jump-top').addEventListener('click', () => window.scrollTo({ top: 0, behavior: smooth() }));
    $('#jump-bottom').addEventListener('click', () => window.scrollTo({ top: document.documentElement.scrollHeight, behavior: smooth() }));
    window.addEventListener('scroll', updateJump, { passive: true });
    window.addEventListener('resize', updateJump);

    new ResizeObserver(updateJump).observe(document.body);

    $('#bm-btn').addEventListener('click', () => { if (state.current) toggleBookmark(state.current.path); });
    $('#upd-allread').addEventListener('click', () => { for (const f of state.bundle.files) if (f.mtime) ver[f.path] = f.mtime; saveVer(); for (const x of document.querySelectorAll('a.upd')) x.classList.remove('upd'); renderMine(); });
    $('#seen-clear').addEventListener('click', () => { mine.seen = []; saveMine(); renderMine(); });
    $('#recent-unit').addEventListener('change', (e) => setRecent(e.target.value, RECENT_STEPS[e.target.value][0]));
    $('#recent-range').addEventListener('input', (e) => setRecent(prefs.ru, recentSteps()[+e.target.value]));


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
        if (timer) runSearch();
        gotoMark(e.shiftKey ? (state.markIdx < 0 ? -1 : state.markIdx - 1) : state.markIdx + 1);
      } else if (e.key === 'Escape' && $('#search').value) {
        e.preventDefault();
        $('#search').value = '';
        runSearch();
      }
    });
    $('#hit-next').addEventListener('click', () => gotoMark(state.markIdx + 1));
    $('#hit-prev').addEventListener('click', () => gotoMark(state.markIdx < 0 ? -1 : state.markIdx - 1));


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
