/* UnrEal 账号商店 — 前端逻辑
 * 数据全部存浏览器 localStorage，不上传任何服务器。
 * 皮肤图片走 valorant-api 官方 CDN，名字→图片的映射离线内置一份。
 */

const LS_DATA = 'unreal_shop_data_v1';
const LS_DB = 'unreal_shop_db_v1';
const LS_ROLE = 'unreal_shop_role_v1';
const LS_STAFF_PASSES = 'unreal_shop_staff_passes_v1'; // 老板设备上的员工密码明文清单（仅本机）
const DB_TTL = 7 * 24 * 3600 * 1000;
const PAGE = 80;

/* 访问口令：线上模式代码里不存任何密码哈希——
 * 老板密码 = 能解开 data-enc.json 的密码（AES-GCM 解密成功即验证通过）；
 * 员工密码 = 在线员工包下发的哈希 / 老板本机清单哈希。
 * 仅 file:// 本地打开时退回哈希比对（不发布到公网，无泄露面）。 */
const FILE_BOSS_HASH = '83e013b93b7b0219d13c8434c516874fd025071a5dc6ed5554dac0a24aa1130a'; // 只用于本地文件打开
let staffHashes = []; // 线上员工包下发的员工密码哈希（老板导出后发布才生效）；默认为空 = 员工无法登录
/* 数据加密参数：AES-256-GCM + PBKDF2-SHA256，与 生成网站数据.py 保持一致 */
const ENC_ITER = 150000;

async function sha256Hex(s) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
async function deriveKey(pass, saltB64) {
  const salt = Uint8Array.from(atob(saltB64), (c) => c.charCodeAt(0));
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ENC_ITER, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
async function decryptPayload(pass, pack) {
  const key = await deriveKey(pass, pack.salt);
  const iv = Uint8Array.from(atob(pack.iv), (c) => c.charCodeAt(0));
  const ct = Uint8Array.from(atob(pack.ct), (c) => c.charCodeAt(0));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}
async function encryptPayload(pass, obj) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const b64 = (u8) => btoa(String.fromCharCode(...u8));
  const saltB64 = b64(salt), ivB64 = b64(iv);
  const key = await deriveKey(pass, saltB64);
  const pt = new TextEncoder().encode(JSON.stringify(obj));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt));
  return { v: 1, kdf: 'PBKDF2-SHA256-' + ENC_ITER, salt: saltB64, iv: ivB64, ct: b64(ct) };
}

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const state = { records: [], q: '', scope: 'all', sort: 'id-asc', shown: 0, view: [], role: '' };
let BOSS_PASS = '';   // 仅内存，老板本次会话用来解密/加密数据包
let staffLocalHashes = []; // 老板本机管理的员工密码哈希（与 localStorage 里的明文清单对应）
let encPack = null;   // 启动时拉取的加密数据包，登录时用来验证老板密码
let dbLoaded = 0;

/* ---------------------------------------------------------------- 小工具 */
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));

const norm = (s) => String(s == null ? '' : s)
  .toLowerCase()
  .replace(/[\s\u00a0\u200b]+/g, '')
  .replace(/[（）]/g, (c) => (c === '（' ? '(' : ')'))
  .replace(/／/g, '/')
  .replace(/：/g, ':')
  .replace(/[・·]/g, '');

let toastTimer;
function toast(msg) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 1900);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (e) { /* 落到下面的兜底 */ }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;top:-999px;opacity:0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  } catch (e) { return false; }
}

/* ---------------------------------------------------------------- 皮肤库 */
function dbFromSeed() {
  const seed = window.SKIN_SEED || {};
  const out = {};
  for (const k in seed) {
    const v = seed[k];
    if (v && v[0] && v[1]) out[k] = { n: v[0], i: v[1] };
  }
  return out;
}

function readDbCache() {
  try {
    const raw = localStorage.getItem(LS_DB);
    if (!raw) return null;
    const j = JSON.parse(raw);
    if (!j || !j.t || Date.now() - j.t > DB_TTL || !j.m) return null;
    if (Object.keys(j.m).length < 500) return null;
    return j.m;
  } catch (e) { return null; }
}

function setDbStatus(txt, cls) {
  const el = $('#db-status');
  el.textContent = txt;
  el.className = 'db-status' + (cls ? ' ' + cls : '');
}

async function initSkinDB() {
  DB = dbFromSeed();
  dbLoaded = Object.keys(DB).length;

  const cached = readDbCache();
  if (cached) {
    DB = cached;
    dbLoaded = Object.keys(DB).length;
    setDbStatus(`皮肤库 ${dbLoaded} 条`, 'ok');
    return;
  }

  setDbStatus(dbLoaded ? `皮肤库 ${dbLoaded} 条` : '皮肤库加载中…', 'ok');

  // 后台向官方接口刷新一次，失败就继续用内置那份
  try {
    const langs = ['zh-TW', 'zh-CN'];
    const out = {};
    const res = await Promise.all(langs.map((l) =>
      fetch('https://valorant-api.com/v1/weapons/skinlevels?language=' + l, { cache: 'force-cache' })
        .then((r) => r.json()).catch(() => null)
    ));
    res.forEach((j) => {
      ((j && j.data) || []).forEach((x) => {
        if (!x.displayIcon || !x.displayName) return;
        const k = norm(x.displayName);
        if (!out[k]) out[k] = { n: x.displayName, i: x.displayIcon };
      });
    });
    if (Object.keys(out).length > 500) {
      DB = out;
      dbLoaded = Object.keys(DB).length;
      setDbStatus(`皮肤库 ${dbLoaded} 条`, 'ok');
      try { localStorage.setItem(LS_DB, JSON.stringify({ t: Date.now(), m: out })); } catch (e) { /* 存不下就算了 */ }
      return;
    }
  } catch (e) { /* 离线也能用内置表 */ }

  setDbStatus(`皮肤库 ${dbLoaded} 条（离线）`, dbLoaded ? 'ok' : 'err');
}

function findSkin(name) {
  const raw = String(name == null ? '' : name).trim();
  if (!raw) return null;

  const noVer = (s) => s
    .replace(/\s*\/+\s*\d+(?:\.\d+)?/g, '')   // 去掉 //2.0 这种版本后缀
    .replace(/\/{2,}/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  let t = raw.split(/[\r\n]/)[0].replace(/等級\s*\d+/g, '').trim();
  const cands = [t, noVer(t)];

  // 名字里带了武器后缀但接口那边没有时，逐级砍掉末尾的词再试
  const words = t.split(/\s+/);
  for (let cut = 1; cut <= 2 && words.length - cut > 0; cut++) {
    const short = words.slice(0, words.length - cut).join(' ');
    cands.push(short, noVer(short));
  }

  for (const c of cands) {
    const k = norm(c);
    if (k && DB[k]) return DB[k];
    const k2 = k.replace(/[。\.!！]+$/, '');
    if (k2 && DB[k2]) return DB[k2];
  }
  return null;
}

/* ---------------------------------------------------------------- 解析数据 */
function parseEntry(tok) {
  let t = String(tok).trim();
  let price = null, disc = null;
  const m = t.match(/^(.*?)\s*[（(]\s*(\d+)\s*(?:vp)?\s*(?:\/\s*(\d+)\s*%\s*)?[)）]\s*$/i);
  if (m) {
    t = m[1].trim();
    price = parseInt(m[2], 10);
    disc = m[3] ? parseInt(m[3], 10) : null;
  }
  return { name: t, price, disc };
}

function splitList(txt) {
  const s = String(txt == null ? '' : txt).trim();
  if (!s) return [];
  let parts = s.split(/\s*[|｜]\s*|\s*、\s*|\s*[;；]\s*/).filter((x) => x.trim());
  if (parts.length <= 1) parts = s.split(/\s{2,}/).filter((x) => x.trim());
  return parts.map(parseEntry).filter((x) => x.name);
}

function parseSkinCell(raw, priceCell) {
  let s = String(raw == null ? '' : raw).trim();
  let nightRaw = '';
  const mi = s.match(/夜市\s*[:：]\s*([\s\S]*)$/);
  if (mi) {
    nightRaw = mi[1];
    s = s.slice(0, mi.index);
  }
  let daily = splitList(s);
  const night = splitList(nightRaw);

  if (daily.length && daily.every((x) => x.price == null) && priceCell) {
    const ps = String(priceCell).split(/[|｜,，;；\s]+/).map((v) => parseInt(v, 10)).filter((v) => !isNaN(v));
    if (ps.length === daily.length) daily = daily.map((x, i) => ({ ...x, price: ps[i] }));
  }
  return { daily, night };
}

const COLS = [
  ['id', ['账号', '编号', '账号名', '用户名', 'account', 'user']],
  ['emailPwd', ['邮箱密码', '邮箱pass', 'emailpwd']],
  ['pwd', ['密码', 'password', 'pwd', 'pass']],
  ['email', ['邮箱', 'email', 'mail']],
  ['skins', ['每日商店', '皮肤', '今日商店', '商店', 'skins', 'store', 'skin']],
  ['prices', ['价格vp', '价格', 'prices', 'price']],
  ['night', ['夜市']],
  ['region', ['地区', '区服', '大区', 'region']],
  ['note', ['备注', 'note', 'remark']],
];

function looksLikeHeader(row) {
  let hit = 0;
  row.forEach((c) => {
    const h = String(c == null ? '' : c).trim().toLowerCase();
    if (!h || h.length > 12) return;
    if (/账号|编号|密码|邮箱|皮肤|商店|夜市|地区|备注|账号名/.test(h)) hit++;
  });
  return hit >= 2 || (hit === 1 && row.length <= 6 && /账号|编号/.test(String(row[0] || '')));
}

function mapHeader(row) {
  const map = {};
  const used = new Set();
  row.forEach((cell, i) => {
    const h = String(cell == null ? '' : cell).trim().toLowerCase().replace(/\s+/g, '');
    if (!h) return;
    for (const [key, keys] of COLS) {
      if (map[key] != null) continue;
      if (keys.some((k) => h.includes(k))) { map[key] = i; used.add(i); break; }
    }
  });
  return map;
}

function rowToRecord(row, map) {
  const g = (k) => {
    const i = map[k];
    if (i == null) return '';
    const v = row[i];
    return v == null ? '' : String(v).trim();
  };
  const id = g('id');
  if (!id) return null;
  const skinsRaw = g('skins') || g('night');
  const parsed = parseSkinCell(skinsRaw || '', g('prices'));
  let night = parsed.night;
  if (!night.length && g('night') && g('night') !== skinsRaw) {
    night = splitList(g('night'));
  }
  return {
    id,
    pwd: g('pwd'),
    email: g('email'),
    emailPwd: g('emailPwd'),
    region: g('region'),
    note: g('note'),
    daily: parsed.daily,
    night,
  };
}

function rowsToRecords(rows) {
  if (!rows || !rows.length) return [];
  let map, start = 0;
  if (looksLikeHeader(rows[0])) {
    map = mapHeader(rows[0]);
    start = 1;
    if (map.id == null) map.id = 0;
  } else {
    map = { id: 0, pwd: 1, email: 2, emailPwd: 3, skins: 4, prices: 5, region: 6, note: 7 };
  }
  const out = [];
  for (let i = start; i < rows.length; i++) {
    const row = rows[i];
    if (!row || row.every((c) => String(c == null ? '' : c).trim() === '')) continue;
    const rec = rowToRecord(row, map);
    if (rec) out.push(rec);
  }
  return out;
}

/* JSON 数组 → 记录（手动导入和在线 data.json 共用） */
function parseJsonRecords(arr) {
  return arr.map((o) => {
    if (typeof o === 'string') return { id: o, pwd: '', email: '', emailPwd: '', region: '', note: '', daily: [], night: [] };
    const p = parseSkinCell(o.skins || o.皮肤 || o.每日商店 || o.daily || '', o.prices || '');
    return {
      id: String(o.id || o.账号 || o.account || '').trim(),
      pwd: String(o.pwd || o.密码 || '').trim(),
      email: String(o.email || o.邮箱 || '').trim(),
      emailPwd: String(o.emailPwd || o.邮箱密码 || '').trim(),
      region: String(o.region || o.地区 || '').trim(),
      note: String(o.note || o.备注 || '').trim(),
      daily: p.daily,
      night: o.night && Array.isArray(o.night) ? o.night : p.night,
    };
  }).filter((r) => r.id);
}

/* ---------------------------------------------------------------- 导入 */
function mergeRecords(incoming) {
  const idx = new Map(state.records.map((r, i) => [norm(r.id), i]));
  let added = 0, updated = 0;
  incoming.forEach((r) => {
    const k = norm(r.id);
    const at = idx.get(k);
    if (at == null) {
      state.records.push(r);
      idx.set(k, state.records.length - 1);
      added++;
      return;
    }
    const old = state.records[at];
    old.pwd = r.pwd || old.pwd;
    old.email = r.email || old.email;
    old.emailPwd = r.emailPwd || old.emailPwd;
    old.region = r.region || old.region;
    old.note = r.note || old.note;
    if (r.daily.length) old.daily = r.daily;
    if (r.night.length) old.night = r.night;
    updated++;
  });
  return { added, updated };
}

async function importFile(file) {
  const ext = (file.name.split('.').pop() || '').toLowerCase();
  let records = [];

  if (ext === 'xlsx' || ext === 'xls') {
    const buf = await file.arrayBuffer();
    const wb = XLSX.read(buf, { type: 'array' });
    let best = [];
    wb.SheetNames.forEach((n) => {
      const rows = XLSX.utils.sheet_to_json(wb.Sheets[n], { header: 1, raw: false, defval: '' });
      if (rows.length > best.length) best = rows;
    });
    records = rowsToRecords(best);
  } else if (ext === 'json') {
    const j = JSON.parse(await file.text());
    if (j && j.ct && j.salt) {
      /* 加密数据包：只有老板能解 */
      if (state.role !== 'boss' || !BOSS_PASS) throw new Error('加密数据包要用老板密码登录后才能导入');
      const rows = await decryptPayload(BOSS_PASS, j);
      const arr = Array.isArray(rows) ? rows : (rows.records || []);
      records = parseJsonRecords(arr);
    } else {
      const arr = Array.isArray(j) ? j : (j.records || j.data || []);
      records = parseJsonRecords(arr);
    }
  } else {
    const txt = await file.text();
    const lines = txt.split(/\r?\n/).filter((l) => l.trim());
    if (!lines.length) throw new Error('文件是空的');
    const first = lines[0];
    let sep;
    if (first.includes('\t')) sep = /\t/;
    else if (first.includes(',')) sep = /\s*,\s*/;
    else if (/-{2,}/.test(first)) sep = /\s*-{2,}\s*/;
    else sep = /\s{2,}/;
    const rows = lines.map((l) => l.split(sep).map((c) => c.trim()));
    records = rowsToRecords(rows);
  }

  if (!records.length) throw new Error('没解析到账号，检查一下表头或列顺序');
  return mergeRecords(records);
}

async function doImport(file) {
  if (state.role === 'staff') { toast('员工身份不能导入数据'); return; }
  try {
    const { added, updated } = await importFile(file);
    saveData();
    state.shown = 0;
    render();
    toast(`导入完成：新增 ${added} 个，更新 ${updated} 个`);
  } catch (e) {
    toast('导入失败：' + (e && e.message ? e.message : e));
  }
}

/* ---------------------------------------------------------------- 存储 */
function loadData() {
  try {
    const j = JSON.parse(localStorage.getItem(LS_DATA) || '[]');
    if (!Array.isArray(j)) return [];
    return j.map((r) => ({
      id: String(r.id || ''),
      pwd: r.pwd || '',
      email: r.email || '',
      emailPwd: r.emailPwd || '',
      region: r.region || '',
      note: r.note || '',
      daily: Array.isArray(r.daily) ? r.daily : [],
      night: Array.isArray(r.night) ? r.night : [],
    })).filter((r) => r.id);
  } catch (e) { return []; }
}

function saveData() {
  try {
    localStorage.setItem(LS_DATA, JSON.stringify(state.records));
  } catch (e) {
    toast('浏览器存储写满了，数据可能没保存');
  }
}

/* ---------------------------------------------------------------- 渲染 */
const SCOPE_LABEL = { all: '全部账号', has: '有每日商店', night: '有夜市', empty: '无皮肤数据' };

function computeView() {
  let arr = state.records.slice();
  const q = state.q.trim().toLowerCase();
  if (q) {
    arr = arr.filter((r) =>
      r.id.toLowerCase().includes(q) ||
      (r.email || '').toLowerCase().includes(q) ||
      r.daily.some((s) => s.name.toLowerCase().includes(q)) ||
      r.night.some((s) => s.name.toLowerCase().includes(q))
    );
  }
  if (state.scope === 'has') arr = arr.filter((r) => r.daily.length);
  if (state.scope === 'night') arr = arr.filter((r) => r.night.length);
  if (state.scope === 'empty') arr = arr.filter((r) => !r.daily.length && !r.night.length);

  const cmp = (a, b) => a.id.localeCompare(b.id, 'zh', { numeric: true, sensitivity: 'base' });
  if (state.sort === 'id-asc') arr.sort(cmp);
  else if (state.sort === 'id-desc') arr.sort((a, b) => cmp(b, a));
  else if (state.sort === 'skins-desc') {
    arr.sort((a, b) => (b.daily.length + b.night.length) - (a.daily.length + a.night.length) || cmp(a, b));
  }
  return arr;
}

function skinLine(r) {
  if (!r.daily.length) return '<span class="empty-v">—</span>';
  return r.daily.map((s) => esc(s.name)).join('、');
}

/* 统一复制格式：账号---密码---邮箱---邮箱密码（缺哪项就跳过，不留空段） */
function copyLine(r) {
  return [r.id, r.pwd, r.email, r.emailPwd]
    .map((v) => (v == null ? '' : String(v).trim()))
    .filter(Boolean)
    .join('---');
}

function cardHTML(r) {
  const mail = state.role === 'staff'
    ? ''
    : `<div class="card-mail"><span class="tag">邮箱：</span>${r.email ? esc(r.email) : '<span class="empty-v">—</span>'}</div>`;
  const region = r.region ? `<div class="card-region">地区：${esc(r.region)}</div>` : '';
  const copyBtn = state.role === 'staff'
    ? '<button class="link-btn" data-act="copy">复制编号</button>'
    : '<button class="link-btn" data-act="copy">复制</button>';
  return `<article class="card" data-id="${esc(r.id)}">
    <div class="card-head">
      <div class="card-id">编号：<span class="mono">${esc(r.id)}</span></div>
      ${mail}
    </div>
    <div class="card-line"><b>每日商店：</b>${skinLine(r)}</div>
    <div class="card-foot">
      ${region}
      <div class="card-actions">
        ${copyBtn}
        <button class="link-btn view" data-act="view">查看图片</button>
      </div>
    </div>
  </article>`;
}

function render(reset = true) {
  state.view = computeView();
  $('#total').textContent = state.view.length;
  const q = state.q.trim();
  $('#filter-label').textContent = '当前筛选：' + SCOPE_LABEL[state.scope] + (q ? ` · 搜索「${q}」` : '');

  const list = $('#list');
  if (!state.records.length) {
    list.innerHTML = '';
    $('#empty').style.display = 'flex';
    $('#more').hidden = true;
    return;
  }
  $('#empty').style.display = 'none';

  if (state.shown === 0 || reset) state.shown = Math.min(PAGE, state.view.length);
  else state.shown = Math.min(state.shown + PAGE, state.view.length);

  const slice = state.view.slice(0, state.shown);
  list.innerHTML = slice.map(cardHTML).join('') ||
    '<div style="grid-column:1/-1;text-align:center;color:#8b939f;padding:40px 0">没有符合条件的账号</div>';
  $('#more').hidden = state.shown >= state.view.length;
}

function loadMore() {
  if (state.shown >= state.view.length) return;
  state.shown = Math.min(state.shown + PAGE, state.view.length);
  const list = $('#list');
  const from = list.querySelectorAll('.card').length;
  const add = state.view.slice(from, state.shown).map(cardHTML).join('');
  list.insertAdjacentHTML('beforeend', add);
  $('#more').hidden = state.shown >= state.view.length;
}

/* ---------------------------------------------------------------- 图片弹窗 */
const VP_ICON = `<svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="#fff" stroke-width="1.6"/><path d="M8 8l4 8 4-8" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

function tileHTML(s, isNight) {
  const hit = findSkin(s.name);
  const media = hit
    ? `<img loading="lazy" src="${esc(hit.i)}" alt="${esc(s.name)}" referrerpolicy="no-referrer">`
    : `<div class="noname">暂无图片</div>`;
  let priceTxt = '';
  if (s.price != null) {
    const disc = isNight && s.disc ? ` <em style="font-style:normal;opacity:.85">-${s.disc}%</em>` : '';
    priceTxt = `<div class="price">${VP_ICON}<span>${s.price}${disc}</span></div>`;
  }
  return `<div class="tile">${media}${priceTxt}<div class="name">${esc(s.name)}</div></div>`;
}

function openShot(rec) {
  const parts = [`编号：${rec.id}`];
  if (rec.region) parts.push(`地区：${rec.region}`);
  if (rec.emailPwd || rec.email) parts.push('送初邮');
  $('#shot-title').textContent = '商店信息　' + parts.join(' 、 ');

  $('#shot-daily').innerHTML = rec.daily.length
    ? rec.daily.map((s) => tileHTML(s, false)).join('')
    : '<div style="grid-column:1/-1;text-align:center;color:#9aa2ae;padding:26px 0">暂无商店数据</div>';

  const hasNight = rec.night.length > 0;
  $('#shot-night-title').hidden = !hasNight;
  $('#shot-night').innerHTML = hasNight ? rec.night.map((s) => tileHTML(s, true)).join('') : '';
  $('#shot-night-empty').hidden = hasNight;

  $('#shot-overlay').classList.add('show');
  document.body.style.overflow = 'hidden';

  const btn = $('#shot-copy');
  btn.onclick = async () => {
    const staff = state.role === 'staff';
    const ok = await copyText(staff ? rec.id : copyLine(rec));
    toast(ok ? (staff ? '已复制编号' : '已复制：账号---密码---邮箱---邮箱密码') : '复制失败，请手动选择');
  };
}

function closeShot() {
  $('#shot-overlay').classList.remove('show');
  document.body.style.overflow = '';
}

/* ---------------------------------------------------------------- 事件 */
function bind() {
  $('#btn-import').addEventListener('click', () => $('#file').click());
  $('#empty-import').addEventListener('click', () => $('#file').click());
  $('#file').addEventListener('change', (e) => {
    const f = e.target.files && e.target.files[0];
    if (f) doImport(f);
    e.target.value = '';
  });

  $('#btn-filter').addEventListener('click', () => $('#filter-overlay').classList.add('show'));
  $$('#filter-overlay [data-close]').forEach((b) =>
    b.addEventListener('click', () => $('#filter-overlay').classList.remove('show')));
  $('#filter-overlay').addEventListener('click', (e) => {
    if (e.target.id === 'filter-overlay') e.currentTarget.classList.remove('show');
  });

  const chipGroup = (sel, key) => {
    $$(sel + ' .chip').forEach((btn) => {
      btn.addEventListener('click', () => {
        $$(sel + ' .chip').forEach((b) => b.classList.remove('on'));
        btn.classList.add('on');
        state[key] = btn.dataset.v;
        state.shown = 0;
        render();
      });
    });
  };
  chipGroup('#f-scope', 'scope');
  chipGroup('#f-sort', 'sort');

  $('#f-reset').addEventListener('click', () => {
    state.scope = 'all';
    state.sort = 'id-asc';
    state.q = '';
    $('#q').value = '';
    $$('#f-scope .chip').forEach((b) => b.classList.toggle('on', b.dataset.v === 'all'));
    $$('#f-sort .chip').forEach((b) => b.classList.toggle('on', b.dataset.v === 'id-asc'));
    state.shown = 0;
    render();
    toast('已重置筛选');
  });

  $('#btn-clear').addEventListener('click', () => {
    if (!state.records.length) { toast('本来就没有数据'); return; }
    if (!confirm(`确定清空 ${state.records.length} 条数据？只清浏览器里的，原始表格不受影响。`)) return;
    state.records = [];
    saveData();
    state.shown = 0;
    render();
    toast('已清空');
  });

  let qTimer;
  $('#q').addEventListener('input', (e) => {
    clearTimeout(qTimer);
    const v = e.target.value;
    qTimer = setTimeout(() => {
      state.q = v;
      state.shown = 0;
      render();
    }, 160);
  });

  $('#list').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    const card = btn.closest('.card');
    const rec = state.records.find((r) => r.id === card.dataset.id);
    if (!rec) return;
    const act = btn.dataset.act;
    if (act === 'view') { openShot(rec); return; }
    if (act === 'copy') {
      const staff = state.role === 'staff';
      const ok = await copyText(staff ? rec.id : copyLine(rec));
      toast(ok ? (staff ? '已复制编号' : '已复制：账号---密码---邮箱---邮箱密码') : '复制失败，请手动选择');
    }
  });

  $('#shot-overlay').addEventListener('click', (e) => {
    if (e.target.id === 'shot-overlay' || e.target.closest('[data-close]')) closeShot();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeShot();
      $('#filter-overlay').classList.remove('show');
    }
  });

  $('#more-btn').addEventListener('click', loadMore);
  window.addEventListener('scroll', () => {
    if (state.shown >= state.view.length) return;
    if (window.innerHeight + window.scrollY > document.body.offsetHeight - 400) loadMore();
  }, { passive: true });

  // 拖拽导入
  let dragDepth = 0;
  const hint = $('#drop-hint');
  window.addEventListener('dragenter', (e) => {
    if (!e.dataTransfer || ![...e.dataTransfer.types].includes('Files')) return;
    dragDepth++;
    hint.classList.add('show');
  });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('dragleave', () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (!dragDepth) hint.classList.remove('show');
  });
  window.addEventListener('drop', (e) => {
    e.preventDefault();
    dragDepth = 0;
    hint.classList.remove('show');
    const f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) doImport(f);
  });
}

/* ---------------------------------------------------------------- 角色 / 权限 */
function applyRoleUI() {
  const boss = state.role === 'boss';
  const badge = $('#role-badge');
  badge.hidden = !state.role;
  if (state.role) {
    badge.textContent = boss ? '老板' : '员工';
    badge.className = 'role-badge ' + (boss ? 'boss' : 'staff');
  }
  $('#btn-logout').hidden = !state.role;
  $('#btn-import').hidden = !boss;
  $('#btn-clear').hidden = !boss;
  $('#empty-import').hidden = !boss;
  $$('.boss-only').forEach((b) => { b.hidden = !boss; });
}

/* 员工：拉在线员工包（不含密码），并在本地再清一遍敏感字段 */
async function syncStaff() {
  if (location.protocol === 'file:') return;
  try {
    const res = await fetch('data-staff.json?_=' + Date.now(), { cache: 'no-store' });
    if (!res.ok) return;
    const j = await res.json();
    if (Array.isArray(j.staffHashes) && j.staffHashes.length) staffHashes = j.staffHashes;
    const arr = Array.isArray(j) ? j : (j.records || j.data || []);
    const recs = parseJsonRecords(arr);
    if (!recs.length) return;
    mergeRecords(recs);
    state.records.forEach((r) => { r.pwd = ''; r.email = ''; r.emailPwd = ''; });
    saveData();
    state.shown = 0;
    render();
  } catch (e) { /* 没有员工包就先用本地缓存 */ }
}

async function tryLogin(pass) {
  const err = $('#login-err');
  const fail = () => {
    err.textContent = '密码不对，再试试';
    const box = $('.login-box');
    box.classList.remove('shake');
    void box.offsetWidth;
    box.classList.add('shake');
  };
  /* 老板验证：能解开加密包的密码才是老板密码（代码里没有老板密码哈希，扒不走） */
  let role = '';
  if (encPack) {
    try {
      const rows = await decryptPayload(pass, encPack);
      const arr = Array.isArray(rows) ? rows : (rows.records || []);
      const recs = parseJsonRecords(arr);
      if (recs.length) {
        role = 'boss';
        const { added } = mergeRecords(recs);
        saveData();
        if (added) toast(`在线数据已同步：新增 ${added} 个账号`);
      }
    } catch (e) { /* 解密失败 = 不是老板密码 */ }
  }
  if (!role) {
    const h = await sha256Hex(pass);
    if (location.protocol === 'file:' && FILE_BOSS_HASH === h) role = 'boss';
    else if (staffHashes.includes(h) || staffLocalHashes.includes(h)) role = 'staff';
  }
  if (!role) { fail(); return; }
  err.textContent = '';
  state.role = role;
  sessionStorage.setItem(LS_ROLE, role);
  if (role === 'boss') BOSS_PASS = pass;
  applyRoleUI();
  $('#login-overlay').classList.add('hide');
  if (role === 'staff') await syncStaff();
  state.shown = 0;
  render();
}

/* 老板导出数据包（用来同步：发回来重新发布，或自己本地导入） */
function rowsFromRecords() {
  const skinStr = (list, isNight) => list.map((s) => {
    let t = s.name || '';
    if (s.price != null) t += `(${s.price}VP${isNight && s.disc ? '/' + s.disc + '%' : ''})`;
    return t;
  }).join('、');
  return state.records.map((r) => ({
    账号: r.id, 密码: r.pwd, 邮箱: r.email, 邮箱密码: r.emailPwd,
    皮肤: skinStr(r.daily, false), 夜市: skinStr(r.night, true),
    地区: r.region, 备注: r.note,
  }));
}

function downloadJSON(name, obj) {
  const blob = new Blob([JSON.stringify(obj)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}

/* ---- 员工密码（老板本机管理，支持备注 / 修改 / 删除） ---- */
let skEditing = -1; // 正在编辑的行号，-1 表示没有

function staffEntries() {
  try {
    const raw = JSON.parse(localStorage.getItem(LS_STAFF_PASSES) || 'null');
    if (Array.isArray(raw)) {
      return raw
        .map((it) => (typeof it === 'string'
          ? { p: it, n: '' }
          : { p: String(it && it.p || ''), n: String(it && it.n || '') }))
        .filter((it) => it.p);
    }
  } catch (e) { /* 忽略坏数据 */ }
  return [];
}
function saveStaffEntries(list) {
  localStorage.setItem(LS_STAFF_PASSES, JSON.stringify(list));
}
async function refreshStaffHashes() {
  staffLocalHashes = await Promise.all(staffEntries().map((it) => sha256Hex(it.p)));
}
function renderStaffKeys() {
  const ul = $('#sk-list');
  const list = staffEntries();
  if (!list.length) {
    ul.innerHTML = '<li class="sk-empty">还没有员工密码，员工现在无法登录</li>';
    return;
  }
  ul.innerHTML = list.map((it, i) => {
    if (i === skEditing) {
      return `<li class="sk-row editing">
        <input class="sk-en" data-i="${i}" value="${esc(it.n)}" placeholder="备注" autocomplete="off">
        <input class="sk-ep" data-i="${i}" value="${esc(it.p)}" placeholder="密码" autocomplete="off">
        <button class="sk-save" data-i="${i}">保存</button>
        <button class="sk-cancel" data-i="${i}">取消</button>
      </li>`;
    }
    return `<li class="sk-row">
      <span class="sk-name">${it.n ? esc(it.n) : '<i class="sk-noname">未备注</i>'}</span>
      <b>${esc(it.p)}</b>
      <span class="sk-ops">
        <button class="sk-edit" data-i="${i}">修改</button>
        <button class="sk-del" data-i="${i}">删除</button>
      </span>
    </li>`;
  }).join('');
  if (skEditing >= 0) {
    const inp = $('.sk-ep', ul);
    if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
  }
}
function addStaffPass() {
  const passInp = $('#sk-input');
  const noteInp = $('#sk-note');
  const p = passInp.value.trim();
  const n = noteInp.value.trim();
  if (!p) { toast('先输入密码再点添加'); return; }
  const list = staffEntries();
  if (list.some((it) => it.p === p)) { toast('这个密码已经存在'); return; }
  list.push({ p, n });
  saveStaffEntries(list);
  passInp.value = '';
  noteInp.value = '';
  refreshStaffHashes();
  renderStaffKeys();
  toast('已添加（本机立即生效，线上要重新导出发布）');
}
function editStaffPass(i, note, pass) {
  const list = staffEntries();
  const cur = list[i];
  if (!cur) return;
  const p = (pass || '').trim();
  if (!p) { toast('密码不能为空'); return; }
  if (list.some((it, k) => k !== i && it.p === p)) { toast('这个密码和其他员工重复了'); return; }
  list[i] = { p, n: (note || '').trim() };
  saveStaffEntries(list);
  skEditing = -1;
  refreshStaffHashes();
  renderStaffKeys();
  toast('已修改（外发要重新导出员工包）');
}
function delStaffPass(i) {
  const list = staffEntries();
  const it = list[i];
  if (!it) return;
  list.splice(i, 1);
  saveStaffEntries(list);
  skEditing = -1;
  refreshStaffHashes();
  renderStaffKeys();
  toast(`已删除${it.n ? ' ' + it.n : ''}，导出员工包重新发布后生效`);
}

function bindAuth() {
  const doLogin = () => {
    const v = $('#login-pass').value.trim();
    if (v) tryLogin(v);
  };
  $('#login-btn').addEventListener('click', doLogin);
  $('#login-pass').addEventListener('keydown', (e) => { if (e.key === 'Enter') doLogin(); });
  $('#login-pass').addEventListener('input', () => { $('#login-err').textContent = ''; });

  $('#btn-logout').addEventListener('click', () => {
    sessionStorage.removeItem(LS_ROLE);
    BOSS_PASS = '';
    location.reload();
  });

  $('#btn-export-enc').addEventListener('click', async () => {
    if (!BOSS_PASS) { toast('请退出后用老板密码重新登录一次再导出'); return; }
    downloadJSON('data-enc.json', await encryptPayload(BOSS_PASS, rowsFromRecords()));
    toast('已导出 data-enc.json（老板加密包）');
  });
  $('#btn-export-staff').addEventListener('click', async () => {
    await refreshStaffHashes();
    downloadJSON('data-staff.json', {
      staffHashes: staffLocalHashes,
      records: state.records.map((r) => ({
        账号: r.id,
        皮肤: rowsFromRecordsSkinOnly(r.daily),
        夜市: rowsFromRecordsSkinOnly(r.night),
        地区: r.region,
      })),
    });
    toast('已导出 data-staff.json（员工包，含最新员工密码）');
  });

  /* ---- 员工密码管理（老板专用） ---- */
  $('#btn-staff-keys').addEventListener('click', () => {
    renderStaffKeys();
    $('#staffkeys-overlay').classList.add('show');
  });
  $$('#staffkeys-overlay [data-close]').forEach((b) =>
    b.addEventListener('click', () => $('#staffkeys-overlay').classList.remove('show')));
  $('#staffkeys-overlay').addEventListener('click', (e) => {
    if (e.target.id === 'staffkeys-overlay') e.currentTarget.classList.remove('show');
  });
  $('#sk-add').addEventListener('click', addStaffPass);
  $('#sk-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') addStaffPass(); });
  $('#sk-note').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#sk-input').focus(); });
  /* 列表内：修改 / 删除 / 保存 / 取消（事件委托，重绘后依然有效） */
  $('#sk-list').addEventListener('click', (e) => {
    const t = e.target.closest('button');
    if (!t) return;
    const i = +t.dataset.i;
    if (t.classList.contains('sk-edit')) {
      skEditing = i;
      renderStaffKeys();
    } else if (t.classList.contains('sk-del')) {
      delStaffPass(i);
    } else if (t.classList.contains('sk-save')) {
      const li = t.closest('li');
      editStaffPass(i, $('.sk-en', li).value, $('.sk-ep', li).value);
    } else if (t.classList.contains('sk-cancel')) {
      skEditing = -1;
      renderStaffKeys();
    }
  });
  $('#sk-list').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.target.classList.contains('sk-ep')) {
      const li = e.target.closest('li');
      editStaffPass(+e.target.dataset.i, $('.sk-en', li).value, e.target.value);
    }
    if (e.key === 'Escape') { skEditing = -1; renderStaffKeys(); }
  });
  $('#sk-restore').addEventListener('click', () => {
    localStorage.setItem(LS_STAFF_PASSES, JSON.stringify([]));
    skEditing = -1;
    refreshStaffHashes();
    renderStaffKeys();
    toast('已清空全部员工密码，导出员工包重新发布后员工将无法登录');
  });
}
function rowsFromRecordsSkinOnly(list) {
  return list.map((s) => {
    let t = s.name || '';
    if (s.price != null) t += `(${s.price}VP${s.disc ? '/' + s.disc + '%' : ''})`;
    return t;
  }).join('、');
}

/* ---------------------------------------------------------------- 启动 */
(async () => {
  state.records = loadData();
  bind();
  bindAuth();
  refreshStaffHashes();
  /* 启动时拉在线数据包：加密包（验证老板密码 + 数据源）和员工包（员工密码哈希） */
  if (location.protocol !== 'file:') {
    try {
      const r1 = await fetch('data-enc.json?_=' + Date.now(), { cache: 'no-store' });
      if (r1.ok) encPack = await r1.json();
    } catch (e) { /* 没有在线包就只用本地数据 */ }
    try {
      const res = await fetch('data-staff.json?_=' + Date.now(), { cache: 'no-store' });
      if (res.ok) {
        const j = await res.json();
        if (Array.isArray(j.staffHashes) && j.staffHashes.length) staffHashes = j.staffHashes;
      }
    } catch (e) { /* 没有在线包就用默认（空）员工密码 */ }
  }
  state.role = sessionStorage.getItem(LS_ROLE) || '';
  if (state.role) {
    applyRoleUI();
    $('#login-overlay').classList.add('hide');
    if (state.role === 'staff') await syncStaff();
    /* 老板刷新页面：密码不存盘，直接用本地缓存，不重新解密 */
  }
  render();
  initSkinDB();
})();
