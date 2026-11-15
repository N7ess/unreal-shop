/* UnrEal 初始号 — 前端逻辑
 * 数据全部存浏览器 localStorage，不上传任何服务器。
 * 皮肤图片走 valorant-api 官方 CDN，名字→图片的映射离线内置一份。
 */

const LS_DATA = 'unreal_shop_data_v1';
const LS_DB = 'unreal_shop_db_v1';
const LS_ROLE = 'unreal_shop_role_v1';
const LS_STAFF_PASSES = 'unreal_shop_staff_passes_v1'; // 老板设备上的员工密码明文清单（仅本机）
const LS_REMEMBER = 'unreal_shop_remember_v1'; // 记住密码（仅存本机 localStorage，勾选后下次自动登录）
const LS_STAFF_NAME = 'unreal_shop_staff_name_v1'; // 当前员工备注（用于顶栏徽章显示）
const LS_DATA_DATE = 'unreal_shop_data_date_v1'; // 每日商店数据所属日期（YYYY-MM-DD），过了凌晨 0 点自动失效
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

/* ---- 云端同步（网站自带 /api 接口，Cloudflare Pages Function + KV）----
 * 老板上传数据 / 增删员工密码 → 立即写进云端仓库；
 * 员工登录 → 自动从云端拉最新数据与密码哈希。
 * 老板身份验证：浏览器里用老板密码派生一个令牌（PBKDF2），服务器只存令牌，密码永不上传。 */
let bossSalt = '';          // 服务端下发的盐值（公开）
let cloudStaffHashes = [];  // 云端生效的员工密码哈希（老板面板增删改都以它为准同步）
let cloudStaffKeys = [];    // 云端的 {h, n} 列表：哈希 + 备注（员工登录后徽章显示自己的备注）
let staffName = '';         // 当前员工登录用的密码对应的备注
let dataDate = '';          // 当前这批每日商店数据属于哪一天；与今天不同 = 已过期（整表清空）
let cloudDataDate = '';      // 云端数据包的上传日期（dataUpdated 派生），清过缓存的设备也能正确判断过期

async function apiSync(path, body, authHex) {
  const opt = { cache: 'no-store' };
  if (body) {
    opt.method = 'POST';
    opt.headers = { 'Content-Type': 'application/json' };
    opt.body = JSON.stringify(body);
  }
  if (authHex) { opt.headers = Object.assign(opt.headers || {}, { 'X-Auth': authHex }); }
  const res = await fetch('api' + path, opt);
  const j = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((j && j.error) || ('HTTP ' + res.status));
  return j;
}

async function syncAuthHex(pass) {
  if (!bossSalt) return '';
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: new TextEncoder().encode('unreal-sync-' + bossSalt), iterations: ENC_ITER, hash: 'SHA-256' },
    base, 256);
  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function bossCloudUpload(allowEmpty) {
  if (location.protocol === 'file:' || !bossSalt) return;
  if (!BOSS_PASS) { toast('请先退出登录，再用老板密码重新登录一次（刷新后密码不保留），才能同步云端'); return; }
  try {
    const auth = await syncAuthHex(BOSS_PASS);
    const enc = await encryptPayload(BOSS_PASS, rowsFromRecords());
    const staff = {
      date: dataDate || dayKey(),
      records: state.records.map((r) => ({
        账号: r.id, 皮肤: rowsFromRecordsSkinOnly(r.daily), 夜市: rowsFromRecordsSkinOnly(r.night), 地区: r.region,
      })),
    };
    const r = await apiSync('/boss/upload', { enc, staff, allowEmpty: !!allowEmpty }, auth);
    toast('已同步到云端（' + r.updated.slice(0, 16).replace('T', ' ') + '），员工下次登录即可看到最新数据');
  } catch (e) {
    toast('云端同步失败：' + (e.message || e) + '（本机数据已保存）');
  }
}

async function syncStaffKeysToCloud(msg, allowEmpty) {
  if (location.protocol === 'file:' || !bossSalt) return;
  if (!BOSS_PASS) { toast('请先退出登录，再用老板密码重新登录一次，员工密码才能同步到云端'); return; }
  try {
    const auth = await syncAuthHex(BOSS_PASS);
    /* 本机清单（带备注）+ 云端已有 的并集一起同步：换设备也能一键找回全部员工密码 */
    const map = new Map();
    (cloudStaffKeys || []).forEach((k) => { if (k && k.h) map.set(k.h, { h: k.h, n: k.n || '' }); });
    const locals = staffEntries();
    const localH = await Promise.all(locals.map((it) => it.h || sha256Hex(it.p)));
    locals.forEach((it, i) => {
      const h = localH[i];
      if (!h) return;
      const old = map.get(h);
      map.set(h, { h, n: (it.n || (old && old.n) || '') });
    });
    const keys = [...map.values()];
    await apiSync('/boss/staff-keys', { keys, allowEmpty: !!allowEmpty }, auth);
    cloudStaffKeys = keys.slice();
    cloudStaffHashes = keys.map((k) => k.h);
    staffHashes = cloudStaffHashes.slice();
    toast(msg || '员工密码已同步到云端，员工立即生效');
  } catch (e) {
    toast('云端同步员工密码失败：' + (e.message || e) + '（本机仍生效）');
  }
}

/* ---------------------------------------------------------------- 每日商店按天失效 */
/* 每天过凌晨 0 点，每日商店/夜市自动清空显示；账号、密码、邮箱、员工密码全部保留。
   原始数据不真删（万一哪天忘了导入还能找回），只在显示层置空；导入新数据后自动覆盖。 */
function dayKey(d) {
  const t = d || new Date();
  const p = (n) => String(n).padStart(2, '0');
  return t.getFullYear() + '-' + p(t.getMonth() + 1) + '-' + p(t.getDate());
}

function setDataDate(v) {
  dataDate = v || '';
  try { localStorage.setItem(LS_DATA_DATE, dataDate); } catch (e) { /* 存不下就只在本会话生效 */ }
}

function isDataExpired() { return !!dataDate && dataDate !== dayKey(); }

function maskRec(r) {
  if (!r) return r;
  if (!isDataExpired()) return r;
  return {
    id: r.id, pwd: r.pwd, email: r.email, emailPwd: r.emailPwd,
    region: r.region, note: r.note, daily: [], night: [],
  };
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

async function importFile(file, resetSkins) {
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
  /* 跨天导入：新表就是当天全量，直接整表替换（昨天的账号/皮肤一条不留） */
  if (resetSkins) {
    state.records = [];
    state.shown = 0;
  }
  return mergeRecords(records);
}

async function doImport(file) {
  if (state.role === 'staff') { toast('员工身份不能导入数据'); return; }
  const newDay = dataDate !== dayKey();
  try {
    const { added, updated } = await importFile(file, newDay);
    setDataDate(dayKey());
    saveData();
    state.shown = 0;
    render();
    toast(`导入完成：新增 ${added} 个，更新 ${updated} 个`);
    if (state.role === 'boss') await bossCloudUpload();
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
  if (isDataExpired()) return [];   /* 过凌晨 0 点：整张列表清空（账号/密码/邮箱一起不显示），等新数据导入 */
  let arr = state.records.map(maskRec);
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
  const notice = $('#day-notice');
  if (notice) {
    const exp = isDataExpired();
    notice.hidden = !exp;
    if (exp) {
      const d = dataDate.slice(5);
      notice.innerHTML = `数据已过期（数据日期 <b>${esc(d)}</b>）—— 已过凌晨 0 点，数据已自动清空，等待今日数据导入。`;
    }
  }
  state.view = computeView();
  $('#total').textContent = state.view.length;
  const q = state.q.trim();
  $('#filter-label').textContent = '当前筛选：' + SCOPE_LABEL[state.scope] + (q ? ` · 搜索「${q}」` : '');

  const list = $('#list');
  if (isDataExpired()) {
    list.innerHTML = '<div class="day-empty">数据过期自动清除<br>等待新数据上传</div>';
    $('#empty').style.display = 'none';
    $('#more').hidden = true;
    return;
  }
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
    if (!confirm(`危险操作！将删除全部 ${state.records.length} 个账号，员工立即看不到任何数据，且不可恢复。确定要清空吗？`)) return;
    if (!confirm('再次确认：真的要清空全部数据吗？（这是最后一次确认）')) return;
    state.records = [];
    saveData();
    state.shown = 0;
    render();
    toast('已清空');
    bossCloudUpload(true);
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
    const found = state.records.find((r) => r.id === card.dataset.id);
    if (!found) return;
    const rec = maskRec(found);
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
    badge.textContent = boss ? '老板' : (staffName || '员工');
    badge.className = 'role-badge ' + (boss ? 'boss' : 'staff');
  }
  $('#btn-logout').hidden = !state.role;
  $('#btn-import').hidden = !boss;
  $('#btn-clear').hidden = !boss;
  $('#empty-import').hidden = !boss;
  $$('.boss-only').forEach((b) => { b.hidden = !boss; });
}

/* 员工：优先拉云端最新员工包（不含密码），本地再清一遍敏感字段；云端不可达时退回静态文件 */
async function syncStaff() {
  if (location.protocol === 'file:') return;
  let j = null;
  try {
    const r = await fetch('api/data/staff', { cache: 'no-store' });
    if (r.ok) j = await r.json();
  } catch (e) { /* 云端不可达 */ }
  if (!j) {
    try {
      const r = await fetch('data-staff.json?_=' + Date.now(), { cache: 'no-store' });
      if (r.ok) j = await r.json();
    } catch (e) { /* 没有员工包就先用本地缓存 */ }
  }
  if (!j) return;
  const arr = Array.isArray(j) ? j : (j.records || j.data || []);
  const recs = parseJsonRecords(arr);
  if (!recs.length) return;
  const packDate = (!Array.isArray(j) && j && j.date) ? String(j.date) : '';
  if (packDate && packDate !== dataDate) {
    /* 云端已经是新一天的包：清掉本机昨天的商店数据，再合并 */
    state.records.forEach((r) => { r.daily = []; r.night = []; });
    setDataDate(packDate);
  }
  mergeRecords(recs);
  state.records.forEach((r) => { r.pwd = ''; r.email = ''; r.emailPwd = ''; });
  saveData();
  state.shown = 0;
  render();
}

/* 按密码哈希找备注：先查云端下发列表，再查老板本机清单 */
async function staffNameFor(h) {
  if (!h) return '';
  const c = (cloudStaffKeys || []).find((k) => k && k.h === h);
  if (c && c.n) return c.n;
  const locals = staffEntries();
  for (const it of locals) {
    const ih = it.h || await sha256Hex(it.p);
    if (ih === h) return it.n || '';
  }
  return c ? c.n || '' : '';
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
  /* 老板验证：能解开加密包的密码才是老板密码（代码里没有老板密码哈希，扒不走）
     注意：清空数据后云端是空包（[]），解开也能成功 —— 只要解密没抛错就算老板，否则空包期老板会被当成密码错误 */
  let role = '';
  if (encPack) {
    try {
      const rows = await decryptPayload(pass, encPack);
      role = 'boss';
      const arr = Array.isArray(rows) ? rows : (rows.records || []);
      const recs = parseJsonRecords(arr);
      if (recs.length) {
        const { added } = mergeRecords(recs);
        saveData();
        if (!dataDate) setDataDate(cloudDataDate || dayKey()); /* 首次拿到的数据按云端包日期算，不清缓存也能正确判断过期 */
        if (added) toast(`在线数据已同步：新增 ${added} 个账号`);
      }
    } catch (e) { /* 解密失败 = 不是老板密码 */ }
  }
  let loginHash = '';
  if (!role) {
    const h = await sha256Hex(pass);
    loginHash = h;
    if (location.protocol === 'file:' && FILE_BOSS_HASH === h) role = 'boss';
    else if (staffHashes.includes(h) || staffLocalHashes.includes(h)) role = 'staff';
  }
  if (!role) { fail(); return; }
  err.textContent = '';
  /* 员工：查出这个密码对应的备注，顶栏徽章直接显示名字 */
  if (role === 'staff') {
    staffName = await staffNameFor(loginHash);
    if (staffName) sessionStorage.setItem(LS_STAFF_NAME, staffName);
    else sessionStorage.removeItem(LS_STAFF_NAME);
  } else {
    staffName = '';
    sessionStorage.removeItem(LS_STAFF_NAME);
  }
  /* 记住密码：勾选则存本机，下次自动登录；没勾就清掉旧记录 */
  const rmb = $('#remember-pass');
  if (rmb && rmb.checked) localStorage.setItem(LS_REMEMBER, pass);
  else localStorage.removeItem(LS_REMEMBER);
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

/* ---- 员工密码（老板管理，支持备注 / 修改 / 删除，改动自动同步云端） ---- */
let skEditing = -1; // 正在编辑的行号，-1 表示没有

function staffEntries() {
  try {
    const raw = JSON.parse(localStorage.getItem(LS_STAFF_PASSES) || 'null');
    if (Array.isArray(raw)) {
      return raw
        .map((it) => (typeof it === 'string'
          ? { p: it, n: '', h: '' }
          : { p: String(it && it.p || ''), n: String(it && it.n || ''), h: String(it && it.h || '') }))
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
async function renderStaffKeys() {
  const ul = $('#sk-list');
  const list = staffEntries();
  /* 补算缺失的哈希缓存（旧数据兼容），并写回 */
  let dirty = false;
  for (const it of list) {
    if (!it.h) { it.h = await sha256Hex(it.p); dirty = true; }
  }
  if (dirty) saveStaffEntries(list);
  const localHs = list.map((it) => it.h);
  const cloudOnly = cloudStaffHashes.filter((h) => !localHs.includes(h));
  if (!list.length && !cloudOnly.length) {
    ul.innerHTML = '<li class="sk-empty">还没有员工密码，员工现在无法登录</li>';
    return;
  }
  const localRows = list.map((it, i) => {
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
  });
  const cloudRows = cloudOnly.map((h) =>
    `<li class="sk-row">
      <span class="sk-name"><i class="sk-noname">云端密码（本机无明文）</i></span>
      <b>${h.slice(0, 10)}…</b>
      <span class="sk-ops">
        <button class="sk-del" data-h="${h}">删除</button>
      </span>
    </li>`);
  ul.innerHTML = localRows.join('') + cloudRows.join('');
  if (skEditing >= 0) {
    const inp = $('.sk-ep', ul);
    if (inp) { inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
  }
}
async function addStaffPass() {
  const passInp = $('#sk-input');
  const noteInp = $('#sk-note');
  const p = passInp.value.trim();
  const n = noteInp.value.trim();
  if (!p) { toast('先输入密码再点添加'); return; }
  const list = staffEntries();
  if (list.some((it) => it.p === p)) { toast('这个密码已经存在'); return; }
  const h = await sha256Hex(p);
  if (!cloudStaffHashes.includes(h)) cloudStaffHashes.push(h);
  list.push({ p, n, h });
  saveStaffEntries(list);
  passInp.value = '';
  noteInp.value = '';
  refreshStaffHashes();
  renderStaffKeys();
  syncStaffKeysToCloud('已添加：本机生效，员工密码已同步云端，员工立即可用');
}
async function editStaffPass(i, note, pass) {
  const list = staffEntries();
  const cur = list[i];
  if (!cur) return;
  const p = (pass || '').trim();
  if (!p) { toast('密码不能为空'); return; }
  if (list.some((it, k) => k !== i && it.p === p)) { toast('这个密码和其他员工重复了'); return; }
  const oldH = cur.h || (await sha256Hex(cur.p));
  const newH = await sha256Hex(p);
  /* 云端哈希列表同步更新：旧哈希移除、新哈希加入 */
  cloudStaffHashes = cloudStaffHashes.filter((h) => h !== oldH);
  if (!cloudStaffHashes.includes(newH)) cloudStaffHashes.push(newH);
  list[i] = { p, n: (note || '').trim(), h: newH };
  saveStaffEntries(list);
  skEditing = -1;
  refreshStaffHashes();
  renderStaffKeys();
  syncStaffKeysToCloud('已修改：旧密码立即失效，新密码立即生效（已同步云端）');
}
async function delStaffPass(i) {
  const list = staffEntries();
  const it = list[i];
  if (!it) return;
  const oldH = it.h || (await sha256Hex(it.p));
  cloudStaffHashes = cloudStaffHashes.filter((h) => h !== oldH);
  list.splice(i, 1);
  saveStaffEntries(list);
  skEditing = -1;
  refreshStaffHashes();
  renderStaffKeys();
  syncStaffKeysToCloud(`已删除${it.n ? ' ' + it.n : ''}：该密码已同步云端立即失效`);
}
async function delCloudHash(h) {
  cloudStaffHashes = cloudStaffHashes.filter((x) => x !== h);
  cloudStaffKeys = (cloudStaffKeys || []).filter((k) => k.h !== h);
  refreshStaffHashes();
  renderStaffKeys();
  syncStaffKeysToCloud('已删除云端密码：该密码立即失效');
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
    sessionStorage.removeItem(LS_STAFF_NAME);
    localStorage.removeItem(LS_REMEMBER); /* 退出即清除记住的密码 */
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
    /* 云端哈希行（本机无明文）：按哈希删除 */
    if (t.dataset.h) { delCloudHash(t.dataset.h); return; }
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
    if (!confirm('危险操作！将删除全部员工密码，所有员工立即无法登录。确定要清空吗？')) return;
    localStorage.setItem(LS_STAFF_PASSES, JSON.stringify([]));
    skEditing = -1;
    cloudStaffHashes = [];
    cloudStaffKeys = [];
    staffHashes = [];
    refreshStaffHashes();
    renderStaffKeys();
    syncStaffKeysToCloud('已清空全部员工密码，并同步云端：所有员工立即无法登录', true);
  });
  $('#sk-sync').addEventListener('click', () => {
    syncStaffKeysToCloud('已把本机员工密码全部同步到云端，员工立即可以登录');
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
  dataDate = localStorage.getItem(LS_DATA_DATE) || '';
  if (!dataDate && state.records.length && location.protocol === 'file:') setDataDate(dayKey());
  bind();
  bindAuth();
  refreshStaffHashes();
  /* 启动时：先拉云端配置（盐值 + 员工密码哈希），再拉最新加密数据包；静态文件作兜底 */
  if (location.protocol !== 'file:') {
    try {
      const cfg = await apiSync('/config');
      if (cfg.bossSalt) bossSalt = cfg.bossSalt;
      if (cfg.dataUpdated) cloudDataDate = String(cfg.dataUpdated).slice(0, 10);
      if (Array.isArray(cfg.staffKeys)) {
        cloudStaffKeys = cfg.staffKeys
          .filter((k) => k && typeof k.h === 'string')
          .map((k) => ({ h: k.h, n: String(k.n || '') }));
      }
      if (Array.isArray(cfg.staffHashes)) {
        cloudStaffHashes = cfg.staffHashes.slice();
        staffHashes = cfg.staffHashes.slice();
        if (!cloudStaffKeys.length) cloudStaffKeys = cloudStaffHashes.map((h) => ({ h, n: '' }));
      }
    } catch (e) { /* 云端不可达，退回静态包 */ }
    if (!encPack) {
      try { const r1 = await fetch('api/data/enc', { cache: 'no-store' }); if (r1.ok) encPack = await r1.json(); } catch (e) { /* 略 */ }
    }
    if (!encPack) {
      try { const r1 = await fetch('data-enc.json?_=' + Date.now(), { cache: 'no-store' }); if (r1.ok) encPack = await r1.json(); } catch (e) { /* 没有在线包就只用本地数据 */ }
    }
    if (!dataDate && state.records.length) setDataDate(cloudDataDate || dayKey());
    if (!staffHashes.length) {
      try {
        const res = await fetch('data-staff.json?_=' + Date.now(), { cache: 'no-store' });
        if (res.ok) {
          const j = await res.json();
          if (Array.isArray(j.staffHashes) && j.staffHashes.length) staffHashes = j.staffHashes;
        }
      } catch (e) { /* 没有员工包就保持空（员工无法登录） */ }
    }
  }
  state.role = sessionStorage.getItem(LS_ROLE) || '';
  staffName = sessionStorage.getItem(LS_STAFF_NAME) || '';
  if (state.role) {
    applyRoleUI();
    $('#login-overlay').classList.add('hide');
    if (state.role === 'staff') await syncStaff();
    /* 老板刷新页面：密码不存盘，直接用本地缓存，不重新解密 */
  } else {
    /* 记住密码：本机存过密码就自动登录 */
    const saved = localStorage.getItem(LS_REMEMBER) || '';
    if (saved) {
      const rmb = $('#remember-pass');
      if (rmb) rmb.checked = true;
      $('#login-pass').value = saved;
      tryLogin(saved);
    }
  }
  render();
  initSkinDB();
  watchDayChange();
})();

/* 页面一直开着也要在过 0 点时自动清空：每 20 秒对一次日期，切回前台也查一次 */
function watchDayChange() {
  let cur = dayKey();
  const tick = () => {
    const now = dayKey();
    if (now === cur) return;
    cur = now;
    render();
    if (isDataExpired()) toast('已过凌晨 0 点：数据已自动清空，等今日数据导入');
  };
  setInterval(tick, 20000);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) tick(); });
}
