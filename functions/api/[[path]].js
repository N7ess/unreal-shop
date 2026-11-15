/* UnrEal 商店云端同步 API（Pages Function，挂载在 /api/*）
 * - GET  /api/config          公开：boss 盐值 + 员工密码哈希列表 + 数据更新时间
 * - GET  /api/data/enc        公开：老板加密数据包（AES-256-GCM，无密钥解不开）
 * - GET  /api/data/staff      公开：员工剪版数据（无密码字段）
 * - POST /api/boss/auth       老板令牌验证（X-Auth = PBKDF2(老板密码) 的 hex，密码不出浏览器）
 * - POST /api/boss/upload     老板上传数据（enc + staff 两份）
 * - POST /api/boss/staff-keys 老板设置员工密码哈希列表
 */
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,X-Auth',
  'Access-Control-Max-Age': '86400',
};
const J = (o, s = 200) =>
  new Response(JSON.stringify(o), { status: s, headers: { ...CORS, 'Content-Type': 'application/json; charset=utf-8' } });

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
  const url = new URL(request.url);
  const p = url.pathname.replace(/^\/api/, '') || '/';
  try {
    if (p === '/' || p === '') return J({ name: 'unreal91-sync', ok: true });

    if (p === '/config' && request.method === 'GET') {
      const [salt, hashes, keys, updated] = await Promise.all([
        env.SHOP.get('boss:salt'),
        env.SHOP.get('staff:hashes'),
        env.SHOP.get('staff:keys'),
        env.SHOP.get('data:updated'),
      ]);
      const hashList = hashes ? JSON.parse(hashes) : [];
      let keyList = keys ? JSON.parse(keys) : [];
      if (!Array.isArray(keyList)) keyList = [];
      /* 老数据只有哈希没有备注时，用哈希列表兜底 */
      if (!keyList.length && hashList.length) keyList = hashList.map((h) => ({ h, n: '' }));
      return J({
        bossSalt: salt || '',
        staffHashes: hashList.length ? hashList : keyList.map((k) => k.h),
        staffKeys: keyList,
        dataUpdated: updated || '',
      });
    }

    if (p === '/data/enc' && request.method === 'GET') {
      const v = await env.SHOP.get('data:enc');
      if (!v) return J({ error: '暂无数据' }, 404);
      return new Response(v, { headers: { ...CORS, 'Content-Type': 'application/json' } });
    }
    if (p === '/data/staff' && request.method === 'GET') {
      const v = await env.SHOP.get('data:staff');
      if (!v) return J({ error: '暂无数据' }, 404);
      return new Response(v, { headers: { ...CORS, 'Content-Type': 'application/json' } });
    }

    const auth = request.headers.get('X-Auth') || '';
    const token = await env.SHOP.get('boss:token');
    if (!token) return J({ error: '服务未初始化' }, 500);

    if (p === '/boss/auth' && request.method === 'POST') {
      return J({ ok: auth === token });
    }

    if (auth !== token) return J({ error: '没有权限' }, 401);

    if (p === '/boss/upload' && request.method === 'POST') {
      const b = await request.json();
      if (!b.enc || !b.staff) return J({ error: '数据不完整' }, 400);
      /* 防误触：空数据包必须显式带 allowEmpty 才写入，防止一键把云端清空 */
      const recs = (b.staff && Array.isArray(b.staff.records)) ? b.staff.records : [];
      if (!recs.length && !b.allowEmpty) return J({ error: '拦截：这次上传的数据是空的。如果确实要清空，请在网页里再确认一次' }, 400);
      const stamp = new Date().toISOString();
      await env.SHOP.put('data:enc', JSON.stringify(b.enc));
      await env.SHOP.put('data:staff', JSON.stringify(b.staff));
      await env.SHOP.put('data:updated', stamp);
      return J({ ok: true, updated: stamp, count: recs.length });
    }

    if (p === '/boss/staff-keys' && request.method === 'POST') {
      const b = await request.json();
      const okHex = (h) => typeof h === 'string' && /^[0-9a-f]{64}$/.test(h);
      /* 兼容两种入参：keys=[{h,n}] 带备注；hashes=[hex] 老格式 */
      let keys = [];
      if (Array.isArray(b.keys)) {
        keys = b.keys.filter((k) => k && okHex(k.h)).map((k) => ({ h: k.h, n: String(k.n || '').slice(0, 24) }));
      } else if (Array.isArray(b.hashes)) {
        keys = b.hashes.filter(okHex).map((h) => ({ h, n: '' }));
      } else {
        return J({ error: '参数错误' }, 400);
      }
      /* 去重（同一个哈希只留一条） */
      const seen = new Set();
      keys = keys.filter((k) => (seen.has(k.h) ? false : (seen.add(k.h), true)));
      /* 防误触：清空全部员工密码必须显式带 allowEmpty */
      if (!keys.length && !b.allowEmpty) return J({ error: '拦截：这次要同步的员工密码是空的。如果确实要清空全部密码，请在网页里再确认一次' }, 400);
      await env.SHOP.put('staff:keys', JSON.stringify(keys));
      await env.SHOP.put('staff:hashes', JSON.stringify(keys.map((k) => k.h)));
      return J({ ok: true, count: keys.length });
    }

    return J({ error: 'not found' }, 404);
  } catch (e) {
    return J({ error: String((e && e.message) || e) }, 500);
  }
}
