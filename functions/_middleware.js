/* 安全中间件：屏蔽不该公开的文件（明文数据包、脚本、配置、含令牌的 bat）
   这些文件留在本地用于生成/上传，但不允许任何人通过网址直接下载。
   例外：/data-staff.json 是旧版缓存页面拉取员工数据的通道 —— 直接回当前云端
   KV 数据（不含密码字段），保证老设备不换代码也能实时同步。 */
const BLOCK_PATHS = [
  '/data-enc.json',
  '/wrangler.toml',
  '/生成网站数据.py',
  '/更新网站.bat',
  '/打开网站.bat',
  '/使用说明.txt',
];
const BLOCK_EXT = /\.(bat|py|toml|json)$/i;   // 除接口外，任何 .json/.bat/.py/.toml 一律不对外

export async function onRequest(context) {
  const url = new URL(context.request.url);
  let p = url.pathname;
  try { p = decodeURIComponent(p); } catch (e) { /* 保持原样 */ }

  /* 旧版页面兼容通道：员工数据实时下发（KV = 云端最新，含日期与员工密码哈希） */
  if (p === '/data-staff.json') {
    try {
      const staff = await context.env.SHOP.get('data:staff');
      if (staff) {
        const hashes = await context.env.SHOP.get('staff:hashes');
        let pack = {};
        try { pack = JSON.parse(staff); } catch (e) { /* 原样返回 */ }
        if (hashes && !pack.staffHashes) {
          try { pack.staffHashes = JSON.parse(hashes); } catch (e) { /* 略 */ }
        }
        return new Response(JSON.stringify(pack), {
          headers: {
            'content-type': 'application/json; charset=utf-8',
            'cache-control': 'no-store',
          },
        });
      }
    } catch (e) { /* KV 不可达时落到下面的 404 */ }
  }

  if (BLOCK_PATHS.includes(p) || BLOCK_EXT.test(p)) {
    return new Response('Not Found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  }
  return context.next();
}
