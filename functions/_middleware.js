/* 安全中间件：屏蔽不该公开的文件（明文数据包、脚本、配置、含令牌的 bat）
   这些文件留在本地用于生成/上传，但不允许任何人通过网址直接下载。 */
const BLOCK_PATHS = [
  '/data-staff.json',
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
  if (BLOCK_PATHS.includes(p) || BLOCK_EXT.test(p)) {
    return new Response('Not Found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  }
  return context.next();
}
