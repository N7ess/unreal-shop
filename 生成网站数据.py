# -*- coding: utf-8 -*-
"""
生成网站数据（每日同步用）
用法：
  python 生成网站数据.py [某个.xlsx]
  不带参数时自动用 ValStore 数据目录里的 账密.xlsx

输出（写到本网站目录）：
  data-enc.json   老板加密包（AES-256-GCM，密码 060213 才能解开，含账号/密码/邮箱/邮箱密码/皮肤）
  data-staff.json 员工包（明文但不含密码/邮箱，只有 编号/皮肤/夜市/地区）

生成后把这两个文件随网站一起重新发布即可同步。
"""
import sys, os, json, base64, glob, datetime

SITE_DIR = os.path.dirname(os.path.abspath(__file__))
BOSS_PASS = "060213"          # 老板密码，改口令时这里同步改
ENC_ITER = 150000             # 与网页 app.js 的 ENC_ITER 一致，别动
DEFAULT_SOURCES = [
    r"D:\UnrEal商店助手(源文件)\数据\账密.xlsx",
    r"D:\UnrEal商店助手(源文件)\查询结果",
]

HEAD_MAP = {
    "id": ["账号", "编号", "账号名", "用户名"],
    "pwd": ["密码", "password"],
    "email": ["邮箱"],
    "email_pwd": ["邮箱密码"],
    "skins": ["皮肤", "每日商店", "今日商店", "商店"],
    "night": ["夜市"],
    "region": ["地区", "区服", "大区"],
    "note": ["备注"],
}

def read_rows(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in (".xlsx", ".xls"):
        import openpyxl
        wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
        ws = wb.active
        return [[("" if c is None else str(c).strip()) for c in r] for r in ws.iter_rows(values_only=True)]
    if ext == ".csv":
        import csv
        with open(path, encoding="utf-8-sig", errors="ignore") as f:
            return [[c.strip() for c in row] for row in csv.reader(f)]
    raise SystemExit("只支持 xlsx / csv")

def col_map(header):
    m = {}
    for i, h in enumerate(header):
        h = h.strip().lower().replace(" ", "")
        for key, names in HEAD_MAP.items():
            if key in m:
                continue
            if h in [n.lower() for n in names]:
                m[key] = i
    return m

def build(path):
    rows = read_rows(path)
    rows = [r for r in rows if any(str(c).strip() for c in r)]
    if not rows:
        raise SystemExit("表是空的")
    header = [str(c).strip() for c in rows[0]]
    hit = sum(1 for h in header if any(h and any(h.lower() == n.lower() for n in ns) for ns in HEAD_MAP.values()))
    if hit >= 2:
        m, start = col_map(header), 1
        m.setdefault("id", 0)
    else:
        m = {"id": 0, "pwd": 1, "email": 2, "email_pwd": 3, "skins": 4}
        start = 1

    def get(r, k):
        i = m.get(k)
        return ("" if i is None or i >= len(r) else str(r[i]).strip())

    full, staff, seen = [], [], set()
    for r in rows[start:]:
        acc = get(r, "id")
        if not acc or acc.lower() in seen:
            continue
        seen.add(acc.lower())
        full.append({
            "账号": acc,
            "密码": get(r, "pwd"),
            "邮箱": get(r, "email"),
            "邮箱密码": get(r, "email_pwd"),
            "皮肤": get(r, "skins"),
            "夜市": get(r, "night"),
            "地区": get(r, "region"),
            "备注": get(r, "note"),
        })
        staff.append({
            "账号": acc,
            "皮肤": get(r, "skins"),
            "夜市": get(r, "night"),
            "地区": get(r, "region"),
        })
    return full, staff

def encrypt(obj, password):
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(16)
    iv = os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ENC_ITER)
    key = kdf.derive(password.encode("utf-8"))
    ct = AESGCM(key).encrypt(iv, json.dumps(obj, ensure_ascii=False).encode("utf-8"), None)
    b64 = lambda b: base64.b64encode(b).decode()
    return {"v": 1, "kdf": f"PBKDF2-SHA256-{ENC_ITER}", "salt": b64(salt), "iv": b64(iv), "ct": b64(ct)}

def pick_source():
    if len(sys.argv) > 1:
        return sys.argv[1]
    cand = []
    for p in DEFAULT_SOURCES:
        if os.path.isfile(p):
            cand.append(p)
        elif os.path.isdir(p):
            xs = sorted(glob.glob(os.path.join(p, "*.xlsx")), key=os.path.getmtime)
            cand.extend(xs[-3:])
    if not cand:
        raise SystemExit("没找到数据文件，把 xlsx 路径当参数传进来")
    return max(cand, key=os.path.getmtime)

def main():
    src = pick_source()
    full, staff = build(src)
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    enc = encrypt({"records": full, "updated": stamp}, BOSS_PASS)
    with open(os.path.join(SITE_DIR, "data-enc.json"), "w", encoding="utf-8") as f:
        json.dump(enc, f, ensure_ascii=False)
    with open(os.path.join(SITE_DIR, "data-staff.json"), "w", encoding="utf-8") as f:
        json.dump({
            "records": staff,
            "updated": stamp,
            # 员工密码哈希由老板在网页「员工密码」里设置后点「导出员工包」生成，
            # 这里保持为空 = 员工密码未设置，员工无法登录
            "staffHashes": [],
        }, f, ensure_ascii=False)
    print(f"来源: {src}")
    print(f"账号数: {len(full)}")
    print(f"已写 data-enc.json（{os.path.getsize(os.path.join(SITE_DIR,'data-enc.json'))//1024} KB，老板密码解密）")
    print(f"已写 data-staff.json（{os.path.getsize(os.path.join(SITE_DIR,'data-staff.json'))//1024} KB，无密码）")

if __name__ == "__main__":
    main()
