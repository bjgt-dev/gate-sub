#!/usr/bin/env python3
"""gate-sub 富集任务：为 VPN Gate SSTP 候选 IP 生成 ip-quality.json。

数据源：
- VPN Gate 官方 API（api/iphone）：候选 IP 列表（proto tcp 过滤，与 Worker 一致）
- ipquery.io 免费 API（无 key）：risk.is_datacenter/is_vpn/is_proxy/is_tor/risk_score，
  location.country_code，isp.asn/isp

策略：
- 已有条目且 updated 在 72h 内：跳过（IP 信誉变化慢，省配额）
- 429/失败：立即停止查询，保留已有数据（永不重试循环，不拿 ban 换数据）
- 无数据不编造：查不到的 IP 不写条目（Worker 侧显示"未知"）
- 输出按 IP 排序的 JSON；同时打印分布摘要供人工审核（采样门）
"""
import csv, io, json, sys, time, base64, re
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

VPNGATE_API = "https://www.vpngate.net/api/iphone/"
IPQUERY = "https://api.ipquery.io/{ip}?format=json"
OUT = "ip-quality.json"
MAX_NEW = 60          # 每次最多新查 60 个 IP
TTL_HOURS = 72        # 条目有效期
REQ_DELAY = 1.2       # 查询间隔（秒），礼貌限速
TIMEOUT = 15

def fetch(url):
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (gate-sub enrich)"})
    with urlopen(req, timeout=TIMEOUT) as r:
        return r.read().decode("utf-8", "replace")

def candidate_ips():
    text = fetch(VPNGATE_API).lstrip("\ufeff")
    if len(text) < 1000:
        raise RuntimeError(f"上游返回过短（{len(text)} 字节），可能被拒")
    reader = csv.DictReader(io.StringIO(text))
    # 表头形如 "#HostName"，做规范化
    fields = {k: k for k in (reader.fieldnames or [])}
    def col(*names):
        for k in reader.fieldnames:
            nk = k.strip().lstrip("#").lstrip("*").lower()
            if nk in names: return k
        return None
    c_host, c_ip = col("hostname"), col("ip")
    c_cc = col("countryshort")
    c_cfg = col("openvpn_configdata_base64") or next(
        (k for k in reader.fieldnames if "base64" in k.lower()), reader.fieldnames[-1])
    ips, seen = [], set()
    for row in reader:
        ip = (row.get(c_ip) or "").strip()
        if not ip or ip in seen: continue
        try:
            cfg = base64.b64decode((row.get(c_cfg) or "").strip()).decode("utf-8", "replace")
        except Exception:
            continue
        if not re.search(r"^proto\s+(tcp|tcp4|tcp6)\b", cfg, re.M):
            continue
        seen.add(ip)
        ips.append(ip)
        if len(ips) >= MAX_NEW * 2:  # 多取一点，优先查已有条目之外的
            break
    return ips

def main():
    try:
        with open(OUT) as f: old = json.load(f)
    except Exception:
        old = {}
    now = datetime.now(timezone.utc)
    now_s = now.isoformat(timespec="seconds")
    fresh = {}
    for ip, v in old.items():
        try:
            upd = datetime.fromisoformat(v.get("updated", "1970-01-01T00:00:00+00:00"))
            if (now - upd).total_seconds() < TTL_HOURS * 3600:
                fresh[ip] = v
        except Exception:
            pass
    try:
        ips = candidate_ips()
    except Exception as e:
        print(f"上游抓取失败: {e}，保留 {len(fresh)} 条旧数据")
        ips = []
    todo = [ip for ip in ips if ip not in fresh][:MAX_NEW]
    print(f"候选 {len(ips)} IP，{len(fresh)} 条仍新鲜，本次新查 {len(todo)} 个")
    stopped = False
    for ip in todo:
        try:
            d = json.loads(fetch(IPQUERY.format(ip=ip)))
        except HTTPError as e:
            print(f"  {ip}: HTTP {e.code}，停止查询")
            stopped = True
            break
        except Exception as e:
            print(f"  {ip}: 失败 {e}，跳过")
            continue
        risk, loc, isp = d.get("risk") or {}, d.get("location") or {}, d.get("isp") or {}
        fresh[ip] = {
            "dc": bool(risk.get("is_datacenter")),
            "vpn": bool(risk.get("is_vpn")),
            "proxy": bool(risk.get("is_proxy")),
            "tor": bool(risk.get("is_tor")),
            "risk": risk.get("risk_score") if isinstance(risk.get("risk_score"), int) else None,
            "cc": (loc.get("country_code") or "").upper() or None,
            "asn": isp.get("asn") or None,
            "isp": isp.get("isp") or isp.get("org") or None,
            "updated": now_s,
        }
        time.sleep(REQ_DELAY)
    out = {ip: fresh[ip] for ip in sorted(fresh)}
    with open(OUT, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    # 分布摘要（采样门：哪个字段无区分度就砍哪个）
    n = len(out)
    dc = sum(1 for v in out.values() if v["dc"])
    vpn = sum(1 for v in out.values() if v["vpn"])
    proxy = sum(1 for v in out.values() if v["proxy"])
    tor = sum(1 for v in out.values() if v["tor"])
    scores = [v["risk"] for v in out.values() if isinstance(v["risk"], int)]
    print(f"==== 分布（共 {n} 条）====")
    print(f"datacenter: {dc} ({dc/n*100:.1f}%)" if n else "datacenter: 0")
    print(f"is_vpn: {vpn} ({vpn/n*100:.1f}%)" if n else "is_vpn: 0")
    print(f"is_proxy: {proxy} ({proxy/n*100:.1f}%)" if n else "is_proxy: 0")
    print(f"is_tor: {tor} ({tor/n*100:.1f}%)" if n else "is_tor: 0")
    if scores:
        s = sorted(scores)
        print(f"risk_score: min={s[0]} p50={s[len(s)//2]} max={s[-1]}")
    if stopped:
        print("注意：因 429/错误提前停止，下次运行继续")
    print(f"已写入 {OUT}（{n} 条）")

if __name__ == "__main__":
    main()
