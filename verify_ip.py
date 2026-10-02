#!/usr/bin/env python3
"""住宅 IP 验证逻辑（v3-final，双顾问已评审：ChatGPT 无否决 / Claude 无否决）。

可独立集成到 update_sub.py 的 check_node()，替换现有简单检测。
仅依赖 Python 标准库（urllib + socket），无第三方包。

用法：
    from verify_ip import classify_ip, load_asn_table

    table = load_asn_table()          # 启动时加载一次（3/3 上游表，失败回退本地）
    r = classify_ip("36.13.8.195", table)
    # r = {"net": "residential", "reason": {...}}
    # 判定标准（宁缺毋滥）：只有 net == "residential" 的才能进订阅；
    # datacenter / unknown 一律淘汰。

判定逻辑（三态）：
  datacenter  = ASN 在 hosting 表 或 hostname 命中机房词（vpngate/vps/cloud/datacenter/hosting）
  residential = 双信号：ASN 不在 hosting 表 且 hostname 命中住宅词（ppp/dsl/cable/fiber/fibre/dyn/bb/residential）
  unknown     = 其余一切（IPv6 / 移动网 / 学术网 / ASN 为空 / 无 PTR / 单信号 / 信息不足）
"""

import json
import re
import socket
import hashlib
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from datetime import datetime, timezone
from urllib.request import Request, urlopen

ASN_TABLE_URLS = [
    "https://raw.githubusercontent.com/danielnavcom/bad-asn-list-1/master/all.txt",
    "https://raw.githubusercontent.com/on13uka/ip-geolocation-api/main/data/hosting-asns.json",
    "https://raw.githubusercontent.com/Mizarka/scraper-blacklist/master/hosting-asn.txt",
]
LOCAL_ASN_TABLE = "hosting-asn.local.txt"  # 与本文件同目录
ASN_TABLE_MAX_AGE_DAYS = 30

IPQUERY = "https://api.ipquery.io/{ip}?format=json"
IPWHOIS = "https://ipwho.is/{ip}"
IPINFO = "https://ipinfo.io/{ip}/json"

TIMEOUT = 15
PTR_TIMEOUT = 8

RESIDENTIAL_WORDS = ["ppp", "dsl", "cable", "fiber", "fibre", "dyn", "bb", "residential"]
RESIDENTIAL_RE = re.compile(r"(?<![a-z0-9])(?:%s)" % "|".join(RESIDENTIAL_WORDS))
DATACENTER_WORDS = ["vpngate", "vps", "cloud", "datacenter", "hosting"]
DATACENTER_RE = re.compile(r"(?<![a-z0-9])(?:%s)(?![a-z0-9])" % "|".join(DATACENTER_WORDS))


def _now_s():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fetch(url, timeout=TIMEOUT):
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (gate-sub verify)"})
    with urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def norm_asn(raw):
    """'AS15169' / 15169 / '15169' -> '15169'；无效 -> None。"""
    if raw is None:
        return None
    s = str(raw).strip().upper()
    if s.startswith("AS"):
        s = s[2:].strip()
    return s if s.isdigit() else None


def load_asn_table(local_path=LOCAL_ASN_TABLE):
    """加载合并 hosting-ASN 表。3/3 上游成功才用；否则回退本地（age<=30天）；
    都不可用抛 RuntimeError（调用方 fail-closed）。返回 set（元素为无前缀数字字符串）。"""
    merged = set()
    ok = 0
    for url in ASN_TABLE_URLS:
        try:
            text = _fetch(url)
            if url.endswith(".json"):
                d = json.loads(text)
                nums = set()
                for p in d.get("providers", {}).values():
                    for a in p.get("asns", []):
                        n = norm_asn(a)
                        if n:
                            nums.add(n)
            else:
                nums = set()
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"^(?:AS)?(\d+)\b", line, re.I)
                    if m:
                        nums.add(m.group(1))
            if len(nums) < 100:
                raise RuntimeError(f"表过小（{len(nums)}）")
            merged |= nums
            ok += 1
        except Exception:
            continue
    if ok == 3:
        try:
            with open(local_path, "w") as f:
                f.write("\n".join(sorted(merged, key=int)) + "\n")
        except Exception:
            pass
        return merged
    # 回退本地
    try:
        with open(local_path) as f:
            local = {n for n in (norm_asn(l) for l in f) if n}
        import os, time
        age_days = (time.time() - os.path.getmtime(local_path)) / 86400
        if len(local) < 100 or age_days > ASN_TABLE_MAX_AGE_DAYS:
            raise RuntimeError(f"本地表不可用（{len(local)} 条，{age_days:.0f} 天）")
        return local
    except Exception as e:
        raise RuntimeError(f"ASN 表不可用（上游 {ok}/3）：{e}")


def _get_asn_geo(ip):
    """返回 (asn_int_or_None, extra_dict, geo_dict)。双源都失败抛 RuntimeError。"""
    raw = None
    try:
        d = json.loads(_fetch(IPQUERY.format(ip=ip)))
        raw = d
    except Exception:
        try:
            d = json.loads(_fetch(IPWHOIS.format(ip=ip)))
            raw = d
        except Exception as e:
            raise RuntimeError(f"ASN 查询双源失败: {e}")
    isp = raw.get("isp") or {}
    conn = raw.get("connection") or {}
    loc = raw.get("location") or {}
    n = norm_asn(isp.get("asn")) or norm_asn(conn.get("asn"))
    risk = raw.get("risk") or {}
    extra = {
        "is_mobile": bool(risk.get("is_mobile")),
        "org": isp.get("org") or isp.get("isp") or conn.get("org") or conn.get("isp") or "",
    }
    geo = {
        "cc": ((loc.get("country_code") or raw.get("country_code") or "").upper() or None),
        "isp": (isp.get("isp") or isp.get("org") or conn.get("isp") or conn.get("org") or None),
    }
    return (int(n) if n else None), extra, geo


def _get_hostname(ip):
    """PTR 反查，失败备用 ipinfo.io；都失败返回 None（本层弃权）。"""
    def _ptr():
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            h = ex.submit(_ptr).result(timeout=PTR_TIMEOUT)
        if h:
            return h
    except Exception:
        pass
    try:
        d = json.loads(_fetch(IPINFO.format(ip=ip), timeout=10))
        h = (d.get("hostname") or "").strip()
        return h or None
    except Exception:
        return None


def _hostname_signal(ptr):
    if not ptr:
        return None, None
    low = ptr.lower()
    m = DATACENTER_RE.search(low)
    if m:
        return "datacenter", m.group(0)
    m = RESIDENTIAL_RE.search(low)
    if m:
        return "residential", m.group(0)
    return None, None


def classify_ip(ip, asn_table=None):
    """验证单个 IP。返回 {"net": "residential"|"datacenter"|"unknown",
    "reason": {...}, "asn": int|None, "cc": str|None, "isp": str|None}。

    asn_table：load_asn_table() 的结果；None 时自动加载（带进程内缓存）。
    只有 net == "residential" 才能进订阅。
    """
    global _TABLE_CACHE
    try:
        _TABLE_CACHE
    except NameError:
        _TABLE_CACHE = None
    table = asn_table if asn_table is not None else _TABLE_CACHE
    if table is None:
        table = load_asn_table()
        _TABLE_CACHE = table

    at = _now_s()
    base = {"asn": None, "cc": None, "isp": None}
    if ":" in ip:
        return {"net": "unknown", "reason": {"unknown_sub": "ipv6", "at": at}, **base}

    try:
        asn, extra, geo = _get_asn_geo(ip)
    except RuntimeError as e:
        return {"net": "unknown",
                "reason": {"unknown_sub": "transport-failed", "error": str(e), "at": at},
                **base}
    base.update(asn=asn, cc=geo["cc"], isp=geo["isp"])

    in_list = str(asn) in table if asn is not None else False
    if in_list:
        return {"net": "datacenter",
                "reason": {"asn": {"asn": asn, "in_hosting_list": True, "at": at}},
                **base}

    ptr = _get_hostname(ip)
    sig, matched = _hostname_signal(ptr)
    if sig == "datacenter":
        return {"net": "datacenter",
                "reason": {"asn": {"asn": asn, "in_hosting_list": False, "at": at},
                           "hostname": {"ptr": ptr, "signal": sig, "matched": matched, "at": at}},
                **base}
    if extra.get("is_mobile"):
        return {"net": "unknown", "reason": {"unknown_sub": "mobile", "at": at}, **base}
    org = (extra.get("org") or "").lower()
    if re.search(r"universit|college|academy|\.edu\b", org):
        return {"net": "unknown",
                "reason": {"unknown_sub": "academic", "org": extra.get("org"), "at": at},
                **base}
    if asn is not None and not in_list and sig == "residential":
        return {"net": "residential",
                "reason": {"asn": {"asn": asn, "in_hosting_list": False, "at": at},
                           "hostname": {"ptr": ptr, "signal": sig, "matched": matched, "at": at}},
                **base}
    sub = "asn-missing" if asn is None else ("no-ptr" if ptr is None else "insufficient")
    return {"net": "unknown",
            "reason": {"asn": {"asn": asn, "in_hosting_list": False, "at": at},
                       "hostname": {"ptr": ptr, "signal": sig, "matched": matched, "at": at},
                       "unknown_sub": sub},
            **base}


if __name__ == "__main__":
    import sys
    table = load_asn_table()
    print(f"ASN 表 {len(table)} 条")
    for ip in sys.argv[1:] or ["219.100.37.239", "36.13.8.195"]:
        r = classify_ip(ip, table)
        print(f"{ip} -> {r['net']} {json.dumps(r['reason'], ensure_ascii=False)[:160]}")
