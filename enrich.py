#!/usr/bin/env python3
"""gate-sub 富集任务 v2：为 VPN Gate SSTP 候选 IP 判定 residential/datacenter/unknown。

规格：~/workspace/gate-deploy/residential-spec-v3-final.md（双顾问已评审）

判定管线（per IP）：
  L1 ASN：ipquery.io isp.asn（备用 ipwho.is connection.asn）对照合并 hosting-ASN 静态表
  L2 hostname：PTR 反查（socket，备用 ipinfo.io），住宅词/机房词启发式
  综合：datacenter = L1 命中 或 L2 机房词；residential = 双信号（L1 非 hosting 且 L2 住宅词）；
        其余 unknown。不在表里 != residential（单信号只能 unknown）。

关键规则：
  - 防抖不对称：淘汰（->datacenter/unknown）立即生效；放行（->residential）需产出结论的轮次连续 2 次一致（7 天 wall-clock 上限）。
  - verdict TTL 90 天；冻结上限 7 天（自 verdict_at 起 wall-clock），超限按 unknown 处理 + 升级告警。
  - 失败按 IP 隔离；整批不下结论仅当表不可用/双源全挂（fail-closed）。
  - overrides.json 人工名单优先级最高（allow 必须有过期时间）。
"""
import csv, io, json, sys, time, base64, re, socket, hashlib
from datetime import datetime, timezone, timedelta
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

VPNGATE_API = "https://www.vpngate.net/api/iphone/"
IPQUERY = "https://api.ipquery.io/{ip}?format=json"
IPWHOIS = "https://ipwho.is/{ip}"
IPINFO = "https://ipinfo.io/{ip}/json"
OUT = "ip-quality.json"
OVERRIDES = "overrides.json"
LOCAL_ASN_TABLE = "hosting-asn.local.txt"

ASN_TABLE_URLS = [
    "https://raw.githubusercontent.com/danielnavcom/bad-asn-list-1/master/all.txt",
    "https://raw.githubusercontent.com/on13uka/ip-geolocation-api/main/data/hosting-asns.json",
    "https://raw.githubusercontent.com/Mizarka/scraper-blacklist/master/hosting-asn.txt",
]
ASN_TABLE_MAX_AGE_DAYS = 30
VERDICT_TTL_DAYS = 90
FREEZE_CAP_DAYS = 7
STALE_META_WARN_DAYS = 3
REQ_DELAY = 1.2
TIMEOUT = 15
PTR_TIMEOUT = 8
MAX_IPS = 200  # 每轮最多判定 IP 数（覆盖全量列表 80 行绰绰有余）

# hostname 启发式词表（v3-final：host 已移出机房词；机房词用词边界匹配）
RESIDENTIAL_WORDS = ["ppp", "dsl", "cable", "fiber", "dyn", "bb", "residential"]
DATACENTER_WORDS = ["vpngate", "vps", "cloud", "datacenter", "hosting"]
DATACENTER_RE = re.compile(r"(?<![a-z0-9])(?:%s)(?![a-z0-9])" % "|".join(DATACENTER_WORDS))

now = datetime.now(timezone.utc)
now_s = now.isoformat(timespec="seconds")
ALERTS = []


def alert(msg):
    ALERTS.append(msg)
    print(f"  [ALERT] {msg}")


def fetch(url, timeout=TIMEOUT):
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (gate-sub enrich)"})
    with urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def norm_asn(raw):
    """ASN 归一化：'AS15169'/15169/'15169' -> '15169'；无效 -> None。"""
    if raw is None:
        return None
    s = str(raw).strip().upper().lstrip("AS").strip()
    return s if s.isdigit() else None


def load_asn_table():
    """拉取 3 个上游表并合并。quorum：3/3 成功才用；否则回退本地表（age<=30d）；
    都不可用 -> fail-closed（抛错，整批不下结论）。返回 (set_of_asn_str, version_info)。"""
    merged, versions = set(), []
    ok = 0
    for url in ASN_TABLE_URLS:
        try:
            text = fetch(url)
            if url.endswith(".json"):
                d = json.loads(text)
                provs = d.get("providers", {})
                nums = set()
                for p in provs.values():
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
            # schema 校验：非空且行数>100
            if len(nums) < 100:
                raise RuntimeError(f"表过小（{len(nums)}），疑似损坏")
            merged |= nums
            versions.append({"url": url, "count": len(nums),
                             "sha256": hashlib.sha256(text.encode()).hexdigest()[:16]})
            ok += 1
        except Exception as e:
            print(f"  ASN 表拉取失败 {url}: {e}")
    if ok == 3:
        # 写本地缓存
        with open(LOCAL_ASN_TABLE, "w") as f:
            f.write("\n".join(sorted(merged, key=int)) + "\n")
        return merged, {"source": "upstream", "tables": versions,
                        "merged": len(merged), "at": now_s}
    # 回退本地
    try:
        with open(LOCAL_ASN_TABLE) as f:
            local = {n for n in (norm_asn(l) for l in f) if n}
        import os
        age_days = (now - datetime.fromtimestamp(os.path.getmtime(LOCAL_ASN_TABLE),
                                                 tz=timezone.utc)).days
        if len(local) < 100 or age_days > ASN_TABLE_MAX_AGE_DAYS:
            raise RuntimeError(f"本地表不可用（{len(local)} 条，{age_days} 天）")
        print(f"  上游表 {ok}/3，回退本地表（{len(local)} 条，{age_days} 天前）")
        return local, {"source": "local-fallback", "merged": len(local),
                       "age_days": age_days, "at": now_s}
    except Exception as e:
        raise RuntimeError(f"ASN 表不可用（上游 {ok}/3，本地回退失败：{e}），fail-closed")


def get_asn(ip):
    """返回 (asn_int_or_None, transport_ok)。transport 失败抛 TransportError；
    成功返回但 ASN 为空 -> (None, True)（数据缺失，走 unknown 结论）。"""
    # 主源 ipquery.io
    try:
        d = json.loads(fetch(IPQUERY.format(ip=ip)))
        isp = d.get("isp") or {}
        n = norm_asn(isp.get("asn"))
        return (int(n) if n else None), True, d
    except HTTPError as e:
        if e.code == 429:
            raise TransportError(f"ipquery 429")
        # 非 429 的 HTTP 错误也算传输失败，试备用
    except Exception:
        pass
    # 备用 ipwho.is
    try:
        d = json.loads(fetch(IPWHOIS.format(ip=ip)))
        conn = d.get("connection") or {}
        n = norm_asn(conn.get("asn"))
        return (int(n) if n else None), True, d
    except Exception as e:
        raise TransportError(f"双源 ASN 查询失败: {e}")


class TransportError(Exception):
    pass


def get_hostname(ip):
    """PTR 反查；失败 -> 备用 ipinfo.io；都失败 -> None（本层弃权，非传输失败）。"""
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
    except FuturesTimeout:
        pass
    except Exception:
        pass
    try:
        d = json.loads(fetch(IPINFO.format(ip=ip), timeout=10))
        h = (d.get("hostname") or "").strip()
        return h or None
    except Exception:
        return None


def hostname_signal(ptr):
    """返回 'residential' / 'datacenter' / None（弃权）。住宅词优先级最高。"""
    if not ptr:
        return None, None
    low = ptr.lower()
    for w in RESIDENTIAL_WORDS:
        if w in low:
            return "residential", w
    m = DATACENTER_RE.search(low)
    if m:
        return "datacenter", m.group(0)
    return None, None


def classify(ip, asn, asn_in_list, ptr):
    """返回 (net, reason_dict)。不抛错（调用方保证输入有效）。"""
    sig, matched = hostname_signal(ptr)
    reason = {
        "asn": {"asn": asn, "in_hosting_list": bool(asn_in_list), "at": now_s},
        "hostname": {"ptr": ptr, "signal": sig, "matched": matched, "at": now_s},
    }
    if asn_in_list or sig == "datacenter":
        return "datacenter", reason
    if asn is not None and not asn_in_list and sig == "residential":
        return "residential", reason
    # unknown 子原因（供 breakdown）
    if asn is None:
        sub = "asn-missing"
    elif ptr is None:
        sub = "no-ptr"
    elif sig is None and not asn_in_list:
        sub = "single-signal" if sig == "residential" or True else "no-signal"
        # 更精确：住宅词未命中且 ASN 未命中 -> 信息不足
        sub = "insufficient"
    else:
        sub = "insufficient"
    reason["unknown_sub"] = sub
    return "unknown", reason


def load_overrides():
    try:
        with open(OVERRIDES) as f:
            return json.load(f)
    except Exception:
        return {}


def override_for(ip, overrides):
    o = overrides.get(ip)
    if not o:
        return None
    exp = o.get("expires")
    if exp:
        try:
            if datetime.fromisoformat(exp) < now:
                return None
        except Exception:
            return None
    net = o.get("net")
    if net not in ("residential", "datacenter"):
        return None
    return net, {"override": {"by": o.get("by"), "why": o.get("why"),
                             "at": o.get("at"), "expires": exp}}


def val(row, key):
    if not key:
        return ""
    v = row.get(key)
    if isinstance(v, list):
        v = "".join(v)
    return (v or "").strip()


def candidate_ips():
    text = fetch(VPNGATE_API).lstrip("\ufeff")
    if len(text) < 1000:
        raise RuntimeError(f"上游返回过短（{len(text)} 字节），可能被拒")
    lines = text.splitlines()
    hi = next((i for i, l in enumerate(lines)
               if l.strip().lstrip("#").startswith("HostName")), None)
    if hi is None:
        raise RuntimeError("无表头")
    reader = csv.DictReader(io.StringIO("\n".join(lines[hi:])))
    if not reader.fieldnames:
        raise RuntimeError("表头解析失败")

    def col(*names):
        for k in reader.fieldnames:
            nk = k.strip().lstrip("#").lstrip("*").lower()
            if nk in names:
                return k
        return None
    c_ip = col("ip")
    c_cfg = col("openvpn_configdata_base64") or next(
        (k for k in reader.fieldnames if "base64" in k.lower()), reader.fieldnames[-1])
    ips, seen = [], set()
    for row in reader:
        ip = val(row, c_ip)
        if not ip or ip == "*" or ip in seen:
            continue
        try:
            cfg = base64.b64decode(val(row, c_cfg)).decode("utf-8", "replace")
        except Exception:
            continue
        if not re.search(r"^proto\s+(tcp|tcp4|tcp6)\b", cfg, re.M):
            continue
        seen.add(ip)
        ips.append(ip)
        if len(ips) >= MAX_IPS:
            break
    return ips


def apply_debounce(old, new_net, reason):
    """不对称防抖。返回 (net, verdict_at, streak)。old 为旧条目或 None。"""
    if old is None:
        # 首判：residential 也需要双信号已在 classify 保证；首轮直接采纳（无历史可比）
        # 但按"放行需 2 次"，首轮 residential 记 streak=1，不直接放行 -> unknown 占位
        if new_net == "residential":
            return "unknown", now_s, {"net": "residential", "count": 1,
                                      "first_at": now_s}, "promote-wait"
        return new_net, now_s, {"net": new_net, "count": 1, "first_at": now_s}, "first"
    cur = old.get("net", "unknown")
    if new_net == cur:
        return cur, old.get("verdict_at", now_s), {"net": cur, "count": 99,
                                                   "first_at": now_s}, "steady"
    # 淘汰方向：立即生效
    if new_net in ("datacenter", "unknown"):
        return new_net, now_s, {"net": new_net, "count": 1,
                                "first_at": now_s}, "demote-fast"
    # 放行方向：需连续 2 次一致（且在 7 天内）
    st = old.get("streak") or {}
    try:
        first_at = datetime.fromisoformat(st.get("first_at", now_s))
    except Exception:
        first_at = now
    if st.get("net") == "residential" and (now - first_at) <= timedelta(days=7):
        return "residential", now_s, {"net": "residential", "count": 99,
                                      "first_at": now_s}, "promote-ok"
    return cur, old.get("verdict_at", now_s), {"net": "residential", "count": 1,
                                               "first_at": now_s}, "promote-wait"


def main():
    print(f"=== enrich v2 {now_s} ===")
    # 1. ASN 表（fail-closed 前置门禁）
    try:
        asn_table, table_info = load_asn_table()
    except RuntimeError as e:
        print(f"  [FATAL] {e}")
        print("  整批不下结论（fail-closed），保留旧文件。")
        sys.exit(2)
    print(f"  ASN 表：{table_info['source']}，{table_info['merged']} 条")

    # 2. 旧数据 + overrides
    try:
        with open(OUT) as f:
            old = json.load(f)
    except Exception:
        old = {}
    old_entries = old.get("entries", old) if isinstance(old, dict) else {}
    # 兼容旧格式（顶层即 entries）
    if "entries" not in old and isinstance(old, dict) and old and "net" in next(iter(old.values()), {}):
        old_entries = old
    overrides = load_overrides()

    # 3. 候选 IP（全量列表）
    try:
        ips = candidate_ips()
    except Exception as e:
        print(f"  上游抓取失败: {e}")
        sys.exit(2)
    print(f"  候选 {len(ips)} IP")

    # 4. 逐 IP 判定
    new_entries, frozen, failed_ips = {}, 0, []
    for ip in ips:
        old_e = old_entries.get(ip)
        # overrides 最高优先级
        ov = override_for(ip, overrides)
        if ov:
            net_ov, reason_ov = ov
            new_entries[ip] = {"net": net_ov, "reason": reason_ov, "checked_at": now_s,
                               "verdict_at": now_s,
                               "streak": {"net": net_ov, "count": 99, "first_at": now_s}}
            continue
        # L1 ASN（传输失败 -> 保留上一轮，冻结）
        try:
            asn, _, raw = get_asn(ip)
        except TransportError as e:
            failed_ips.append(ip)
            if old_e and old_e.get("net"):
                new_entries[ip] = dict(old_e, frozen=True)
                frozen += 1
            continue
        except Exception as e:
            failed_ips.append(ip)
            if old_e and old_e.get("net"):
                new_entries[ip] = dict(old_e, frozen=True)
                frozen += 1
            continue
        # L2 hostname（失败=弃权）
        ptr = get_hostname(ip)
        asn_in_list = str(asn) in asn_table if asn is not None else False
        new_net, reason = classify(ip, asn, asn_in_list, ptr)
        net, verdict_at, streak, how = apply_debounce(old_e, new_net, reason)
        e = {"net": net, "reason": reason, "checked_at": now_s,
             "verdict_at": verdict_at, "streak": streak, "how": how,
             "cc": None, "asn": asn, "isp": None}
        # 尽量保留 ipquery 的附加字段
        try:
            isp_d = (raw.get("isp") or {})
            loc_d = (raw.get("location") or {})
            e["cc"] = (loc_d.get("country_code") or "").upper() or None
            e["isp"] = isp_d.get("isp") or isp_d.get("org") or None
        except Exception:
            pass
        new_entries[ip] = e
        time.sleep(REQ_DELAY)

    # 5. 冻结超限（7 天 wall-clock 自 verdict_at）-> unknown + 升级告警
    for ip, e in list(new_entries.items()):
        if e.get("frozen"):
            try:
                va = datetime.fromisoformat(e.get("verdict_at", now_s))
            except Exception:
                va = now
            if (now - va) > timedelta(days=FREEZE_CAP_DAYS):
                e["net"] = "unknown"
                e["reason"] = {"stale": True, "frozen_days": (now - va).days}
                e["frozen"] = False
                alert(f"{ip} 冻结超 {FREEZE_CAP_DAYS} 天，转 unknown（升级告警）")

    # 6. 保留旧条目中不在本轮列表但仍有效的（verdict 90 天内），其余修剪
    for ip, e in old_entries.items():
        if ip in new_entries or not isinstance(e, dict) or not e.get("net"):
            continue
        try:
            va = datetime.fromisoformat(e.get("verdict_at", e.get("checked_at", now_s)))
        except Exception:
            continue
        if (now - va) <= timedelta(days=VERDICT_TTL_DAYS):
            new_entries[ip] = e

    # 7. 统计 + 突变检测
    counts = {"residential": 0, "datacenter": 0, "unknown": 0}
    unknown_sub = {}
    for e in new_entries.values():
        n = e.get("net", "unknown")
        counts[n] = counts.get(n, 0) + 1
        if n == "unknown":
            sub = (e.get("reason") or {}).get("unknown_sub", "insufficient")
            unknown_sub[sub] = unknown_sub.get(sub, 0) + 1
    prev_counts = ((old.get("meta") or {}).get("verdict_counts")
                   if isinstance(old, dict) else None) or {}
    pr = prev_counts.get("residential", 0)
    cr = counts["residential"]
    if pr > 0 and abs(cr - pr) / pr >= 0.5:
        alert(f"residential 数量突变 {pr} -> {cr}（±50%），检查表/源是否异常")
    if pr == 0 and cr > 0:
        pass
    # residential 连续 3 天为 0 告警
    zsince = ((old.get("meta") or {}).get("zero_residential_since")
              if isinstance(old, dict) else None)
    if cr == 0:
        if not zsince:
            zsince = now_s
        else:
            try:
                if (now - datetime.fromisoformat(zsince)).days >= 3:
                    alert("residential 连续 3 天为 0：区分'确实无住宅节点'与'信号过严'")
            except Exception:
                pass
    else:
        zsince = None
    if frozen / max(len(ips), 1) > 0.2:
        alert(f"单轮冻结比 {frozen}/{len(ips)} 超 20%")
    if failed_ips and not new_entries:
        alert("整批传输失败（双源全挂），本轮未下新结论")

    meta = {"generated_at": now_s, "asn_table": table_info,
            "last_success": now_s if new_entries else (old.get("meta") or {}).get("last_success"),
            "verdict_counts": counts, "unknown_breakdown": unknown_sub,
            "frozen_count": frozen, "failed_ips": failed_ips[:20],
            "zero_residential_since": zsince}
    out = {"meta": meta,
           "entries": {ip: new_entries[ip] for ip in sorted(new_entries)}}
    with open(OUT, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)

    print("==== 分布 ====")
    print(f"  residential: {counts['residential']}, datacenter: {counts['datacenter']}, "
          f"unknown: {counts['unknown']}, 冻结: {frozen}")
    print(f"  unknown 原因: {unknown_sub}")
    if ALERTS:
        print(f"  !! {len(ALERTS)} 条告警（见上）")
    print(f"已写入 {OUT}")

    # 双样本自检（验收门）
    for sip, expect in (("219.100.37.239", "datacenter"), ("36.13.8.195", "residential")):
        got = (new_entries.get(sip) or {}).get("net")
        flag = "OK " if got == expect else "FAIL"
        print(f"  自检 {flag} {sip}: 期望 {expect}，实际 {got}")


if __name__ == "__main__":
    main()
