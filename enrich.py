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
from verify_ip import classify_ip, load_asn_table as _load_table, norm_asn

VPNGATE_API = "https://www.vpngate.net/api/iphone/"
OUT = "ip-quality.json"
OVERRIDES = "overrides.json"

now = datetime.now(timezone.utc)
now_s = now.isoformat(timespec="seconds")
ALERTS = []

TIMEOUT = 15
REQ_DELAY = 1.2  # API 间隔（秒），防 429


def alert(msg):
    ALERTS.append(msg)
    print(f"  [ALERT] {msg}")


def fetch(url, timeout=TIMEOUT):
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (gate-sub enrich)"})
    with urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def load_asn_table():
    """包装 verify_ip.load_asn_table，附带审计信息。返回 (table_set, info)。"""
    table = _load_table()
    src = getattr(_load_table, "last_source", "unknown")
    info = {"count": len(table), "merged": len(table), "source": src,
            "sha": hashlib.sha256(
                "\n".join(sorted(table, key=int)).encode()).hexdigest()[:12],
            "at": now_s}
    return table, info



def load_overrides():
    try:
        with open(OVERRIDES) as f:
            return json.load(f)
    except Exception:
        return {}


def override_for(ip, overrides):
    """人工名单最高优先级。allow 必须有合法 expires（缺失/naive/非法 -> 无效+告警，不静默忽略）；
    deny 的 expires 可选。返回 (net, reason) 或 None。"""
    o = overrides.get(ip)
    if not o or not isinstance(o, dict):
        return None
    if ip.startswith("_"):
        return None
    net = o.get("net")
    if net not in ("residential", "datacenter"):
        return None
    exp = o.get("expires")
    dt = None
    if exp:
        try:
            dt = datetime.fromisoformat(exp)
            if dt.tzinfo is None:
                raise ValueError("naive datetime（需带时区）")
        except Exception as e:
            alert(f"overrides {ip}: expires 非法（{e}），该条目已忽略")
            return None
        if dt < now:
            return None  # 已过期
        if (dt - now) <= timedelta(days=7):
            alert(f"overrides {ip}: 将在 7 天内过期")
    elif net == "residential":
        alert(f"overrides {ip}: allow 缺少 expires，已忽略（allow 必须有过期时间）")
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

    # 4. 逐 IP 判定（verify_ip.classify_ip 为唯一判定入口）
    new_entries, frozen, failed_ips = {}, 0, []
    for ip in ips:
        old_e = old_entries.get(ip)
        # overrides 最高优先级
        ov = override_for(ip, overrides)
        if ov:
            net_ov, reason_ov = ov
            new_entries[ip] = {"net": net_ov, "raw_net": net_ov, "reason": reason_ov,
                               "checked_at": now_s, "verdict_at": now_s,
                               "streak": {"net": net_ov, "count": 99, "first_at": now_s}}
            continue
        try:
            r = classify_ip(ip, asn_table)
        except Exception as e:
            # classify_ip 内部已处理传输失败；此处为兜底
            failed_ips.append(ip)
            if old_e and old_e.get("net"):
                new_entries[ip] = dict(old_e, frozen=True)
                frozen += 1
            continue
        # 传输失败 -> 保留上一轮，冻结（不下新结论）
        if (r.get("reason") or {}).get("unknown_sub") == "transport-failed":
            failed_ips.append(ip)
            if old_e and old_e.get("net"):
                new_entries[ip] = dict(old_e, frozen=True)
                frozen += 1
            continue
        new_net, reason = r["net"], r["reason"]
        net, verdict_at, streak, how = apply_debounce(old_e, new_net, reason)
        new_entries[ip] = {"net": net, "raw_net": new_net, "reason": reason,
                           "checked_at": now_s, "verdict_at": verdict_at,
                           "streak": streak, "how": how,
                           "cc": r.get("cc"), "asn": r.get("asn"), "isp": r.get("isp")}
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

    # 6. 保留旧条目中不在本轮列表但仍有效的（verdict 90 天内），其余修剪。
    #    P1-2：保留条目同样执行 7 天冻结上限检查（冻结超限 -> unknown + 告警）。
    pruned = 0
    for ip, e in old_entries.items():
        if ip in new_entries or not isinstance(e, dict) or not e.get("net"):
            continue
        try:
            va = datetime.fromisoformat(e.get("verdict_at", e.get("checked_at", now_s)))
        except Exception:
            continue
        age_days = (now - va).days
        if age_days <= VERDICT_TTL_DAYS:
            if age_days > FREEZE_CAP_DAYS and e.get("net") != "unknown":
                e = dict(e)
                e["net"] = "unknown"
                e["reason"] = {"stale": True, "frozen_days": age_days,
                               "note": "step6 freeze cap"}
                alert(f"{ip} step6 冻结超 {FREEZE_CAP_DAYS} 天，转 unknown")
            new_entries[ip] = e
        else:
            pruned += 1
    if pruned:
        print(f"  修剪过期条目 {pruned} 条（verdict 超 90 天）")

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
        # P2-6：空表 fail-open 导致的突增场景，必须告警（原先 pass 是缺口）
        alert(f"residential 从 0 突增到 {cr}：检查是否空表 fail-open 或源异常")
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

    # P2-2：本地回退连续计数（3 次升级告警）
    prev_fb = ((old.get("meta") or {}).get("local_fallback_streak", 0)
               if isinstance(old, dict) else 0)
    fb_streak = prev_fb + 1 if table_info["source"] == "local-fallback" else 0
    if fb_streak >= 3:
        alert(f"ASN 表连续回退本地 {fb_streak} 次，升级告警：检查上游表")

    meta = {"generated_at": now_s, "asn_table": table_info,
            "local_fallback_streak": fb_streak,
            "last_success": now_s if new_entries else (old.get("meta") or {}).get("last_success"),
            "verdict_counts": counts, "unknown_breakdown": unknown_sub,
            "frozen_count": frozen, "frozen_ratio": round(frozen / max(len(ips), 1), 3),
            "failed_ips": failed_ips[:20],
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

    # 双样本自检（验收门）：比对防抖前 raw_net（P1-1：首轮 residential 走 promote-wait，
    # 直接比对 net 会在首轮误报；验收的是分类本身，不是防抖）
    for sip, expect in (("219.100.37.239", "datacenter"), ("36.13.8.195", "residential")):
        e_s = new_entries.get(sip) or {}
        got = e_s.get("raw_net", e_s.get("net"))
        flag = "OK " if got == expect else "FAIL"
        extra = "" if got == expect else f"（how={e_s.get('how')}）"
        print(f"  自检 {flag} {sip}: 期望 {expect}，实际 {got}{extra}")


if __name__ == "__main__":
    main()
