# verify_ip.py 接口说明（给 update_sub.py 集成用）

## 文件位置
`verify_ip.py`（与 `update_sub.py` 放同一目录即可）+ `hosting-asn.local.txt`（ASN 本地表，同目录）

## 依赖
仅 Python 标准库（urllib / socket / re / json）。无第三方包。

## 函数签名

```python
from verify_ip import classify_ip, load_asn_table

table = load_asn_table()          # 启动时调用一次；返回 set（2592 个 ASN，无 AS 前缀）
result = classify_ip("36.13.8.195", table)
```

`classify_ip(ip: str, asn_table: set | None) -> dict` 返回：
```python
{
  "net": "residential" | "datacenter" | "unknown",
  "reason": { ... },   # 判定依据（ASN 是否命中机房表 / hostname 信号 / unknown 子原因）
  "asn": 2516,         # int 或 None
  "cc": "JP",          # 国家码 或 None
  "isp": "Kddi Corporation",  # 或 None
}
```

## 集成到 check_node() 的建议写法

```python
from verify_ip import classify_ip, load_asn_table

_ASN_TABLE = load_asn_table()  # 模块级加载一次

def check_node(node):
    # ... 现有连通性检测 ...
    r = classify_ip(node["ip"], _ASN_TABLE)
    # 宁缺毋滥：只有 residential 进订阅
    if r["net"] != "residential":
        return None  # 或标记淘汰
    node["net"] = r["net"]
    node["net_reason"] = r["reason"]
    return node
```

## 判定逻辑（v3-final，双顾问已评审）
- `datacenter`：ASN 在 hosting 表（3 个上游表合并，2592 条），或 hostname 命中机房词
  （vpngate/vps/cloud/datacenter/hosting，词边界匹配）
- `residential`：双信号 —— ASN 不在 hosting 表 **且** hostname 命中住宅词
  （ppp/dsl/cable/fiber/fibre/dyn/bb/residential，token 边界匹配）
- `unknown`：其余一切（IPv6 / 移动网 / 学术网 / ASN 查不到 / 无 PTR / 单信号 / 传输失败）
  → 一律按淘汰处理，不进订阅

## 注意事项
1. `load_asn_table()` 优先拉 3 个上游表（需 3/3 成功），失败回退本地表；
   都不可用时抛 `RuntimeError` —— 调用方应 fail-closed（本轮不下结论），不要用空表。
2. `classify_ip` 内部对单个 IP 的 API 失败已隔离（返回 unknown），不会抛错拖垮批量；
   只有表加载失败会抛。
3. 每次调用约 2-4 个 HTTP 请求（ASN + PTR + 备用），批量时建议间隔 ~1 秒防 429。
4. 判定是"尽力而为"的启发式：宁可 unknown 淘汰，不可误放机房。
