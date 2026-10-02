# gate-sub

VPN Gate SSTP 动态订阅生成器（Cloudflare Workers），给手机 Karing 客户端用。

- `worker.js`：订阅 Worker（v4.5）。配置全走环境变量：`UUID` / `EDT_DOMAIN` /
  `ALLOW_PUBLIC` / `SUB_TOKEN`（可选）/ `QUALITY_URL`（可选，ip-quality.json 的 raw 地址）
  / `SSTP_USER` / `SSTP_PASS` / `BLOCKLIST_HOSTS` / `MIRROR_URL`（可选）。
- `ip-quality.json`：IP 富集映射（`enrich.py` 生成，不要手改）。
  key=IP，value=`{dc,vpn,proxy,tor,risk,cc,asn,isp,updated}`。
- `enrich.py`：富集脚本（GitHub Actions 每 6 小时跑）。数据源 ipquery.io 免费 API。
- `.github/workflows/enrich.yml`：定时富集工作流。

## 命名规则（铁律）

节点名只保留：国家-城市、稳定序号（host 短 hash）、有可信数据时的质量段。
确认是机房 IP 时追加 `[机房]`；其他不标。`risk_score` 等易变分数不进节点名，
走 `/quality` 页面。未知不编造。

## 本地测试

```bash
node --check worker.js && node test-v4.mjs
```

（测试文件不进仓库：内含真实配置常量。）
