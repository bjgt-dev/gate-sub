#!/usr/bin/env python3
"""
订阅维护脚本 - 为 GitHub Actions 设计
每天运行一次，检测节点存活并更新 sub.txt
"""
import base64
import json
import os
import urllib.parse
import urllib.request

UUID = os.environ.get("SUB_UUID", "49e5bfce-7063-4a37-a825-9bf9890955f5")
DOMAIN = os.environ.get("EDT_DOMAIN", "gate-edt.tianzy2017.workers.dev")
CHECK_WORKER = os.environ.get("CHECK_WORKER", "https://gate-check.tianzy2017.workers.dev")

# 候选 SSTP 节点池（用户实测可用的 + VPN Gate 公开节点）
# 格式: (host, port, name)
CANDIDATES = [
    ("36.13.8.195", 443, "日本-东京-KDDI-01"),
    ("27.84.177.35", 443, "日本-02"),
]

def base64_obfuscate_encode(plaintext, key):
    data = plaintext.encode('utf-8')
    kb = key.encode('utf-8')
    mixed = bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))
    return base64.b64encode(mixed).decode('ascii')

def build_vless_link(host, port, name):
    chain = {"type": "sstp", "username": "vpn", "password": "vpn", "hostname": host, "port": port}
    enc = base64_obfuscate_encode(json.dumps(chain, separators=(',', ':')), UUID)
    path = '/video/' + urllib.parse.quote(enc, safe='').replace('%2F', '/')
    link = f"vless://{UUID}@{DOMAIN}:443?security=tls&type=ws&host={DOMAIN}&sni={DOMAIN}&fp=chrome&path={path}&encryption=none#{urllib.parse.quote(name)}"
    return link

def check_node(host, port, timeout=15):
    """通过 check Worker 检测 SSTP 节点是否可用"""
    try:
        url = f"{CHECK_WORKER}/check?proxyip={host}:{port}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data.get("success", False)
    except Exception as e:
        print(f"Check {host}:{port} failed: {e}")
        return False

def main():
    alive = []
    for host, port, name in CANDIDATES:
        print(f"Checking {name} ({host}:{port})...")
        if check_node(host, port):
            print(f"  ✓ alive")
            alive.append((host, port, name))
        else:
            print(f"  ✗ dead")

    # 至少保留 1 个节点，避免订阅变空
    # 如果全死，保留原来的候选（让用户至少有东西可连）
    if not alive:
        print("WARNING: all nodes dead, keeping candidates anyway")
        alive = CANDIDATES

    links = [build_vless_link(h, p, n) for h, p, n in alive]
    sub = "\n".join(links)
    b64 = base64.b64encode(sub.encode('utf-8')).decode('ascii')

    with open("sub.txt", "w") as f:
        f.write(b64)

    print(f"Done: {len(links)} nodes written to sub.txt")

if __name__ == "__main__":
    main()
