/**
 * gate-sub v4.4 — VPN Gate SSTP 动态订阅生成器（加固版）
 * ============================================================================
 * v4.2 相对 v4.1 的修复（ChatGPT 发散评审）：
 * 1. 降级不再毒化健康缓存：健康 key 只写健康构建；降级构建走独立 degraded key
 *    （60s 短 TTL）；有健康旧缓存时降级直接返回旧缓存、不写 degraded。
 *    （修"降级 200 覆盖用户好节点"的最大隐患）
 * 2. MAX_STALE_S 24h → 6h（VPN Gate 高 churn，24h 名单大概率半死）。
 * 3. stale 命中改写响应头：max-age=0 + Age，避免下游误以为新鲜再缓存。
 * 4. /refresh 复用 single-flight。
 * 5. /status 增加 lastError、各阶段耗时、degraded 标记、degraded 缓存年龄。
 * 6. sessions 列缺失时显式降级为全 0（不再静默错位）；排序改 Score 主、Sessions 次。
 * 7. probeTimeout 成功后 clearTimeout。
 * v4.5 相对 v4.4 的变更：
 * - 富集映射不再打包：运行时从 QUALITY_URL（GitHub raw 的 ip-quality.json）
 *   拉取，Cache API 缓存 1 小时。Actions 更新映射后自动生效，免重新部署。
 *   拉取失败回退空映射（无标签、不编造），不影响主流程。
 * ============================================================================
 */
import { connect } from 'cloudflare:sockets';

function loadConfig(env) {
  const cfg = {
    UUID: env.UUID || '',
    EDT_DOMAIN: env.EDT_DOMAIN || '',
    SUB_TOKEN: env.SUB_TOKEN || '',
    ALLOW_PUBLIC: env.ALLOW_PUBLIC === 'true',
    VPNGATE_API: 'https://www.vpngate.net/api/iphone/',
    MIRROR_URL: env.MIRROR_URL || '',
    SSTP_USER: env.SSTP_USER || 'vpn',
    SSTP_PASS: env.SSTP_PASS || 'vpn',
    BLOCKLIST_HOSTS: env.BLOCKLIST_HOSTS || '',
    QUALITY_URL: env.QUALITY_URL || '',
  };
  const missing = [];
  if (!cfg.UUID) missing.push('UUID');
  if (!cfg.EDT_DOMAIN) missing.push('EDT_DOMAIN');
  if (missing.length) throw new Error('缺少环境变量: ' + missing.join(', '));
  return cfg;
}

const VERSION = 'v4.5';
const MAX_NODES = 10;
const CANDIDATE_MULTIPLIER = 3;
const CACHE_TTL_S = 600;               // 健康缓存 10 分钟
const DEGRADED_TTL_S = 60;             // 降级缓存 60 秒（短 TTL，快速恢复）
const MAX_STALE_S = 21600;             // 6h max-stale
const TCP_TIMEOUT_MS = 2500;
const FETCH_TIMEOUT_MS = 8000;
const TCP_CONCURRENCY = 10;
const PROBE_BUDGET_MS = 8000;
const HEALTH_TTL_S = 60;
const SSTP_PORT = 443;

const DEFAULT_BLOCKLIST = ['fing.opengw.net', 'opengw.opengw.net'];
function buildBlocklist(extra) {
  const set = new Set();
  const norm = h => h.trim().toLowerCase().replace(/\.+$/, '');
  for (const h of DEFAULT_BLOCKLIST) set.add(norm(h));
  for (const h of String(extra || '').split(',')) if (h.trim()) set.add(norm(h));
  return set;
}

function stableId(host) {
  let h = 0x811c9dc5;
  const s = host.toLowerCase().replace(/\.+$/, '');
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0').slice(-6);
}

// 混淆编码（注意：混淆非加密。密钥即 URL 明文中的 UUID，任何拿到订阅链接的
// 人都能解码；此处仅为兼容消费端 atob() 解码流程，不提供安全性。）
function base64ObfuscateEncode(plaintext, key) {
  const data = new TextEncoder().encode(plaintext);
  const kb = new TextEncoder().encode(key);
  const mixed = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) mixed[i] = data[i] ^ kb[i % kb.length];
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < mixed.length; i += CHUNK)
    binary += String.fromCharCode.apply(null, mixed.subarray(i, i + CHUNK));
  return btoa(binary);
}

function parseCsvRow(line) {
  const fields = [];
  let cur = '', inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inQuotes) {
      if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else inQuotes = false; }
      else cur += c;
    } else if (c === '"') inQuotes = true;
    else if (c === ',') { fields.push(cur); cur = ''; }
    else cur += c;
  }
  fields.push(cur);
  return fields;
}

function b64decodeToText(b64) {
  const bin = atob(b64.replace(/\s+/g, ''));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder('utf-8').decode(bytes);
}

function normHost(host0) {
  let host = (host0 || '').trim().replace(/\.+$/, '');
  if (host && !host.includes('.')) host += '.opengw.net';
  return host;
}

function extractSstpFromCsv(csvText, blocklist) {
  const lines = csvText.replace(/^\ufeff/, '').split(/\r?\n/);
  let headerIdx = -1, header = null;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim().replace(/^#+/, '');
    if (t.startsWith('HostName')) { headerIdx = i; header = parseCsvRow(t); break; }
  }
  if (headerIdx < 0) throw new Error('CSV 缺少 HostName 表头');
  const lower = header.map(h => h.trim().replace(/^\*/, '').toLowerCase());
  for (const required of ['hostname', 'ip', 'score']) {
    if (!lower.includes(required)) throw new Error('CSV 表头缺失关键列: ' + required);
  }
  const col = (name, fb) => { const i = lower.indexOf(name); return i >= 0 ? i : fb; };
  let cfgCol = col('openvpn_configdata_base64', -1);
  if (cfgCol < 0) { cfgCol = lower.findIndex(h => h.includes('base64')); if (cfgCol < 0) cfgCol = header.length - 1; }
  const cHost = col('hostname', 0), cIp = col('ip', 1), cScore = col('score', 2);
  const cCountryLong = col('countrylong', 5), cCountryShort = col('countryshort', 6);
  const cSessions = col('numvpnsessions', -1);   // 缺失时为 -1，显式降级，不静默错位
  // 启发式过滤：用 OpenVPN 配置中的 proto tcp 推断该主机可能支持 TCP 443。
  // 注意这是启发式（OpenVPN TCP 与 SSTP 无必然对应），会误杀少量 SSTP-only 节点，
  // 但可过滤掉明确只跑 UDP 的主机；误杀代价低于把 UDP-only 节点发给用户。
  const PROTO_TCP = /^proto\s+(tcp|tcp4|tcp6)\b/m;
  const nodes = [];
  for (let i = headerIdx + 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim() || line.trim() === '*') continue;
    const f = parseCsvRow(line);
    if (f.length < 7) continue;
    const host = normHost(f[cHost]), ip = (f[cIp] || '').trim();
    if (!host || !ip) continue;
    if (blocklist.has(host.toLowerCase())) continue;
    let cfg = '';
    try { cfg = b64decodeToText((f[cfgCol] || '').trim()); } catch (_) {}
    if (!PROTO_TCP.test(cfg)) continue;
    nodes.push({
      host, port: SSTP_PORT, ip,
      country: (f[cCountryLong] || '').trim(),
      countryCode: (f[cCountryShort] || '').trim().toUpperCase(),
      score: parseInt((f[cScore] || '0').trim(), 10) || 0,
      sessions: cSessions >= 0 ? (parseInt((f[cSessions] || '0').trim(), 10) || 0) : 0,
    });
  }
  const seen = new Set(), uniq = [];
  for (const n of nodes) {
    const k = n.host.toLowerCase();
    if (!seen.has(k)) { seen.add(k); uniq.push(n); }
  }
  // 排序：Score 主，Sessions>0 次（score 已综合质量，sessions 只做次要加权）
  uniq.sort((a, b) => (b.score - a.score) || ((b.sessions > 0) - (a.sessions > 0)));
  return uniq;
}

function extractSstpFromMirrorJson(data, blocklist) {
  const items = Array.isArray(data) ? data : [data];
  const servers = [];
  for (const it of items) {
    if (it && Array.isArray(it.servers)) servers.push(...it.servers);
    else if (it && typeof it === 'object') servers.push(it);
  }
  const PROTO_TCP = /^proto\s+(tcp|tcp4|tcp6)\b/m;
  const nodes = [];
  for (const s of servers) {
    const host = normHost(String(s.hostname || s.host || '')), ip = String(s.ip || '').trim();
    if (!host || !ip) continue;
    if (blocklist.has(host.toLowerCase())) continue;
    let cfg = '';
    try { cfg = b64decodeToText(String(s.openvpn_configdata_base64 || s.config_b64 || '').trim()); } catch (_) {}
    if (!PROTO_TCP.test(cfg)) continue;
    nodes.push({
      host, port: SSTP_PORT, ip,
      country: String(s.countrylong || s.country_long || s.country || '').trim(),
      countryCode: String(s.countryshort || s.country_short || '').trim().toUpperCase(),
      score: parseInt(s.score || '0', 10) || 0,
      sessions: parseInt(s.numvpnsessions || s.sessions || '0', 10) || 0,
    });
  }
  const seen = new Set(), uniq = [];
  for (const n of nodes) {
    const k = n.host.toLowerCase();
    if (!seen.has(k)) { seen.add(k); uniq.push(n); }
  }
  uniq.sort((a, b) => (b.score - a.score) || ((b.sessions > 0) - (a.sessions > 0)));
  return uniq;
}

async function fetchWithTimeout(url, ms, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally { clearTimeout(t); }
}

async function fetchSstpNodes(cfg, blocklist, stats) {
  const t0 = Date.now();
  try {
    const r = await fetchWithTimeout(cfg.VPNGATE_API, FETCH_TIMEOUT_MS,
      { headers: { 'User-Agent': 'Mozilla/5.0 (gate-sub)' } });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const text = await r.text();
    const nodes = extractSstpFromCsv(text, blocklist);
    stats.fetchMs = Date.now() - t0;
    if (nodes.length > 0) return { nodes, source: 'vpngate', rawLines: text.split('\n').length };
    throw new Error('官方源解析出 0 节点');
  } catch (e) {
    stats.fetchMs = Date.now() - t0;
    stats.lastError = '主源失败: ' + e.message;
    console.error('主源失败:', e.message);
  }
  if (!cfg.MIRROR_URL) throw new Error('主源失败且未配置镜像源');
  const tM = Date.now();
  const r = await fetchWithTimeout(cfg.MIRROR_URL, FETCH_TIMEOUT_MS,
    { headers: { 'User-Agent': 'Mozilla/5.0 (gate-sub)' } });
  if (!r.ok) throw new Error('镜像源 HTTP ' + r.status);
  const data = await r.json();
  const nodes = extractSstpFromMirrorJson(data, blocklist);
  stats.fetchMs = Date.now() - t0;   // 含镜像耗时
  stats.lastError = null;            // 镜像成功，清掉主源失败记录，避免误导 /status
  return { nodes, source: 'mirror', rawLines: null };
}

async function tcpAlive(host, port) {
  let timer = null;
  try {
    const sock = connect({ hostname: host, port });
    const closer = new Promise(resolve => {
      timer = setTimeout(() => { try { sock.close(); } catch (_) {} resolve(false); }, TCP_TIMEOUT_MS);
    });
    const opener = (async () => {
      try { await sock.opened; return true; }
      catch (_) { return false; }
      finally { try { sock.close(); } catch (_) {} }
    })();
    const ok = await Promise.race([opener, closer]);
    if (timer) clearTimeout(timer);
    return ok;
  } catch (_) {
    if (timer) clearTimeout(timer);
    return false;
  }
}

async function filterAlive(nodes, concurrency = TCP_CONCURRENCY) {
  const results = new Array(nodes.length);
  let idx = 0, probedDone = 0;
  let budgetExpired = false;
  const budgetTimer = setTimeout(() => { budgetExpired = true; }, PROBE_BUDGET_MS);
  async function worker() {
    while (idx < nodes.length && !budgetExpired) {
      const i = idx++;
      results[i] = { n: nodes[i], ok: await tcpAlive(nodes[i].host, nodes[i].port) };
      probedDone++;
    }
  }
  const workers = [];
  for (let i = 0; i < Math.min(concurrency, nodes.length); i++) workers.push(worker());
  await Promise.all(workers);
  clearTimeout(budgetTimer);
  return {
    alive: results.filter(x => x && x.ok).map(x => x.n),
    probedDone, probedTotal: nodes.length, budgetExpired,
  };
}

const CC_ZH = { JP: '日本', KR: '韩国', US: '美国', GB: '英国', DE: '德国', FR: '法国', AU: '澳洲', CA: '加拿大', SG: '新加坡', TH: '泰国', RU: '俄罗斯', NL: '荷兰', TW: '台湾', HK: '香港' };

// 富集映射：运行时从 QUALITY_URL（GitHub raw 的 ip-quality.json）拉取，
// Cache API 缓存 1 小时。key=IP，value={dc,vpn,proxy,tor,risk,cc,asn,isp,updated}。
// 拉取失败回退空映射（无标签、不编造），不影响主流程。
const QUALITY_TTL_S = 3600;
async function getQualityMap(cache, qualityUrl) {
  if (!qualityUrl) return {};
  const key = new Request(`quality-map:${VERSION}:${qualityUrl}`, { method: 'GET' });
  try {
    const hit = await cache.match(key);
    if (hit) {
      try { const j = await hit.json(); if (j && typeof j === 'object' && !Array.isArray(j)) return j; } catch (_) {}
    }
  } catch (_) {}
  try {
    const r = await fetchWithTimeout(qualityUrl, FETCH_TIMEOUT_MS,
      { headers: { 'User-Agent': 'Mozilla/5.0 (gate-sub)' } });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const j = await r.json();
    if (!j || typeof j !== 'object' || Array.isArray(j)) throw new Error('bad shape');
    try {
      await cache.put(key, new Response(JSON.stringify(j), {
        headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${QUALITY_TTL_S}` },
      }));
    } catch (_) {}
    return j;
  } catch (e) { console.error('quality map 加载失败:', e.message); return {}; }
}
// 节点名只放几乎静态的段：确认机房才标 [机房]。
// is_datacenter=false 可能是"未知"，不承诺"住宅"；is_vpn 对 VPN Gate 节点
// 大批量 true、无区分度，不进名；risk_score 等易变分数走 /quality 页面。
// fuzzy 分数只显示、绝不用于过滤摘牌。
function qualityTag(ip, m) {
  const map = m || {};
  const q = map[ip];
  if (q && q.dc === true) return '[机房]';
  return '';
}

function nodeDisplayName(cfg, node, qmap) {
  const ccZh = CC_ZH[node.countryCode] || node.countryCode || '';
  const base = ccZh ? `${ccZh}-${stableId(node.host)}` : `${node.countryCode || '??'}-${stableId(node.host)}`;
  return base + qualityTag(node.ip, qmap);
}

function buildVlessLink(cfg, node, qmap) {
  const uuid = cfg.UUID, domain = cfg.EDT_DOMAIN;
  const chain = { type: 'sstp', username: cfg.SSTP_USER, password: cfg.SSTP_PASS, hostname: node.host, port: node.port };
  const enc = base64ObfuscateEncode(JSON.stringify(chain), uuid);
  const path = '/video/' + encodeURIComponent(enc).replace(/%2F/g, '/');
  const name = nodeDisplayName(cfg, node, qmap);
  return `vless://${uuid}@${domain}:443?security=tls&type=ws&host=${domain}&sni=${domain}&fp=chrome&path=${path}&encryption=none#${encodeURIComponent(name)}`;
}

function safeEqual(a, b) {
  const ab = String(a), bb = String(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab.charCodeAt(i) ^ bb.charCodeAt(i);
  return diff === 0;
}

// 分阶段构建：抓取 → 拨测；拨测超时/无存活则降级为已抓取的 TopN（不二次抓取）
// 返回 { links, stats, healthy }
async function buildSubscription(cfg, blocklist, qmap) {
  const stats = {
    source: 'unknown', rawLines: null, candidates: 0, probedDone: 0, probedTotal: 0,
    alive: 0, degraded: false, budgetExpired: false, fetchMs: -1, probeMs: -1, lastError: null,
  };
  const fetched = await fetchSstpNodes(cfg, blocklist, stats);
  const candidates = fetched.nodes.slice(0, MAX_NODES * CANDIDATE_MULTIPLIER);
  stats.source = fetched.source; stats.rawLines = fetched.rawLines;
  stats.candidates = candidates.length; stats.probedTotal = candidates.length;

  const t1 = Date.now();
  const probe = filterAlive(candidates);
  const r = await Promise.race([
    probe,
    new Promise(resolve => setTimeout(() => resolve(null), PROBE_BUDGET_MS + 2000)),
  ]);
  stats.probeMs = Date.now() - t1;

  if (r && r.alive.length > 0) {
    stats.probedDone = r.probedDone; stats.budgetExpired = r.budgetExpired; stats.alive = r.alive.length;
    return { links: r.alive.slice(0, MAX_NODES).map(n => buildVlessLink(cfg, n, qmap)), nodes: r.alive.slice(0, MAX_NODES), stats, healthy: true };
  }
  if (r) { stats.probedDone = r.probedDone; stats.budgetExpired = r.budgetExpired; }
  stats.degraded = true;
  stats.lastError = stats.lastError || '拨测无存活/超时';
  console.error('订阅构建降级:', stats.lastError);
  const picked = fetched.nodes.slice(0, MAX_NODES);
  if (picked.length === 0) throw new Error(stats.lastError || '无可用节点');
  return { links: picked.map(n => buildVlessLink(cfg, n, qmap)), nodes: picked, stats, healthy: false };
}

function b64urlEncodeText(s) {
  const bytes = new TextEncoder().encode(s);
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK)
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecodeToText(s) {
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder('utf-8').decode(bytes);
}

function makeSubResponse(links, stats, maxAge) {
  const meta = b64urlEncodeText(JSON.stringify({ builtAt: Date.now(), stats }));
  return new Response(links.join('\n') + '\n', {
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': `public, max-age=${maxAge}`,
      'x-gate-meta': meta,
    },
  });
}

// stale 命中改写响应头：max-age=0 + Age，避免下游误以为新鲜（ChatGPT F-C）
function markStale(resp, ageS) {
  const meta = resp.headers.get('x-gate-meta') || '{"builtAt":0}';
  return new Response(resp.body, {
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'public, max-age=0',
      'age': String(Math.round(ageS)),
      'x-gate-meta': meta,
    },
  });
}

function cacheKeys(url) {
  const base = `${url.origin}/sub:${VERSION}`;
  return {
    healthy: new Request(base, { method: 'GET' }),
    degraded: new Request(base + ':degraded', { method: 'GET' }),
    quality: new Request(base + ':quality', { method: 'GET' }),
  };
}

// /quality 页面用的行数据：节点自身字段 + 富集字段（无富集时为 null，不编造）
function buildQualityRows(cfg, nodes, qmap) {
  const map = qmap || {};
  return nodes.map(n => {
    const q = map[n.ip] || null;
    const qcc = q && q.cc ? String(q.cc).toUpperCase() : null;
    const ncc = n.countryCode ? String(n.countryCode).toUpperCase() : null;
    return {
      name: nodeDisplayName(cfg, n, qmap),
      host: n.host, ip: n.ip,
      country: n.country, countryCode: n.countryCode,
      score: n.score, sessions: n.sessions,
      datacenter: q ? q.dc === true : null,
      vpn: q ? q.vpn === true : null,
      proxy: q ? q.proxy === true : null,
      tor: q ? q.tor === true : null,
      risk_score: q && typeof q.risk === 'number' ? q.risk : null,
      asn: (q && q.asn) || null, isp: (q && q.isp) || null,
      geo_country: qcc,
      geo_mismatch: qcc && ncc ? qcc !== ncc : null,
      quality_updated: (q && q.updated) || null,
    };
  });
}

function enrichmentInfo(qmap) {
  const map = qmap || {};
  const keys = Object.keys(map);
  let latest = null;
  for (const k of keys) {
    const u = map[k].updated;
    if (u && (!latest || u > latest)) latest = u;
  }
  return { entries: keys.length, lastUpdated: latest };
}

function readMeta(resp) {
  try { return JSON.parse(b64urlDecodeToText(resp.headers.get('x-gate-meta') || '')); }
  catch (_) { return { builtAt: 0, stats: {} }; }
}

// SWR single-flight：模块级共享
let refreshPromise = null;
function triggerBackgroundRefresh(cache, keys, cfg, blocklist) {
  if (refreshPromise) return refreshPromise;
  refreshPromise = (async () => {
    try {
      const qmap = await getQualityMap(cache, cfg.QUALITY_URL);
      const { links, nodes, stats, healthy } = await buildSubscription(cfg, blocklist, qmap);
      await cache.put(healthy ? keys.healthy : keys.degraded,
        makeSubResponse(links, stats, healthy ? CACHE_TTL_S : DEGRADED_TTL_S));
      await putQualityRows(cache, keys, cfg, nodes, healthy ? CACHE_TTL_S : DEGRADED_TTL_S, qmap);
    } catch (e) { console.error('后台刷新失败:', e.message); }
    finally { refreshPromise = null; }
  })();
  return refreshPromise;
}

async function putQualityRows(cache, keys, cfg, nodes, ttlS, qmap) {
  try {
    const rows = buildQualityRows(cfg, nodes, qmap);
    await cache.put(keys.quality, new Response(JSON.stringify({ builtAt: Date.now(), rows }), {
      headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${ttlS}` },
    }));
  } catch (e) { console.error('quality 缓存写入失败:', e.message); }
}

let healthCache = null;
async function checkUpstream(cfg) {
  const now = Date.now();
  if (healthCache && now - healthCache.at < HEALTH_TTL_S * 1000) return healthCache.upstream;
  let upstream = 'unknown';
  try {
    const r = await fetchWithTimeout(cfg.VPNGATE_API, 8000,
      { method: 'HEAD', headers: { 'User-Agent': 'Mozilla/5.0 (gate-sub)' } });
    upstream = r.ok ? 'ok' : 'http-' + r.status;
  } catch (e) { upstream = 'unreachable'; }
  healthCache = { at: now, upstream };
  return upstream;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const blocklist = buildBlocklist(env.BLOCKLIST_HOSTS);

    if (url.pathname === '/') {
      let cfgStatus = 'ok', upstream = 'unknown';
      try { loadConfig(env); } catch (e) { cfgStatus = 'missing-env'; }
      if (cfgStatus === 'ok') upstream = await checkUpstream(loadConfig(env));
      const body = `gate-sub ${VERSION} · 订阅生成器\nconfig: ${cfgStatus}\nupstream: ${upstream}\n`;
      return new Response(body, { headers: { 'content-type': 'text/plain' } });
    }

    if (url.pathname === '/status') {
      const cache = caches.default;
      const keys = cacheKeys(url);
      let cfg = null;
      try { cfg = loadConfig(env); } catch (_) {}
      const qmap = cfg ? await getQualityMap(cache, cfg.QUALITY_URL) : {};
      let h = null, d = null, q = null;
      try {
        const hitH = await cache.match(keys.healthy);
        if (hitH) { const m = readMeta(hitH); h = { age_s: Math.round((Date.now() - m.builtAt) / 1000), ...m.stats }; }
        const hitD = await cache.match(keys.degraded);
        if (hitD) { const m = readMeta(hitD); d = { age_s: Math.round((Date.now() - m.builtAt) / 1000), ...m.stats }; }
        const hitQ = await cache.match(keys.quality);
        if (hitQ) {
          try {
            const jq = await hitQ.json();
            q = { age_s: Math.round((Date.now() - jq.builtAt) / 1000), rows: jq.rows.length };
          } catch (_) {}
        }
      } catch (_) {}
      const info = {
        version: VERSION,
        colo: request.cf ? request.cf.colo : 'unknown',
        healthyCache: h, degradedCache: d, qualityCache: q,
        enrichment: enrichmentInfo(qmap),
      };
      return new Response(JSON.stringify(info, null, 2), { headers: { 'content-type': 'application/json' } });
    }

    // /quality：人读页面。每行：节点名 | 类型 | 风险分 | ASN/ISP | 国家异地 | 富集时间。
    // 富集缺失的字段显示为 "-"（未知），不编造。需与 /sub 同样的鉴权。
    if (url.pathname === '/quality') {
      let cfg;
      try { cfg = loadConfig(env); }
      catch (e) { return new Response('misconfigured\n', { status: 500 }); }
      if (!cfg.SUB_TOKEN && !cfg.ALLOW_PUBLIC) {
        return new Response('misconfigured\n', { status: 500 });
      }
      if (cfg.SUB_TOKEN) {
        const token = (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '')
          || url.searchParams.get('token') || '';
        if (!safeEqual(token, cfg.SUB_TOKEN)) return new Response('unauthorized\n', { status: 401 });
      }
      const cache = caches.default;
      const keys = cacheKeys(url);
      let hitQ = null;
      try { hitQ = await cache.match(keys.quality); } catch (_) {}
      if (!hitQ) {
        // 冷 colo 自愈：触发一次后台构建，下次访问就有数据
        if (ctx && ctx.waitUntil) ctx.waitUntil(triggerBackgroundRefresh(cache, keys, cfg, buildBlocklist(env.BLOCKLIST_HOSTS)));
        return new Response('quality 数据正在生成：稍后回来刷新\n', { status: 503, headers: { 'content-type': 'text/plain; charset=utf-8' } });
      }
      let rows = [];
      try { rows = (await hitQ.json()).rows || []; } catch (_) {}
      const line = r => {
        const type = r.datacenter === true ? '机房' : r.datacenter === false ? '非机房' : '-';
        const risk = typeof r.risk_score === 'number' ? String(r.risk_score) : '-';
        const vpn = r.vpn === true ? 'VPN' : r.proxy === true ? '代理' : r.tor === true ? 'Tor' : '-';
        const asn = r.asn || '-';
        const geo = r.geo_mismatch === true ? '异地!' : r.geo_country || '-';
        return `${r.name} | 类型:${type} | 风险:${risk} | 标记:${vpn} | ${asn} | 地理:${geo} | 会话:${r.sessions}`;
      };
      const body = [
        `# gate-sub ${VERSION} /quality（${rows.length} 节点）`,
        '# 风险分=ipquery 恶意可能性 0-100（越低越好）；"-"=未知，不代表干净',
        '# 类型只标"机房"为确定值；"非机房"可能是未知，注册重要账号前请人工复核',
        '',
        ...rows.map(line),
        '',
      ].join('\n');
      return new Response(body, { headers: { 'content-type': 'text/plain; charset=utf-8' } });
    }

    if (url.pathname === '/refresh') {
      let cfg;
      try { cfg = loadConfig(env); } catch (e) { return new Response('misconfigured\n', { status: 500 }); }
      const token = url.searchParams.get('token') || '';
      if (!cfg.SUB_TOKEN || !safeEqual(token, cfg.SUB_TOKEN)) return new Response('forbidden\n', { status: 403 });
      const cache = caches.default, keys = cacheKeys(url);
      await triggerBackgroundRefresh(cache, keys, cfg, blocklist);
      return new Response('refresh triggered\n', { headers: { 'content-type': 'text/plain' } });
    }

    if (url.pathname !== '/sub') {
      return new Response('not found\n', { status: 404 });
    }

    let cfg;
    try { cfg = loadConfig(env); }
    catch (e) {
      console.error('配置错误:', e.message);
      return new Response('subscription service misconfigured\n', { status: 500 });
    }

    if (!cfg.SUB_TOKEN && !cfg.ALLOW_PUBLIC) {
      console.error('拒绝启动：未配置 SUB_TOKEN 且未显式 ALLOW_PUBLIC=true');
      return new Response('subscription service misconfigured: set SUB_TOKEN or ALLOW_PUBLIC=true\n', { status: 500 });
    }
    if (cfg.SUB_TOKEN) {
      const token = (request.headers.get('authorization') || '').replace(/^Bearer\s+/i, '')
        || url.searchParams.get('token') || '';
      if (!safeEqual(token, cfg.SUB_TOKEN)) return new Response('unauthorized\n', { status: 401 });
    }

    const cache = caches.default;
    const keys = cacheKeys(url);
    let hitH = null, hitD = null;
    try {
      hitH = await cache.match(keys.healthy);
      hitD = await cache.match(keys.degraded);
    } catch (e) { console.error('缓存读取失败:', e.message); }
    const ageH = hitH ? (Date.now() - readMeta(hitH).builtAt) / 1000 : Infinity;
    const ageD = hitD ? (Date.now() - readMeta(hitD).builtAt) / 1000 : Infinity;

    // 1. 健康强缓存命中
    if (hitH && ageH <= CACHE_TTL_S) return hitH;

    // 1b. 降级短缓存命中（故障冷启动时避免每次都全量重建）
    if (hitD && ageD <= DEGRADED_TTL_S) return hitD;

    // 2. 实时构建
    let qmap = {};
    try { qmap = await getQualityMap(cache, cfg.QUALITY_URL); } catch (_) {}
    try {
      const { links, nodes, stats, healthy } = await buildSubscription(cfg, blocklist, qmap);
      if (healthy) {
        const resp = makeSubResponse(links, stats, CACHE_TTL_S);
        try {
          await cache.put(keys.healthy, resp.clone());
          await putQualityRows(cache, keys, cfg, nodes, CACHE_TTL_S, qmap);
        } catch (e) { console.error('缓存写入失败:', e.message); }
        return resp;
      }
      // 降级：优先返回健康旧缓存（不写 degraded 污染），都没有才返回降级短缓存
      if (hitH && ageH <= MAX_STALE_S) {
        if (ctx && ctx.waitUntil) ctx.waitUntil(triggerBackgroundRefresh(cache, keys, cfg, blocklist));
        return markStale(hitH, ageH);
      }
      const resp = makeSubResponse(links, stats, DEGRADED_TTL_S);
      try {
        await cache.put(keys.degraded, resp.clone());
        await putQualityRows(cache, keys, cfg, nodes, DEGRADED_TTL_S, qmap);
      } catch (e) { console.error('降级缓存写入失败:', e.message); }
      return resp;
    } catch (e) {
      console.error('订阅生成失败:', e.message);
      // 3. 构建抛错：健康旧缓存（6h 内）→ 降级旧缓存（60s 内）→ 502
      if (hitH && ageH <= MAX_STALE_S) {
        if (ctx && ctx.waitUntil) ctx.waitUntil(triggerBackgroundRefresh(cache, keys, cfg, blocklist));
        return markStale(hitH, ageH);
      }
      // degraded 条目 TTL 本来就只有 60s，这里不再用 6h 口径误导
      if (hitD && ageD <= DEGRADED_TTL_S) return markStale(hitD, ageD);
      return new Response('# subscription temporarily unavailable\n', { status: 502 });
    }
  },
};
