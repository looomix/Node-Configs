import asyncio
import base64
import json
import logging
import os
import re
import shutil
from datetime import datetime

import aiohttp
import pytz
import yaml
from bs4 import BeautifulSoup

from converters import clash_proxy, is_valid_ss, parse_uri, singbox_outbound

# 获取当前脚本所在目录的绝对路径
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))

# 使用绝对路径引用文件
URLS_FILE = os.path.join(SCRIPT_DIR, 'urls.txt')
KEYWORDS_FILE = os.path.join(SCRIPT_DIR, 'key.json')
PROTOCOL_OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'configs/protocols')
CLASH_OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'configs/clash')
SINGBOX_OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'configs/singbox')
README_FILE = os.path.join(PROJECT_ROOT, 'README.md')
STATS_FILE = os.path.join(PROJECT_ROOT, 'stats.json')

REQUEST_TIMEOUT = 20
CONCURRENT_REQUESTS = 10
FETCH_RETRIES = 3
MAX_CONFIG_LENGTH = 1500
MIN_PERCENT25_COUNT = 15

# 熔断参数：节点数低于上次的 60% 且上次已超过 300 个时视为异常，直接中止
MIN_NODE_RATIO = float(os.environ.get('MIN_NODE_RATIO', '0.6'))
MIN_NODE_FLOOR = int(os.environ.get('MIN_NODE_FLOOR', '300'))

GITHUB_REPO_PATH = 'looomix/Node-Configs'
GITHUB_BRANCH = 'main'

USER_AGENT = 'Mozilla/5.0 (compatible; Node-Configs/2.0; +https://github.com/looomix/Node-Configs)'

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

PROTOCOL_CATEGORIES = [
    "Vmess", "Vless", "Trojan", "ShadowSocks", "ShadowSocksR",
    "Tuic", "Hysteria2", "WireGuard"
]

# 用于判断一段文本是否真的是订阅内容
PROTOCOL_MARKERS = (
    'vmess://', 'vless://', 'trojan://', 'ss://', 'ssr://',
    'shadowsocks://', 'tuic://', 'tuic5://', 'hy2://',
    'hysteria2://', 'wireguard://',
)


def decode_base64_subscription(text):
    """整段响应若是 base64 订阅内容则解码为明文，否则返回 None。"""
    if not isinstance(text, str) or not text.strip():
        return None

    compact = re.sub(r'\s+', '', text)
    if len(compact) < 16:
        return None

    normalized = compact.replace('-', '+').replace('_', '/')
    normalized += '=' * (-len(normalized) % 4)
    try:
        decoded = base64.b64decode(normalized, validate=False).decode('utf-8')
    except (ValueError, UnicodeDecodeError):
        return None

    # 解码结果必须确实包含节点链接，避免把普通文本误判为 base64
    if not any(marker in decoded.lower() for marker in PROTOCOL_MARKERS):
        return None

    printable = sum(1 for ch in decoded if ch.isprintable() or ch in '\r\n\t')
    if printable / max(len(decoded), 1) < 0.95:
        return None
    return decoded


def extract_text_from_html(html):
    soup = BeautifulSoup(html, 'html.parser')
    for tag in soup(['script', 'style', 'noscript']):
        tag.decompose()
    # stripped_strings 逐行取文本，避免嵌套标签导致的重复
    return '\n'.join(soup.stripped_strings)


def normalize_body(body, content_type):
    """把响应体统一转换成待匹配的纯文本，兼容 HTML 页面与 base64 订阅。"""
    text = body.decode('utf-8', 'ignore')
    looks_like_html = 'html' in (content_type or '').lower() and '<' in text

    if looks_like_html:
        plain_text = extract_text_from_html(text)
        decoded = decode_base64_subscription(text)
        # 页面被 base64 包裹时，解码后的节点会更多
        if decoded and decoded.count('://') > plain_text.count('://'):
            return decoded
        return plain_text

    decoded = decode_base64_subscription(text)
    if decoded:
        return decoded
    return text


def filter_reason(config):
    """返回被过滤的原因；返回 None 表示保留。"""
    if 'i_love_' in config.lower():
        return 'i_love_'
    if config.count('%25') >= MIN_PERCENT25_COUNT:
        return 'percent25'
    if len(config) >= MAX_CONFIG_LENGTH:
        return 'too_long'
    if '%2525' in config:
        return 'double_encoded'
    return None


UUID_PATTERN = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
    r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)


def is_mislabeled_ss(config):
    """部分源站把 Vless 节点错写成 ss://，这里做识别。

    合法的 Shadowsocks 凭据必须能解出「已知加密方式:密码」，不可能是一个裸
    UUID；因此「解不出 SS 凭据 + 凭据是 UUID + 带 vless 参数」基本可判定为错标。
    """
    if not config.startswith('ss://'):
        return False
    if is_valid_ss(config):
        return False

    body = config[len('ss://'):]
    if '@' not in body:
        return False
    userinfo = re.split(r'@', body, 1)[0]
    if not UUID_PATTERN.match(userinfo):
        return False

    lowered = config.lower()
    return ('security=' in lowered or 'encryption=' in lowered
            or 'pbk=' in lowered or 'flow=' in lowered)


SCHEME_BOUNDARY = re.compile(
    r'(?=(?:vmess|vless|trojan|ssr|ss|shadowsocks|hysteria2|hy2|tuic5|tuic|wireguard)://)',
    re.IGNORECASE,
)

SCHEME_TO_CATEGORY = {
    'vmess': 'Vmess',
    'vless': 'Vless',
    'trojan': 'Trojan',
    'ss': 'ShadowSocks',
    'shadowsocks': 'ShadowSocks',
    'ssr': 'ShadowSocksR',
    'tuic': 'Tuic',
    'tuic5': 'Tuic',
    'hy2': 'Hysteria2',
    'hysteria2': 'Hysteria2',
    'wireguard': 'WireGuard',
}


def category_of(config):
    """根据 scheme 判断一条链接属于哪个协议分类。"""
    if '://' not in config:
        return None
    return SCHEME_TO_CATEGORY.get(config.split('://', 1)[0].lower())


def split_glued_links(config):
    """源站偶尔把两条链接直接粘在一起，这里按 scheme 边界拆开。"""
    if config.count('://') < 2:
        return [config]
    pieces = [piece for piece in SCHEME_BOUNDARY.split(config) if piece]
    return pieces or [config]


async def fetch_url(session, url):
    for attempt in range(1, FETCH_RETRIES + 1):
        try:
            async with session.get(url, timeout=REQUEST_TIMEOUT) as response:
                response.raise_for_status()
                body = await response.read()
                content_type = response.headers.get('Content-Type', '')
                text = normalize_body(body, content_type)
                logging.info(f"Successfully fetched: {url} "
                             f"(attempt {attempt}/{FETCH_RETRIES}, {len(body)} bytes)")
                return url, text
        except Exception as e:
            if attempt < FETCH_RETRIES:
                logging.warning(f"Failed to fetch or process {url} "
                                f"(attempt {attempt}/{FETCH_RETRIES}): {e}. Retrying...")
                await asyncio.sleep(attempt)
            else:
                logging.error(f"Failed to fetch or process {url} "
                              f"after {FETCH_RETRIES} attempts: {e}")
    return url, None


def find_matches(text, protocol_patterns):
    """按协议正则提取节点，并统计被过滤掉的条目。"""
    matches = {}
    stats = {'i_love_': 0, 'percent25': 0, 'too_long': 0,
             'double_encoded': 0, 'reclassified': 0}

    for category, patterns in protocol_patterns.items():
        found_configs = set()
        for pattern_str in patterns:
            if not isinstance(pattern_str, str):
                continue
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                logging.error(f"Regex error for '{pattern_str}' in category '{category}': {e}")
                continue

            for raw_item in pattern.findall(text):
                for item in split_glued_links(raw_item.strip()):
                    item = item.strip()
                    if not item:
                        continue
                    # 粘连拆分后，每条链接必须归到自己 scheme 对应的分类
                    if category_of(item) != category:
                        continue
                    reason = filter_reason(item)
                    if reason:
                        stats[reason] += 1
                        continue
                    found_configs.add(item)

        if found_configs:
            matches[category] = found_configs

    # 把被源站错标成 ss:// 的 Vless 节点归位，避免生成无法使用的链接
    ss_configs = matches.get('ShadowSocks', set())
    if ss_configs:
        mislabeled = {c for c in ss_configs if is_mislabeled_ss(c)}
        if mislabeled:
            matches['ShadowSocks'] = ss_configs - mislabeled
            if not matches['ShadowSocks']:
                del matches['ShadowSocks']
            matches.setdefault('Vless', set()).update(
                'vless://' + c[len('ss://'):] for c in mislabeled
            )
            stats['reclassified'] += len(mislabeled)

    return matches, stats


def save_to_file(directory, category_name, items_set):
    if not items_set:
        return 0
    file_path = os.path.join(directory, f"{category_name}.txt")
    count = len(items_set)
    try:
        with open(file_path, 'w', encoding='utf-8', newline='\n') as f:
            for item in sorted(items_set):
                f.write(f"{item}\n")
        logging.info(f"Saved {count} items to {file_path}")
        return count
    except Exception as e:
        logging.error(f"Failed to write file {file_path}: {e}")
        return 0


def collect_nodes(final_configs):
    """把各协议链接解析成统一节点，返回 (nodes, skipped_by_protocol)。

    同名同参数的重复节点只保留一份，避免 Clash / sing-box 里出现重复条目。
    """
    nodes = []
    skipped = {}
    seen = set()

    for category in PROTOCOL_CATEGORIES:
        for uri in sorted(final_configs.get(category, ())):
            node = parse_uri(uri)
            if node is None:
                skipped[category] = skipped.get(category, 0) + 1
                continue

            identity = tuple(sorted(
                (key, str(value)) for key, value in node.items() if key != 'name'
            ))
            if identity in seen:
                continue
            seen.add(identity)
            nodes.append(node)

    return nodes, skipped


FLAG_PATTERN = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
REGIONAL_BASE = 0x1F1E6

TYPE_LABELS = {
    'vmess': 'Vmess',
    'vless': 'Vless',
    'trojan': 'Trojan',
    'ss': 'SS',
    'ssr': 'SSR',
    'hysteria2': 'Hy2',
    'tuic': 'Tuic',
}


def _country_code(name):
    """从节点名里的国旗 emoji 还原国家/地区代码（🇺🇸 -> US）。"""
    match = FLAG_PATTERN.search(name or '')
    if not match:
        return ''
    letters = ''.join(chr(ord(ch) - REGIONAL_BASE + ord('A'))
                      for ch in match.group(0))
    return letters if letters.isalpha() else ''


def _flag_emoji(code):
    return ''.join(chr(REGIONAL_BASE + ord(ch) - ord('A')) for ch in code)


def assign_unique_names(nodes):
    """把节点名规范成 `🇺🇸 US-Vless-001` 这种可读且唯一的形式。

    源站给的节点名里混着大量广告（t.me 频道、机场推广）、纯编号和时间戳，
    直接显示在客户端里既难看也无法分辨。这里只保留国旗（服务商自己标的，
    比任何猜测都准）与协议信息，序号按协议 + 地址 + 端口稳定排序生成，
    保证每次运行同一节点拿到的名字不变，Clash 与 sing-box 两边也一致。
    """
    def sort_key(node):
        # 参数参与排序，避免同地址同端口但凭据不同的节点序号在两次运行间互换
        params = tuple(sorted((key, str(value)) for key, value in node.items()
                              if key != 'name'))
        return (node['type'], node['server'], node['port'], params)

    nodes.sort(key=sort_key)
    counters = {}
    for node in nodes:
        proto = TYPE_LABELS.get(node['type'], node['type'])
        index = counters.get(node['type'], 0) + 1
        counters[node['type']] = index

        code = _country_code(node.get('name'))
        prefix = f"{_flag_emoji(code)} {code}-" if code else ''
        node['name'] = f"{prefix}{proto}-{index:03d}"
    return nodes


def write_clash_config(nodes):
    proxies = []
    dropped = 0
    for node in nodes:
        proxy = clash_proxy(node)
        if proxy is None:
            dropped += 1
            continue
        proxies.append(proxy)
    if dropped:
        logging.warning(f"跳过 {dropped} 个 Clash 无法表达的节点")
    names = [proxy['name'] for proxy in proxies]

    groups = [{'name': '🚀 节点选择', 'type': 'select',
               'proxies': (['♻️ 自动选择'] if names else []) + ['DIRECT'] + names}]
    if names:
        groups.append({'name': '♻️ 自动选择', 'type': 'url-test',
                       'url': 'https://www.gstatic.com/generate_204',
                       'interval': 300, 'tolerance': 50,
                       'proxies': names})
    groups.append({'name': '🐟 漏网之鱼', 'type': 'select',
                   'proxies': ['🚀 节点选择', 'DIRECT']})

    config = {
        'mixed-port': 7890,
        'allow-lan': False,
        'mode': 'rule',
        'log-level': 'info',
        'ipv6': False,
        'external-controller': '127.0.0.1:9090',
        'proxies': proxies,
        'proxy-groups': groups,
        'rules': [
            'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
            'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
            'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
            'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
            'GEOIP,CN,DIRECT',
            'MATCH,🐟 漏网之鱼',
        ],
    }

    os.makedirs(CLASH_OUTPUT_DIR, exist_ok=True)
    config_path = os.path.join(CLASH_OUTPUT_DIR, 'config.yaml')
    with open(config_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('# Node-Configs 自动生成，配合 mihomo / Clash.Meta 内核使用\n')
        yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False,
                       default_flow_style=False, width=4096)

    provider_path = os.path.join(CLASH_OUTPUT_DIR, 'proxies.yaml')
    with open(provider_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('# Node-Configs 自动生成，可作为 proxy-provider 引用\n')
        yaml.safe_dump({'proxies': proxies}, f, allow_unicode=True,
                       sort_keys=False, default_flow_style=False, width=4096)

    logging.info(f"Saved {len(proxies)} proxies to {config_path}")
    return len(proxies)


def write_singbox_config(nodes):
    outbounds_nodes = []
    dropped = 0
    for node in nodes:
        outbound = singbox_outbound(node)
        if outbound is None:
            dropped += 1
            continue
        outbounds_nodes.append(outbound)
    if dropped:
        logging.warning(f"跳过 {dropped} 个 sing-box 不支持的节点（如 SSR / shadow-tls 插件）")

    tags = [outbound['tag'] for outbound in outbounds_nodes]

    outbounds = []
    outbounds.append({'type': 'selector', 'tag': '🚀 节点选择',
                      'outbounds': ((['♻️ 自动选择'] if tags else []) + ['DIRECT'] + tags)})
    if tags:
        outbounds.append({'type': 'urltest', 'tag': '♻️ 自动选择',
                          'outbounds': tags,
                          'url': 'https://www.gstatic.com/generate_204',
                          'interval': '5m', 'tolerance': 50})
    outbounds.extend(outbounds_nodes)
    outbounds.append({'type': 'direct', 'tag': 'DIRECT'})
    outbounds.append({'type': 'block', 'tag': 'BLOCK'})

    config = {
        'log': {'level': 'info', 'timestamp': True},
        'inbounds': [
            {'type': 'mixed', 'tag': 'mixed-in',
             'listen': '127.0.0.1', 'listen_port': 2080},
        ],
        'outbounds': outbounds,
        'route': {
            'rules': [
                {'ip_is_private': True, 'outbound': 'DIRECT'},
                {'protocol': 'dns', 'outbound': 'DIRECT'},
            ],
            'final': '🚀 节点选择',
            'auto_detect_interface': True,
        },
        'experimental': {'cache_file': {'enabled': True}},
    }

    os.makedirs(SINGBOX_OUTPUT_DIR, exist_ok=True)
    config_path = os.path.join(SINGBOX_OUTPUT_DIR, 'config.json')
    with open(config_path, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
        f.write('\n')

    # 只导出 outbounds，方便合并进已有配置
    outbounds_path = os.path.join(SINGBOX_OUTPUT_DIR, 'outbounds.json')
    with open(outbounds_path, 'w', encoding='utf-8', newline='\n') as f:
        json.dump({'outbounds': outbounds}, f, ensure_ascii=False, indent=2)
        f.write('\n')

    logging.info(f"Saved {len(nodes)} outbounds to {config_path}")
    return len(nodes)


def generate_readme(protocol_counts, convert_stats=None,
                    github_repo_path=GITHUB_REPO_PATH, github_branch=GITHUB_BRANCH):
    tz = pytz.timezone('Asia/Shanghai')
    now = datetime.now(tz)
    time_str = now.strftime("%H:%M")
    date_str = now.strftime("%Y-%m-%d")

    raw_protocols = f"https://raw.githubusercontent.com/{github_repo_path}/refs/heads/{github_branch}/configs/protocols"
    raw_clash = f"https://raw.githubusercontent.com/{github_repo_path}/refs/heads/{github_branch}/configs/clash"
    raw_singbox = f"https://raw.githubusercontent.com/{github_repo_path}/refs/heads/{github_branch}/configs/singbox"

    total_configs = sum(protocol_counts.values())
    convert_stats = convert_stats or {}
    converted = convert_stats.get('converted', 0)
    skipped = convert_stats.get('skipped', {})
    skipped_total = sum(skipped.values())
    merged_duplicates = max(total_configs - converted - skipped_total, 0)

    md = f"""# 🧩 Node-Configs

<p align="center">
  <img src="https://img.shields.io/github/license/{github_repo_path}?style=flat-square&color=blue" alt="License" />
  <img src="https://img.shields.io/badge/python-3.9%2B-3776AB?style=flat-square&logo=python" alt="Python 3.9+" />
  <img src="https://img.shields.io/github/actions/workflow/status/{github_repo_path}/main.yml?style=flat-square" alt="GitHub Workflow Status" />
  <img src="https://img.shields.io/github/last-commit/{github_repo_path}?style=flat-square" alt="Last Commit" />
  <br>
  <img src="https://img.shields.io/github/issues/{github_repo_path}?style=flat-square" alt="GitHub Issues" />
  <img src="https://img.shields.io/badge/Configs-{total_configs}-blue?style=flat-square" alt="Total Configs" />
  <img src="https://img.shields.io/github/stars/{github_repo_path}?style=social" alt="GitHub Stars" />
  <img src="https://img.shields.io/badge/status-active-brightgreen?style=flat-square" alt="Project Status" />
  <img src="https://img.shields.io/badge/language-中文%20%26%20English-007EC6?style=flat-square" alt="Language" />
</p>

## 最后更新: {time_str} {date_str}

---

## 📖 关于项目

自动从多个公开来源抓取网络节点，解析、去重后按协议分类，并同步转换成 **Clash / sing-box 可直接导入的完整配置**。
所有文件每 12 小时由 GitHub Actions 自动更新。

> 节点来源均为互联网公开数据，本项目只做聚合与格式转换，**不承诺任何节点的可用性与安全性**，请自行甄别。

---

## ⚡ 一键订阅

> 复制下面任意一条链接，粘贴到客户端的「订阅 / 远程配置」里即可，无需下载文件。

| 客户端 | 订阅链接 | 说明 |
|:---:|:---|:---|
| **Clash / mihomo**<br>Clash Verge / ClashX Meta / FlClash | [`configs/clash/config.yaml`]({raw_clash}/config.yaml) | 完整配置：节点 + 策略组 + 规则，导入即用 |
| **sing-box** | [`configs/singbox/config.json`]({raw_singbox}/config.json) | 完整配置：mixed 入站 + selector/urltest 出站 |
| **v2rayN / v2rayNG / NekoRay / Karing** | [`configs/protocols/AllProtocols.txt`]({raw_protocols}/AllProtocols.txt) | 原始分享链接，逐条导入 |

补充文件：
- Clash 只要节点列表（可作 proxy-provider）：[`configs/clash/proxies.yaml`]({raw_clash}/proxies.yaml)
- sing-box 只要出站列表（可合并进已有配置）：[`configs/singbox/outbounds.json`]({raw_singbox}/outbounds.json)

---

## 📊 概览

| 指标 | 数值 |
|:---|:---:|
| 分享链接总数 | {total_configs} |
| 无法转换的链接 | {skipped_total} |
| 重复节点（已合并） | {merged_duplicates} |
| **可转换唯一节点** | **{converted}** |

> 无法转换的链接通常是因为该协议暂不支持生成 Clash / sing-box 结构（如 WireGuard），原始链接仍在 `configs/protocols/` 中可用。

---

## 🛠️ 使用方法

**Clash / mihomo**
1. 复制上面的 `config.yaml` 订阅链接；
2. Clash Verge / ClashX Meta →「配置」→ 粘贴链接 → 导入；
3. 选择「🚀 节点选择」里的节点即可。

**sing-box**
1. 复制上面的 `config.json` 订阅链接（或用 `outbounds.json` 合并进已有配置）；
2. 启动后本地 `127.0.0.1:2080` 即为 mixed 代理端口（HTTP + SOCKS5）。

**v2rayN / v2rayNG / NekoRay / Karing**
1. 使用上面的 `AllProtocols.txt` 链接订阅，或到 `configs/protocols/` 目录按协议取对应文件；
2. 在客户端「从剪贴板导入 / 订阅」中导入。

> **建议**: 为获得最佳性能，请定期更新订阅。

---

## 📢 注意事项
- 本项目仅用于学习和研究目的，所有节点均来自互联网公开来源。
- 请根据您所在国家的法律法规负责任地使用。
- 如遇问题或建议，请使用 [Issues](https://github.com/{github_repo_path}/issues)。
"""

    try:
        with open(README_FILE, 'w', encoding='utf-8', newline='\n') as f:
            f.write(md)
        logging.info(f"Successfully generated {README_FILE}")
    except Exception as e:
        logging.error(f"Failed to write {README_FILE}: {e}")


def load_previous_converted():
    """读取上一次成功运行写下的节点数，用于判断本次是否异常。"""
    try:
        with open(STATS_FILE, 'r', encoding='utf-8') as f:
            return int(json.load(f).get('converted') or 0)
    except (OSError, ValueError, TypeError):
        return 0


def enforce_node_floor(converted, links):
    """节点数较上次骤降时中止。

    上游源集体挂掉时脚本仍会「成功」产出几百个节点，若直接提交就会把仓库里
    上千个有效节点覆盖成残缺版本，而且没有任何告警。这里做一道熔断。
    """
    previous = load_previous_converted()
    if previous < MIN_NODE_FLOOR:
        logging.info(f"上次节点数 {previous} 低于熔断基线 {MIN_NODE_FLOOR}，跳过检查")
        return

    ratio = converted / previous
    if ratio < MIN_NODE_RATIO:
        logging.critical(
            f"熔断：节点数从 {previous} 降到 {converted}（{ratio:.0%}，"
            f"阈值 {MIN_NODE_RATIO:.0%}），疑似上游源大面积失败。"
            "本次未写入任何文件，也不会提交。"
            f"确认是真实下降可删除 {os.path.basename(STATS_FILE)} 或调低 MIN_NODE_RATIO 后重跑。")
        raise SystemExit(3)

    logging.info(f"熔断检查通过：{converted} 个节点（上次 {previous}，{ratio:.0%}，"
                 f"链接 {links} 条）")


def save_stats(links, converted, clash_count, singbox_count, sources_ok,
               sources_total, skipped):
    payload = {
        'updated_at': datetime.now(pytz.timezone('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S'),
        'links': links,
        'converted': converted,
        'clash': clash_count,
        'singbox': singbox_count,
        'sources_ok': sources_ok,
        'sources_total': sources_total,
        'skipped': skipped,
    }
    try:
        with open(STATS_FILE, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=False)
            f.write('\n')
        logging.info(f"Saved stats to {STATS_FILE}")
    except Exception as e:
        logging.error(f"Failed to write {STATS_FILE}: {e}")


async def main():
    if not os.path.exists(URLS_FILE) or not os.path.exists(KEYWORDS_FILE):
        logging.critical("Input files not found.")
        return

    with open(URLS_FILE, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]
    with open(KEYWORDS_FILE, 'r', encoding='utf-8') as f:
        all_patterns = json.load(f)

    protocol_patterns = {
        category: patterns
        for category, patterns in all_patterns.items()
        if category in PROTOCOL_CATEGORIES
    }

    missing = [c for c in PROTOCOL_CATEGORIES if c not in protocol_patterns]
    if missing:
        logging.warning(f"key.json 中缺少以下协议的正则: {', '.join(missing)}")

    logging.info(f"Loaded {len(urls)} URLs and "
                 f"{len(protocol_patterns)} protocol categories from key.json.")

    sem = asyncio.Semaphore(CONCURRENT_REQUESTS)

    async def fetch_with_sem(session, url_to_fetch):
        async with sem:
            return await fetch_url(session, url_to_fetch)

    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT * FETCH_RETRIES + 10)
    headers = {'User-Agent': USER_AGENT, 'Accept': '*/*'}
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        fetched_pages = await asyncio.gather(*[fetch_with_sem(session, u) for u in urls])

    final_configs = {category: set() for category in protocol_patterns}
    filter_totals = {'i_love_': 0, 'percent25': 0, 'too_long': 0,
                     'double_encoded': 0, 'reclassified': 0}

    logging.info("Processing pages for config extraction...")
    for url, text in fetched_pages:
        if not text:
            logging.warning(f"No content parsed from: {url}")
            continue

        page_matches, stats = find_matches(text, protocol_patterns)
        page_total = 0
        for category, configs in page_matches.items():
            final_configs[category].update(configs)
            page_total += len(configs)
        for key, value in stats.items():
            filter_totals[key] += value

        logging.info(f"Parsed {page_total} configs from {url}")

    filtered = {k: v for k, v in filter_totals.items() if k != 'reclassified' and v}
    if filtered:
        logging.info("Filtered out: " + ", ".join(f"{k}={v}" for k, v in filtered.items()))
    if filter_totals['reclassified']:
        logging.info(f"Reclassified {filter_totals['reclassified']} mislabeled "
                     f"ss:// configs as vless://")

    # 汇总所有协议（先算总数，供熔断判断用）
    all_protocols_combined = set()
    for configs in final_configs.values():
        all_protocols_combined.update(configs)

    # 解析出统一节点结构；先做熔断判断，异常时一个文件都不写
    nodes, skipped = collect_nodes(final_configs)
    assign_unique_names(nodes)
    enforce_node_floor(len(nodes), len(all_protocols_combined))

    if os.path.exists(PROTOCOL_OUTPUT_DIR):
        shutil.rmtree(PROTOCOL_OUTPUT_DIR)
    os.makedirs(PROTOCOL_OUTPUT_DIR, exist_ok=True)
    logging.info(f"Saving protocol files to directory: {PROTOCOL_OUTPUT_DIR}")

    protocol_counts = {}
    for category in PROTOCOL_CATEGORIES:
        count = save_to_file(PROTOCOL_OUTPUT_DIR, category, final_configs.get(category, set()))
        if count:
            protocol_counts[category] = count
    save_to_file(PROTOCOL_OUTPUT_DIR, "AllProtocols", all_protocols_combined)

    # 生成 Clash / sing-box 配置
    clash_count = write_clash_config(nodes)
    singbox_count = write_singbox_config(nodes)

    if skipped:
        logging.info("Unconvertible links: " +
                     ", ".join(f"{k}={v}" for k, v in sorted(skipped.items())))

    convert_stats = {'converted': len(nodes), 'clash': clash_count,
                     'singbox': singbox_count, 'skipped': skipped}
    generate_readme(protocol_counts, convert_stats=convert_stats,
                    github_repo_path=GITHUB_REPO_PATH, github_branch=GITHUB_BRANCH)

    sources_ok = sum(1 for _, text in fetched_pages if text)
    save_stats(len(all_protocols_combined), len(nodes), clash_count,
               singbox_count, sources_ok, len(urls), skipped)

    logging.info(f"Total unique links: {len(all_protocols_combined)}")
    logging.info(f"Converted nodes: {len(nodes)} (clash={clash_count}, sing-box={singbox_count})")
    logging.info(f"Sources: {sources_ok}/{len(urls)} fetched")
    logging.info("--- Script Finished ---")


if __name__ == "__main__":
    asyncio.run(main())
