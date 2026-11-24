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

import health
from converters import (clash_proxy, is_valid_ss, parse_uri,
                        sanitize_clash_proxy, sanitize_singbox_outbound,
                        singbox_outbound)

# 获取当前脚本所在目录的绝对路径
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))

# 使用绝对路径引用文件
URLS_FILE = os.path.join(SCRIPT_DIR, 'urls.txt')
KEYWORDS_FILE = os.path.join(SCRIPT_DIR, 'key.json')
PROTOCOL_OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'configs/protocols')
CLASH_OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'configs/clash')
CLASH_SPLIT_DIR = os.path.join(PROJECT_ROOT, 'configs/clash/split')
SINGBOX_OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'configs/singbox')
STATUS_FILE = os.path.join(PROJECT_ROOT, 'configs/status.json')
README_FILE = os.path.join(PROJECT_ROOT, 'README.md')
STATS_FILE = os.path.join(PROJECT_ROOT, 'stats.json')

REQUEST_TIMEOUT = 20
CONCURRENT_REQUESTS = 10
FETCH_RETRIES = 3
MAX_CONFIG_LENGTH = 1500
MIN_PERCENT25_COUNT = 15

# 分片：单文件节点太多时手机端解析会明显变慢，按协议切成每片不超过 N 个
SPLIT_CHUNK = int(os.environ.get('SPLIT_CHUNK', '300'))

# 熔断参数：可用节点数低于上次的 60% 且上次已超过 300 个时视为异常，直接中止
MIN_NODE_RATIO = float(os.environ.get('MIN_NODE_RATIO', '0.6'))
MIN_NODE_FLOOR = int(os.environ.get('MIN_NODE_FLOOR', '300'))

GITHUB_REPO_PATH = 'looomix/Node-Configs'
GITHUB_BRANCH = 'main'

# 形如数字 / 布尔 / null 的字符串必须显式加引号。
# PyYAML 按 YAML 1.1 判断要不要加引号，而 mihomo 用的是 YAML 1.2：
# `short-id: 08` 在 1.1 里是字符串、在 1.2 里是整数 8，客户端解码十六进制失败后
# 直接拒绝加载整份配置。密码、short-id 这类字段经常是纯数字，必须兜住。
RISKY_SCALAR = re.compile(
    r'^(?:'
    r'[-+]?(?:\d[\d_]*(?:\.[\d_]*)?|\.[\d_]+)(?:[eE][-+]?\d+)?'
    r'|y|n|yes|no|true|false|on|off|null|none|~'
    r')$',
    re.IGNORECASE,
)


class ConfigDumper(yaml.SafeDumper):
    """字符串一律安全输出，避免被读成数字/布尔。"""


def _represent_str(dumper, data):
    style = '"' if RISKY_SCALAR.match(data) or data != data.strip() else None
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style=style)


ConfigDumper.add_representer(str, _represent_str)

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
    userinfo = re.split(r'@', body, maxsplit=1)[0]
    if not UUID_PATTERN.match(userinfo):
        return False

    lowered = config.lower()
    return ('security=' in lowered or 'encryption=' in lowered
            or 'pbk=' in lowered or 'flow=' in lowered)


SCHEME_BOUNDARY = re.compile(
    r'(?=(?:vmess|vless|trojan|ssr|ss|shadowsocks|hysteria2|hy2|tuic5|tuic|wireguard)://)',
    re.IGNORECASE,
)

# scheme 名按长度倒序，用于判断某个 `xx://` 是否其实是更长 scheme 的尾巴
SCHEME_NAMES = ('shadowsocks', 'wireguard', 'hysteria2', 'trojan', 'vless',
                'vmess', 'tuic5', 'tuic', 'ssr', 'hy2', 'ss')

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


def _is_scheme_tail(config, position, token):
    """判断 position 处的 `token://` 是不是更长 scheme 的尾巴（`vless://` 里的 `ss://`）。"""
    for name in SCHEME_NAMES:
        if name == token or not name.endswith(token):
            continue
        start = position - (len(name) - len(token))
        if start < 0:
            continue
        if (config[start:position + len(token)].lower() == name
                and config[position + len(token):position + len(token) + 3] == '://'):
            return True
    return False


def split_glued_links(config):
    """源站偶尔把两条链接直接粘在一起，这里按 scheme 边界拆开。

    注意 `vless://` / `vmess://` 的第 4 个字符起就是 `ss://`，直接把零宽断言
    当分隔符用会把 `vless://a` 切成 `vle` + `ss://a`，两条节点一起报废。
    所以每个候选位置都要先回看，确认它不是更长 scheme 的尾巴。
    """
    if config.count('://') < 2:
        return [config]

    starts = []
    for match in SCHEME_BOUNDARY.finditer(config):
        position = match.start()
        token = config[position:].split('://', 1)[0].lower()
        if _is_scheme_tail(config, position, token):
            continue
        starts.append(position)

    if not starts:
        return [config]
    pieces = [config[start:end]
              for start, end in zip(starts, starts[1:] + [len(config)])]
    return [piece for piece in pieces if piece] or [config]


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


def build_clash_proxies(nodes):
    """节点 -> Clash proxy 列表，每个都过了白名单闸。"""
    proxies = []
    reasons = {}
    for node in nodes:
        proxy, reason = sanitize_clash_proxy(clash_proxy(node), node)
        if proxy is None:
            reasons[reason] = reasons.get(reason, 0) + 1
            continue
        proxies.append(proxy)
    if reasons:
        detail = ", ".join(f"{k}={v}" for k, v in sorted(reasons.items()))
        logging.warning(f"跳过 {sum(reasons.values())} 个会让 mihomo 拒绝加载的节点（{detail}）")
    return proxies


def clash_document(proxies):
    """把节点列表包成一份完整的 Clash 配置（含策略组与规则）。"""
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

    return {
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


def dump_clash(document, path, header):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        if header:
            f.write(header)
        yaml.dump(document, f, Dumper=ConfigDumper, allow_unicode=True,
                  sort_keys=False, default_flow_style=False, width=4096)


def write_clash_config(proxies, path=None, write_provider=True):
    """写出 Clash 配置；proxies 已经过白名单闸，这里只负责落盘。"""
    if path is None:
        path = os.path.join(CLASH_OUTPUT_DIR, 'config.yaml')
    if write_provider:
        # 主配置旁边同时留一份仅节点的 provider 文件
        dump_clash({'proxies': proxies},
                   os.path.join(CLASH_OUTPUT_DIR, 'proxies.yaml'),
                   '# Node-Configs 自动生成，可作为 proxy-provider 引用\n')
    dump_clash(clash_document(proxies), path,
               '# Node-Configs 自动生成，配合 mihomo / Clash.Meta 内核使用\n')
    logging.info(f"Saved {len(proxies)} proxies to {path}")
    return path


def write_clash_splits(proxies, chunk=None):
    """按协议把节点切成若干片，供 proxy-provider 分批加载。

    单文件两千多个节点在 iOS 的 Stash / Shadowrocket 里解析会明显卡顿，
    切成每片 ≤300 个后可以只订阅自己需要的协议。
    """
    chunk = max(1, int(chunk or SPLIT_CHUNK))
    if not proxies:
        return []
    if os.path.isdir(CLASH_SPLIT_DIR):
        shutil.rmtree(CLASH_SPLIT_DIR)
    os.makedirs(CLASH_SPLIT_DIR, exist_ok=True)

    buckets = {}
    for proxy in proxies:
        buckets.setdefault(proxy['type'], []).append(proxy)

    written = []
    for ptype in sorted(buckets):
        items = buckets[ptype]
        for part_index, start in enumerate(range(0, len(items), chunk), 1):
            part = items[start:start + chunk]
            name = f'{ptype}-{part_index}.yaml'
            dump_clash({'proxies': part}, os.path.join(CLASH_SPLIT_DIR, name),
                       f'# Node-Configs 分片 {ptype} 第 {part_index} 片，'
                       f'{len(part)} 个节点，可作为 proxy-provider\n')
            written.append((name, len(part)))
    logging.info(f"生成 {len(written)} 个分片，共覆盖 {len(proxies)} 个节点")
    return written


# 移动端轻量版保留的协议：hysteria2 / tuic 走 QUIC，弱网下握手成功率最高；
# vless 只留 REALITY（不需要自签证书，被中间设备干扰的概率最低）。
LIGHT_TYPES = frozenset({'hysteria2', 'tuic'})


def select_light_nodes(nodes):
    return [node for node in nodes
            if node['type'] in LIGHT_TYPES
            or (node['type'] == 'vless' and node.get('reality_pbk'))]


def build_singbox_outbounds(nodes):
    """节点 -> sing-box outbound 列表，每个都过了白名单闸。"""
    outbounds_nodes = []
    reasons = {}
    for node in nodes:
        outbound, reason = sanitize_singbox_outbound(singbox_outbound(node), node)
        if outbound is None:
            reasons[reason] = reasons.get(reason, 0) + 1
            continue
        outbounds_nodes.append(outbound)
    if reasons:
        detail = ", ".join(f"{k}={v}" for k, v in sorted(reasons.items()))
        logging.warning(f"跳过 {sum(reasons.values())} 个 sing-box 不支持的节点（{detail}）")
    return outbounds_nodes


def singbox_document(outbounds_nodes):
    tags = [outbound['tag'] for outbound in outbounds_nodes]

    outbounds = [{'type': 'selector', 'tag': '🚀 节点选择',
                  'outbounds': ((['♻️ 自动选择'] if tags else []) + ['DIRECT'] + tags)}]
    if tags:
        outbounds.append({'type': 'urltest', 'tag': '♻️ 自动选择',
                          'outbounds': tags,
                          'url': 'https://www.gstatic.com/generate_204',
                          'interval': '5m', 'tolerance': 50})
    outbounds.extend(outbounds_nodes)
    outbounds.append({'type': 'direct', 'tag': 'DIRECT'})
    outbounds.append({'type': 'block', 'tag': 'BLOCK'})

    return {
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


def dump_singbox(document, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(document, f, ensure_ascii=False, indent=2)
        f.write('\n')


def write_singbox_config(outbounds_nodes, path=None, write_provider=True):
    """写出 sing-box 配置；outbounds_nodes 已过白名单闸。"""
    if path is None:
        path = os.path.join(SINGBOX_OUTPUT_DIR, 'config.json')
    if write_provider:
        # 只导出 outbounds，方便合并进已有配置
        dump_singbox({'outbounds': singbox_document(outbounds_nodes)['outbounds']},
                     os.path.join(SINGBOX_OUTPUT_DIR, 'outbounds.json'))
    dump_singbox(singbox_document(outbounds_nodes), path)
    logging.info(f"Saved {len(outbounds_nodes)} outbounds to {path}")
    return path


def generate_readme(protocol_counts, convert_stats=None,
                    github_repo_path=GITHUB_REPO_PATH, github_branch=GITHUB_BRANCH):
    tz = pytz.timezone('Asia/Shanghai')
    now = datetime.now(tz)
    time_str = now.strftime("%H:%M")
    date_str = now.strftime("%Y-%m-%d")

    raw_protocols = f"https://raw.githubusercontent.com/{github_repo_path}/refs/heads/{github_branch}/configs/protocols"
    raw_clash = f"https://raw.githubusercontent.com/{github_repo_path}/refs/heads/{github_branch}/configs/clash"
    raw_singbox = f"https://raw.githubusercontent.com/{github_repo_path}/refs/heads/{github_branch}/configs/singbox"

    # 镜像：国内直连 raw.githubusercontent.com 常被中断（Android 端报 EOF），
    # 统一走 gh-proxy.com 前缀转发，链接格式就是「镜像前缀 + 原始 raw 地址」。
    proxy_clash = f"https://gh-proxy.com/{raw_clash}"
    proxy_singbox = f"https://gh-proxy.com/{raw_singbox}"
    proxy_protocols = f"https://gh-proxy.com/{raw_protocols}"

    total_configs = sum(protocol_counts.values())
    convert_stats = convert_stats or {}
    converted = convert_stats.get('converted', 0)
    # 徽章展示真正写进配置的节点数：解析出来但被客户端白名单拦掉的节点
    # （xhttp 传输层、2022 密钥长度不对等）不该算进「可用节点」。
    available = convert_stats.get('clash') or converted
    light_count = convert_stats.get('light') or 0
    xhttp_count = convert_stats.get('xhttp') or 0

    health = convert_stats.get('health') or {}
    reason = health.get('skipped_reason')
    if reason == 'disabled':
        health_line = "本次运行未启用存活探测"
    elif reason == 'probe-unreliable':
        health_line = ("本次存活探测的连通率过低，判定为探测环境异常，"
                       "已跳过按探测结果剔除（节点数未受影响）")
    elif reason == 'too-many-dead':
        health_line = (f"本次探测有 {health.get('unreachable', 0)}/{health.get('checked', 0)} "
                       f"个地址拒绝连接，超过阈值，按探测环境异常处理，未剔除")
    elif reason == 'too-few-nodes':
        health_line = "节点样本过少，跳过存活探测剔除"
    elif health.get('checked'):
        ratio = health.get('alive_ratio') or 0
        health_line = (
            f"最近一次 TCP 探测：{health.get('alive', 0)}/{health.get('checked', 0)} 可连通"
            f"（<b>{ratio:.0%}</b>），已剔除 {health.get('dropped', 0)} 个拒绝连接的地址")
    else:
        health_line = "本次运行未启用存活探测"

    if xhttp_count:
        xhttp_note = (
            f"> 配置里含 <b>{xhttp_count}</b> 个 `network: xhttp` 节点（Xray 的 splithttp 传输）。\n"
            "> **需要 mihomo ≥ 1.19**（Clash Verge Rev 1.7+、FlClash 0.8+ 均已内置）；\n"
            "> 低于这个版本的客户端会因 `unsupported network` 拒绝加载整份配置，"
            "请改用「轻量版」。\n")
        xhttp_faq = (
            f"配置里有 {xhttp_count} 个 xhttp（splithttp）节点，需要 mihomo ≥ 1.19。"
            "老版本客户端遇到不认识的传输层会**拒绝加载整份配置**，改用 "
            f"[`light.yaml`]({raw_clash}/light.yaml)（不含 xhttp）即可，"
            "或升级到 Clash Verge Rev 1.7+ / FlClash 0.8+。")
    else:
        xhttp_note = ""
        xhttp_faq = ("本批节点里没有 xhttp 传输层的节点，任何 mihomo 版本都能直接导入。"
                     f"如需规避个别协议的兼容问题，可以改用 [`light.yaml`]({raw_clash}/light.yaml)。")

    md = f"""# 🧩 Node-Configs

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/{github_repo_path}/main.yml?style=flat-square&label=update" alt="Update Status" />
  <img src="https://img.shields.io/badge/nodes-{available}-blue?style=flat-square" alt="Nodes" />
  <img src="https://img.shields.io/badge/links-{total_configs}-informational?style=flat-square" alt="Links" />
  <img src="https://img.shields.io/badge/python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.9+" />
  <img src="https://img.shields.io/github/last-commit/{github_repo_path}?style=flat-square" alt="Last Commit" />
  <img src="https://img.shields.io/github/stars/{github_repo_path}?style=social" alt="Stars" />
</p>

<p align="center">
  从公开来源自动聚合网络节点，转换成 <b>Clash / mihomo</b> 与 <b>sing-box</b> 可直接导入的订阅配置<br>
  每 12 小时自动更新 · 最后更新 <b>{date_str} {time_str}</b><br>
  <sub>{health_line}</sub>
</p>

## ⚡ 快速订阅

复制链接，粘贴到客户端的「订阅 / 远程配置」即可，无需下载文件。

| 客户端 | 订阅链接（raw） | 镜像链接（gh-proxy） | 内容 |
|:---|:---|:---|:---|
| **Clash / mihomo**<br><sub>Clash Verge · ClashX Meta · FlClash</sub> | [`config.yaml`]({raw_clash}/config.yaml) | [`config.yaml`]({proxy_clash}/config.yaml) | 节点 + 策略组 + 规则，导入即用 |
| **sing-box** | [`config.json`]({raw_singbox}/config.json) | [`config.json`]({proxy_singbox}/config.json) | mixed 入站 + selector / urltest 出站 |
| **v2rayN / v2rayNG**<br><sub>NekoRay · Karing · Hiddify</sub> | [`AllProtocols.txt`]({raw_protocols}/AllProtocols.txt) | [`AllProtocols.txt`]({proxy_protocols}/AllProtocols.txt) | 原始分享链接 |
| **轻量版**（{light_count} 节点）<br><sub>只含 hy2 / tuic / vless-reality</sub> | [`light.yaml`]({raw_clash}/light.yaml) · [`light.json`]({raw_singbox}/light.json) | [Clash]({proxy_clash}/light.yaml) · [sing-box]({proxy_singbox}/light.json) | 弱网 / 移动端首选，解析最快 |

如果只想复用节点、不想用本项目提供的规则：

- Clash： [`proxies.yaml`]({raw_clash}/proxies.yaml) · [镜像]({proxy_clash}/proxies.yaml) — 可作为 `proxy-provider`
- sing-box： [`outbounds.json`]({raw_singbox}/outbounds.json) · [镜像]({proxy_singbox}/outbounds.json) — 可合并进已有配置
- 分片： `configs/clash/split/<协议>-<序号>.yaml`，每片 ≤300 个节点，适合按协议单独订阅

> **raw 链接导入报 `EOF` / `connection reset`？** 这不是配置错误，是国内直连
> `raw.githubusercontent.com` 被中断。用右边那列 **gh-proxy 镜像**即可，它的规则就是
> 「`https://gh-proxy.com/` + 原始 raw 地址」，例如 Clash：
> `https://gh-proxy.com/https://raw.githubusercontent.com/{github_repo_path}/{github_branch}/configs/clash/config.yaml`

## 🛠️ 客户端配置

**Clash / mihomo** —— 混合端口 `7890`，控制面板 `127.0.0.1:9090`

1. 「配置」→ 粘贴上面的 `config.yaml` 链接 → 导入；
2. 策略组选 `🚀 节点选择`（手动）或 `♻️ 自动选择`（每 5 分钟测速取最快）；
3. 规则为「局域网与国内直连，其余走 `🐟 漏网之鱼`」。

{xhttp_note}
**sing-box** —— mixed 入站 `127.0.0.1:2080`（HTTP + SOCKS5）

1. 直接使用 `config.json`，或用 `outbounds.json` 替换已有配置的出站部分；
2. 修改端口只需改 `inbounds[0].listen_port`；
3. sing-box 不支持 xhttp 与 SSR，这两类节点只会出现在 Clash 配置里。

**v2rayN / v2rayNG / NekoRay / Karing**

1. 订阅 `AllProtocols.txt`，或到 `configs/protocols/` 取单个协议文件；
2. 客户端「从剪贴板导入 / 订阅」中导入即可。

## 📁 目录结构

```text
Node-Configs/
├── configs/
│   ├── clash/
│   │   ├── config.yaml      # 完整配置：节点 + 策略组 + 规则
│   │   ├── light.yaml       # 轻量版：只含 hy2 / tuic / vless-reality
│   │   ├── proxies.yaml     # 仅节点，可作 proxy-provider
│   │   └── split/           # 按协议分片，每片 ≤300 节点
│   ├── singbox/
│   │   ├── config.json      # 完整配置：mixed 入站 + 出站
│   │   ├── light.json       # 轻量版
│   │   └── outbounds.json   # 仅出站，可合并进已有配置
│   ├── protocols/           # 原始分享链接，按协议分文件
│   │   ├── AllProtocols.txt
│   │   ├── Vless.txt / Vmess.txt / Trojan.txt
│   │   └── ShadowSocks.txt / Hysteria2.txt
│   └── status.json          # 最近一次存活探测结果（按协议分列）
├── Files/
│   ├── scrip.py             # 抓取、解析、生成入口
│   ├── converters.py        # 分享链接 → Clash / sing-box 结构
│   ├── health.py            # 节点 TCP 连通性探测
│   ├── check_config.py      # 提交前字段自检
│   ├── tests/               # pytest 用例
│   ├── key.json             # 各协议正则
│   └── urls.txt             # 节点来源列表
├── stats.json               # 最近一次运行统计（供熔断对比）
└── README.md
```

## 🔄 自动更新

- `schedule` 每 12 小时跑一次，也可在 Actions 页手动 `workflow_dispatch`；
- 修改 `Files/**` 或工作流本身会立即触发一次重建；
- **存活探测**：生成配置前对每个节点做一次 TCP 连接（3 秒超时、并发 100），
  只做 TCP 不握 TLS —— REALITY 节点会主动拒绝指纹不对的 ClientHello，
  TLS 结果反而会误杀好节点。端口拒绝 / 域名解析失败的直接剔除；
  超时的保留（可能是探测环境问题）。剔除比例超过 50% 时判定为探测环境异常，整批保留；
- **熔断**：本次可用节点数低于上次 60% 时直接失败退出，不写入、不提交；
- **源健康度**：每个源解析出的节点数记录在 `stats.json`，连续 2 次为 0 会在 Actions 日志里标红；
- **校验**：`pytest` 跑转换器单测 → `check_config.py` 按客户端白名单检查每个字段 →
  用 mihomo 与 sing-box 真实内核各加载一次。任何一步失败都阻止提交；
- 想加源只需编辑 `Files/urls.txt`（每行一个地址，支持 base64 订阅与纯文本），推送后自动生效。

## ❓ 常见问题

<details>
<summary><b>导入后节点大面积超时？</b></summary>

公开节点存活周期很短，换节点或稍后重新订阅通常即可恢复。建议先用 `♻️ 自动选择`，它会自动挑当前延迟最低的节点。项目每 12 小时会做一次 TCP 探测并把结果写进 `configs/status.json`，可以先看那里的存活率再判断是不是上游整体挂了。
</details>

<details>
<summary><b>报 <code>unsupported network: xhttp</code> 怎么办？</b></summary>

{xhttp_faq}
</details>

<details>
<summary><b>节点名 <code>🇺🇸 US-Vless-001</code> 是什么含义？</b></summary>

`国旗 + 国家码 + 协议 + 序号`。国家码由源站自带的国旗 emoji 反推，不做文本猜测；源站没标国旗的节点只有协议与序号。名字按节点参数稳定排序，但上游增删节点时序号仍可能变动。
</details>

<details>
<summary><b>端口被占用怎么改？</b></summary>

Clash 改 `mixed-port`（默认 `7890`）与 `external-controller`（默认 `9090`）；sing-box 改 `inbounds[0].listen_port`（默认 `2080`）。更推荐用 `proxies.yaml` / `outbounds.json` 合并进自己的配置，避免每次更新被覆盖。
</details>

<details>
<summary><b>导入时报 <code>unknown method</code> / <code>invalid REALITY short ID</code> 之类的错误？</b></summary>

这两个客户端遇到不认识的字段值是**拒绝加载整份配置**，而不是跳过单个节点。本仓库在生成时会按 mihomo / sing-box 的白名单过滤（加密方式、UUID、REALITY 密钥、传输层类型等），并在提交前用真实内核跑一遍校验，所以正常情况下不会再有这类报错。

如果仍然遇到，说明拿到的是旧缓存：raw 链接加 `?t=时间戳`（镜像链接同样支持，把
`?t=` 加在整条地址末尾即可）再导入一次。
</details>

<details>
<summary><b>为什么某些协议没有出现？</b></summary>

只保留能解析为合法 URI 且能被目标客户端表达的节点：sing-box 不支持 SSR 与 xhttp，这两类只进 Clash 配置；加密方式、密钥长度不合法的节点会被两侧同时丢弃，避免一条坏节点拖垮整份配置。个别源站把两条链接粘在一起或截断，这类残片会被丢弃并计入「无法转换」。
</details>

## ⚠️ 免责声明

- 本项目仅做公开数据的聚合与格式转换，**不托管、不提供、不保证**任何节点的可用性与安全性；
- 所有节点均来自互联网公开来源，请在遵守所在地法律法规的前提下使用；
- 使用风险自负，因使用本项目内容造成的任何后果由使用者自行承担；
- 问题与建议请提交 [Issues](https://github.com/{github_repo_path}/issues)。
"""

    try:
        with open(README_FILE, 'w', encoding='utf-8', newline='\n') as f:
            f.write(md)
        logging.info(f"Successfully generated {README_FILE}")
    except Exception as e:
        logging.error(f"Failed to write {README_FILE}: {e}")


def load_previous_stats():
    """读取上一次成功运行的统计，用于熔断对比与源健康度累计。"""
    try:
        with open(STATS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _stat_int(stats, *keys):
    for key in keys:
        try:
            value = int(stats.get(key) or 0)
        except (TypeError, ValueError):
            continue
        if value:
            return value
    return 0


def enforce_node_floor(available, links, previous_stats=None):
    """可用节点数较上次骤降时中止。

    口径是「真正写进 Clash 配置的节点数」。之前比的是解析数，出现白名单一次性
    拦掉几百个节点、或者新加的存活探测清掉一批时，熔断完全没反应，等于没装。
    上游源集体挂掉时脚本仍会「成功」产出几百个节点，若直接提交就会把仓库里
    上千个有效节点覆盖成残缺版本，所以这道闸必须在写文件之前。
    """
    stats = previous_stats if previous_stats is not None else load_previous_stats()
    previous = _stat_int(stats, 'clash', 'converted')
    if previous < MIN_NODE_FLOOR:
        logging.info(f"上次可用节点数 {previous} 低于熔断基线 {MIN_NODE_FLOOR}，跳过检查")
        return

    ratio = available / previous
    if ratio < MIN_NODE_RATIO:
        logging.critical(
            f"熔断：可用节点数从 {previous} 降到 {available}（{ratio:.0%}，"
            f"阈值 {MIN_NODE_RATIO:.0%}），疑似上游源大面积失败或探测环境异常。"
            "本次未写入任何文件，也不会提交。"
            f"确认是真实下降可删除 {os.path.basename(STATS_FILE)} 或调低 MIN_NODE_RATIO 后重跑。")
        raise SystemExit(3)

    logging.info(f"熔断检查通过：{available} 个可用节点（上次 {previous}，"
                 f"{ratio:.0%}，链接 {links} 条）")


def report_source_health(source_counts, previous_stats):
    """累计每个源连续零产出的次数，并把问题源标进 Actions 日志。

    `sources_ok` 只看「有没有返回内容」，返回一页 404/HTML 也算成功，
    源悄悄失效时没有任何信号。这里按「解析出的节点数」判断：
    连续 2 次为 0 就用 error 注解标红，单次为 0 给一条 warning。
    """
    streaks = previous_stats.get('source_zero_streak')
    streaks = streaks if isinstance(streaks, dict) else {}

    new_streaks = {}
    for url, count in source_counts.items():
        try:
            streak = int(streaks.get(url) or 0)
        except (TypeError, ValueError):
            streak = 0
        if count:
            new_streaks[url] = 0
            continue
        streak += 1
        new_streaks[url] = streak
        if streak >= 2:
            logging.error(f"源连续 {streak} 次解析出 0 个节点：{url}")
            print(f"::error::节点源连续 {streak} 次解析出 0 个节点：{url}")
        else:
            logging.warning(f"源本次解析出 0 个节点：{url}")
            print(f"::warning::节点源本次解析出 0 个节点：{url}")
    return new_streaks


def save_stats(links, converted, clash_count, singbox_count, sources_ok,
               sources_total, skipped, source_counts=None, source_streaks=None,
               health_summary=None, splits=None, light_count=0):
    health_summary = health_summary or {}
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
    if health_summary:
        payload['health'] = {
            'checked': health_summary.get('checked', 0),
            'alive': health_summary.get('alive', 0),
            'unreachable': health_summary.get('unreachable', 0),
            'unknown': health_summary.get('unknown', 0),
            'alive_ratio': health_summary.get('alive_ratio', 0),
            'dropped': health_summary.get('dropped', 0),
        }
        if health_summary.get('skipped_reason'):
            payload['health']['skipped_reason'] = health_summary['skipped_reason']
    if light_count:
        payload['light'] = light_count
    if splits:
        payload['splits'] = len(splits)
    if source_counts:
        payload['sources'] = dict(sorted(source_counts.items()))
    if source_streaks is not None:
        payload['source_zero_streak'] = dict(sorted(source_streaks.items()))

    try:
        with open(STATS_FILE, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=False)
            f.write('\n')
        logging.info(f"Saved stats to {STATS_FILE}")
    except Exception as e:
        logging.error(f"Failed to write {STATS_FILE}: {e}")


async def main():
    if not os.path.exists(URLS_FILE) or not os.path.exists(KEYWORDS_FILE):
        # 静默 return 会让 CI 继续用仓库里的旧配置"通过"校验并提交无变化的空跑
        logging.critical("Input files not found: %s / %s", URLS_FILE, KEYWORDS_FILE)
        raise SystemExit(1)

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

    # 每个源解析出的节点数：0 条意味着源失效，退回 HTML / 空订阅，
    # 只看「有没有返回内容」是发现不了的
    source_counts = {url: 0 for url in urls}

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

        source_counts[url] = page_total
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

    previous_stats = load_previous_stats()
    source_streaks = report_source_health(source_counts, previous_stats)

    # 解析出统一节点结构
    nodes, skipped = collect_nodes(final_configs)
    assign_unique_names(nodes)

    # 存活探测：只剔除「端口拒绝 / 域名解析失败」的地址，探测环境异常时整批保留
    nodes, health_summary = await health.check(nodes)

    # 先算可用节点数（Clash 实际写入量）再做熔断，异常时一个文件都不写
    proxies = build_clash_proxies(nodes)
    outbounds_nodes = build_singbox_outbounds(nodes)
    enforce_node_floor(len(proxies), len(all_protocols_combined), previous_stats)
    health.save_status(health_summary, STATUS_FILE)

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
    clash_count = len(proxies)
    singbox_count = len(outbounds_nodes)
    write_clash_config(proxies)
    write_singbox_config(outbounds_nodes)
    splits = write_clash_splits(proxies)

    # 轻量版：直接复用已过闸的条目，避免对同一批节点重复跑一遍校验
    light_names = {node['name'] for node in select_light_nodes(nodes)}
    light_proxies = [proxy for proxy in proxies if proxy['name'] in light_names]
    light_outbounds = [outbound for outbound in outbounds_nodes
                       if outbound['tag'] in light_names]
    write_clash_config(light_proxies, os.path.join(CLASH_OUTPUT_DIR, 'light.yaml'),
                       write_provider=False)
    write_singbox_config(light_outbounds, os.path.join(SINGBOX_OUTPUT_DIR, 'light.json'),
                         write_provider=False)

    if skipped:
        logging.info("Unconvertible links: " +
                     ", ".join(f"{k}={v}" for k, v in sorted(skipped.items())))

    sources_ok = sum(1 for _, text in fetched_pages if text)

    convert_stats = {'converted': len(nodes), 'clash': clash_count,
                     'singbox': singbox_count, 'skipped': skipped,
                     'health': health_summary, 'light': len(light_proxies),
                     'xhttp': sum(1 for proxy in proxies
                                  if proxy.get('network') == 'xhttp')}
    generate_readme(protocol_counts, convert_stats=convert_stats,
                    github_repo_path=GITHUB_REPO_PATH, github_branch=GITHUB_BRANCH)

    save_stats(len(all_protocols_combined), len(nodes), clash_count,
               singbox_count, sources_ok, len(urls), skipped,
               source_counts=source_counts, source_streaks=source_streaks,
               health_summary=health_summary, splits=splits,
               light_count=len(light_proxies))

    logging.info(f"Total unique links: {len(all_protocols_combined)}")
    logging.info(f"Converted nodes: {len(nodes)} (clash={clash_count}, "
                 f"sing-box={singbox_count}, light={len(light_proxies)}, "
                 f"splits={len(splits)})")
    logging.info(f"Sources: {sources_ok}/{len(urls)} fetched")
    logging.info("--- Script Finished ---")


if __name__ == "__main__":
    asyncio.run(main())
