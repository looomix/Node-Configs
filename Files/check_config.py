"""发布前自检：确认生成的 Clash / sing-box 配置能被客户端加载。

mihomo 与 sing-box 遇到「不认识的字段值」时不会跳过该节点，而是拒绝加载整份
配置，用户看到的就是「无法导入」。这个脚本在提交前把所有已知会触发整体失败的
情况再验一遍，有问题直接让 CI 变红，避免坏配置被推到线上。

白名单一律从 converters 里取，不再各写一份 —— 之前 check_config 与 converters
各维护一套，改了一处忘另一处就会出现「生成时放行、自检时报错」或者反过来漏检。

用法：python Files/check_config.py [仓库根目录]
"""

import base64
import glob
import json
import os
import re
import sys

import yaml

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from converters import (  # noqa: E402  (需要在 sys.path 调整之后导入)
    CLASH_FINGERPRINTS,
    CLASH_FLOWS,
    CLASH_NETWORKS,
    CLASH_SS_CIPHERS,
    HY2_OBFS_TYPES,
    SINGBOX_FLOWS,
    SINGBOX_OUTBOUND_TYPES,
    SINGBOX_SS_CIPHERS,
    SINGBOX_SS_PLUGINS,
    SINGBOX_TRANSPORTS,
    SHORT_ID_RE,
    SSR_OBFS,
    SSR_PROTOCOLS,
    SUPPORTED_TYPES,
    TUIC_CONGESTION,
    TUIC_UDP_RELAY,
    V2RAY_SECURITY,
    XHTTP_MODES,
)

ROOT = (os.path.abspath(sys.argv[1]) if len(sys.argv) > 1
        else os.path.dirname(SCRIPT_DIR))
CLASH_DIR = os.path.join(ROOT, 'configs', 'clash')
CLASH_SPLIT_DIR = os.path.join(CLASH_DIR, 'split')
SINGBOX_DIR = os.path.join(ROOT, 'configs', 'singbox')

# PyYAML 按 YAML 1.1 决定要不要给字符串加引号，而 mihomo / sing-box 按 YAML 1.2
# 解析：`short-id: 08` 在 1.2 里是整数 8，客户端会直接拒绝加载整份配置。
RISKY_SCALAR_RE = re.compile(
    r'^(?:[-+]?(?:\d[\d_]*(?:\.[\d_]*)?|\.[\d_]+)(?:[eE][-+]?\d+)?'
    r'|y|n|yes|no|true|false|on|off|null|none|~)$',
    re.IGNORECASE,
)
STRING_FIELDS = {
    'name', 'server', 'uuid', 'password', 'sni', 'servername', 'cipher',
    'method', 'network', 'flow', 'client-fingerprint', 'obfs',
    'obfs-password', 'plugin', 'public-key', 'short-id', 'public_key',
    'short_id', 'fingerprint', 'path', 'host', 'service-name', 'security',
    'mode',
}

UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                     r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')

errors = []


def fail(message):
    errors.append(message)


def b64_len(value):
    text = re.sub(r'\s+', '', str(value or ''))
    if not text:
        return -1
    text = text.replace('-', '+').replace('_', '/')
    text += '=' * (-len(text) % 4)
    try:
        return len(base64.b64decode(text, validate=True))
    except Exception:
        return -1


def key_len_ok(method, password):
    if not str(method).startswith('2022-blake3'):
        return True
    need = 16 if 'aes-128' in method else 32
    return b64_len(password) == need


def scan_unquoted_scalars(path):
    """找出被输出成裸数字/布尔的字符串字段。

    这类值在 YAML 1.2 解析器里会变成 int/bool，客户端反序列化失败后
    整份配置报废，必须强制加引号。
    """
    try:
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except OSError:
        return
    for number, line in enumerate(lines, 1):
        match = re.match(r'^\s*-?\s*([A-Za-z0-9_-]+):\s+(.+?)\s*$', line)
        if not match:
            continue
        key, value = match.group(1), match.group(2)
        if key not in STRING_FIELDS:
            continue
        if value.startswith(('"', "'", '[', '{', '&', '*', '|', '>')):
            continue
        if RISKY_SCALAR_RE.match(value):
            fail(f'{os.path.basename(path)}:{number}: {key} 的值 {value!r} '
                 f'未加引号，客户端会当成数字/布尔解析')


# --------------------------------------------------------------------------
# Clash
# --------------------------------------------------------------------------

def validate_clash_proxy(proxy, where, seen_names):
    ptype = proxy.get('type')
    if ptype not in SUPPORTED_TYPES:
        fail(f'{where}: 未知类型 {ptype}')
        return
    name = str(proxy.get('name') or '')
    if not name:
        fail(f'{where}: name 为空')
    elif name in seen_names:
        fail(f'{where}: name 重复')
    seen_names.add(name)

    if not str(proxy.get('server') or '').strip():
        fail(f'{where}: server 为空')
    port = proxy.get('port')
    if not isinstance(port, int) or not 0 < port < 65536:
        fail(f'{where}: port 非法 {port!r}')

    if ptype in ('vmess', 'vless'):
        if not UUID_RE.match(str(proxy.get('uuid') or '')):
            fail(f'{where}: uuid 非法 {proxy.get("uuid")!r}')
    if ptype in ('ss', 'ssr'):
        cipher = str(proxy.get('cipher') or '')
        if cipher not in CLASH_SS_CIPHERS:
            fail(f'{where}: cipher 客户端不认识 {cipher!r}')
        if not key_len_ok(cipher, proxy.get('password')):
            fail(f'{where}: {cipher} 密钥长度不对')
    if ptype in ('ss', 'ssr', 'trojan', 'hysteria2', 'tuic'):
        if not str(proxy.get('password') or ''):
            fail(f'{where}: password 为空')

    network = proxy.get('network')
    if network is not None and network not in CLASH_NETWORKS:
        fail(f'{where}: network 非法 {network!r}')
    if network == 'xhttp':
        opts = proxy.get('xhttp-opts') or {}
        host = opts.get('host')
        if host is not None and not isinstance(host, str):
            fail(f'{where}: xhttp-opts.host 必须是字符串，实际 {type(host).__name__}')
        mode = opts.get('mode')
        if mode is not None and str(mode) not in XHTTP_MODES:
            fail(f'{where}: xhttp-opts.mode 不受支持 {mode!r}')
    if network == 'h2':
        opts = proxy.get('h2-opts') or {}
        host = opts.get('host')
        if host is not None and not isinstance(host, list):
            fail(f'{where}: h2-opts.host 必须是数组，实际 {type(host).__name__}')

    fingerprint = proxy.get('client-fingerprint')
    if fingerprint and fingerprint not in CLASH_FINGERPRINTS:
        fail(f'{where}: client-fingerprint 非法 {fingerprint!r}')
    flow = proxy.get('flow')
    if flow and flow not in CLASH_FLOWS:
        fail(f'{where}: flow 非法 {flow!r}')
    if ptype == 'hysteria2':
        obfs = proxy.get('obfs')
        if obfs and obfs not in HY2_OBFS_TYPES:
            fail(f'{where}: hysteria2 obfs 只支持 salamander，实际 {obfs!r}')
        if obfs and not proxy.get('obfs-password'):
            fail(f'{where}: hysteria2 启用 obfs 但缺少 obfs-password')
    reality = proxy.get('reality-opts')
    if reality:
        if b64_len(reality.get('public-key')) != 32:
            fail(f'{where}: reality public-key 非法')
        short_id = reality.get('short-id')
        if short_id is not None and not SHORT_ID_RE.match(str(short_id)):
            fail(f'{where}: reality short-id 非法 {short_id!r}')
    if ptype == 'ssr':
        if str(proxy.get('protocol') or 'origin').lower() not in SSR_PROTOCOLS:
            fail(f'{where}: ssr protocol 不受支持 {proxy.get("protocol")!r}')
        if str(proxy.get('obfs') or 'plain').lower() not in SSR_OBFS:
            fail(f'{where}: ssr obfs 不受支持 {proxy.get("obfs")!r}')
    if ptype == 'tuic':
        if proxy.get('congestion-controller') not in (None, *TUIC_CONGESTION):
            fail(f'{where}: tuic congestion-controller 非法')
        if proxy.get('udp-relay-mode') not in (None, *TUIC_UDP_RELAY):
            fail(f'{where}: tuic udp-relay-mode 非法')
    if ptype == 'vmess':
        cipher = str(proxy.get('cipher') or 'auto')
        if cipher not in V2RAY_SECURITY:
            fail(f'{where}: vmess cipher 非法 {cipher!r}')


def check_clash_file(path, label, require_groups=False):
    """校验一份 Clash 文件，返回节点数。"""
    if not os.path.exists(path):
        fail(f'缺少 {path}')
        return 0
    try:
        with open(path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as e:
        fail(f'{label}: YAML 解析失败 {e}')
        return 0

    proxies = config.get('proxies')
    if not isinstance(proxies, list):
        fail(f'{label}: proxies 不是列表')
        return 0

    names = set()
    for index, proxy in enumerate(proxies):
        if not isinstance(proxy, dict):
            fail(f'{label}#{index}: 不是对象')
            continue
        validate_clash_proxy(proxy, f'{label}#{index} {proxy.get("name")}', names)

    scan_unquoted_scalars(path)

    if require_groups:
        group_names = {g.get('name') for g in config.get('proxy-groups') or []}
        # 分组引用的节点必须真实存在，否则 mihomo 报 "proxy not found"
        for group in config.get('proxy-groups') or []:
            for target in group.get('proxies') or []:
                if target in names or target in ('DIRECT', 'REJECT'):
                    continue
                if target in group_names:
                    continue
                fail(f"{label} proxy-group {group.get('name')}: 引用了不存在的节点 {target!r}")
        if not config.get('rules'):
            fail(f'{label}: 缺少 rules')
    return len(proxies)


def check_clash():
    provider = os.path.join(CLASH_DIR, 'proxies.yaml')
    count = check_clash_file(os.path.join(CLASH_DIR, 'config.yaml'),
                             'config.yaml', require_groups=True)
    light = check_clash_file(os.path.join(CLASH_DIR, 'light.yaml'),
                             'light.yaml', require_groups=True)
    if light and count and light > count:
        fail(f'light.yaml 的节点数 {light} 大于完整配置 {count}')

    if os.path.exists(provider):
        try:
            with open(provider, 'r', encoding='utf-8') as f:
                provider_data = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError) as e:
            fail(f'proxies.yaml 解析失败 {e}')
        else:
            if len(provider_data.get('proxies') or []) != count:
                fail('proxies.yaml 与 config.yaml 的节点数不一致')
        scan_unquoted_scalars(provider)

    # 分片：每个文件只含 proxies，节点条目同样要过白名单
    for path in sorted(glob.glob(os.path.join(CLASH_SPLIT_DIR, '*.yaml'))):
        check_clash_file(path, f'split/{os.path.basename(path)}')
    return count


# --------------------------------------------------------------------------
# sing-box
# --------------------------------------------------------------------------

def validate_singbox_outbound(outbound, where):
    otype = outbound.get('type')
    if otype not in SINGBOX_OUTBOUND_TYPES:
        fail(f'{where}: 类型不受支持 {otype!r}')
        return

    if not str(outbound.get('server') or '').strip():
        fail(f'{where}: server 为空')
    port = outbound.get('server_port')
    if not isinstance(port, int) or not 0 < port < 65536:
        fail(f'{where}: server_port 非法 {port!r}')

    if otype in ('vmess', 'vless'):
        if not UUID_RE.match(str(outbound.get('uuid') or '')):
            fail(f'{where}: uuid 非法 {outbound.get("uuid")!r}')
    if otype == 'shadowsocks':
        method = str(outbound.get('method') or '')
        if method not in SINGBOX_SS_CIPHERS:
            fail(f'{where}: method 不受支持 {method!r}')
        if not key_len_ok(method, outbound.get('password')):
            fail(f'{where}: {method} 密钥长度不对')
        plugin = str(outbound.get('plugin') or '')
        if plugin not in SINGBOX_SS_PLUGINS:
            fail(f'{where}: plugin 不受支持 {plugin!r}')
    if otype in ('shadowsocks', 'trojan', 'hysteria2', 'tuic'):
        if not str(outbound.get('password') or ''):
            fail(f'{where}: password 为空')
    if otype == 'tuic' and not UUID_RE.match(str(outbound.get('uuid') or '')):
        fail(f'{where}: tuic uuid 非法 {outbound.get("uuid")!r}')

    flow = outbound.get('flow')
    if flow and flow not in SINGBOX_FLOWS:
        fail(f'{where}: flow 非法 {flow!r}')

    transport = outbound.get('transport') or {}
    if transport:
        if transport.get('type') not in SINGBOX_TRANSPORTS:
            fail(f'{where}: transport 不受支持 {transport.get("type")!r}')
    tls = outbound.get('tls') or {}
    if isinstance(tls, dict):
        utls = tls.get('utls') or {}
        fingerprint = utls.get('fingerprint')
        if fingerprint and fingerprint not in CLASH_FINGERPRINTS:
            fail(f'{where}: utls fingerprint 非法 {fingerprint!r}')
        reality = tls.get('reality') or {}
        if reality:
            if b64_len(reality.get('public_key')) != 32:
                fail(f'{where}: reality public_key 非法')
            if not utls.get('enabled'):
                fail(f'{where}: REALITY 必须启用 uTLS，否则 sing-box 拒绝加载')
            short_id = reality.get('short_id')
            if short_id is not None and not SHORT_ID_RE.match(str(short_id)):
                fail(f'{where}: reality short_id 非法 {short_id!r}')

    obfs = outbound.get('obfs') or {}
    if obfs:
        if obfs.get('type') not in HY2_OBFS_TYPES:
            fail(f'{where}: obfs 只支持 salamander，实际 {obfs.get("type")!r}')
        if not str(obfs.get('password') or ''):
            fail(f'{where}: obfs 缺少 password')


def check_singbox_file(path, label):
    if not os.path.exists(path):
        fail(f'缺少 {path}')
        return 0
    try:
        with open(path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except (OSError, ValueError) as e:
        fail(f'{label}: JSON 解析失败 {e}')
        return 0

    outbounds = config.get('outbounds') or []
    tags = set()
    node_tags = set()

    for index, outbound in enumerate(outbounds):
        otype = outbound.get('type')
        tag = str(outbound.get('tag') or '')
        where = f'{label}#{index} {tag}'
        if not tag:
            fail(f'{where}: tag 为空')
            continue
        if tag in tags:
            fail(f'{where}: tag 重复')
        tags.add(tag)

        if otype in ('selector', 'urltest', 'direct', 'block'):
            continue
        if otype not in SINGBOX_OUTBOUND_TYPES:
            fail(f'{where}: 类型不受支持 {otype!r}')
            continue
        node_tags.add(tag)
        transport = outbound.get('transport')
        if isinstance(transport, dict) and transport.get('type') == 'xhttp':
            fail(f'{where}: sing-box 不支持 xhttp 传输层')
        validate_singbox_outbound(outbound, where)

    for outbound in outbounds:
        if outbound.get('type') in ('selector', 'urltest'):
            for target in outbound.get('outbounds') or []:
                if target in tags:
                    continue
                fail(f"{label} outbound {outbound.get('tag')}: "
                     f"引用了不存在的 tag {target!r}")

    final = (config.get('route') or {}).get('final')
    if final and final not in tags:
        fail(f'{label} route.final 指向不存在的 tag {final!r}')
    return len(node_tags)


def check_singbox():
    count = check_singbox_file(os.path.join(SINGBOX_DIR, 'config.json'), 'config.json')
    light = check_singbox_file(os.path.join(SINGBOX_DIR, 'light.json'), 'light.json')
    if light and count and light > count:
        fail(f'light.json 的节点数 {light} 大于完整配置 {count}')
    return count


def main():
    clash_count = check_clash()
    singbox_count = check_singbox()

    if errors:
        print(f'配置校验失败，共 {len(errors)} 处：')
        for message in errors[:40]:
            print('  -', message)
        if len(errors) > 40:
            print(f'  ... 另有 {len(errors) - 40} 处')
        return 1

    print(f'配置校验通过：clash {clash_count} 个节点，sing-box {singbox_count} 个节点')
    return 0


if __name__ == '__main__':
    sys.exit(main())
