"""发布前自检：确认生成的 Clash / sing-box 配置能被客户端加载。

mihomo 与 sing-box 遇到「不认识的字段值」时不会跳过该节点，而是拒绝加载整份
配置，用户看到的就是「无法导入」。这个脚本在提交前把所有已知会触发整体失败的
情况再验一遍，有问题直接让 CI 变红，避免坏配置被推到线上。

用法：python Files/check_config.py
"""

import json
import os
import re
import sys

import yaml

ROOT = (os.path.abspath(sys.argv[1]) if len(sys.argv) > 1
        else os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CLASH_DIR = os.path.join(ROOT, 'configs', 'clash')
SINGBOX_DIR = os.path.join(ROOT, 'configs', 'singbox')

CLASH_SS_CIPHERS = {
    'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
    'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
    'rc4-md5', 'chacha20', 'chacha20-ietf', 'xchacha20',
    'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305',
    'none',
}
SINGBOX_SS_CIPHERS = CLASH_SS_CIPHERS - {'chacha20'}

CLASH_TYPES = {'vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria2', 'tuic'}
# sing-box 的 Shadowsocks 类型名是 shadowsocks，写成 ss 会 unknown outbound type
SINGBOX_TYPES = {'vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'tuic'}
NETWORKS = {'tcp', 'ws', 'grpc', 'h2', 'http'}
FINGERPRINTS = {'chrome', 'firefox', 'safari', 'ios', 'android',
                'edge', '360', 'qq', 'random', 'randomized'}
FLOWS = {'xtls-rprx-vision', 'xtls-rprx-vision-udp443'}
SINGBOX_FLOWS = {'xtls-rprx-vision'}
V2RAY_SECURITY = {'auto', 'none', 'zero', 'aes-128-gcm',
                  'chacha20-poly1305', 'aes-128-ctr'}

SHORT_ID_RE = re.compile(r'^(?:[0-9a-fA-F]{2}){0,8}$')

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
}

UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                     r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')

errors = []


def fail(message):
    errors.append(message)


def b64_len(value):
    import base64
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


def check_clash():
    path = os.path.join(CLASH_DIR, 'config.yaml')
    provider = os.path.join(CLASH_DIR, 'proxies.yaml')
    if not os.path.exists(path):
        fail(f'缺少 {path}')
        return 0

    with open(path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)
    proxies = config.get('proxies') or []
    names = set()

    for index, proxy in enumerate(proxies):
        where = f"clash#{index} {proxy.get('name')}"
        ptype = proxy.get('type')
        if ptype not in CLASH_TYPES:
            fail(f'{where}: 未知类型 {ptype}')
            continue
        name = str(proxy.get('name') or '')
        if not name:
            fail(f'{where}: name 为空')
        elif name in names:
            fail(f'{where}: name 重复')
        names.add(name)

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
        if network is not None and network not in NETWORKS:
            fail(f'{where}: network 非法 {network!r}')
        fingerprint = proxy.get('client-fingerprint')
        if fingerprint and fingerprint not in FINGERPRINTS:
            fail(f'{where}: client-fingerprint 非法 {fingerprint!r}')
        flow = proxy.get('flow')
        if flow and flow not in FLOWS:
            fail(f'{where}: flow 非法 {flow!r}')
        if ptype == 'hysteria2':
            obfs = proxy.get('obfs')
            if obfs and obfs != 'salamander':
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
        if ptype == 'vmess':
            cipher = str(proxy.get('cipher') or 'auto')
            if cipher not in V2RAY_SECURITY:
                fail(f'{where}: vmess cipher 非法 {cipher!r}')

    scan_unquoted_scalars(path)
    scan_unquoted_scalars(provider)

    # 分组引用的节点必须真实存在，否则 mihomo 报 "proxy not found"
    for group in config.get('proxy-groups') or []:
        for target in group.get('proxies') or []:
            if target in names or target in ('DIRECT', 'REJECT'):
                continue
            if any(target == g.get('name') for g in config.get('proxy-groups') or []):
                continue
            fail(f"proxy-group {group.get('name')}: 引用了不存在的节点 {target!r}")

    if os.path.exists(provider):
        with open(provider, 'r', encoding='utf-8') as f:
            provider_data = yaml.safe_load(f) or {}
        if len(provider_data.get('proxies') or []) != len(proxies):
            fail('proxies.yaml 与 config.yaml 的节点数不一致')

    return len(proxies)


def check_singbox():
    path = os.path.join(SINGBOX_DIR, 'config.json')
    if not os.path.exists(path):
        fail(f'缺少 {path}')
        return 0

    with open(path, 'r', encoding='utf-8') as f:
        config = json.load(f)

    outbounds = config.get('outbounds') or []
    tags = set()
    node_tags = set()

    for index, outbound in enumerate(outbounds):
        otype = outbound.get('type')
        tag = str(outbound.get('tag') or '')
        where = f'singbox#{index} {tag}'
        if not tag:
            fail(f'{where}: tag 为空')
        elif tag in tags and otype not in ('selector', 'urltest'):
            fail(f'{where}: tag 重复')
        tags.add(tag)

        if otype in ('selector', 'urltest', 'direct', 'block'):
            continue
        if otype not in SINGBOX_TYPES:
            fail(f'{where}: 类型不受支持 {otype!r}')
            continue
        node_tags.add(tag)

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
            if plugin not in ('', 'obfs-local', 'v2ray-plugin'):
                fail(f'{where}: plugin 不受支持 {plugin!r}')
        if otype in ('shadowsocks', 'trojan', 'hysteria2', 'tuic'):
            if not str(outbound.get('password') or ''):
                fail(f'{where}: password 为空')

        flow = outbound.get('flow')
        if flow and flow not in SINGBOX_FLOWS:
            fail(f'{where}: flow 非法 {flow!r}')

        tls = outbound.get('tls') or {}
        utls = tls.get('utls') or {}
        fingerprint = utls.get('fingerprint')
        if fingerprint and fingerprint not in FINGERPRINTS:
            fail(f'{where}: utls fingerprint 非法 {fingerprint!r}')
        reality = tls.get('reality') or {}
        if reality:
            if b64_len(reality.get('public_key')) != 32:
                fail(f'{where}: reality public_key 非法')
            if not (tls.get('utls') or {}).get('enabled'):
                fail(f'{where}: REALITY 必须启用 uTLS，否则 sing-box 拒绝加载')
            short_id = reality.get('short_id')
            if short_id is not None and not SHORT_ID_RE.match(str(short_id)):
                fail(f'{where}: reality short_id 非法 {short_id!r}')

        obfs = outbound.get('obfs') or {}
        if obfs:
            if obfs.get('type') != 'salamander':
                fail(f'{where}: obfs 只支持 salamander，实际 {obfs.get("type")!r}')
            if not str(obfs.get('password') or ''):
                fail(f'{where}: obfs 缺少 password')

    for outbound in outbounds:
        if outbound.get('type') in ('selector', 'urltest'):
            for target in outbound.get('outbounds') or []:
                if target in node_tags or target in tags:
                    continue
                fail(f"outbound {outbound.get('tag')}: 引用了不存在的 tag {target!r}")

    final = (config.get('route') or {}).get('final')
    if final and final not in tags:
        fail(f'route.final 指向不存在的 tag {final!r}')

    return len(node_tags)


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
