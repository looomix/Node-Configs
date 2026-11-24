"""把分享链接（vmess/vless/trojan/ss/ssr/hysteria2/tuic）转换成 Clash 与 sing-box 配置。

只做纯函数转换，不依赖网络。无法解析的链接统一返回 None，由调用方统计丢弃。
"""

import base64
import json
import re
from urllib.parse import parse_qs, unquote, urlsplit

# 各客户端真正认识的 Shadowsocks 加密方式。
#
# 这里必须逐字匹配客户端实现的枚举：名字写错时 mihomo / sing-box 不会「跳过这个
# 节点」，而是在**解析配置**阶段报错并拒绝整份文件，用户那边看到的就是
# 「无法导入」。典型例子是 chacha20-poly1305 —— 这个名字 mihomo 不认识，
# 正式名称是 chacha20-ietf-poly1305（机场/订阅里两种写法都很常见）。
CLASH_SS_CIPHERS = frozenset({
    'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
    'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
    'rc4-md5', 'chacha20', 'chacha20-ietf', 'xchacha20',
    'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305',
    'none',
})

# sing-box 支持的范围更窄一些（没有裸 chacha20）
SINGBOX_SS_CIPHERS = frozenset({
    'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
    'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
    'rc4-md5', 'chacha20-ietf', 'xchacha20',
    'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305',
    'none',
})

# 解析阶段的可接受集合：只有两个客户端之一能认的才算「有用节点」，
# 剩下的（bf-cfb / camellia / salsa20 / rc4 …）写进任何配置都会加载失败
SS_CIPHERS = CLASH_SS_CIPHERS | SINGBOX_SS_CIPHERS

# 客户端互为别名/旧名的写法，统一收敛成规范名
SS_CIPHER_ALIASES = {
    'chacha20-poly1305': 'chacha20-ietf-poly1305',
    'chacha20-poly1305-ietf': 'chacha20-ietf-poly1305',
    'aead-chacha20-poly1305': 'chacha20-ietf-poly1305',
    'xchacha20-poly1305': 'xchacha20-ietf-poly1305',
    'xchacha20-poly1305-ietf': 'xchacha20-ietf-poly1305',
    'aes-128-gcm-2022': '2022-blake3-aes-128-gcm',
    'aes-256-gcm-2022': '2022-blake3-aes-256-gcm',
    'plain': 'none',
    'dummy': 'none',
}

SUPPORTED_TYPES = ('vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria2', 'tuic')

# mihomo 的 transport 白名单。Xray/sing-box 的写法跟 mihomo 不完全一致
# （raw / gun / splithttp …），出现不认识的值时 mihomo 会直接
# 「unsupported network」整份配置加载失败，所以先归一、再按白名单过滤。
CLASH_NETWORKS = frozenset({'tcp', 'ws', 'grpc', 'h2', 'httpupgrade'})

NETWORK_ALIASES = {
    'raw': 'tcp',
    'none': 'tcp',
    'http': 'h2',
    'websocket': 'ws',
    'gun': 'grpc',
    'splithttp': 'xhttp',
}


def normalize_network(value, default='tcp'):
    """把各内核的 transport 写法收敛成统一名字。"""
    text = str(value or '').strip().lower()
    if not text:
        return default
    return NETWORK_ALIASES.get(text, text)


# uTLS 指纹白名单（mihomo 与 sing-box 的交集偏保守）
CLASH_FINGERPRINTS = ('chrome', 'firefox', 'safari', 'ios', 'android',
                      'edge', '360', 'qq', 'random', 'randomized')

CLASH_FLOWS = frozenset({'xtls-rprx-vision', 'xtls-rprx-vision-udp443'})
SINGBOX_FLOWS = frozenset({'xtls-rprx-vision'})
HY2_OBFS_TYPES = frozenset({'salamander'})
TUIC_CONGESTION = frozenset({'cubic', 'new_reno', 'bbr'})
TUIC_UDP_RELAY = frozenset({'native', 'quic'})
V2RAY_SECURITY = frozenset({
    'auto', 'none', 'zero', 'aes-128-gcm', 'chacha20-poly1305', 'aes-128-ctr',
})

_UUID_DASHED = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
    r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_UUID_BARE = re.compile(r'^[0-9a-fA-F]{32}$')

# sing-box 不支持 SSR，一旦写进 outbounds 会让整份配置校验失败（不是跳过该节点），
# 因此输出前必须按白名单过滤。
SINGBOX_TYPES = {'vmess', 'vless', 'trojan', 'ss', 'hysteria2', 'tuic'}

# sing-box 的 outbound 类型名跟协议名并不完全一致：Shadowsocks 必须写
# `shadowsocks`，写成 `ss` 会被判定为 unknown outbound type 而拒绝启动。
SINGBOX_TYPE_NAMES = {'ss': 'shadowsocks'}

# sing-box 的 shadowsocks 插件只认这几种（写入前已归一为这里的名字）
SINGBOX_SS_PLUGINS = {'', 'obfs-local', 'v2ray-plugin'}

# 插件名归一：不同客户端/机场写法不一样
SS_PLUGIN_ALIASES = {
    'obfs': 'obfs-local',
    'obfs-local': 'obfs-local',
    'simple-obfs': 'obfs-local',
    'v2ray-plugin': 'v2ray-plugin',
    'shadow-tls': 'shadow-tls',
}


def _b64decode(data):
    if not data:
        return ''
    data = re.sub(r'\s+', '', data)
    data = data.replace('-', '+').replace('_', '/')
    data += '=' * (-len(data) % 4)
    try:
        return base64.b64decode(data, validate=False).decode('utf-8', 'ignore')
    except Exception:
        return ''


def _as_int(value, default=0):
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return default
    return number if 0 < number < 65536 else default


def _first(mapping, *keys, default=''):
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, list):
            value = value[0] if value else ''
        if value:
            return str(value).strip()
    return default


def _alpn_list(value):
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [v.strip() for v in value.split(',') if v.strip()]
    return []


def _truthy(value):
    return str(value).strip().lower() in ('1', 'true', 'yes', 'on')


def normalize_ss_method(method):
    """把各家写法不一的加密方式收敛成客户端认识的规范名。"""
    method = str(method or '').strip().lower()
    return SS_CIPHER_ALIASES.get(method, method)


def normalize_uuid(value):
    """校验并规范化 UUID；不是合法 UUID 时返回空串。

    mihomo 解析 vmess/vless 时会 `uuid.FromString`，格式不对就直接报错，
    同样是「一个节点拖垮整份配置」，所以必须在解析阶段拦住。
    """
    text = str(value or '').strip().lower()
    if _UUID_DASHED.match(text):
        return text
    if _UUID_BARE.match(text):
        return (f'{text[0:8]}-{text[8:12]}-{text[12:16]}-'
                f'{text[16:20]}-{text[20:32]}')
    return ''


_SHORT_ID = re.compile(r'^(?:[0-9a-fA-F]{2}){0,8}$')


def normalize_short_id(value):
    """REALITY 的 short-id 必须是偶数位十六进制；写错 mihomo 会整份配置报错。"""
    text = str(value or '').strip()
    return text.lower() if _SHORT_ID.match(text) else ''


def normalize_fingerprint(value):
    """把 sing-box 风格的指纹名映射到 uTLS 认识的名字；认不出返回空串。"""
    text = str(value or '').strip().lower()
    if not text:
        return ''
    if text in CLASH_FINGERPRINTS:
        return text
    # hello<浏览器>_<版本> 这类写法在源站很常见，取内含的浏览器名
    for name in sorted(CLASH_FINGERPRINTS, key=len, reverse=True):
        if name in text:
            return name
    return ''


def _b64_byte_len(value):
    text = re.sub(r'\s+', '', str(value or ''))
    if not text:
        return -1
    text = text.replace('-', '+').replace('_', '/')
    text += '=' * (-len(text) % 4)
    try:
        return len(base64.b64decode(text, validate=True))
    except Exception:
        return -1


def ss_key_len_ok(method, password):
    """2022-blake3 系列对密钥字节数有硬性要求，长度不对客户端会拒绝启动。"""
    if not method.startswith('2022-blake3'):
        return True
    need = 16 if 'aes-128' in method else 32
    return _b64_byte_len(password) == need


def _name_from_fragment(fragment):
    return unquote(fragment or '').strip()


def _query_dict(parts):
    return {k: v[0] for k, v in parse_qs(parts.query).items()}


def _base_node(node_type, name, server, port):
    if not server or not port:
        return None
    return {'type': node_type, 'name': name, 'server': server, 'port': port,
            'tls': False, 'network': 'tcp', 'insecure': False}


# --------------------------------------------------------------------------
# 各协议解析
# --------------------------------------------------------------------------

def _parse_vmess(uri):
    body = uri[len('vmess://'):]
    fragment = ''
    if '#' in body:
        body, fragment = body.split('#', 1)
    raw = _b64decode(body)
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None

    server = str(data.get('add') or '').strip().strip('[]')
    port = _as_int(data.get('port'))
    node = _base_node('vmess', str(data.get('ps') or _name_from_fragment(fragment)).strip(),
                      server, port)
    if not node or not data.get('id'):
        return None

    node['uuid'] = normalize_uuid(data.get('id'))
    if not node['uuid']:
        return None
    node['alter_id'] = _as_int(data.get('aid'), 0)
    node['cipher'] = str(data.get('scy') or 'auto').strip() or 'auto'
    node['network'] = normalize_network(data.get('net'))
    node['path'] = str(data.get('path') or '').strip()
    node['host'] = str(data.get('host') or '').strip()
    node['service_name'] = node['path'] if node['network'] == 'grpc' else ''
    node['tls'] = str(data.get('tls') or '').strip().lower() in ('tls', 'reality', 'true')
    node['sni'] = str(data.get('sni') or node['host'] or '').strip()
    node['alpn'] = _alpn_list(data.get('alpn'))
    node['fp'] = str(data.get('fp') or '').strip()
    return node


def _parse_vless(uri):
    parts = urlsplit(uri)
    node = _base_node('vless', _name_from_fragment(parts.fragment),
                      (parts.hostname or '').strip('[]'), _as_int(parts.port))
    if not node or not parts.username:
        return None

    query = _query_dict(parts)
    node['uuid'] = normalize_uuid(unquote(parts.username))
    if not node['uuid']:
        return None
    node['flow'] = _first(query, 'flow')
    node['network'] = normalize_network(_first(query, 'type'))
    node['path'] = _first(query, 'path') or '/'
    node['host'] = _first(query, 'host')
    node['service_name'] = _first(query, 'serviceName', 'servicename') or (
        node['path'] if node['network'] == 'grpc' else '')
    node['sni'] = _first(query, 'sni', 'peer') or node['host']
    node['fp'] = _first(query, 'fp')
    node['alpn'] = _alpn_list(_first(query, 'alpn'))
    node['insecure'] = _truthy(_first(query, 'allowInsecure', 'insecure'))
    security = (_first(query, 'security') or 'none').lower()
    node['tls'] = security in ('tls', 'reality', 'xtls')
    node['reality_pbk'] = _first(query, 'pbk')
    node['reality_sid'] = normalize_short_id(_first(query, 'sid'))
    if node['reality_pbk']:
        node['tls'] = True
    return node


def _parse_trojan(uri):
    parts = urlsplit(uri)
    node = _base_node('trojan', _name_from_fragment(parts.fragment),
                      (parts.hostname or '').strip('[]'), _as_int(parts.port))
    if not node or not parts.username:
        return None

    query = _query_dict(parts)
    # 密码里可能含冒号，urlsplit 会把它拆成 username/password，这里拼回去
    password = unquote(parts.username)
    if parts.password:
        password = f"{password}:{unquote(parts.password)}"
    node['password'] = password.strip()
    node['network'] = normalize_network(_first(query, 'type'))
    node['path'] = _first(query, 'path') or '/'
    node['host'] = _first(query, 'host')
    node['service_name'] = _first(query, 'serviceName') or (
        node['path'] if node['network'] == 'grpc' else '')
    node['sni'] = _first(query, 'sni', 'peer') or node['host']
    node['fp'] = _first(query, 'fp')
    node['alpn'] = _alpn_list(_first(query, 'alpn'))
    node['insecure'] = _truthy(_first(query, 'allowInsecure', 'insecure'))
    node['tls'] = (_first(query, 'security') or 'tls').lower() != 'none'
    return node


def _parse_hysteria2(uri):
    if uri.startswith('hy2://'):
        uri = 'hysteria2://' + uri[len('hy2://'):]
    parts = urlsplit(uri)
    node = _base_node('hysteria2', _name_from_fragment(parts.fragment),
                      (parts.hostname or '').strip('[]'), _as_int(parts.port))
    if not node:
        return None

    query = _query_dict(parts)
    password = unquote(parts.username or '')
    if parts.password:
        password = f"{password}:{unquote(parts.password)}"
    if not password:
        return None

    node['password'] = password
    node['sni'] = _first(query, 'sni', 'peer')
    node['insecure'] = _truthy(_first(query, 'insecure', 'allowInsecure'))
    node['obfs'] = _first(query, 'obfs')
    node['obfs_password'] = _first(query, 'obfs-password', 'obfs_password')
    node['alpn'] = _alpn_list(_first(query, 'alpn'))
    node['tls'] = True
    return node


def _parse_tuic(uri):
    parts = urlsplit(uri)
    node = _base_node('tuic', _name_from_fragment(parts.fragment),
                      (parts.hostname or '').strip('[]'), _as_int(parts.port))
    if not node or not parts.username:
        return None

    query = _query_dict(parts)
    userinfo = unquote(parts.username)
    if ':' in userinfo:
        node['uuid'], node['password'] = userinfo.split(':', 1)
    else:
        node['uuid'] = userinfo
        node['password'] = unquote(parts.password or '')
    node['sni'] = _first(query, 'sni', 'peer')
    node['alpn'] = _alpn_list(_first(query, 'alpn'))
    node['insecure'] = _truthy(_first(query, 'insecure', 'allowInsecure'))
    node['congestion_control'] = _first(query, 'congestion_control', 'congestion-controller')
    node['udp_relay_mode'] = _first(query, 'udp_relay_mode', 'udp-relay-mode')
    node['tls'] = True
    return node


def _parse_ss(uri):
    body = uri[len('ss://'):]
    name = ''
    if '#' in body:
        body, fragment = body.split('#', 1)
        name = _name_from_fragment(fragment)

    query = {}
    if '?' in body:
        body, query_string = body.split('?', 1)
        query = {k: v[0] for k, v in parse_qs(query_string).items()}

    if '@' in body:
        userinfo, hostport = body.rsplit('@', 1)
        if ':' in userinfo:
            method, password = userinfo.split(':', 1)
            method, password = unquote(method), unquote(password)
        else:
            decoded = _b64decode(userinfo)
            if ':' not in decoded:
                return None
            method, password = decoded.split(':', 1)
    else:
        decoded = _b64decode(body)
        if '@' not in decoded:
            return None
        userinfo, hostport = decoded.rsplit('@', 1)
        if ':' not in userinfo:
            return None
        method, password = userinfo.split(':', 1)

    if ':' not in hostport:
        return None
    server, port_text = hostport.rsplit(':', 1)
    server = server.strip().strip('[]')
    port = _as_int(port_text)
    node = _base_node('ss', name, server, port)
    if not node:
        return None

    method = normalize_ss_method(method)
    if method not in SS_CIPHERS:
        return None

    node['method'] = method
    node['password'] = password

    # 插件参数形如 plugin=v2ray-plugin;mode=websocket;host=a.com;path=/ws
    # 整串塞给客户端会直接失效，这里拆成插件名与参数两部分
    raw_plugin = (query.get('plugin') or '').strip()
    plugin_name, plugin_opts = '', ''
    if raw_plugin:
        pieces = raw_plugin.split(';')
        plugin_name = pieces[0].strip()
        plugin_opts = ';'.join(pieces[1:]).strip()
    if not plugin_opts:
        plugin_opts = (query.get('plugin_opts') or query.get('plugin-opts') or '').strip()
    node['plugin'] = plugin_name
    node['plugin_opts'] = plugin_opts
    return node


def _parse_ssr(uri):
    raw = _b64decode(uri[len('ssr://'):])
    if not raw:
        return None

    main, _, query_string = raw.partition('/?')
    tail = main.rsplit(':', 5)
    if len(tail) != 6:
        return None
    server, port_text, protocol, method, obfs, password_b64 = tail

    port = _as_int(port_text)
    server = server.strip().strip('[]')
    node = _base_node('ssr', '', server, port)
    if not node:
        return None

    method = normalize_ss_method(method)
    if method not in SS_CIPHERS:
        return None

    query = {}
    if query_string:
        query = {k: _b64decode(v[0]) for k, v in parse_qs(query_string).items()}

    node['method'] = method
    node['password'] = _b64decode(password_b64)
    node['protocol'] = protocol.strip() or 'origin'
    node['protocol_param'] = query.get('protoparam', '')
    node['obfs'] = obfs.strip() or 'plain'
    node['obfs_param'] = query.get('obfsparam', '')
    node['name'] = query.get('remarks', '')
    return node


_PARSERS = {
    'vmess': _parse_vmess,
    'vless': _parse_vless,
    'trojan': _parse_trojan,
    'ss': _parse_ss,
    'ssr': _parse_ssr,
    'hysteria2': _parse_hysteria2,
    'tuic': _parse_tuic,
    'tuic5': _parse_tuic,
}


def parse_uri(uri):
    """把一条分享链接解析成统一的节点字典；无法解析返回 None。"""
    if not isinstance(uri, str):
        return None
    uri = uri.strip()
    scheme = uri.split('://', 1)[0].lower() if '://' in uri else ''
    if scheme == 'hy2':
        scheme = 'hysteria2'
    elif scheme == 'shadowsocks':
        scheme = 'ss'
    parser = _PARSERS.get(scheme)
    if not parser:
        return None
    try:
        node = parser(uri)
    except Exception:
        return None
    if not node or node['type'] not in SUPPORTED_TYPES:
        return None
    if not node.get('name'):
        node['name'] = f"{node['server']}:{node['port']}"
    return node


def is_valid_ss(uri):
    """判断一条 ss:// 是否真的是可用的 Shadowsocks 链接。"""
    node = _parse_ss(uri) if isinstance(uri, str) and uri.startswith('ss://') else None
    return node is not None


# --------------------------------------------------------------------------
# Clash（mihomo / Clash.Meta）输出
# --------------------------------------------------------------------------

def _clash_transport(proxy, node):
    network = node.get('network', 'tcp')
    if network == 'ws':
        proxy['network'] = 'ws'
        opts = {'path': node.get('path') or '/'}
        if node.get('host'):
            opts['headers'] = {'Host': node['host']}
        proxy['ws-opts'] = opts
    elif network == 'httpupgrade':
        # mihomo 没有独立的 httpupgrade transport，等价写法是 ws + v2ray-http-upgrade
        proxy['network'] = 'ws'
        opts = {'path': node.get('path') or '/', 'v2ray-http-upgrade': True}
        if node.get('host'):
            opts['headers'] = {'Host': node['host']}
        proxy['ws-opts'] = opts
    elif network == 'grpc':
        proxy['network'] = 'grpc'
        proxy['grpc-opts'] = {'grpc-service-name': node.get('service_name') or ''}
    elif network == 'h2':
        proxy['network'] = 'h2'
        opts = {'path': node.get('path') or '/'}
        if node.get('host'):
            opts['host'] = [node['host']]
        proxy['h2-opts'] = opts


def _clash_tls(proxy, node):
    if not node.get('tls'):
        return
    proxy['tls'] = True
    if node.get('sni'):
        proxy['servername'] = node['sni']
    if node.get('insecure'):
        proxy['skip-cert-verify'] = True
    if node.get('fp'):
        proxy['client-fingerprint'] = node['fp']
    if node.get('alpn'):
        proxy['alpn'] = node['alpn']
    if node.get('reality_pbk'):
        reality = {'public-key': node['reality_pbk']}
        if node.get('reality_sid'):
            reality['short-id'] = node['reality_sid']
        proxy['reality-opts'] = reality


def _ss_plugin_options(node):
    """把 plugin_opts 的 `k=v;k2=v2` 解析成字典，无值的裸键（如 tls）记为 true。"""
    options = {}
    for item in (node.get('plugin_opts') or '').split(';'):
        item = item.strip()
        if not item:
            continue
        if '=' in item:
            key, value = item.split('=', 1)
            options[key.strip().lower()] = value.strip()
        else:
            options[item.lower()] = 'true'
    return options


def _clash_ss_plugin(proxy, node):
    """处理 Shadowsocks 插件；返回 False 表示该插件 Clash 无法表达。"""
    raw = (node.get('plugin') or '').strip().lower()
    if not raw:
        return True

    plugin = SS_PLUGIN_ALIASES.get(raw)
    if not plugin:
        # 认不出的插件不能降级成裸 SS，否则客户端连得上端口却握手失败
        return False

    options = _ss_plugin_options(node)

    if plugin == 'obfs-local':
        proxy['plugin'] = 'obfs'
        plugin_opts = {'mode': options.get('obfs') or options.get('mode') or 'http'}
        host = options.get('obfs-host') or options.get('host')
        if host:
            plugin_opts['host'] = host
        proxy['plugin-opts'] = plugin_opts
        return True

    if plugin == 'v2ray-plugin':
        proxy['plugin'] = 'v2ray-plugin'
        mode = (options.get('mode') or 'websocket').lower()
        plugin_opts = {'mode': 'websocket' if mode in ('ws', 'websocket') else mode}
        for key in ('host', 'path'):
            if options.get(key):
                plugin_opts[key] = options[key]
        if _truthy(options.get('tls', '')) or options.get('tls') in ('1', 'true'):
            plugin_opts['tls'] = True
        proxy['plugin-opts'] = plugin_opts
        return True

    if plugin == 'shadow-tls':
        proxy['plugin'] = 'shadow-tls'
        plugin_opts = {}
        for key in ('host', 'password', 'version'):
            if options.get(key):
                plugin_opts[key] = options[key]
        proxy['plugin-opts'] = plugin_opts
        return True

    return False


def clash_proxy(node):
    """节点字典 -> Clash proxy 条目；返回 None 表示 Clash 无法表达。"""
    name = node['name']
    proxy = {'name': name, 'type': node['type'],
             'server': node['server'], 'port': node['port']}
    node_type = node['type']

    if node_type == 'vmess':
        proxy['uuid'] = node['uuid']
        proxy['alterId'] = node.get('alter_id', 0)
        proxy['cipher'] = node.get('cipher') or 'auto'
        proxy['udp'] = True
        _clash_tls(proxy, node)
        _clash_transport(proxy, node)

    elif node_type == 'vless':
        proxy['uuid'] = node['uuid']
        proxy['udp'] = True
        if node.get('flow'):
            proxy['flow'] = node['flow']
        _clash_tls(proxy, node)
        _clash_transport(proxy, node)

    elif node_type == 'trojan':
        proxy['password'] = node['password']
        proxy['udp'] = True
        _clash_tls(proxy, node)
        _clash_transport(proxy, node)

    elif node_type == 'ss':
        proxy['cipher'] = node['method']
        proxy['password'] = node['password']
        proxy['udp'] = True
        # 插件映射失败时不能降级成裸 SS（会连不上），直接放弃这个节点
        if not _clash_ss_plugin(proxy, node):
            return None

    elif node_type == 'ssr':
        proxy['cipher'] = node['method']
        proxy['password'] = node['password']
        proxy['protocol'] = node.get('protocol') or 'origin'
        proxy['obfs'] = node.get('obfs') or 'plain'
        if node.get('protocol_param'):
            proxy['protocol-param'] = node['protocol_param']
        if node.get('obfs_param'):
            proxy['obfs-param'] = node['obfs_param']
        proxy['udp'] = True

    elif node_type == 'hysteria2':
        proxy['password'] = node['password']
        if node.get('sni'):
            proxy['sni'] = node['sni']
        if node.get('insecure'):
            proxy['skip-cert-verify'] = True
        if node.get('obfs'):
            proxy['obfs'] = node['obfs']
            proxy['obfs-password'] = node.get('obfs_password', '')

    elif node_type == 'tuic':
        proxy['uuid'] = node['uuid']
        proxy['password'] = node['password']
        if node.get('sni'):
            proxy['sni'] = node['sni']
        if node.get('alpn'):
            proxy['alpn'] = node['alpn']
        if node.get('congestion_control'):
            proxy['congestion-controller'] = node['congestion_control']
        if node.get('udp_relay_mode'):
            proxy['udp-relay-mode'] = node['udp_relay_mode']
        if node.get('insecure'):
            proxy['skip-cert-verify'] = True

    return proxy


# --------------------------------------------------------------------------
# sing-box 输出
# --------------------------------------------------------------------------

def _singbox_tls(node):
    if not node.get('tls'):
        return None
    tls = {'enabled': True}
    if node.get('sni'):
        tls['server_name'] = node['sni']
    if node.get('insecure'):
        tls['insecure'] = True
    if node.get('alpn'):
        tls['alpn'] = node['alpn']
    fingerprint = normalize_fingerprint(node.get('fp'))
    if fingerprint:
        tls['utls'] = {'enabled': True, 'fingerprint': fingerprint}
    if node.get('reality_pbk'):
        reality = {'enabled': True, 'public_key': node['reality_pbk']}
        if node.get('reality_sid'):
            reality['short_id'] = node['reality_sid']
        tls['reality'] = reality
        # sing-box 的 REALITY 必须搭配 uTLS，缺指纹会直接拒绝启动
        tls.setdefault('utls', {'enabled': True, 'fingerprint': 'chrome'})
    return tls


def _singbox_transport(node):
    network = node.get('network', 'tcp')
    if network == 'httpupgrade':
        transport = {'type': 'httpupgrade', 'path': node.get('path') or '/'}
        if node.get('host'):
            transport['host'] = node['host']
        return transport
    if network == 'ws':
        transport = {'type': 'ws', 'path': node.get('path') or '/'}
        if node.get('host'):
            transport['headers'] = {'Host': node['host']}
        return transport
    if network == 'grpc':
        return {'type': 'grpc', 'service_name': node.get('service_name') or ''}
    if network in ('h2', 'http'):
        transport = {'type': 'http', 'path': node.get('path') or '/'}
        if node.get('host'):
            transport['host'] = [node['host']]
        return transport
    return None


def singbox_outbound(node):
    """节点字典 -> sing-box outbound；返回 None 表示 sing-box 无法表达。"""
    if node['type'] not in SINGBOX_TYPES:
        return None

    outbound = {'type': SINGBOX_TYPE_NAMES.get(node['type'], node['type']),
                'tag': node['name'],
                'server': node['server'], 'server_port': node['port']}
    node_type = node['type']

    if node_type == 'vmess':
        outbound['uuid'] = node['uuid']
        outbound['alter_id'] = node.get('alter_id', 0)
        outbound['security'] = node.get('cipher') or 'auto'

    elif node_type == 'vless':
        outbound['uuid'] = node['uuid']
        if node.get('flow'):
            outbound['flow'] = node['flow']

    elif node_type == 'trojan':
        outbound['password'] = node['password']

    elif node_type == 'ss':
        outbound['method'] = node['method']
        outbound['password'] = node['password']
        raw_plugin = (node.get('plugin') or '').strip().lower()
        plugin = SS_PLUGIN_ALIASES.get(raw_plugin) or ''
        if raw_plugin and not plugin:
            # 认不出的插件不写入，否则 sing-box 会因未知 plugin 拒绝启动
            return None
        if plugin not in SINGBOX_SS_PLUGINS:
            # shadow-tls 等插件 sing-box 不支持，带上会导致配置校验失败
            return None
        if plugin:
            outbound['plugin'] = plugin
        if node.get('plugin_opts'):
            outbound['plugin_opts'] = node['plugin_opts']

    elif node_type == 'hysteria2':
        outbound['password'] = node['password']
        if node.get('obfs'):
            outbound['obfs'] = {'type': node['obfs'],
                                'password': node.get('obfs_password', '')}

    elif node_type == 'tuic':
        outbound['uuid'] = node['uuid']
        outbound['password'] = node['password']
        if node.get('congestion_control'):
            outbound['congestion_control'] = node['congestion_control']
        if node.get('udp_relay_mode'):
            outbound['udp_relay_mode'] = node['udp_relay_mode']

    tls = _singbox_tls(node)
    if tls:
        outbound['tls'] = tls

    if node_type in ('vmess', 'vless', 'trojan'):
        transport = _singbox_transport(node)
        if transport:
            outbound['transport'] = transport

    return outbound


# --------------------------------------------------------------------------
# 出口前的最后一道闸
#
# 两个客户端对「不认识的字段值」都是**整份配置拒绝加载**，而不是跳过单条：
# 加密方式写错、UUID 非法、2022 密钥长度不对、transport 不认识……任意一条都会让
# 用户看到「导入失败」。所以每个节点在写入前都要过一遍白名单校验，宁可丢一条，
# 也不能让 2000 条配置全部作废。
# --------------------------------------------------------------------------

def _port_ok(port):
    try:
        return 0 < int(port) < 65536
    except (TypeError, ValueError):
        return False


def sanitize_clash_proxy(proxy, node):
    """校验并修正 Clash proxy；返回 (proxy, '') 或 (None, 丢弃原因)。"""
    if not proxy:
        return None, 'unsupported'

    node_type = str(proxy.get('type') or '')
    if not str(proxy.get('server') or '').strip():
        return None, 'server'
    if not _port_ok(proxy.get('port')):
        return None, 'port'
    if not str(proxy.get('name') or '').strip():
        return None, 'name'

    if node_type in ('vmess', 'vless', 'trojan'):
        if (node.get('network') or 'tcp').lower() not in CLASH_NETWORKS:
            return None, f"network:{node.get('network')}"

    if node_type in ('vmess', 'vless'):
        if not _UUID_DASHED.match(str(proxy.get('uuid') or '')):
            return None, 'uuid'
        if node_type == 'vmess':
            security = str(proxy.get('cipher') or 'auto').lower()
            proxy['cipher'] = security if security in V2RAY_SECURITY else 'auto'

    if node_type in ('ss', 'ssr'):
        cipher = str(proxy.get('cipher') or '').lower()
        if cipher not in CLASH_SS_CIPHERS:
            return None, f'cipher:{cipher}'
        if not str(proxy.get('password') or ''):
            return None, 'password'
        if not ss_key_len_ok(cipher, proxy['password']):
            return None, f'key:{cipher}'

    if node_type in ('trojan', 'hysteria2', 'tuic'):
        if not str(proxy.get('password') or ''):
            return None, 'password'

    fingerprint = proxy.get('client-fingerprint')
    if fingerprint:
        normalized = normalize_fingerprint(fingerprint)
        if normalized:
            proxy['client-fingerprint'] = normalized
        else:
            proxy.pop('client-fingerprint', None)

    reality = proxy.get('reality-opts') or {}
    if reality.get('public-key') is not None:
        if _b64_byte_len(reality.get('public-key')) != 32:
            return None, 'reality-key'
        short_id = reality.get('short-id')
        if short_id is not None and not _SHORT_ID.match(str(short_id)):
            reality.pop('short-id', None)

    if proxy.get('flow') and proxy['flow'] not in CLASH_FLOWS:
        proxy.pop('flow', None)

    if node_type == 'hysteria2':
        if proxy.get('obfs') not in HY2_OBFS_TYPES or \
                not str(proxy.get('obfs-password') or ''):
            proxy.pop('obfs', None)
            proxy.pop('obfs-password', None)

    if node_type == 'tuic':
        if proxy.get('congestion-controller') not in TUIC_CONGESTION:
            proxy.pop('congestion-controller', None)
        if proxy.get('udp-relay-mode') not in TUIC_UDP_RELAY:
            proxy.pop('udp-relay-mode', None)

    alpn = proxy.get('alpn')
    if alpn:
        cleaned = [str(item).strip() for item in alpn if str(item).strip()]
        if cleaned:
            proxy['alpn'] = cleaned
        else:
            proxy.pop('alpn', None)

    return proxy, ''


def sanitize_singbox_outbound(outbound, node):
    """校验并修正 sing-box outbound；返回 (outbound, '') 或 (None, 丢弃原因)。"""
    if not outbound:
        return None, 'unsupported'

    # outbound 里的 type 是 sing-box 的写法（ss -> shadowsocks），协议判断用原始类型
    node_type = str(node.get('type') or '')
    if not str(outbound.get('server') or '').strip():
        return None, 'server'
    if not _port_ok(outbound.get('server_port')):
        return None, 'port'
    if not str(outbound.get('tag') or '').strip():
        return None, 'tag'

    if node_type in ('vmess', 'vless', 'trojan'):
        if (node.get('network') or 'tcp').lower() not in CLASH_NETWORKS:
            return None, f"network:{node.get('network')}"

    if node_type in ('vmess', 'vless'):
        if not _UUID_DASHED.match(str(outbound.get('uuid') or '')):
            return None, 'uuid'
        if node_type == 'vmess':
            security = str(outbound.get('security') or 'auto').lower()
            outbound['security'] = security if security in V2RAY_SECURITY else 'auto'

    if node_type == 'ss':
        method = str(outbound.get('method') or '').lower()
        if method not in SINGBOX_SS_CIPHERS:
            return None, f'method:{method}'
        if not str(outbound.get('password') or ''):
            return None, 'password'
        if not ss_key_len_ok(method, outbound['password']):
            return None, f'key:{method}'

    if node_type in ('trojan', 'hysteria2', 'tuic'):
        if not str(outbound.get('password') or ''):
            return None, 'password'

    if outbound.get('flow') and outbound['flow'] not in SINGBOX_FLOWS:
        outbound.pop('flow', None)

    tls = outbound.get('tls') or {}
    if isinstance(tls, dict) and tls:
        utls = tls.get('utls')
        if isinstance(utls, dict):
            normalized = normalize_fingerprint(utls.get('fingerprint'))
            if normalized:
                utls['fingerprint'] = normalized
            else:
                tls.pop('utls', None)
        reality = tls.get('reality')
        if isinstance(reality, dict) and _b64_byte_len(reality.get('public_key')) != 32:
            return None, 'reality-key'
        if isinstance(reality, dict):
            short_id = reality.get('short_id')
            if short_id is not None and not _SHORT_ID.match(str(short_id)):
                reality.pop('short_id', None)
            # REALITY 必须启用 uTLS，否则 sing-box 报 "uTLS is required by reality client"
            if not isinstance(tls.get('utls'), dict):
                tls['utls'] = {'enabled': True, 'fingerprint': 'chrome'}

    obfs = outbound.get('obfs')
    if isinstance(obfs, dict):
        if obfs.get('type') not in HY2_OBFS_TYPES or not str(obfs.get('password') or ''):
            outbound.pop('obfs', None)

    if node_type == 'tuic':
        if outbound.get('congestion_control') not in TUIC_CONGESTION:
            outbound.pop('congestion_control', None)
        if outbound.get('udp_relay_mode') not in TUIC_UDP_RELAY:
            outbound.pop('udp_relay_mode', None)

    return outbound, ''
