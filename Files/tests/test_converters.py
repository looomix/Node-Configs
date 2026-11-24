"""转换器单测。

覆盖的都是「一个节点写坏 → 整份配置被客户端拒绝加载」的分支：
加密方式、UUID、REALITY 密钥、传输层、插件、密钥长度。历史上这几个地方
各出过一次事故，加用例是为了以后改白名单时能被立刻挡住。
"""

import base64
import json

import pytest

import converters as cv

UUID = '11112222-3333-4444-5555-666677778888'
# 32 字节 base64，去掉补位后 43 个字符，正是 REALITY public-key 的合法形态
PBK = base64.b64encode(b'\x01' * 32).decode().rstrip('=')


def b64(text):
    return base64.b64encode(text.encode()).decode()


def make_vless(query='', fragment='n', userinfo=UUID):
    return f'vless://{userinfo}@1.2.3.4:443?{query}#{fragment}'


def make_clash(node):
    proxy, reason = cv.sanitize_clash_proxy(cv.clash_proxy(node), node)
    assert reason == '' or proxy is None, f'既返回了 proxy 又有 reason={reason}'
    return proxy


def make_singbox(node):
    outbound, reason = cv.sanitize_singbox_outbound(cv.singbox_outbound(node), node)
    assert reason == '' or outbound is None, f'既返回了 outbound 又有 reason={reason}'
    return outbound


# --------------------------------------------------------------------------
# 基础解析
# --------------------------------------------------------------------------

def test_parse_vless_reality_keeps_keys():
    node = cv.parse_uri(make_vless(
        f'encryption=none&security=reality&sni=a.com&fp=chrome&pbk={PBK}&sid=ab12&type=tcp'))
    assert node['type'] == 'vless'
    assert node['uuid'] == UUID
    assert node['reality_pbk'] == PBK
    assert node['reality_sid'] == 'ab12'
    assert node['tls'] is True

    proxy = make_clash(node)
    assert proxy['reality-opts'] == {'public-key': PBK, 'short-id': 'ab12'}


def test_trojan_reality_keeps_keys():
    """trojan + REALITY 曾经只读 security，pbk/sid 被丢掉导致全部连不上。"""
    node = cv.parse_uri(
        f'trojan://pass@1.2.3.4:443?security=reality&pbk={PBK}&sid=ab&sni=a.com#t')
    assert node['reality_pbk'] == PBK
    proxy = make_clash(node)
    assert proxy['reality-opts']['public-key'] == PBK


def test_invalid_reality_pbk_is_dropped():
    node = cv.parse_uri(make_vless('security=reality&pbk=not-a-32-byte-key'))
    assert make_clash(node) is None
    assert make_singbox(node) is None


@pytest.mark.parametrize('sid,expected', [
    ('ab12', 'ab12'),
    ('ABCD', 'abcd'),
    ('', ''),
    ('a', ''),        # 奇数位
    ('xyz', ''),      # 非十六进制
    ('1234567890abcdef00', ''),  # 超过 8 字节
])
def test_short_id_normalization(sid, expected):
    assert cv.normalize_short_id(sid) == expected


def test_invalid_short_id_is_removed_but_node_kept():
    node = cv.parse_uri(make_vless(f'security=reality&pbk={PBK}&sid=zz'))
    proxy = make_clash(node)
    assert proxy is not None
    assert 'short-id' not in proxy['reality-opts']


@pytest.mark.parametrize('uuid,ok', [
    (UUID, True),
    (UUID.replace('-', ''), True),
    ('00000000-0000-0000-0000-000000000000', True),
    ('Fluffy_VPN-Oth8rOq3', False),
    ('', False),
    ('1111-2222', False),
])
def test_uuid_validation(uuid, ok):
    assert bool(cv.normalize_uuid(uuid)) is ok


def test_vmess_bare_uuid_is_expanded():
    payload = {'add': '1.2.3.4', 'port': '443', 'id': UUID.replace('-', ''),
               'aid': '0', 'net': 'ws', 'host': 'a.com', 'path': '/ws',
               'tls': 'tls', 'ps': 'vm'}
    node = cv.parse_uri('vmess://' + b64(json.dumps(payload)))
    assert node['uuid'] == UUID
    assert make_clash(node)['uuid'] == UUID


def test_mislabeled_ss_is_parseable_as_ss():
    """ss://<UUID> 这种源站错标，parse_uri 侧仍可能解析失败，交给 scrip 纠正。"""
    assert cv.is_valid_ss(f'ss://{UUID}@1.2.3.4:443?security=reality') is False


# --------------------------------------------------------------------------
# Shadowsocks
# --------------------------------------------------------------------------

def test_shadowsocks_long_scheme():
    """shadowsocks:// 长写法曾按 len('ss://') 截断导致整条解析失败。"""
    uri = 'shadowsocks://' + b64('aes-256-gcm:pass') + '@1.2.3.4:8388#n'
    node = cv.parse_uri(uri)
    assert node is not None
    assert node['method'] == 'aes-256-gcm'
    assert node['password'] == 'pass'


@pytest.mark.parametrize('raw,expected', [
    ('chacha20-poly1305', 'chacha20-ietf-poly1305'),
    ('CHACHA20-ietf-poly1305', 'chacha20-ietf-poly1305'),
    ('plain', 'none'),
    ('aes-256-gcm', 'aes-256-gcm'),
])
def test_ss_method_alias(raw, expected):
    assert cv.normalize_ss_method(raw) == expected


def test_ss_unknown_cipher_is_rejected_at_parse():
    uri = 'ss://' + b64('bf-cfb:pass') + '@1.2.3.4:8388'
    assert cv.parse_uri(uri) is None


def test_ss_2022_key_length():
    short = base64.b64encode(b'\x01' * 16).decode()
    good = base64.b64encode(b'\x01' * 32).decode()

    bad_node = cv.parse_uri(f'ss://2022-blake3-aes-256-gcm:{short}@1.2.3.4:8388#x')
    assert bad_node is not None, '解析阶段不拦，交给出口闸'
    assert make_clash(bad_node) is None
    assert make_singbox(bad_node) is None

    good_node = cv.parse_uri(f'ss://2022-blake3-aes-256-gcm:{good}@1.2.3.4:8388#x')
    assert make_clash(good_node) is not None


def test_ss_plugin_unknown_is_dropped():
    uri = ('ss://' + b64('aes-256-gcm:pass') + '@1.2.3.4:8388'
           '?plugin=mystery-plugin;mode=x#n')
    node = cv.parse_uri(uri)
    assert node['plugin'] == 'mystery-plugin'
    assert make_clash(node) is None
    assert make_singbox(node) is None


def test_ss_obfs_plugin_maps_to_clash():
    uri = ('ss://' + b64('aes-256-gcm:pass') + '@1.2.3.4:8388'
           '?plugin=obfs-local;obfs=http;obfs-host=a.com#n')
    proxy = make_clash(cv.parse_uri(uri))
    assert proxy['plugin'] == 'obfs'
    assert proxy['plugin-opts'] == {'mode': 'http', 'host': 'a.com'}


def test_ssr_shadow_tls_not_written_to_singbox():
    """sing-box 不认识 shadow-tls，写进去整份配置会校验失败。"""
    uri = ('ss://' + b64('aes-256-gcm:pass') + '@1.2.3.4:8388'
           '?plugin=shadow-tls;host=a.com;password=x#n')
    node = cv.parse_uri(uri)
    assert make_clash(node) is not None
    assert make_singbox(node) is None


# --------------------------------------------------------------------------
# 传输层
# --------------------------------------------------------------------------

@pytest.mark.parametrize('raw,expected', [
    ('raw', 'tcp'), ('none', 'tcp'), ('http', 'h2'), ('websocket', 'ws'),
    ('gun', 'grpc'), ('splithttp', 'xhttp'), ('xhttp', 'xhttp'),
    ('ws', 'ws'), ('', 'tcp'), (None, 'tcp'),
])
def test_network_aliases(raw, expected):
    assert cv.normalize_network(raw) == expected


def test_xhttp_is_supported_by_clash_only():
    uri = make_vless('type=xhttp&path=%2Fx&host=a.com&mode=auto&security=tls')
    node = cv.parse_uri(uri)
    proxy = make_clash(node)
    assert proxy['network'] == 'xhttp'
    assert proxy['xhttp-opts'] == {'path': '/x', 'host': 'a.com', 'mode': 'auto'}
    # sing-box 至今不支持 xhttp，必须继续过滤
    assert make_singbox(node) is None


@pytest.mark.parametrize('raw_mode,kept', [
    ('auto', True), ('packet-up', True), ('stream-up', True),
    ('stream-one', True), ('AUTO', True), ('bogus', False), ('', False),
])
def test_xhttp_mode_whitelist(raw_mode, kept):
    node = cv.parse_uri(make_vless(f'type=xhttp&path=%2Fx&mode={raw_mode}&security=tls'))
    proxy = make_clash(node)
    assert ('mode' in proxy['xhttp-opts']) is kept
    if kept:
        assert proxy['xhttp-opts']['mode'] == raw_mode.lower()


def test_xhttp_host_must_be_string():
    """mihomo 的 xhttp-opts.host 是字符串，h2-opts.host 才是数组。"""
    node = cv.parse_uri(make_vless('type=xhttp&path=%2Fx&host=a.com&security=tls'))
    proxy = make_clash(node)
    assert isinstance(proxy['xhttp-opts']['host'], str)

    # 即使上游给成非字符串，出口闸也要修正成字符串
    node['network'] = 'xhttp'
    broken = {'name': 'x', 'type': 'vless', 'server': '1.2.3.4', 'port': 443,
              'uuid': UUID, 'network': 'xhttp',
              'xhttp-opts': {'path': '/x', 'host': ['a.com']}}
    fixed, reason = cv.sanitize_clash_proxy(broken, node)
    assert reason == ''
    assert fixed['xhttp-opts']['host'] == 'a.com'


def test_h2_host_is_list():
    proxy = make_clash(cv.parse_uri(make_vless('type=http&path=%2F&host=a.com&security=tls')))
    assert proxy['network'] == 'h2'
    assert proxy['h2-opts']['host'] == ['a.com']


def test_httpupgrade_maps_to_ws_in_clash():
    proxy = make_clash(cv.parse_uri(make_vless(
        'type=httpupgrade&path=%2Fup&host=a.com&security=tls')))
    assert proxy['network'] == 'ws'
    assert proxy['ws-opts']['v2ray-http-upgrade'] is True

    outbound = make_singbox(cv.parse_uri(make_vless(
        'type=httpupgrade&path=%2Fup&host=a.com&security=tls')))
    assert outbound['transport'] == {'type': 'httpupgrade', 'path': '/up', 'host': 'a.com'}


def test_unsupported_network_dropped_on_both_sides():
    node = cv.parse_uri(make_vless('type=kcp&security=tls'))
    node['network'] = 'kcp'
    assert make_clash(node) is None
    assert make_singbox(node) is None


# --------------------------------------------------------------------------
# 其它协议
# --------------------------------------------------------------------------

def test_hysteria2_obfs_requires_password():
    node = cv.parse_uri('hysteria2://pass@1.2.3.4:443?sni=a.com&obfs=salamander#h')
    proxy = make_clash(node)
    assert 'obfs' not in proxy, '缺少 obfs-password 时不能只写 obfs'

    node = cv.parse_uri(
        'hysteria2://pass@1.2.3.4:443?sni=a.com&obfs=salamander&obfs-password=pw#h')
    proxy = make_clash(node)
    assert proxy['obfs'] == 'salamander'
    assert proxy['obfs-password'] == 'pw'


def test_hysteria2_bad_obfs_dropped():
    node = cv.parse_uri(
        'hysteria2://pass@1.2.3.4:443?obfs=unknown&obfs-password=pw#h')
    assert 'obfs' not in make_clash(node)
    assert 'obfs' not in make_singbox(node)


def test_tuic_invalid_uuid_dropped_from_singbox():
    """sing-box 会在 initialize outbound 阶段拒绝非法 uuid。"""
    node = cv.parse_uri(f'tuic://{UUID}:pass@1.2.3.4:443?sni=a.com#t')
    assert make_singbox(node) is not None

    node['uuid'] = 'not-a-uuid'
    assert make_singbox(node) is None


def test_tuic_enums_are_pruned():
    node = cv.parse_uri(
        f'tuic://{UUID}:pass@1.2.3.4:443?sni=a.com'
        '&congestion_control=bogus&udp_relay_mode=bogus#t')
    proxy = make_clash(node)
    assert 'congestion-controller' not in proxy
    assert 'udp-relay-mode' not in proxy


def test_ssr_type_is_not_written_to_singbox():
    main = '1.2.3.4:8388:origin:aes-256-cfb:plain:%s' % b64('pass')
    query = '/?remarks=' + b64('ssr')
    uri = 'ssr://' + b64(main + query)
    node = cv.parse_uri(uri)
    assert node['type'] == 'ssr'
    assert make_clash(node) is not None
    assert make_singbox(node) is None


@pytest.mark.parametrize('protocol,obfs', [
    ('origin', 'plain'),
    ('auth_chain_a', 'tls1.2_ticket_auth'),
    ('verify_sha1', 'plain'),      # 不支持
    ('origin', 'tls_ticket'),      # 不支持
])
def test_ssr_protocol_obfs_whitelist(protocol, obfs):
    main = f'1.2.3.4:8388:{protocol}:aes-256-cfb:{obfs}:{b64("pass")}'
    node = cv.parse_uri('ssr://' + b64(main + '/?remarks=' + b64('x')))
    assert node is not None
    supported = protocol in cv.SSR_PROTOCOLS and obfs in cv.SSR_OBFS
    assert (make_clash(node) is not None) is supported


def test_unknown_fragment_name_falls_back_to_host_port():
    node = cv.parse_uri(make_vless('security=tls'))
    assert node['name'] == 'n'
    node = cv.parse_uri(f'vless://{UUID}@1.2.3.4:443?security=tls')
    assert node['name'] == '1.2.3.4:443'


def test_parse_uri_never_raises():
    for junk in ['', 'not a uri', 'vmess://', 'ss://', 'vless://u@:0',
                 'trojan://', 'hysteria2://', 'tuic://', 'ssr://', '://x']:
        assert cv.parse_uri(junk) is None


def test_parse_uri_rejects_non_string():
    assert cv.parse_uri(None) is None
    assert cv.parse_uri(123) is None


# --------------------------------------------------------------------------
# sing-box 专有约束
# --------------------------------------------------------------------------

def test_singbox_ss_type_name_is_shadowsocks():
    node = cv.parse_uri('ss://' + b64('aes-256-gcm:pass') + '@1.2.3.4:8388#n')
    outbound = make_singbox(node)
    assert outbound['type'] == 'shadowsocks'


def test_singbox_reality_always_has_utls():
    node = cv.parse_uri(make_vless(f'security=reality&pbk={PBK}&sid=ab&sni=a.com'))
    node['fp'] = ''          # 源站没给指纹
    outbound = make_singbox(node)
    assert outbound['tls']['utls']['enabled'] is True
    assert outbound['tls']['utls']['fingerprint'] in cv.CLASH_FINGERPRINTS


def test_singbox_unknown_fingerprint_is_removed():
    node = cv.parse_uri(make_vless('security=tls&fp=hello_chrome_120&sni=a.com'))
    assert make_singbox(node)['tls']['utls']['fingerprint'] == 'chrome'

    node = cv.parse_uri(make_vless('security=tls&fp=definitely-not-a-fp&sni=a.com'))
    outbound = make_singbox(node)
    assert 'utls' not in outbound.get('tls', {})


def test_vmess_security_unknown_falls_back_to_auto():
    payload = {'add': '1.2.3.4', 'port': '443', 'id': UUID,
               'scy': 'totally-unknown', 'net': 'tcp', 'tls': 'tls'}
    node = cv.parse_uri('vmess://' + b64(json.dumps(payload)))
    assert make_clash(node)['cipher'] == 'auto'
    assert make_singbox(node)['security'] == 'auto'


def test_flow_whitelist():
    node = cv.parse_uri(make_vless('security=tls&flow=xtls-rprx-vision&sni=a.com'))
    assert make_clash(node)['flow'] == 'xtls-rprx-vision'

    node = cv.parse_uri(make_vless('security=tls&flow=unknown-flow&sni=a.com'))
    assert 'flow' not in make_clash(node)
    assert 'flow' not in make_singbox(node)


def test_empty_server_or_port_rejected():
    assert cv.parse_uri(f'vless://{UUID}@:443?security=tls') is None
    assert cv.parse_uri(f'vless://{UUID}@1.2.3.4:0?security=tls') is None
    assert cv.parse_uri(f'vless://{UUID}@1.2.3.4:99999?security=tls') is None
