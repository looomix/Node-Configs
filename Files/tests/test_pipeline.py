"""抓取/清洗环节的单测：粘连链接拆分、命名、存活剔除策略。"""

import health
import scrip


# --------------------------------------------------------------------------
# 粘连链接拆分
# --------------------------------------------------------------------------

def test_split_single_link_untouched():
    uri = 'vless://u@a.com:443?type=ws#n'
    assert scrip.split_glued_links(uri) == [uri]


def test_split_vless_pair():
    glued = ('vless://u1@a.com:443?type=ws#n1'
             'vless://u2@b.com:443?type=ws#n2')
    assert scrip.split_glued_links(glued) == [
        'vless://u1@a.com:443?type=ws#n1',
        'vless://u2@b.com:443?type=ws#n2',
    ]


def test_split_does_not_cut_at_ss_inside_vless():
    """`vless://` 的第 4 个字符起就是 `ss://`，曾经被切成 'vle' + 'ss://...'。"""
    pieces = scrip.split_glued_links('vless://abc@a.com:443#n')
    assert pieces == ['vless://abc@a.com:443#n']


def test_split_mixed_schemes():
    glued = 'vless://u@a.com:443#n1ss://YWVzLTI1Ni1nY206cA==@b.com:8388#n2'
    assert scrip.split_glued_links(glued) == [
        'vless://u@a.com:443#n1',
        'ss://YWVzLTI1Ni1nY206cA==@b.com:8388#n2',
    ]


def test_split_keeps_each_link_in_its_own_category():
    glued = 'ss://YWVzLTI1Ni1nY206cA==@b.com:8388#n2vless://u@a.com:443#n1'
    pieces = scrip.split_glued_links(glued)
    assert [scrip.category_of(p) for p in pieces] == ['ShadowSocks', 'Vless']


# --------------------------------------------------------------------------
# 过滤规则
# --------------------------------------------------------------------------

def test_filter_reason():
    assert scrip.filter_reason('vless://u@a.com#i_love_you') == 'i_love_'
    assert scrip.filter_reason('vless://u@a.com#%25' * 16) == 'percent25'
    assert scrip.filter_reason('vless://u@a.com#' + 'x' * 1600) == 'too_long'
    assert scrip.filter_reason('vless://u@a.com#%2525') == 'double_encoded'
    assert scrip.filter_reason('vless://u@a.com#n') is None


def test_mislabeled_ss_detection():
    uuid = '11112222-3333-4444-5555-666677778888'
    assert scrip.is_mislabeled_ss(f'ss://{uuid}@a.com:443?security=reality') is True
    assert scrip.is_mislabeled_ss(f'ss://{uuid}@a.com:443?encryption=none') is True
    # 真正的 shadowsocks 不能误判
    assert scrip.is_mislabeled_ss(
        'ss://YWVzLTI1Ni1nY206cGFzcw==@a.com:8388#n') is False
    # 既不是 UUID 也没有 vless 参数
    assert scrip.is_mislabeled_ss('ss://user@a.com:443') is False


# --------------------------------------------------------------------------
# 命名
# --------------------------------------------------------------------------

def test_assign_unique_names_is_stable_and_unique():
    def sample():
        return [
            {'type': 'vless', 'server': '1.2.3.4', 'port': 443,
             'uuid': 'b', 'name': '🚀 t.me/广告频道'},
            {'type': 'vless', 'server': '1.2.3.4', 'port': 443,
             'uuid': 'a', 'name': '🇺🇸 US Node'},
            {'type': 'ss', 'server': '5.6.7.8', 'port': 8388,
             'method': 'aes-256-gcm', 'password': 'p', 'name': '123'},
        ]

    nodes = sample()
    scrip.assign_unique_names(nodes)
    names = [node['name'] for node in nodes]
    assert len(set(names)) == len(names)
    assert all('t.me' not in name for name in names)
    assert any(name.startswith('🇺🇸 US-Vless') for name in names)

    # 同样的输入再跑一次（名字来自源站），结果必须完全一致
    again = sample()
    scrip.assign_unique_names(again)
    assert [node['name'] for node in again] == names


def test_country_code_from_flag():
    assert scrip._country_code('🇺🇸 US') == 'US'
    assert scrip._country_code('🇯🇵 日本') == 'JP'
    assert scrip._country_code('no flag') == ''


# --------------------------------------------------------------------------
# 存活剔除策略
# --------------------------------------------------------------------------

def make_nodes(count, proto='vless'):
    return [{'type': proto, 'server': f'10.0.0.{i}', 'port': 443}
            for i in range(count)]


def test_filter_keeps_timeout_drops_refused():
    nodes = make_nodes(100)
    results = {i: ('refused' if i < 10 else
                   ('alive' if i < 60 else 'unknown')) for i in range(100)}
    kept, summary = health.filter_unreachable(nodes, results)
    assert len(kept) == 90
    assert summary['dropped'] == 10
    assert summary['alive'] == 50
    assert summary['unreachable'] == 10
    assert summary['unknown'] == 40


def test_filter_skips_when_too_many_dead():
    """一大半地址被 RST 时更可能是探测环境问题，不能把节点全删了。"""
    nodes = make_nodes(100)
    results = {i: ('refused' if i < 70 else 'alive') for i in range(100)}
    kept, summary = health.filter_unreachable(nodes, results)
    assert len(kept) == 100
    assert summary['dropped'] == 0
    assert summary['skipped_reason'] == 'too-many-dead'


def test_filter_skips_when_probe_environment_is_broken():
    nodes = make_nodes(100)
    results = {i: ('alive' if i < 2 else 'unknown') for i in range(100)}
    kept, summary = health.filter_unreachable(nodes, results)
    assert len(kept) == 100
    assert summary['skipped_reason'] == 'probe-unreliable'


def test_filter_skips_for_small_sample():
    nodes = make_nodes(10)
    results = {i: 'refused' for i in range(10)}
    kept, summary = health.filter_unreachable(nodes, results)
    assert len(kept) == 10
    assert summary['skipped_reason'] == 'too-few-nodes'


def test_filter_disabled_keeps_everything(monkeypatch):
    monkeypatch.setattr(health, 'ENABLED', False)
    nodes = make_nodes(100)
    results = {i: 'refused' for i in range(100)}
    kept, summary = health.filter_unreachable(nodes, results)
    assert len(kept) == 100
    assert summary['skipped_reason'] == 'disabled'


def test_summarize_by_protocol():
    nodes = make_nodes(50) + make_nodes(50, 'ss')
    results = {i: 'alive' for i in range(100)}
    summary = health._summarize(nodes, results)
    assert summary['by_protocol']['vless']['alive'] == 50
    assert summary['by_protocol']['ss']['alive'] == 50
    assert summary['alive_ratio'] == 1.0
