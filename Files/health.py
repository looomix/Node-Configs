"""节点连通性探测：给最终配置做一轮轻量清洗，剔除确认不可达的地址。

只做 **TCP 连接**，不做 TLS 握手，原因是 REALITY / 自签证书 / uTLS 指纹
这三类节点的握手结果和「能不能用」没有必然关系（REALITY 服务端会主动拒绝
指纹不对的 ClientHello，正常客户端却能连上）。TCP 层通不通是唯一能用一次
握手就判定的事实。

判定分三类：
  alive   连接成功；
  refused 端口拒绝（RST）或域名解析失败 —— 这类地址一定是死的；
  unknown 超时 / 网络不可达 —— 可能是本地防火墙或探测环境问题，保留。

剔除只针对 refused，且有两道保护：
  * 死节点占比超过 MAX_DROP_RATIO 时，认定是探测环境异常（例如 CI 出口被限速），
    整批保留，只记录数字；
  * 样本量小于 MIN_SAMPLE 时不做剔除。
"""

import asyncio
import json
import logging
import os
import socket
from datetime import datetime

import pytz

DEFAULT_TIMEOUT = float(os.environ.get('HEALTH_TIMEOUT', '3'))
DEFAULT_CONCURRENCY = int(os.environ.get('HEALTH_CONCURRENCY', '100'))

# 死节点占比超过这个值就认为探测环境有问题，不做剔除
MAX_DROP_RATIO = float(os.environ.get('HEALTH_MAX_DROP_RATIO', '0.5'))
# 连通率低于这个值时同样判定探测环境不可信（例如出口被墙、机房限速），
# 此时既不剔除也不对外展示这个百分比
MIN_ALIVE_RATIO = float(os.environ.get('HEALTH_MIN_ALIVE_RATIO', '0.1'))
# 样本太少时百分比没有意义，不剔除
MIN_SAMPLE = 50

ENABLED = os.environ.get('HEALTH_CHECK', '1').lower() not in ('0', 'false', 'no', 'off')

_ALIVE, _REFUSED, _UNKNOWN = 'alive', 'refused', 'unknown'


async def _probe(host, port, timeout):
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
    except asyncio.TimeoutError:
        return _UNKNOWN
    except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError):
        return _REFUSED
    except socket.gaierror:
        # 域名根本解析不了，这个节点一定是死的
        return _REFUSED
    except (OSError, ValueError):
        # 网络不可达、参数非法等：无法据此判定节点本身
        return _UNKNOWN
    else:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, AttributeError):
            pass
        return _ALIVE


async def probe_nodes(nodes, timeout=DEFAULT_TIMEOUT,
                      concurrency=DEFAULT_CONCURRENCY):
    """并发探测节点，返回 {序号: 结果}。序号与传入列表下标一致。"""
    semaphore = asyncio.Semaphore(max(1, concurrency))
    results = {}

    async def worker(index, node):
        async with semaphore:
            try:
                results[index] = await _probe(str(node.get('server')),
                                              int(node.get('port')), timeout)
            except Exception as e:
                # 任何单个节点都不该影响整批探测（IDN 域名、极端端口串等）
                logging.debug(f"探测 {node.get('server')}:{node.get('port')} 失败: {e}")
                results[index] = _UNKNOWN

    await asyncio.gather(*(worker(i, node) for i, node in enumerate(nodes)))
    return results


def _summarize(nodes, results):
    by_protocol = {}
    for index, node in enumerate(nodes):
        bucket = by_protocol.setdefault(
            node['type'], {'checked': 0, _ALIVE: 0, _REFUSED: 0, _UNKNOWN: 0})
        bucket['checked'] += 1
        bucket[results.get(index, _UNKNOWN)] += 1

    alive = sum(1 for value in results.values() if value == _ALIVE)
    refused = sum(1 for value in results.values() if value == _REFUSED)
    checked = len(nodes)
    return {
        'checked': checked,
        'alive': alive,
        'unreachable': refused,
        'unknown': checked - alive - refused,
        'alive_ratio': round(alive / checked, 4) if checked else 0,
        'by_protocol': by_protocol,
    }


def filter_unreachable(nodes, results):
    """按探测结果挑出要保留的节点；返回 (保留列表, 说明字典)。"""
    summary = _summarize(nodes, results)
    checked = summary['checked']
    refused = summary['unreachable']

    if not ENABLED:
        summary['dropped'] = 0
        summary['skipped_reason'] = 'disabled'
        return list(nodes), summary

    if checked < MIN_SAMPLE:
        summary['dropped'] = 0
        summary['skipped_reason'] = 'too-few-nodes'
        return list(nodes), summary

    if summary['alive_ratio'] < MIN_ALIVE_RATIO:
        # 连一个都连不上，说明这台机器到境外的 TCP 出站本身就不通
        # （CI 跑在国内网络、或出口被限速）。此时任何剔除都是在拿环境问题
        # 当节点问题，整批保留，也不把这个百分比写进 README。
        logging.warning(
            f"存活探测：仅 {summary['alive']}/{checked} 个节点可连通"
            f"（{summary['alive_ratio']:.1%}，低于 {MIN_ALIVE_RATIO:.0%}），"
            f"判定为探测环境不可信，本次不剔除节点")
        summary['dropped'] = 0
        summary['skipped_reason'] = 'probe-unreliable'
        return list(nodes), summary

    if refused / checked > MAX_DROP_RATIO:
        # 一大半节点都 RST，更可能是探测环境（CI 出口、本地网络）被限速，
        # 而不是上游突然全部关站。此时保留全部，仅记录数字。
        logging.warning(
            f"存活探测：{refused}/{checked} 个节点拒绝连接（{refused / checked:.0%}），"
            f"超过 {MAX_DROP_RATIO:.0%} 阈值，判定为探测环境异常，本次不剔除节点")
        summary['dropped'] = 0
        summary['skipped_reason'] = 'too-many-dead'
        return list(nodes), summary

    kept = [node for index, node in enumerate(nodes)
            if results.get(index) != _REFUSED]
    summary['dropped'] = len(nodes) - len(kept)
    return kept, summary


def save_status(summary, path):
    payload = {
        'updated_at': datetime.now(pytz.timezone('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S'),
        'enabled': ENABLED,
        'method': 'tcp-connect',
        'timeout_seconds': DEFAULT_TIMEOUT,
    }
    payload.update(summary)
    payload['by_protocol'] = {
        proto: {
            'checked': value['checked'],
            'alive': value[_ALIVE],
            'unreachable': value[_REFUSED],
            'unknown': value[_UNKNOWN],
        }
        for proto, value in sorted(summary.get('by_protocol', {}).items())
    }
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8', newline='\n') as f:
            json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=False)
            f.write('\n')
        logging.info(f"Saved health status to {path}")
    except OSError as e:
        logging.error(f"Failed to write {path}: {e}")
    return payload


async def check(nodes, status_path=None):
    """探测并返回 (保留节点, 统计)。探测被禁用时原样返回。"""
    if not ENABLED:
        logging.info("存活探测已通过 HEALTH_CHECK=0 关闭，跳过")
        return list(nodes), {'checked': len(nodes), 'alive': 0,
                             'unreachable': 0, 'unknown': 0,
                             'alive_ratio': 0, 'dropped': 0,
                             'skipped_reason': 'disabled'}

    if not nodes:
        return [], {'checked': 0, 'alive': 0, 'unreachable': 0,
                    'unknown': 0, 'alive_ratio': 0, 'dropped': 0}

    logging.info(f"存活探测：{len(nodes)} 个节点，超时 {DEFAULT_TIMEOUT:g}s，"
                 f"并发 {DEFAULT_CONCURRENCY}")
    results = await probe_nodes(nodes)
    kept, summary = filter_unreachable(nodes, results)
    logging.info(
        f"存活探测结果：可连通 {summary['alive']}，拒绝连接 {summary['unreachable']}，"
        f"无响应 {summary['unknown']}，存活率 {summary['alive_ratio']:.1%}，"
        f"剔除 {summary['dropped']}")

    if status_path:
        save_status(summary, status_path)
    return kept, summary
