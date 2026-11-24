# 🧩 Node-Configs

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/looomix/Node-Configs/main.yml?style=flat-square&label=update" alt="Update Status" />
  <img src="https://img.shields.io/badge/nodes-2366-blue?style=flat-square" alt="Nodes" />
  <img src="https://img.shields.io/badge/links-3314-informational?style=flat-square" alt="Links" />
  <img src="https://img.shields.io/badge/python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.9+" />
  <img src="https://img.shields.io/github/last-commit/looomix/Node-Configs?style=flat-square" alt="Last Commit" />
  <img src="https://img.shields.io/github/stars/looomix/Node-Configs?style=social" alt="Stars" />
</p>

<p align="center">
  从公开来源自动聚合网络节点，转换成 <b>Clash / mihomo</b> 与 <b>sing-box</b> 可直接导入的订阅配置<br>
  每 12 小时自动更新 · 最后更新 <b>2026-11-25 06:16</b><br>
  <sub>最近一次 TCP 探测：2218/2448 可连通（<b>91%</b>），已剔除 78 个拒绝连接的地址</sub>
</p>

## ⚡ 快速订阅

复制链接，粘贴到客户端的「订阅 / 远程配置」即可，无需下载文件。

| 客户端 | 订阅链接（raw） | 镜像链接（gh-proxy） | 内容 |
|:---|:---|:---|:---|
| **Clash / mihomo**<br><sub>Clash Verge · ClashX Meta · FlClash</sub> | [`config.yaml`](https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/clash/config.yaml) | [`config.yaml`](https://gh-proxy.com/https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/clash/config.yaml) | 节点 + 策略组 + 规则，导入即用 |
| **sing-box** | [`config.json`](https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/singbox/config.json) | [`config.json`](https://gh-proxy.com/https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/singbox/config.json) | mixed 入站 + selector / urltest 出站 |
| **v2rayN / v2rayNG**<br><sub>NekoRay · Karing · Hiddify</sub> | [`AllProtocols.txt`](https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/protocols/AllProtocols.txt) | [`AllProtocols.txt`](https://gh-proxy.com/https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/protocols/AllProtocols.txt) | 原始分享链接 |
| **轻量版**（905 节点）<br><sub>只含 hy2 / tuic / vless-reality</sub> | [`light.yaml`](https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/clash/light.yaml) · [`light.json`](https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/singbox/light.json) | [Clash](https://gh-proxy.com/https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/clash/light.yaml) · [sing-box](https://gh-proxy.com/https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/singbox/light.json) | 弱网 / 移动端首选，解析最快 |

如果只想复用节点、不想用本项目提供的规则：

- Clash： [`proxies.yaml`](https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/clash/proxies.yaml) · [镜像](https://gh-proxy.com/https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/clash/proxies.yaml) — 可作为 `proxy-provider`
- sing-box： [`outbounds.json`](https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/singbox/outbounds.json) · [镜像](https://gh-proxy.com/https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/singbox/outbounds.json) — 可合并进已有配置
- 分片： `configs/clash/split/<协议>-<序号>.yaml`，每片 ≤300 个节点，适合按协议单独订阅

> **raw 链接导入报 `EOF` / `connection reset`？** 这不是配置错误，是国内直连
> `raw.githubusercontent.com` 被中断。用右边那列 **gh-proxy 镜像**即可，它的规则就是
> 「`https://gh-proxy.com/` + 原始 raw 地址」，例如 Clash：
> `https://gh-proxy.com/https://raw.githubusercontent.com/looomix/Node-Configs/main/configs/clash/config.yaml`

## 🛠️ 客户端配置

**Clash / mihomo** —— 混合端口 `7890`，控制面板 `127.0.0.1:9090`

1. 「配置」→ 粘贴上面的 `config.yaml` 链接 → 导入；
2. 策略组选 `🚀 节点选择`（手动）或 `♻️ 自动选择`（每 5 分钟测速取最快）；
3. 规则为「局域网与国内直连，其余走 `🐟 漏网之鱼`」。

> 配置里含 <b>329</b> 个 `network: xhttp` 节点（Xray 的 splithttp 传输）。
> **需要 mihomo ≥ 1.19**（Clash Verge Rev 1.7+、FlClash 0.8+ 均已内置）；
> 低于这个版本的客户端会因 `unsupported network` 拒绝加载整份配置，请改用「轻量版」。

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

配置里有 329 个 xhttp（splithttp）节点，需要 mihomo ≥ 1.19。老版本客户端遇到不认识的传输层会**拒绝加载整份配置**，改用 [`light.yaml`](https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/clash/light.yaml)（不含 xhttp）即可，或升级到 Clash Verge Rev 1.7+ / FlClash 0.8+。
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
- 问题与建议请提交 [Issues](https://github.com/looomix/Node-Configs/issues)。
