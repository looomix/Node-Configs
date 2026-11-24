# 🧩 Node-Configs

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/looomix/Node-Configs/main.yml?style=flat-square&label=update" alt="Update Status" />
  <img src="https://img.shields.io/badge/nodes-2390-blue?style=flat-square" alt="Nodes" />
  <img src="https://img.shields.io/badge/links-3152-informational?style=flat-square" alt="Links" />
  <img src="https://img.shields.io/badge/python-3.9%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.9+" />
  <img src="https://img.shields.io/github/last-commit/looomix/Node-Configs?style=flat-square" alt="Last Commit" />
  <img src="https://img.shields.io/github/stars/looomix/Node-Configs?style=social" alt="Stars" />
</p>

<p align="center">
  从公开来源自动聚合网络节点，转换成 <b>Clash / mihomo</b> 与 <b>sing-box</b> 可直接导入的订阅配置<br>
  每 12 小时自动更新 · 最后更新 <b>2026-11-24 10:17</b>
</p>

## ⚡ 快速订阅

复制链接，粘贴到客户端的「订阅 / 远程配置」即可，无需下载文件。

| 客户端 | 订阅链接 | 内容 |
|:---|:---|:---|
| **Clash / mihomo**<br><sub>Clash Verge · ClashX Meta · FlClash</sub> | [`config.yaml`](https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/clash/config.yaml) | 节点 + 策略组 + 规则，导入即用 |
| **sing-box** | [`config.json`](https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/singbox/config.json) | mixed 入站 + selector / urltest 出站 |
| **v2rayN / v2rayNG**<br><sub>NekoRay · Karing · Hiddify</sub> | [`AllProtocols.txt`](https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/protocols/AllProtocols.txt) | 原始分享链接 |

如果只想复用节点、不想用本项目提供的规则：

- Clash： [`proxies.yaml`](https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/clash/proxies.yaml) — 可作为 `proxy-provider`
- sing-box： [`outbounds.json`](https://raw.githubusercontent.com/looomix/Node-Configs/refs/heads/main/configs/singbox/outbounds.json) — 可合并进已有配置

> **连不上 `raw.githubusercontent.com`？**（Android 端常报 `EOF` / `connection reset`，并非配置错误）
> 在链接前加镜像前缀 `https://gh-proxy.com/` 即可，例如 Clash：
> `https://gh-proxy.com/https://raw.githubusercontent.com/looomix/Node-Configs/main/configs/clash/config.yaml`
> 备选：`https://ghfast.top/` 前缀，或 jsDelivr `https://cdn.jsdelivr.net/gh/looomix/Node-Configs@main/configs/clash/config.yaml`

## 🛠️ 客户端配置

**Clash / mihomo** —— 混合端口 `7890`，控制面板 `127.0.0.1:9090`

1. 「配置」→ 粘贴上面的 `config.yaml` 链接 → 导入；
2. 策略组选 `🚀 节点选择`（手动）或 `♻️ 自动选择`（每 5 分钟测速取最快）；
3. 规则为「局域网与国内直连，其余走 `🐟 漏网之鱼`」。

**sing-box** —— mixed 入站 `127.0.0.1:2080`（HTTP + SOCKS5）

1. 直接使用 `config.json`，或用 `outbounds.json` 替换已有配置的出站部分；
2. 修改端口只需改 `inbounds[0].listen_port`。

**v2rayN / v2rayNG / NekoRay / Karing**

1. 订阅 `AllProtocols.txt`，或到 `configs/protocols/` 取单个协议文件；
2. 客户端「从剪贴板导入 / 订阅」中导入即可。

## 📁 目录结构

```text
Node-Configs/
├── configs/
│   ├── clash/
│   │   ├── config.yaml      # 完整配置：节点 + 策略组 + 规则
│   │   └── proxies.yaml     # 仅节点，可作 proxy-provider
│   ├── singbox/
│   │   ├── config.json      # 完整配置：mixed 入站 + 出站
│   │   └── outbounds.json   # 仅出站，可合并进已有配置
│   └── protocols/           # 原始分享链接，按协议分文件
│       ├── AllProtocols.txt
│       ├── Vless.txt / Vmess.txt / Trojan.txt
│       └── ShadowSocks.txt / Hysteria2.txt
├── Files/
│   ├── scrip.py             # 抓取、解析、生成入口
│   ├── converters.py        # 分享链接 → Clash / sing-box 结构
│   ├── key.json             # 各协议正则
│   └── urls.txt             # 节点来源列表
├── stats.json               # 最近一次运行统计（供熔断对比）
└── README.md
```

## 🔄 自动更新

- `schedule` 每 12 小时跑一次，也可在 Actions 页手动 `workflow_dispatch`；
- 修改 `Files/**` 或工作流本身会立即触发一次重建；
- 提交前有熔断：本次节点数低于上次 60% 时直接失败退出，不写入、不提交，避免上游集体失败把仓库覆盖成残缺版本；
- 想加源只需编辑 `Files/urls.txt`（每行一个地址，支持 base64 订阅与纯文本），推送后自动生效。

## ❓ 常见问题

<details>
<summary><b>导入后节点大面积超时？</b></summary>

公开节点存活周期很短，换节点或稍后重新订阅通常即可恢复。建议先用 `♻️ 自动选择`，它会自动挑当前延迟最低的节点。
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
<summary><b>为什么某些协议没有出现？</b></summary>

只保留能解析为合法 URI 的节点；sing-box 不支持 SSR，因此 SSR 只出现在 Clash 与原始 txt 中。个别源站把两条链接粘在一起或截断，这类残片会被丢弃并计入「无法转换」。
</details>

## ⚠️ 免责声明

- 本项目仅做公开数据的聚合与格式转换，**不托管、不提供、不保证**任何节点的可用性与安全性；
- 所有节点均来自互联网公开来源，请在遵守所在地法律法规的前提下使用；
- 使用风险自负，因使用本项目内容造成的任何后果由使用者自行承担；
- 问题与建议请提交 [Issues](https://github.com/looomix/Node-Configs/issues)。
