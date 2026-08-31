# hermes-beszel-dashboard

> 把 [beszel](https://github.com/henrygd/beszel)（轻量服务器监控）的整个面板搬进 [Hermes Agent](https://github.com/NousResearch/hermes-agent) dashboard 的插件。不 fork beszel——用「补丁重放」模式吃上游更新，附带可扩展的安全事件采集（探针）架构。

## 为什么

- beszel 是 hub+agent 架构、PocketBase 内核、单二进制超轻量，但 UI 是独立 SPA，得另开网页
- Hermes dashboard 支持多文件插件资产（`/dashboard-plugins/<name>/<path>`），beszel 的 vite 构建产物可以整体塞进插件目录
- 双登录问题用**后端反代**解决：浏览器只认 Hermes 会话，plugin_api.py 持 beszel token 转发 PocketBase API

```
 各 VPS:   beszel-agent(资源指标) + beszel-sec-agent(安全事件)
                          │ ws                │ https POST
                          ▼                   ▼
控制机:            beszel hub ──REST──┐   /ingest (token)
                                     ▼         ▼
                      plugin_api.py 聚合 ──► beszel 唯一 UI
```

## 项目结构

```
├── install.sh              # 一键安装（build → 部署 → enable → 重启）
├── patches/                # beszel 前端魔改补丁（版本化，可重放）
│   ├── 001-pb-baseurl.patch
│   ├── 002-strip-auth-pages.patch
│   └── 003-hermes-tab.patch
├── scripts/
│   ├── build-beszel.sh     # 拉上游 → 打补丁 → vite build
│   └── upgrade.sh          # beszel 新版 → 补丁重放 → 产物更新
├── hub/                    # beszel hub 部署物（systemd unit + 拉取脚本）
├── plugin/
│   ├── manifest.json       # hermes 插件清单
│   └── dashboard/
│       ├── dist/           # beszel 构建产物（build 生成，gitignore）
│       └── plugin_api.py   # PocketBase 反代 + 数据聚合
├── agent/
│   └── beszel-sec-agent.py    # 安全事件探针（SSH 爆破/fail2ban/nginx 扫描）
└── tests/e2e.sh            # 端到端验证
```

## 快速开始

```bash
git clone https://github.com/<you>/hermes-beszel-dashboard
cd hermes-beszel-dashboard
./install.sh
```

## 上游升级

beszel 发新版后：

```bash
./scripts/upgrade.sh   # 重拉上游 → 重放 patches/ → 重 build → 更新产物
```

## License

- 本项目代码：MIT
- beszel：MIT（[上游仓库](https://github.com/henrygd/beszel)）
