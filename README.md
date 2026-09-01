# hermes-beszel-dashboard

> **一个 [Hermes Agent](https://github.com/NousResearch/hermes-agent) dashboard 插件**：把 [beszel](https://github.com/henrygd/beszel)（轻量服务器监控）的整个面板搬进 Hermes 的 dashboard，并在其上叠加一个多机**监控室**（SSH 爆破 / fail2ban / nginx 扫描的采集、聚合、地理定位与攻击地图）。English README: [README.en.md](README.en.md)

**这不是一个独立应用**，它以插件形式存在，随 hermes 一起运行：

- 前端：beszel 的完整 Web 面板，以 iframe 形式挂载在 hermes dashboard 的 beszel tab 下
- 后端：`plugin_api.py`（FastAPI router），挂在 `/api/plugins/beszel/` 下，负责 PocketBase 反代 + 安全事件 API
- 安装：中心侧一条命令装进 `~/.hermes/plugins/beszel/`，agent 侧一条命令装采集器

不 fork beszel——前端用「补丁重放」模式吃上游更新；后端以插件 API 形式挂载，beszel 原有功能（系统指标、agent 通道、机器管理）原样保留。

```
 各 VPS:   beszel-agent(资源指标) + security-collector(安全事件)
                          │ ws                │ https POST /security/ingest
                          ▼                   ▼
控制机:            beszel hub(PocketBase)   token 认证 + 幂等去重 + GeoIP
                          │                    │
                          ▼                    ▼
              plugin_api.py 聚合 ──► hermes dashboard 唯一 UI
```

## 功能

**beszel 原生（未改动）**
- 多机 CPU / 内存 / 磁盘 / 网络 / 温度监控，实时 SSE 推送
- beszel hub + agent 全套管理

**监控室（本项目新增）**
- 三源采集：`auth.log`（SSH 爆破，含用户名提取）、`fail2ban.log`（ban/unban）、nginx access log（扫描/攻击路径）
- 多机架构：agent 无状态只推送（60s 窗口合并抗刷），中心统一入库；`event_id` 幂等 UPSERT，断网用 jsonl 磁盘缓冲补推
- 中心侧 GeoIP 富化（dbip-city-lite，月度自动更新+热重载），攻击地图按真实坐标渲染
- 攻击者卡片（按 IP 聚合）、IP 时间线、实时事件流、全局筛选（`ip:` `type:` `country:` 语法）、CSV/JSON 导出、90 天自动轮换
- 安全：bearer token 复用 beszel 的 universal token（webui `/settings/tokens` 管理）、machine_id 与 beszel systems 表校验、严格输入校验（白名单/IP/时间窗/count 上限/批量上限）、全参数化 SQL

## 项目结构

```
├── install.sh                  # 中心侧安装脚本（一条命令）
├── agent/
│   ├── install-agent.sh        # agent 侧安装脚本（一条命令）
│   ├── security_collector.py   # 安全事件探针：tail 三源日志，push 或本地直写
│   └── security-collector.service  # systemd unit 示例
├── scripts/
│   └── release.sh              # 构建前端 dist → 打包 → 创建 GitHub Release
├── patches/                    # beszel 前端魔改补丁（版本化，可重放）
│   ├── 001..007-*.patch        #   反代 baseURL、去 beszel 登录页、tab 接入等
│   ├── 007-security-ui-enhancements.tsx   # 007 补丁应用后的完整前端快照
│   ├── 008-attack-map.patch    #   攻击地图 + 机器列表接入 security/machines
│   └── 008-attack-map.tsx      #   当前完整前端快照（重放下一个补丁的基底）
├── plugin/
│   ├── manifest.json           # hermes 插件清单
│   └── dashboard/
│       ├── dist/               # beszel vite 构建产物（assets 部分不进 git，走 release）
│       └── plugin_api.py       # PocketBase 反代 + /security/* API（ingest/machines/events/...）
├── hub/                        # 控制机部署物（beszel hub/agent systemd + nginx 反代示例）
└── tests/
    └── smoke.sh                # 部署后冒烟测试（登录→machines→ingest→无token拒收）
```

## 使用说明

安装分两步：先在控制机装中心侧，再去每台被监控机装 agent 侧。

### 中心侧（控制机，跑 hermes + beszel hub 的那台）

**前置**：hermes 已安装（`hermes` 命令可用）。没装的话先装 Hermes Agent：

```bash
curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash
```

**一条命令安装**：

```bash
curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/master/install.sh | bash
```

脚本自动完成：

1. 安装 beszel hub（复用官方脚本，监听 `127.0.0.1:8090`，不暴露公网——面板流量走插件反代）
2. 非交互创建 beszel superuser（`beszel superuser upsert`，**无需浏览器注册**，交互式询问邮箱密码）
3. 从 GitHub Release 下载预构建的插件 dist（`dist/assets`/`index.html` 是 gitignore 的构建产物，走 release 分发）
4. 白名单插件 + 写 beszel 凭据文件 + 下载 GeoIP 库（dbip-city-lite）
5. 重启 dashboard

脚本最后会提示**一个手动步骤**：把 `BESZEL_SUPERUSER_EMAIL` 环境变量加进 hermes-dashboard 的 systemd user unit（`~/.config/systemd/user/hermes-dashboard.service` 的 `[Service]` 段）。这是 plugin_api.py 登录 beszel hub 需要的，漏了会白屏。

装完后去 beszel webui（`http://127.0.0.1:8090`）登录，在 `/settings/tokens` 生成 **universal token**（或添加系统复制公钥+token），供 agent 侧使用。

### agent 侧（每台被监控 VPS）

**一条命令安装**（去中心机 beszel webui 复制公钥和 token）：

```bash
curl -fsSL https://raw.githubusercontent.com/<owner>/<repo>/master/agent/install-agent.sh \
  | bash -s -- -k "<公钥>" -t "<token>" -url "https://<中心域名>" \
      -center "https://<中心域名>/api/plugins/beszel/security/ingest"
```

脚本自动完成：

1. 安装 beszel agent（复用官方脚本，含 Cloudflare 挡时 fallback GitHub raw；`--china-mirrors` 可用国内镜像）
2. 安装 security-collector（安全事件采集），token 复用 beszel 的（universal 或 per-system 均可，中心两种都认）
3. 写 systemd unit + 启用两个服务 + 自检

**agent 侧采集的三类日志**（默认路径，不存在时跳过对应源，不致命）：

| 日志 | 默认路径 | 说明 |
|---|---|---|
| fail2ban | `/var/log/fail2ban.log` | ban/unban 事件 |
| nginx | `/var/log/nginx/access.log` | 扫描/攻击路径（依赖 fail2ban nginx jail） |
| sshd | `/var/log/auth.log` | 爆破尝试（含用户名提取） |

**验证**：

```bash
systemctl status security-collector
journalctl -u security-collector -f   # 应看到 [collector] starting, mode=push
```

断网/中心不可达时事件写入 `security-push-buffer.jsonl`（`--flush-interval` 周期自动补推，推完即清），恢复后无需人工干预。

### 认证与 token

ingest 认证复用 beszel 的 token 体系，**无需为安全事件单独生成 token**：

- **per-system token**（UUID，webui「添加系统」时生成，存 `fingerprints` 表）：绑死一台机器，中心从 token 反查机器名，防伪造最强
- **universal token**（`/settings/tokens` 里生成，存 `universal_tokens` 表）：多台机器共用，机器身份由 agent 自报 + 查 `systems` 表校验

两种 token 都认，agent 侧填哪个都行。连新机器：要么 webui「添加系统」复制公钥+token，要么直接用 universal token（自动注册）。

### 面板使用

- hermes dashboard → beszel tab：系统监控（beszel 原生）+ 监控室（安全事件）
- 监控室筛选语法：`ip:1.2.3.4`、`type:auth_fail`、`country:NL`，可组合；Attackers / Active Bans 支持搜索、筛选、排序、翻页、点开 IP 详情
- 事件类型：`ban` / `unban` / `scan` / `attack` / `auth_fail` / `auth_success`

## 开发：构建前端 + 发布

普通安装**不需要**构建前端（预构建产物在 GitHub Release）。只有开发/改前端时才需要：

```bash
# 准备 beszel 前端源码 + 重放补丁
git clone https://github.com/henrygd/beszel /tmp/beszel
cd /tmp/beszel/internal/site
for p in 001 002 003 004 005 006 007 008; do
  git apply /path/to/hermes-beszel-dashboard/patches/$p-*.patch
done
npm install && npm run build

# 发布新版本（构建 dist → 打包 → 创建 GitHub Release）
scripts/release.sh v0.1.0-beta "版本说明"
```

> 补丁基于 2026-08 的 beszel master。上游大版本更新后补丁可能需要适配，`patches/NNN-*.tsx` 快照文件是 diff 基底。

## License

- 本项目代码：MIT（见 [LICENSE](LICENSE)）
- [beszel](https://github.com/henrygd/beszel)：MIT（版权 © henrygd）——见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
- 前端使用的 Inter 字体：SIL Open Font License
