# hermes-beszel-dashboard

> 把 [beszel](https://github.com/henrygd/beszel)（轻量服务器监控）的整个面板搬进 [Hermes Agent](https://github.com/NousResearch/hermes-agent) dashboard 的插件，并在其上叠加一个多机安全事件作战室（SSH 爆破 / fail2ban / nginx 扫描的采集、聚合、地理定位与攻击地图）。

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

**Security 作战室（本项目新增）**
- 三源采集：`auth.log`（SSH 爆破，含用户名提取）、`fail2ban.log`（ban/unban）、nginx access log（扫描/攻击路径）
- 多机架构：agent 无状态只推送（60s 窗口合并抗刷），中心统一入库；`event_id` 幂等 UPSERT，断网用 jsonl 磁盘缓冲补推
- 中心侧 GeoIP 富化（dbip-city-lite，月度自动更新+热重载），攻击地图按真实坐标渲染
- 攻击者卡片（按 IP 聚合）、IP 时间线、实时事件流、全局筛选（`ip:` `type:` `country:` 语法）、CSV/JSON 导出、90 天自动轮换
- 安全：bearer token（hmac 常量时间比对，machine_id 从 token 推导）、严格输入校验（白名单/IP/时间窗/count 上限/批量上限）、全参数化 SQL

## 项目结构

```
├── install.sh                  # 部署插件到 ~/.hermes/plugins/ + 白名单 + 重启
├── patches/                    # beszel 前端魔改补丁（版本化，可重放）
│   ├── 001..007-*.patch        #   反代 baseURL、去 beszel 登录页、tab 接入等
│   ├── 007-security-ui-enhancements.tsx   # 007 补丁应用后的完整前端快照
│   ├── 008-attack-map.patch    #   攻击地图 + 机器列表接入 security/machines
│   └── 008-attack-map.tsx      #   当前完整前端快照（重放下一个补丁的基底）
├── plugin/
│   ├── manifest.json           # hermes 插件清单
│   └── dashboard/
│       ├── dist/               # beszel vite 构建产物（assets 部分不进 git）
│       └── plugin_api.py       # PocketBase 反代 + /security/* API（ingest/machines/events/...）
├── agent/
│   ├── security_collector.py   # 安全事件探针：tail 三源日志，push 或本地直写
│   └── security-collector.service  # systemd unit 示例
├── hub/                        # 控制机部署物（beszel hub/agent systemd + nginx 反代示例）
└── NOTES.md                    # 设计决策、踩坑记录（中文）
```

## 工作原理

### 前端：补丁重放

beszel 的 SPA 构建产物整体塞进 hermes 插件的静态目录，浏览器只认 hermes 会话。对 beszel 源码的每一处魔改都做成 `patches/NNN-*.patch`：升级 beszel 时，重放补丁序列 → vite build → 部署 dist。`patches/NNN-*.tsx` 是每个补丁应用后的完整前端快照，作为下一个补丁的 diff 基底。

### 后端：插件 API 双通道

`plugin_api.py` 持有 beszel hub（PocketBase）的 service token：

- `/api/plugins/beszel/pb/*` → 反代 PocketBase API（系统指标，beszel 原功能）
- `/api/plugins/beszel/security/*` → 本项目自己的 SQLite 安全事件库（与 PB 完全独立）

### 安全事件多机通道

```
agent（任意机器）                     中心（控制机）
tail auth.log/f2b/nginx
  → 解析 + 60s 窗口合并
  → POST /security/ingest ──────►  token 认证（machine_id 从 token 推导）
  （失败 → jsonl 磁盘缓冲补推）      → 严格校验（类型白名单/公网 IP/时间窗/count）
                                    → UPSERT（event_id 幂等）
                                    → GeoIP 富化（中心侧 mmdb）
                                    → SQLite → 前端
```

本机也可以跑本地直写模式（不加 `--push`），两种模式同一份代码。

## 快速开始

前提：一台跑 hermes-agent 的控制机 + 若干装 beszel-agent 的被监控机。

```bash
# 1. 控制机：装 beszel hub（见 hub/ 下的 systemd 示例），装好 hermes
# 2. 控制机：构建前端（需要 node）：
#    git clone https://github.com/henrygd/beszel /tmp/beszel
#    for p in patches/*.patch; do patch -d /tmp/beszel -p1 --forward < $p; done
#    # 把 patches/NNN-*.tsx 快照依次复制到 /tmp/beszel/internal/site/src/components/routes/security.tsx
#    #（每个补丁的基底由快照提供，实际操作见 NOTES.md「补丁重放」）
#    cd /tmp/beszel/internal/site && npm install && npm run build
#    cp -r dist/* <repo>/plugin/dashboard/dist/   # 保留 loader.js
# 3. 部署插件：
cd hermes-beszel-dashboard
./install.sh
# 4. 中心：生成 agent token（见 NOTES.md「security_tokens.json」）
# 5. 各机器：部署 agent/security_collector.py（push 模式，见 agent/security-collector.service 示例）
```

配置文件（都不进 git，见 `.gitignore`）：
- `security_tokens.json` — `{machine_id: token}`，0600
- `machine_locations.json` — 机器坐标手动覆盖（GeoIP 误判兜底）
- `security-trusted-sources.json` — 运维自身 IP/网段（不记为攻击）

## 上游升级

beszel 发新版后：重拉上游 → 按序重放 `patches/` → build → 更新 `plugin/dashboard/dist/`（详见 NOTES.md）。

## License

- 本项目代码：MIT（见 [LICENSE](LICENSE)）
- [beszel](https://github.com/henrygd/beszel)：MIT（版权 © henrygd）——见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
- 前端使用的 Inter 字体：SIL Open Font License
