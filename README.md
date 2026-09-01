# hermes-beszel-dashboard

> 把 [beszel](https://github.com/henrygd/beszel)（轻量服务器监控）的整个面板搬进 [Hermes Agent](https://github.com/NousResearch/hermes-agent) dashboard 的插件，并在其上叠加一个多机**监控室**（SSH 爆破 / fail2ban / nginx 扫描的采集、聚合、地理定位与攻击地图）。English README: [README.en.md](README.en.md)

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
```

## 使用说明

### 中心侧（控制机，跑 hermes + beszel hub 的那台）

#### 1. 装 beszel hub

按 [beszel 官方文档](https://beszel.dev) 安装 hub（PocketBase 内核，监听 `127.0.0.1:8090` 即可，不必暴露公网——面板流量走插件反代）。`hub/` 下有 systemd 参考件。

#### 2. 构建前端产物

需要 node/npm：

```bash
git clone https://github.com/henrygd/beszel /tmp/beszel
cd /tmp/beszel/internal/site
# 依次应用补丁：001 → 008（顺序不能乱）
for p in 001 002 003 004 005 006 007 008; do
  git apply /path/to/hermes-beszel-dashboard/patches/$p-*.patch
done
# 008 的基底是 007 应用后的 security.tsx：应用 007 补丁后，
# 先把 patches/007-security-ui-enhancements.tsx 复制为 src/components/routes/security.tsx
# 再应用 008 补丁，最后把 008-attack-map.tsx 也复制过去（保持工作区与快照一致）
npm install && npm run build
cp -r dist/* /path/to/hermes-beszel-dashboard/plugin/dashboard/dist/
```

> 补丁基于 2026-08 的 beszel master（v0.14.x）。上游大版本更新后补丁可能需要适配，快照文件就是 diff 基底。

#### 3. 部署插件 + 配置

```bash
cd hermes-beszel-dashboard
./install.sh          # 拷插件到 ~/.hermes/plugins/beszel/ + 白名单 + 重启 dashboard
```

中心侧配置文件（都在 `~/.hermes/plugins/beszel/`，权限 0600，**不进 git**）：

| 文件 | 格式 | 作用 |
|---|---|---|
| `machine_locations.json` | `{"<machine_id或name>": {"lat": .., "lon": .., "city": .., "country": ..}}` | 机器坐标手动覆盖（GeoIP 把 IP 段判错时兜底），可选 |

> **认证不再用独立的 security_tokens.json**。agent 的 ingest 凭据 = beszel 的 **universal token**（在 beszel webui 的 `/settings/tokens` 里管理），机器身份 = beszel 里注册的系统名（`systems` 表）。连新机器时，在 beszel webui 里加系统即可，无需为安全事件单独生成 token。

环境变量（写入 systemd user unit 或 `.env`）：

| 变量 | 默认 | 作用 |
|---|---|---|
| `BESZEL_SUPERUSER_EMAIL` | `admin@example.com` | PB superuser 身份（`_read_password()` 从 cred 文件读密码） |
| `BESZEL_CRED_FILE` | `/root/hermes-workspace/reports/dashboard-credentials.txt` | 凭据文件路径（内容格式：`<email> / <password>` 行） |

#### 4. 下载 GeoIP 库

中心负责把 IP 翻译成坐标，agent 不需要：

```bash
mkdir -p /root/hermes-workspace/reports
curl -Lo /root/hermes-workspace/dbip-city-lite.mmdb.gz \
  https://download.db-ip.com/free/dbip-city-lite-$(date +%Y-%m).mmdb.gz
gunzip /root/hermes-workspace/dbip-city-lite.mmdb.gz
# 之后采集器/中心进程内线程每月自动检查更新，无需 cron
```

#### 5. 验证

```bash
# agent 侧推一条测试事件（把 <token> 换成 beszel universal token，<机器名> 换成 beszel 系统名）
curl -s -X POST http://127.0.0.1:9119/api/plugins/beszel/security/ingest \
  -H "Content-Type: application/json" -H "Authorization: Bearer <token>" \
  -d '{"machine_id":"<机器名>","events":[{"event_id":"smoke:1","event_type":"auth_fail","src_ip":"8.8.8.8",
       "ts":"'"$(date -u +%Y-%m-%dT%H:%M:%S+00:00)"'","count":1,"raw_excerpt":"smoke test"}]}'
# 期望：{"ok":true,"accepted":1,...}；浏览器打开 dashboard 的 beszel tab 能看到监控室数据
```

更完整的部署后冒烟测试（登录 → machines → ingest → 无 token 拒收，一条命令）：

```bash
tests/smoke.sh http://127.0.0.1:9119 <dashboard用户名> <dashboard密码> <某台机器的token>
```

### agent 侧（每台被监控 VPS）

#### 1. 前置

被采集的三类日志（路径都是默认值，不存在时会跳过对应源，不致命）：

| 日志 | 默认路径 | 说明 |
|---|---|---|
| fail2ban | `/var/log/fail2ban.log` | ban/unban 事件 |
| nginx | `/var/log/nginx/access.log` | 扫描/攻击路径（依赖你的 fail2ban nginx jail） |
| sshd | `/var/log/auth.log` | 爆破尝试（含用户名提取） |

#### 2. 部署

```bash
mkdir -p /opt/beszel-sec-agent
cp agent/security_collector.py /opt/beszel-sec-agent/
echo "<beszel universal token（hub 的 /settings/tokens 里那个）>" > /opt/beszel-sec-agent/agent_token.txt
chmod 600 /opt/beszel-sec-agent/agent_token.txt

# 可选：运维自身 IP/网段（这些来源的事件不记为攻击）
cat > /opt/beszel-sec-agent/trusted-sources.json << 'EOF'
{"trusted_sources": ["203.0.113.7"]}
EOF

cp agent/security-collector.service /etc/systemd/system/
# 编辑 unit：把 --center-url 换成你的中心地址（
#   https://your-centre-host/api/plugins/beszel/security/ingest
# ），按需设 SEC_MACHINE_ID / SEC_TRUSTED_SOURCES_FILE 环境变量
systemctl daemon-reload && systemctl enable --now security-collector
```

关键参数：

| 参数/环境变量 | 默认 | 说明 |
|---|---|---|
| `--push` | 关 | 不加则本地直写 SQLite（单机模式） |
| `--center-url` | 无 | 中心的 ingest URL |
| `--token-file` | 无 | beszel universal token 文件（0600），比 `--token` 稳 |
| `--flush-interval` | 30 | 推送周期（秒） |
| `SEC_MACHINE_ID` | hostname | 机器标识，必须 = beszel 里注册的系统名（默认 hostname 正好一致） |
| `SEC_TRUSTED_SOURCES_FILE` | `<repo>../security-trusted-sources.json` | 可信来源列表路径 |

#### 3. 验证

```bash
systemctl status security-collector
journalctl -u security-collector -f     # 应看到 [collector] starting, mode=push
```

断网/中心不可达时事件写入 `security-push-buffer.jsonl`（`--flush-interval` 周期自动补推，推完即清），恢复后无需人工干预。

### 面板使用

- hermes dashboard → beszel tab：系统监控（beszel 原生）+ 监控室（安全事件）
- 监控室筛选语法：`ip:1.2.3.4`、`type:auth_fail`、`country:NL`，可组合
- 事件类型：`ban` / `unban` / `scan` / `attack` / `auth_fail` / `auth_success`

## 上游升级

beszel 发新版后：重拉上游 → 按序重放 `patches/`（以 `patches/NNN-*.tsx` 快照为基底逐个 diff）→ build → 更新 `plugin/dashboard/dist/`。

## License

- 本项目代码：MIT（见 [LICENSE](LICENSE)）
- [beszel](https://github.com/henrygd/beszel)：MIT（版权 © henrygd）——见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
- 前端使用的 Inter 字体：SIL Open Font License
