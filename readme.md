# Lite-Plus-agent

Lite-Plus 的跨平台节点监控与节点管理 Agent。本仓库版本在基础监控之外，支持安全远程终端、文件管理、远程命令、Cloudflare Access、在线配置下发、配置结果回执，以及双核节点管理。

当前稳定版本：`0.0.2.8`

使用 MCP 代理功能，Lite需升级至 2.3.3 或更高版本。

## 安装与升级

### Linux 一键安装

请优先使用 Lite-Plus 后台“添加节点”生成的一键部署命令，命令会自动带入面板地址、节点 Token 和所选安装配置。

也可以直接调用安装脚本：

```bash
bash <(curl -sL https://raw.githubusercontent.com/nuomiiiii/Lite-Plus-agent/main/install.sh) \
  --endpoint "https://example.com" \
  --token "your-token" \
  --enable-remote-control=false
```

安装脚本支持 Linux、macOS 和 FreeBSD，并可通过 `--install-dir`、`--install-service-name`、`--install-ghproxy`、`--install-version` 调整安装过程。需要开启远程控制时，把 `--enable-remote-control=false` 换成 `--enable-remote-control`。

### 从 komari-agent 迁移

机器上如果已经在跑上游 `komari-agent`，不要用 Lite-Plus 后台新节点的部署命令（那会换新 Token）。在原机器上执行迁移脚本：它会自行完成夺舍，装成 Lite-Plus-agent，确认新服务起来后再卸掉 `komari-agent`。已安装的 Lite-agent 用 Plus 后台部署指令升级后，会迁到 `lite-plus-agent` 服务名和 Lite-Plus 安装目录。

主控地址没变：

```bash
curl -sL https://raw.githubusercontent.com/nuomiiiii/Lite-Plus-agent/main/migrate.sh | sudo bash
```

主控换了新地址：

```bash
curl -sL https://raw.githubusercontent.com/nuomiiiii/Lite-Plus-agent/main/migrate.sh | sudo bash -s -- \
  --endpoint "https://lite.example.com"
```

Windows：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "iwr https://raw.githubusercontent.com/nuomiiiii/Lite-Plus-agent/main/migrate.ps1 -UseBasicParsing -OutFile 'migrate.ps1'; & .\migrate.ps1"
```

新地址同样追加 `--endpoint "https://lite.example.com"`。GitHub 访问困难时可加 `--install-ghproxy`。不要给迁移脚本传 `--token`，也不要改安装目录或服务名，否则不会按原节点接手，也不会卸掉上游 Agent。

Docker 请用原来的 `-e` `-t` 重建 Lite-Plus-agent 容器，不要在容器里跑迁移脚本。

### Docker

```bash
docker pull ghcr.io/nuomiiiii/lite-plus-agent:latest
```

也可以拉取固定版本：

```bash
docker pull ghcr.io/nuomiiiii/lite-plus-agent:0.0.2.8
```

容器的启动参数、宿主机目录挂载和节点 Token 请以 Lite 后台生成的部署命令为准。Docker 部署不会在容器内替换 Agent 二进制；升级时需拉取新镜像并重建容器。

### 二进制运行

从 [Releases](https://github.com/nuomiiiii/Lite-Plus-agent/releases) 下载与系统和架构匹配的文件，赋予执行权限后启动：

```bash
chmod +x ./Lite-Plus-agent-linux-amd64
./Lite-Plus-agent-linux-amd64 \
  --endpoint "https://example.com" \
  --token "your-token" \
  --enable-remote-control=false
```

未禁用自动更新的二进制安装会自动检查稳定版本，也可以通过 Lite 面板发起 Agent 更新。自动更新只替换程序文件，不会修改服务启动参数、容器参数或节点 Token。

## 主要能力

- 上报 CPU、内存、磁盘、网络、负载、进程、GPU、系统信息和累计流量等节点数据。
- 执行 Lite 下发的延迟监测、任务和批量命令。
- 支持独立远程终端、窗口尺寸同步、目录浏览、文件上传下载、文件与目录复制等远程管理能力。
- 支持从 Lite 在线热更新可下发配置，并回报当前生效配置和应用结果。
- 支持 Cloudflare Access Service Token；主连接、数据上报、任务结果和远程管理请求均可携带认证头。
- 支持 v2 协议压缩、IPv4/IPv6 连接偏好、自定义 DNS、自定义上报 IP 和网卡筛选。

## 远程管理与安全

- Agent 只主动连接配置的 Lite Server，不监听公网控制端口。
- 远程终端、文件管理和远程命令由节点本地开关控制：`--enable-remote-control` / `remote_control_enabled`。Lite 后台一键安装会明确写入开启或关闭；没勾选时写入 `--enable-remote-control=false`。
- 已安装节点如果只有 `-e -t`、从未写过 `--disable-web-ssh`，升级后远程控制保持开启。旧配置里的 `disable_web_ssh` 会迁成 `remote_control_enabled`。
- 远程终端和文件管理继续受站点「允许远程管理」、管理员登录、2FA 和一次性票据保护。节点未启用远程控制时，终端、文件和 exec 都会被拒绝。
- 文件操作会拦截符号链接、文件系统根目录、复制到自身、目标已存在等危险情况；列表支持分页，上传下载有并发和大小上限。

> 从 `2.1.6` 或更早版本升级时，如果节点仍使用旧 Token，应先升级 Lite Server/Web，再在后台轮换节点 Token，并在 24 小时内重新执行该节点的部署命令。仅等待 Agent 自动更新不会替换服务或容器中的 Token。

## 配置方式

Agent 参数可以通过 JSON 配置文件、环境变量或命令行参数传入。

使用环境变量：

```bash
export AGENT_ENDPOINT="https://example.com"
export AGENT_TOKEN="your-token"
./Lite-Plus-agent
```

使用 JSON 配置文件：

```bash
./Lite-Plus-agent --config ./config.json
```

`config.json` 示例：

```json
{
  "endpoint": "https://example.com",
  "token": "your-token",
  "interval": 3,
  "disable_auto_update": false,
  "remote_control_enabled": false,
  "ignore_unsafe_cert": false
}
```

配置优先级从低到高为：**默认值 < JSON 配置文件 < 环境变量 < 明确传入的命令行参数**。没有在命令行中显式指定的参数不会用命令行默认值覆盖配置文件或环境变量。

常用配置项：

| JSON 字段 | 环境变量 | 命令行参数 | 说明 |
| --- | --- | --- | --- |
| `endpoint` | `AGENT_ENDPOINT` | `--endpoint`, `-e` | Lite 面板地址 |
| `token` | `AGENT_TOKEN` | `--token`, `-t` | 节点 Token |
| `interval` | `AGENT_INTERVAL` | `--interval`, `-i` | 数据采集间隔，单位秒 |
| `disable_auto_update` | `AGENT_DISABLE_AUTO_UPDATE` | `--disable-auto-update` | 禁用自动更新 |
| `remote_control_enabled` | `AGENT_REMOTE_CONTROL_ENABLED` | `--enable-remote-control` | 启用远程终端、文件和命令；新装请显式写 `true` 或 `false` |
| `ignore_unsafe_cert` | `AGENT_IGNORE_UNSAFE_CERT` | `--ignore-unsafe-cert`, `-u` | 忽略不安全证书 |
| `max_retries` | `AGENT_MAX_RETRIES` | `--max-retries`, `-r` | 最大重试次数 |
| `reconnect_interval` | `AGENT_RECONNECT_INTERVAL` | `--reconnect-interval`, `-c` | 重连间隔，单位秒 |
| `info_report_interval` | `AGENT_INFO_REPORT_INTERVAL` | `--info-report-interval` | 基础信息上报间隔，单位分钟 |
| `include_nics` | `AGENT_INCLUDE_NICS` | `--include-nics` | 仅统计指定网卡，逗号分隔，支持通配符 |
| `exclude_nics` | `AGENT_EXCLUDE_NICS` | `--exclude-nics` | 排除指定网卡，逗号分隔，支持通配符 |
| `include_mountpoints` | `AGENT_INCLUDE_MOUNTPOINTS` | `--include-mountpoint` | 仅统计指定挂载点，分号分隔 |
| `month_rotate` | `AGENT_MONTH_ROTATE` | `--month-rotate` | 流量重置日，`0` 为禁用，或填写 `1` 至 `31` |
| `memory_include_cache` | `AGENT_MEMORY_INCLUDE_CACHE` | `--memory-include-cache` | 内存使用量包含缓存和缓冲区 |
| `memory_report_raw_used` | `AGENT_MEMORY_REPORT_RAW_USED` | `--memory-exclude-bcf` | 使用排除 buffer/cache/free 的原始内存口径 |
| `enable_gpu` | `AGENT_ENABLE_GPU` | `--gpu` | 启用详细 GPU 监控 |
| `custom_ipv4` | `AGENT_CUSTOM_IPV4` | `--custom-ipv4` | 自定义上报 IPv4 地址 |
| `custom_ipv6` | `AGENT_CUSTOM_IPV6` | `--custom-ipv6` | 自定义上报 IPv6 地址 |
| `get_ip_addr_from_nic` | `AGENT_GET_IP_ADDR_FROM_NIC` | `--get-ip-addr-from-nic` | 从网卡获取上报 IP 地址 |
| `auto_discovery_key` | `AGENT_AUTO_DISCOVERY_KEY` | `--auto-discovery` | 已下线。原先自动发现带上来的机器升级后仍能上报；若离线请重新安装 Agent。 |
| `cf_access_client_id` | `AGENT_CF_ACCESS_CLIENT_ID` | `--cf-access-client-id` | Cloudflare Access Service Token Client ID |
| `cf_access_client_secret` | `AGENT_CF_ACCESS_CLIENT_SECRET` | `--cf-access-client-secret` | Cloudflare Access Service Token Client Secret，必须与 Client ID 同时配置 |
| `custom_dns` | `AGENT_CUSTOM_DNS` | `--custom-dns` | 自定义 DNS 服务器 |
| `protocol_version` | `AGENT_PROTOCOL_VERSION` | `--protocol-version` | 上报协议版本，仅支持 `2` |
| `disable_compression` | `AGENT_DISABLE_COMPRESSION` | `--disable-compression` | 禁用 v2 传输压缩 |
| `prefer_ip_version` | `AGENT_PREFER_IP_VERSION` | `--prefer-ip-version` | 面板连接优先使用的 IP 版本，可选 `4` 或 `6` |

完整参数可运行：

```bash
./Lite-Plus-agent --help
```

## 在线配置下发

自 `2.2.0.0` 起，配合兼容版本的 Lite Server，可以在线修改以下配置，无需重启 Agent：

- 数据采集间隔 `interval`
- 流量重置日 `month_rotate`
- 包含网卡 `include_nics`
- 排除网卡 `exclude_nics`
- 包含挂载点 `include_mountpoints`
- 内存缓存统计口径 `memory_include_cache`
- 详细 GPU 监控 `enable_gpu`

Agent 会向 Lite 回报当前实际生效的配置。保存配置后，状态会按实际进度更新；Agent 应用成功回报 `applied`，应用失败回报 `failed`，并携带对应配置版本和失败原因。结果合并遵循最新版本优先，旧结果不会覆盖较新的配置状态；节点离线期间多次修改时，恢复连接后只接收并应用最新配置。

在线配置会校验取值，其中采集间隔为 `1` 至 `3600` 秒；流量重置日为 `0` 或 `1` 至 `31`。文本配置会拒绝控制字符和超长内容。

以下七项属于安装或安全边界，可以由 Lite 保留以便以后重新安装，但**不能远程下发修改**：

1. 启用远程控制 `remote_control_enabled`
2. 忽略不安全证书 `ignore_unsafe_cert`
3. 禁用自动更新 `disable_auto_update`
4. 从网卡获取 IP `get_ip_addr_from_nic`
5. GitHub 代理
6. 安装目录
7. 服务名

在线配置与状态同步：Lite 需升级至 Lite 2.3.1 或更高版本。

## 自动更新

本仓库构建的 Agent 默认从 `nuomiiiii/Lite-Plus-agent` 的 GitHub Releases 检查稳定版本，并只下载与当前系统和架构匹配的 `Lite-Plus-agent-*` 文件。已安装的 Lite-Plus-agent 不会再去 Lite-agent 或 komari-agent 仓查找更新。

以下任一方式可禁用自动更新：

- 命令行：`--disable-auto-update`
- 环境变量：`AGENT_DISABLE_AUTO_UPDATE=true`
- JSON 配置：`"disable_auto_update": true`

`2.2.0.1` 修复了禁用自动更新配置可能被配置文件覆盖的问题：明确设置为 `true` 的节点不会再意外更新；未禁用的节点仍正常检查和升级；显式设置为 `false` 时也不会被误判为禁用。

## Cloudflare Access

Client ID 与 Client Secret 必须成对配置，可以选择命令行参数、环境变量或 JSON 配置文件。凭据只保存在 Agent 所在节点，Lite Server 与 Lite Web 不保存 Cloudflare Access Service Token。

```bash
./Lite-Plus-agent \
  --endpoint "https://example.com" \
  --token "your-token" \
  --cf-access-client-id "your-client-id" \
  --cf-access-client-secret "your-client-secret"
```

## 关键版本

| 版本 | 主要内容 |
| --- | --- |
| `0.0.2.8` | 修复部分防火墙放行写不进本机入站表的 bug。修复只有回环或链路本地地址时仍按双栈落地、可能把另一边锁死的 bug。安装包和空载占用减小。 |
| `0.0.2.7` | 修复开启在线 IP 限制后，出站地址族不生效，以及 UDP 无法按 IPv4 / IPv6 出站的 bug。 |
| `0.0.2.6` | 修复开启在线 IP 限制后，UDP 无法出站的 bug。 |
| `0.0.2.5` | 本机没有可用防火墙时，可在后台安装 nftables。修复再次保存或重启后旧的默认拒绝仍排在新放行前面、可能被挡在墙外的 bug。Shadowsocks 出站可选择 TCP、UDP 或 TCP, UDP。 |
| `0.0.2.4` | 本机没有可用防火墙时，可在后台安装 nftables。修复再次保存或重启后旧的默认拒绝仍排在新放行前面、可能被挡在墙外的 bug。Shadowsocks 出站可选择 TCP、UDP 或 TCP, UDP。 |
| `0.0.2.3` | 本机没有可用防火墙时，可在后台安装 nftables。修复再次保存或重启后旧的默认拒绝仍排在新放行前面、可能被挡在墙外的 bug。Shadowsocks 出站可选择 TCP、UDP 或 TCP, UDP。 |
| `0.0.2.2` | Shadowsocks 入站可选择 TCP、UDP 或 TCP, UDP。sing-box 的 UDP 入站可打开 UDP 分片，默认关闭。 |
| `0.0.2.1` | 修复勾了「同时放行该端口」时，同一条放行会被写进防火墙两次的 bug。 |
| `0.0.2.0` | Linux 入站由 Plus 接管：已有 iptables-nft 入站时进同一张表，只有 nft inet filter 时接到同一条 input 链，干净机器走 nft；ufw / firewalld 走各自后端。 |

完整发布记录和升级说明请查看 [GitHub Releases](https://github.com/nuomiiiii/Lite-Plus-agent/releases)。
