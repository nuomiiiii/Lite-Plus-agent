# Lite-Plus-agent

Lite-Plus 的跨平台节点监控与节点管理 Agent。本仓库版本在基础监控之外，支持安全远程终端、文件管理、远程命令、Cloudflare Access、在线配置下发、配置结果回执，以及双核节点管理。

当前稳定版本：`0.0.1.9`

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
docker pull ghcr.io/nuomiiiii/lite-plus-agent:0.0.1.9
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
| `0.0.1.9` | 修复刚开机还能连上、过一会又被挡在墙外的 bug。防火墙在自动更新之前落地；本机其它防火墙后写冲掉 Plus 规则后会把全部已放行端口补回去。修复本机已有 iptables-nft 入站（1Panel、宝塔、fail2ban、CSF 等）时，Plus 在另一张表里放行的端口仍被后面丢掉的 bug。 |
| `0.0.1.8` | 修复重启后防火墙规则要等 Agent 起来才落地、可能被挡在墙外的 bug。开机即加载全部已放行端口，不只 SSH。 |
| `0.0.1.7` | 修复 sing-box 开启设备数限制后，Shadowsocks UDP 等连接因包头空间不够而异常的 bug。修复 Xray 入站处理异常时可能把整个 Agent 打崩的 bug。 |
| `0.0.1.6` | 防火墙规则可不指定端口，表示全部端口。修复同步主机规则时，自定义链里的简单入站（如 1Panel）收不进 Plus 的 bug。没写端口的按全部端口处理。修复已关闭的 Xray 出站和路由仍会被写进配置的 bug。 |
| `0.0.1.5` | 远程控制打开后，可在 Plus 后台管理本机入站防火墙：规则、禁止 ping、入站默认拒绝。Linux 支持 nft / iptables / ufw / firewalld，Windows 走系统防火墙。默认拒绝会留下回环、已建立连接，以及 SSH / 远程桌面 / WinRM；SSH 端口可改。失败会回滚。节点出站可按后台设置走仅 IPv4、仅 IPv6、优先 IPv4 或优先 IPv6。 |
| `0.0.1.4` | sing-box 的 VLESS 入站会写入用户或入站上的 Flow（Vision）。WebSocket、明文入站不会带。`xtls-rprx-vision-udp443` 在 sing-box 上会收成 `xtls-rprx-vision`；Xray 仍可用 udp443。配 Lite-Plus `0.0.7`，主控和节点要一起升。 |
| `0.0.1.3` | 修复节点限速比后台设置大约快 8 倍的 bug。修复 Trojan、VMess、XHTTP、SplitHTTP 看不到客户端真实 IP 的 bug。修复 VLESS、Reality 等入站不上报在线客户端 IP 的 bug。修复路由域名按完整匹配、不识别后缀/关键词/正则的 bug。 |
| `0.0.1.2` | 修复 Xray 流量计量导致 XUDP 连接无法正常关闭。上下行流量都会计入配额。 |
| `0.0.1.1` | 修复出站切换协议后残留设置导致 sing-box 无法启动。路由可按网段、端口、来源 IP 匹配，并按优先级生效。 |
| `0.0.1.0` | HTTP 入站可用入站里配置的用户名密码，并可开启透明代理。SOCKS 入站同样接受用户名密码，不再只认 UUID。 |
| `0.0.0.9` | 进一步尝试优化 Linux 环境下 Agent 的内存占用。入站补齐 HTTP。Shadowsocks 入站按完整协议可用，默认加密 `2022-blake3-aes-128-gcm`。证书申请支持多 SAN。 |
| `0.0.0.8` | 尝试一种新的内存优化方案。修复双栈通配入站重复绑端口、无法启动的问题。来自 @jasper-khan #3，并进行优化修改。 |
| `0.0.0.6` | Lite-Plus-agent 第六个版本。产品号与 Lite-agent 分开。按内存档（256/512/1024/2048/3072/4096）和实际核数收软上限，并定期把空闲内存还给系统。同进程双核（Xray v26.6.27、sing-box v1.14.3）。基线 Lite-agent `2.3.10.0`。 |
| `0.0.0.5` | Lite-Plus-agent 第五个版本。产品号与 Lite-agent 分开。路由 `geosite:` / `geoip:` 按实际内核拉 geo 文件；在线 IP 只计当前会话；节点证书申请改为 RSA 2048。同进程双核（Xray v26.6.27、sing-box v1.14.3）。基线 Lite-agent `2.3.10.0`。 |
| `0.0.0.4` | Lite-Plus-agent 第四个版本。产品号与 Lite-agent 分开。同进程双核节点管理（Xray v26.6.27、sing-box v1.14.3），后台下发的入站、节点用户、证书、额度和限速在本进程生效。默认安装目录、服务名和 Release 资产改为 `Lite-Plus-agent` / `lite-plus-agent`。从 Lite-agent 或 komari-agent 默认路径升级会搬到 Plus 布局。自动更新只认本仓。许可 GPL-3.0。基线 Lite-agent `2.3.10.0`。 |
| `0.0.0.3` | Lite-Plus-agent 第一版。产品号与 Lite-agent 分开。同进程双核节点管理（Xray v26.6.27、sing-box v1.14.3），后台下发的入站、节点用户、证书、额度和限速在本进程生效。默认安装目录、服务名和 Release 资产改为 `Lite-Plus-agent` / `lite-plus-agent`。从 Lite-agent 或 komari-agent 默认路径升级会搬到 Plus 布局。自动更新只认本仓。许可 GPL-3.0。基线 Lite-agent `2.3.10.0`。 |
| `0.0.0.2` | Lite-Plus-agent 第一版。产品号与 Lite-agent 分开。同进程双核节点管理（Xray v26.6.27、sing-box v1.14.3），后台下发的入站、节点用户、证书、额度和限速在本进程生效。默认安装目录、服务名和 Release 资产改为 `Lite-Plus-agent` / `lite-plus-agent`。从 Lite-agent 或 komari-agent 默认路径升级会搬到 Plus 布局。自动更新只认本仓。许可 GPL-3.0。基线 Lite-agent `2.3.10.0`。 |
| `0.0.0.1` | Lite-Plus-agent 第一版。产品号与 Lite-agent 分开。同进程双核节点管理（Xray v26.6.27、sing-box v1.14.3），后台下发的入站、节点用户、证书、额度和限速在本进程生效。默认安装目录、服务名和 Release 资产改为 `Lite-Plus-agent` / `lite-plus-agent`。从 Lite-agent 或 komari-agent 默认路径升级会搬到 Plus 布局。自动更新只认本仓。许可 GPL-3.0。基线 Lite-agent `2.3.10.0`。 |
| `2.1.0` | 支持由 Lite 下发流量重置日；完善参数校验、事件去重和网络统计稳定性。 |
| `2.1.5` | 新增安全远程终端与文件管理协议，支持独立会话、目录浏览和文件传输。 |
| `2.1.6` | Agent Token 改用 `Authorization: Bearer` 请求头；旧节点需轮换 Token 并重新部署。 |
| `2.1.61` | 修复稳定版自动更新和版本比较，新增远程文件与目录复制。 |
| `2.1.62` | 恢复 Cloudflare Access Service Token，并覆盖连接、上报、任务与远程管理请求。 |
| `2.1.11.1` | 首个四段小版本；修复 Lite Server 与 Agent 同机部署时远程管理被误拦截的问题，`2.1.11` 可识别并自动升级到本版本。 |
| `2.2.0.0` | 新增七项在线热更新配置、当前配置同步及明确的七项禁止下发边界。 |
| `2.2.0.1` | 修复禁用自动更新失效问题，新增配置应用结果回执与最新版本优先合并。 |
| `2.2.0.2` | 修复 WebSocket 断开后进程仍在、面板显示离线的问题；写超时后立即重连，在线状态不再依赖采集间隔或探测任务。 |
| `2.3.0.0` | 独立仓 `nuomiiiii/Lite-agent` 发版；自动更新只认本仓 `Lite-agent-*` 产物。默认节点会迁到 Lite 安装目录，进程名为 `Lite-agent`。WebSocket 增加读超时与心跳保活，握手后检查连接是否还活着，断开后短延迟重连；假死连接大约 1 分钟内会重连。 |
| `2.3.0.1` | 回程探测会附带是否到达目标。目标是域名时，面板也能判断探测是否走到解析后的 IP。 |
| `2.3.0.2` | 回程探测只认本次探测的 ICMP 回包，避免把无关或上一跳晚到的包当成路径跳点。 |
| `2.3.1.0` | 远程控制改为正向开关。已装节点没写过禁止远程的，升级后仍开启；旧的 `disable_web_ssh` 会迁到新配置。新装由 Lite 一键命令明确写入开启或关闭。从默认 komari-agent 路径升级时，仍会带走节点身份、流量统计和配置文件。文件管理增加队列、并发上限和列表分页。远程命令会记下执行状态；同一条命令不会因重试再跑一遍，进程中断后会补报执行状态未知。Windows 命令输出会尽量转成可读文本。是否允许远程由站点开关和节点本地开关共同决定。Lite 需升级至 Lite 2.3.1 或更高版本。 |
| `2.3.1.1` | 已下线自动发现功能，不再注册新节点。原先自动发现带上来的机器，升级后仍能正常上报，若遇到离线，请重新安装 Agent。 |
| `2.3.3.0` | 新增 MCP 代理功能：远程控制开启后，AI客户端可通过 MCP 代理远程执行命令和操作文件。文件管理增加读写和分块下载。网页里原来的列表、上传、下载用法不变。现有上报、远程终端和文件管理可继续在 Lite 2.3.2 使用。使用 MCP 代理功能，Lite需升级至 2.3.3 或更高版本。 |
| `2.3.3.1` | Linux 上部分 AMD 显卡在 rocm-smi 无法使用时，改为读取系统接口上报 GPU 占用、显存和温度。 |
| `2.3.3.2` | 新增从上游 komari-agent 迁到 Lite-agent 的迁移脚本；个别线路拦压缩基础上报时自动 HTTP 压缩回退。 |
| `2.3.3.3` | 含 2.3.3.2 的迁移脚本和 HTTP 压缩回退，并优化 Agent 运行时内存占用。 |
| `2.3.3.4` | 流量重置改为按时区、日期、时分秒计算。已有节点升级后，原来只填了重置日的，会按北京时间当天 00:00:00 继续重置。 |
| `2.3.3.5` | 优化流量统计跨过重置时刻统计逻辑，会按重置前后分开记录，重置前的流量不会算进新周期。 |
| `2.3.3.6` | 修复Linux/Windows客户端在远程终端时，部分情况下命令无法tab补全的bug |
| `2.3.3.7` | Windows 开启远程控制后不再弹出桌面提示；修复 Windows 安装脚本误报服务未运行和误提 komari-agent |
| `2.3.6.0` | 远程文件上传和下载更快；管理后台一起更新后走二进制并并行上传，只升级 Agent 时原方式仍可用 |
| `2.3.6.1` | btrfs 容器（如 LXC/LXD）设置了磁盘配额时，面板上的磁盘总量和已用量改为容器自己的配额，不再显示整个存储池。没有设置配额、不是 btrfs，或配额读不到时，磁盘显示与以前相同。感谢 IShinji 的 [PR #2](https://github.com/nuomiiiii/Lite-agent/pull/2)。 |
| `2.3.6.2` | ICMP、TCP、HTTP 探测延迟保留毫秒小数。Lite 2.3.7 同版本第二次更新开始用 value_ms 保存到 0.01 ms；旧 Lite 使用兼容整数 value，探测结果仍可正常接收。极小延迟按保存精度可能显示为 0.00 ms。失败时仍记为失败。 |
| `2.3.6.3` | LXC/LXD 容器的运行时间改为容器自己的开机时长，不再显示宿主机的开机时长。读不到容器自己的时长时，仍按原来的方式显示。感谢 IShinji 的 [PR #3](https://github.com/nuomiiiii/Lite-agent/pull/3)。 |
| `2.3.6.4` | HTTP 探测改为带上常见浏览器请求头。原先部分站点会拒绝默认请求并返回 403，延迟被记成失败。未返回成功状态时，探测结果仍记为失败。 |
| `2.3.10.0` | 修复 CVE-2026-111943。当前 Agent 不受该问题影响，此次一并跟进。 |

| `2.3.10.1` | 修复远程终端执行输出很多、耗时较长的命令后，过几分钟无法输入的 bug。请配套 Lite 2.3.10 同版本第一次更新。 |
完整发布记录和升级说明请查看 [GitHub Releases](https://github.com/nuomiiiii/Lite-Plus-agent/releases)。
