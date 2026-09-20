# reverse-ssh-kit

给自己的 Windows 电脑建立可撤销的、开机自动恢复的远程维护通道。电脑可以位于 NAT 后面，无需自己的公网 IP 或域名；你需要一台可从公网连接 SSH 的 Linux 中继服务器。

本项目把原生 OpenSSH、Windows 服务和任务计划程序组成一套部署流程。Mac/Linux 管理端生成每台设备的登记材料，Linux 中继限制转发端口，Windows 主动连接中继。没有自研隧道协议、常驻 Web 管理面板或第三方控制面。

**初始版本：请先在备用 Windows 设备验证。** 五项 CI 已通过，包含 GitHub Windows Server 2022 虚拟机上的普通用户/管理员真实安装、密钥登录、SFTP、离线重试和卸载，以及 Linux 中继集成测试。实体 Windows 10/11 电脑首次接入、重启、电池与睡眠唤醒仍需现场验收。已有其他工具管理的 Windows SSH 配置会被明确拒绝接管。

```text
管理端 Mac/Linux ──SSH──> Linux 公网中继
                             127.0.0.1:22024
                                   ↑ 反向 SSH（电脑主动连出）
                              Windows 127.0.0.1:22
```

## 适用范围

- 管理端：Mac/Linux、Python 3.9+、`ssh` / `ssh-keygen` / `scp`。
- 中继：Debian/Ubuntu、root 安装权限、OpenSSH 服务及 `sshd_config.d` Include；现有 SSH 管理入口应保持可用。
- 被管理电脑：Windows 10/11、64 位 Windows PowerShell 5.1、管理员安装权限，以及可安装的 Windows OpenSSH Client/Server 可选功能。
- 一个 Windows 安装登记一台设备；每台设备使用不同名称、反向端口及密钥。中继可登记多台设备。
- 支持 IPv4/DNS 中继地址。v1 不支持 IPv6 地址字面量、自定义 Windows 用户名或接管其他 SSH 安装。
- Windows 可选功能下载失败时显式报错并提供微软安装文档；不下载来源不明的 MSI，也不自动切换到未验证的安装布局。

## 接入一台新电脑

以下地址都是文档示例。先阅读脚本；不要在来源不明的终端中粘贴私人密钥。

### 1. 从可信管理通道取得中继主机公钥

使用你原本已验证身份的服务器管理连接：

```sh
ssh admin@203.0.113.10 'sudo cat /etc/ssh/ssh_host_ed25519_key.pub' > /tmp/relay-host-key.pub
ssh-keygen -lf /tmp/relay-host-key.pub -E sha256
```

首次认识这台中继时，应通过服务器控制台核对指纹。单独运行 `ssh-keyscan` 获取公钥不构成身份验证。

### 2. 在管理端生成本台设备的私人材料

```sh
python3 kit.py prepare receiver \
  --relay-host 203.0.113.10 \
  --relay-host-key /tmp/relay-host-key.pub \
  --remote-port 22024 \
  --output "$HOME/.config/reverse-ssh-kit/receiver"
```

名称为 1–16 位小写字母、数字或连字符，首位必须是字母。反向端口范围为 1024–65535，且必须未被其他设备占用。中继 SSH 非 22 端口时加 `--relay-port`。

输出目录权限为 `0700`，已有目录不会被覆盖；输出位置必须在源代码仓库之外。

- `operator_key`：留在管理端，用于进入中继受限跳板和 Windows 维护账号。
- `tunnel_key.pub` / `operator_key.pub`：交给中继登记的公钥。
- `windows-bundle/`：交给目标 Windows 的私密安装材料，包含该设备的出站隧道私钥，**不包含 operator_key 私钥**。
- `ssh_config`：管理端使用的配置，两跳都验证主机公钥。

**整个输出目录和 Windows bundle 都不能提交到 GitHub、公开分享或作为公开 CI 附件上传。**

### 3. 在中继登记这台设备

通过原有管理员连接，把本项目的 `relay.sh` 和刚生成的两个 `.pub` 文件传到中继，然后执行：

```sh
sudo bash relay.sh install receiver 22024 tunnel_key.pub operator_key.pub
sudo bash relay.sh status receiver
```

脚本为该设备创建受限的 `rsk-t-receiver` 和 `rsk-a-receiver` 账号。前者只可监听分配的回环端口，后者只可连接该端口；都没有 shell、PTY 或密码登录权限。验证 `sshd` 配置和实际生效权限后 reload，不 restart 服务。脚本会强制中继的 SSH 转发监听使用 loopback；若中继原有服务依赖公开反向端口，请先评估这一影响，或使用专用中继。

### 4. 在目标 Windows 安装

通过可信通道传输 `windows-bundle`，打开**管理员身份的 64 位 Windows PowerShell**：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows-bundle\install.ps1 -BundlePath .\windows-bundle
```

默认建立普通维护账号。若明确需要安装驱动、管理服务等管理员能力，显式加 `-AdminAccess`。这会给持有 operator 私钥的人该电脑的管理员访问能力。

安装器保护文件 ACL，配置仅监听 `127.0.0.1:22`、仅公钥登录的 sshd，设置服务自动启动，以及 SYSTEM 身份的 `ReverseSshKit` 开机任务。任务允许电池供电、没有默认的 72 小时运行时限，并在网络不可用时重试。不会关闭防火墙、Defender 或修改电脑睡眠设置。

已有未被本工具管理的 `sshd_config`、账号、任务、SSH 监听会让安装失败。不要为了绕过检查直接删除其他软件的配置。失败时查看提示，用本项目卸载流程清理已登记的部分状态。

### 5. 核对并固定 Windows 主机身份

在 Windows 的管理员 PowerShell 中运行：

```powershell
& "$env:ProgramData\ReverseSshKit\status.ps1" -ExportHostKey "$env:USERPROFILE\Desktop\receiver-host.pub"
```

在目标电脑上核对显示的 SHA256 指纹，通过可信通道把**公钥文件**传回管理端：

```sh
python3 kit.py trust "$HOME/.config/reverse-ssh-kit/receiver" \
  --host-key /tmp/receiver-host.pub \
  --fingerprint 'SHA256:从目标电脑核对的指纹'
```

指纹不匹配会拒绝；已有不同主机公钥也不会被静默覆盖。

### 6. 使用和传文件

```sh
ssh -F "$HOME/.config/reverse-ssh-kit/receiver/ssh_config" receiver hostname
scp -F "$HOME/.config/reverse-ssh-kit/receiver/ssh_config" ./example.txt receiver:example.txt
```

Windows 默认远程 shell 是 `cmd.exe`。PowerShell 长脚本建议先用 `scp` 传文件，再调用 `powershell.exe -NoProfile -File`，避免 Windows 命令行长度和引号问题。

部署完成后移除 Windows 安装材料的临时传输副本，保留受保护的管理端目录。后续设备重新执行上述流程，使用新的名称和端口。

## 检查、断开与恢复

请在 Windows **本机管理员控制台**执行卸载；停止 sshd 会切断该电脑的 SSH 会话。

Windows：

```powershell
& "$env:ProgramData\ReverseSshKit\status.ps1"
& "$env:ProgramData\ReverseSshKit\uninstall.ps1"
```

中继：

```sh
sudo bash relay.sh status receiver
sudo bash relay.sh revoke receiver
```

**撤销应在中继和 Windows 两端处理。**中继撤销会禁止新连接并终止该设备当前的隧道/跳板会话；仅删公钥不能结束已经建立的 SSH 会话。Windows 卸载只清理本工具拥有的资源，保留系统 OpenSSH 可选功能；资源被其他软件改动时会停止并要求人工核对。

- 客户端 `ServerAliveInterval=15`、`ServerAliveCountMax=3` 发现失联，外层循环重连；端口绑定失败会使 SSH 退出并留下日志。
- 笔记本睡眠或关机时不可访问；唤醒/联网后重连，开机任务负责重启后的恢复。
- 有隧道不等于 Windows sshd 健康，最终应从管理端执行 `hostname` 或传输文件验证。
- 本项目不承诺零中断，也不负责游戏视频流的 UDP 传输。

## 验证

```sh
python3 -m unittest discover -s tests -v
# 只在自动创建的、可丢弃的 Docker 容器内操作 Linux 账号/sshd：
bash tests/test_relay.sh
# 使用其他 Docker context：
DOCKER_CONTEXT=your-context bash tests/test_relay.sh
```

Windows 上只解析脚本并测试纯配置校验，不安装服务：

```powershell
powershell.exe -NoProfile -File tests\test_windows.ps1
```

为自己的第一台目标设备完成以下验收再用于日常维护：首次安装与严格指纹登录；Windows 重启后未登录状态；开机无网后恢复网络；隧道进程异常退出；睡眠唤醒；电池运行；端口冲突时显式失败；中继撤销后已有连接和新连接均不可用；本地卸载只移除本工具资源。见 [测试计划](test/test-plan.md) 和 [本次验证记录](test/test-report.md)。

## 为什么选择 OpenSSH

当前需求是少量电脑的 SSH/SFTP 维护。原生 OpenSSH 已经提供加密、密钥认证、反向转发和细粒度权限；这个项目只维护部署、恢复和撤销流程。frp/rathole 适合更多代理类型，Tailscale 适合多服务私网，但都会增加当前目标不需要的运行组件或控制面。详见 [决策记录](.agents/notes/implemented/architecture/2026-09-20-native-openssh.md)。

参考：[OpenSSH ssh_config](https://man.openbsd.org/ssh_config)、[sshd_config](https://man.openbsd.org/sshd_config)、[Windows OpenSSH](https://learn.microsoft.com/windows-server/administration/openssh/openssh_install_firstuse)、[Windows Task Scheduler](https://learn.microsoft.com/windows/win32/taskschd/tasksettings)。

MIT License。请仅在拥有或获授权管理的设备上使用。
