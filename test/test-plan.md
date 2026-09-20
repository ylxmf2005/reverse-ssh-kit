# TestPlan: reverse-ssh-kit initial release

## 计划状态

- 被测对象：本仓库首个版本的 Python CLI、Linux relay、Windows PowerShell 脚本和 GitHub Actions。
- 计划状态：executing。
- 任务承诺：可公开复用的、每设备隔离的 OpenSSH 登记/恢复/撤销流程；真实 Windows 生命周期状态必须明确标注。
- 结论边界：验证离线材料、安全限制、原生解析和隔离 Linux 路径；不把这些证据等同于物理 Windows 安装/重启验收。

## 测试事实账本

- 环境与路由：Mac 上 Python 3.9+；Docker 内 Debian Bookworm OpenSSH；Windows 11 PowerShell 5.1 上仅 parser 与纯配置测试；GitHub 托管 runner。
- 身份与权限：宿主机普通用户；隔离容器 root；Windows 测试不执行安装器、不修改真实 sshd。
- 数据与清理责任：本地临时密钥和目录由测试清理；Linux 测试仅在其创建的容器中创建账号/端口，退出时删除容器和测试镜像；Windows 测试只保留临时测试材料后清理。
- 观察面：CLI 返回码、材料内容/权限、原生 ssh 配置解析、真实 SSH 连接/监听/进程、PowerShell 解析输出、Actions 状态。
- 已知限制：当前无可用于全新安装/重启/睡眠试验的备用 Windows；现用主机的旧通道不能被测试接管。

## 风险与覆盖

| 风险或承诺 | 失败后果 | 覆盖用例 |
| --- | --- | --- |
| 私钥交给错误一端、忽略 hostkey 或注入配置 | 未授权访问、凭据泄露 | TC-001 |
| relay 转发越权、公开监听、撤销遗漏现有会话 | 横向连接或无法撤权 | TC-002 |
| PS5.1 不兼容或接受恶意配置 | 目标端无法安装或执行错误命令 | TC-003 |
| Windows ACL/服务/任务真实行为与设计不符 | 失去无人值守能力或错误修改系统 | TC-004 |
| 发布私人凭据、重要代码缺陷 | 用户安全受损 | TC-005 |
| 测试只在开发机偶然通过 | 用户无法重放 | TC-006 |

## 用例

### TC-001 — Operator CLI and host identity
- 优先级：P0。
- 环境与身份：普通用户，临时目录和临时 ssh-keygen 密钥。
- 实际动作：`python3 -m unittest discover -s tests -v`。
- 预期：拒绝仓库内私人输出、已有目录、危险输入和错误指纹；bundle 无 operator 私钥；两跳严格校验；已有不同 hostkey 不覆盖。
- 观察面与窗口：测试退出码、文件内容/权限、ssh -G，单次执行应在一分钟内完成。
- 失败处理：修复后重跑受影响测试，失败阻止发布。
- 清理：TemporaryDirectory 自动清理；不留真实凭据。
- 证据边界：不证明 Windows 服务和权限实际可用。

### TC-002 — Relay live restrictions and revocation
- 优先级：P0。
- 环境与身份：`bash tests/test_relay.sh` 创建的专用 Docker 容器。
- 实际动作：安装两台假设备；启动真实 OpenSSH 反向连接；验证允许的目标可到达；尝试 shell/SFTP/跨设备转发/错误密钥/公开绑定/Unix socket；撤销一个设备并尝试重连；注入 reload/配置错误。
- 预期：只允许精确 loopback 端口，禁用其他能力；撤销切断既有会话并拒绝新认证；另一设备及 sshd master 保持；失败保留显式可恢复状态。
- 观察面与窗口：sshd -T、ss/进程、真实 SSH 返回码，每个拒绝动作有超时；超时不算拒绝通过。
- 清理：自动删除专用容器/镜像；不得对宿主 sshd 执行 --inside。
- 证据边界：Linux 替代目标只证明 SSH 链路，不证明 Windows ACL。

### TC-003 — Native Windows parser and input validation
- 优先级：P0。
- 实际动作：Windows PowerShell 5.1 执行 `tests/test_windows.ps1`。
- 预期：四个脚本解析成功；3个合法配置接受、25个非法配置拒绝；不安装服务或修改账号。
- 清理：测试临时 JSON 由 finally 删除；额外传输的测试目录由操作者删除。
- 证据边界：只证明语法及纯函数校验。

### TC-004 — Physical Windows lifecycle
- 优先级：P0，用于“日常无人值守稳定性已验证”的结论。
- 前置数据：获授权的全新备用 Windows、可信 relay、独立登记材料、可用本机控制台。
- 实际动作：按README安装并pin hostkey；ssh hostname/scp；重启且不登录；断网再恢复；终止隧道子进程；睡眠再唤醒；电池运行；制造反向端口冲突；双端撤销与卸载。
- 预期：有效连接自动恢复，失败可定位；撤销同时阻止新/旧访问；仅管理的资源被删除，原系统组件保留。
- 观察面与窗口：每次恢复给网络稳定后两分钟；控制台服务/任务/ACL和外部SSH结果同时确认。
- 失败处理：保留本机控制台与诊断；不得以 parser 测试替代。
- 清理：双端卸载测试设备，删除传输私钥副本。
- 证据边界：在本次缺少备用目标时记录 blocked，初版文档明确风险。

### TC-005 — Independent review and publication hygiene
- 优先级：P0。
- 实际动作：独立安全/正确性冷读；扫描所有拟跟踪文件与提交历史的私钥、token、私人地址/路径/机型；确认代码仓库不含生成目录。
- 预期：重要 finding 已修复/复核，公开内容无私人部署资料。
- 清理：无生产改动；生成目录始终在仓库外。

### TC-006 — Hosted CI
- 优先级：P1。
- 实际动作：推送已审查代码后等待 GitHub Actions 的 Python、relay、Windows 三个 job。
- 预期：三项成功；失败保留记录并修复重跑，不把提交成功当成测试成功。
- 清理：不上传任何 enrollment 或私钥作 artifact。

## 执行顺序与依赖

TC-001/002/003 可并行；TC-005 复核最终代码后才能公开推送；TC-006 依赖推送；TC-004依赖备用目标，不能操作现用电脑来绕过该条件。

## 计划攻击与开放缺口

即使自动化全绿，Windows服务注册、权限、恢复或卸载仍可能错误。因此初始发布必须保留 TC-004 未验证说明；不能宣称已完成生产稳定性验收。

### TC-007 — Disposable hosted Windows installation

- Priority: P0 for installation claims, distinct from physical lifecycle TC-004.
- Environment: a fresh GitHub-hosted Windows 2022 VM per matrix case, elevated Windows PowerShell 5.1; false/true AdminAccess cases are isolated.
- Action: `tests/test_windows_install.ps1` creates temporary per-device keys outside the checkout, installs the Windows capability implementation, authenticates through loopback SSH, transfers a file through SFTP, observes repeated refused-relay attempts, checks task/effective-policy/ACL settings, repeats installation, then uninstalls and reads back ownership cleanup.
- Safety: strong hosted-runner gates; stock default sshd configuration is removed only when its hash matches the capability default. Never invoke on a personal/self-hosted computer.
- Expected: the permitted operator authenticates, privilege matches the switch, only loopback listens, retry/task settings are present, repeated enrollment is idempotent and owned resources disappear on uninstall. Capability failure is BLOCKED/failed, never a pass.
- Cleanup: finally removes test keys and owned task/processes; the hosted VM is disposed by GitHub. No private artifacts are uploaded.
- Evidence boundary: this does not prove physical reboot, sleep, battery transitions or successful relay reconnection on a desktop Windows device. Linux tests separately prove the relay path.
