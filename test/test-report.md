# Test Report: reverse-ssh-kit initial release

## 总体结论

- 状态：executing。
- 能否交付：not-yet，发布前独立审查及Linux集成仍在进行。
- 核心依据：operator单测和真实PowerShell解析/纯配置测试已通过；Windows物理生命周期尚未执行。
- 被测对象：本仓库初始工作树，后续提交包含本报告。

## 被测环境

- Mac/Python3.9，临时生成Ed25519密钥；真实Windows11/PowerShell5.1仅运行无部署副作用测试；Linux集成使用Docker隔离。
- 观察面：命令退出码、ssh配置解析、文件权限、原生PowerShell输出；无生产sshd改动。
- 执行日期：2026-09-20。

## 证据完整度

| 范围 | 用例 | 可复核内容 | 缺口 |
| --- | --- | --- | --- |
| 自动化源代码和实际输出 | TC-001 | `tests/test_kit.py`、CLI材料和拒绝路径 | 不含物理Windows |
| 隔离真实SSH | TC-002 | `tests/test_relay.sh` | 等待最终结果 |
| 原生解释器 | TC-003 | `tests/test_windows.ps1`、parser/27个配置案例 | 不执行安装/卸载 |
| 生命周期 | TC-004 | 已列明确验收步骤 | 尚未执行 |

## 覆盖台账

| 用例 | 场景 | 状态 | 最强证据 |
| --- | --- | --- | --- |
| TC-001 | Operator CLI | passed | 8项单元测试通过 |
| TC-002 | Relay | partial | 集成测试进行中 |
| TC-003 | Windows parser/config | passed | 四脚本parse成功，3合法/24非法配置通过 |
| TC-004 | Windows真实生命周期 | blocked | 缺少获授权的全新备用Windows |
| TC-005 | 审查/发布检查 | partial | 初次源代码泄漏扫描无发现，审查进行中 |
| TC-006 | GitHub CI | blocked | 尚未公开推送 |

## 逐用例执行记录

### TC-001 — Operator CLI — passed
运行 `python3 -m unittest discover -s tests -v`。首次执行中，仓库内输出拒绝测试因Mac临时目录别名未canonicalize的测试fixture失败；将fixture源路径resolve后，同一用例和全部8项CLI测试通过。产品本身使用resolved源码根路径。生成密钥、目录权限、pin/refuse/重复登记和SSH配置解析均在临时目录观察；TemporaryDirectory已清理。另5项Windows静态检查通过，Mac上原生PS用例明确skip。

### TC-002 — Relay — partial
专用Docker容器内运行真实OpenSSH集成测试；最终组数和清理结果待记录。默认Docker context不可用，使用已运行的替代context，不启动或重配其他虚拟机。

### TC-003 — Windows native parser/config — passed
将仅含4个脚本和测试脚本的归档传入Windows临时诊断目录，PowerShell5.1运行 `test_windows.ps1`，退出0。输出：四个PARSE OK，CONFIG OK: 3 valid and 24 invalid inputs。未调用install/uninstall或变更服务/账户。脚本临时JSON由finally清理；传输目录将在本轮最后清理。此结果不证明运行时部署。

### TC-004 — Physical Windows lifecycle — blocked
未执行。已连接的现用电脑有其他工具维护的SSH和正在使用的通道；为了测试接管它们将违背当前安全边界。需要一台新的备用目标或明确的隔离Windows测试环境。README开头与SECURITY.md明确此限制。

### TC-005 — Independent review / secret scan — partial
对拟跟踪文件扫描真实部署域名/IP、私人机型/账号/路径、私钥头和token形状，初次16个文件无发现。独立代码审查进行中；尚未据此宣称全部通过。

### TC-006 — Hosted CI — blocked
尚未推送，不能声称GitHub流水线成功。

## 失败、未完成与重测范围

- 历史红色：TC-001测试fixture路径别名，已修正并重测通过。
- 尚未证明：TC-004真实安装、ACL、重启、断网、电池和睡眠恢复。
- 发布前剩余：TC-002、005、006。

## 清理证明

Python测试临时目录已由上下文管理器删除。Docker与Windows传输目录最终清理结果待记录。没有改动现用电脑的SSH配置。

## 证据与重放入口

见 [TestPlan](test-plan.md)、`tests/`目录和GitHub Actions workflow。公开报告仅保留非敏感结果，不包含私人部署标识或密钥。

## 当前环境交接

当前代码需要独立审查与集成结果收敛后才能作为初始测试版公开。真实Windows生命周期验收仍是后续部署门槛。
