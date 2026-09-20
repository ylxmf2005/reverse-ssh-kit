# Test Report: reverse-ssh-kit initial release

## Overall conclusion

- Status: partial.
- Delivery: suitable as an explicitly limited initial test release with hosted CI passing; physical Windows lifecycle reliability is not yet accepted.
- Evidence: operator tests, 13 groups of real Linux SSH integration, native Windows parser/config validation, and independent review have passed.
- Object: the initial repository implementation, with the DNS-contract fix included. All five hosted CI jobs pass at code commit 2f546dde9e00d087b77875a72845c2c840e620f6: Python, relay, native Windows parsing, standard-user installation, and administrator installation.

## Environments

- macOS / Python 3.9; temporary Ed25519 identities.
- Disposable Debian 12 container / OpenSSH 9.2p1, with real sshd and client connections.
- Windows 11 / Windows PowerShell 5.1, parser and pure configuration tests only.
- Execution date: 2026-09-20. No production relay or existing Windows SSH configuration was changed.

## Evidence completeness

| Scope | Case | Evidence | Limit |
| --- | --- | --- | --- |
| Files, permissions and SSH configuration | TC-001 | tests/test_kit.py | Not Windows installation |
| Live SSH, listeners and established sessions | TC-002 | tests/test_relay.sh, 13 passed groups | Linux target fixture |
| Native PowerShell | TC-003 | evidence/windows-native.txt | Parser and pure validation only |
| Physical lifecycle | TC-004 | Explicit acceptance steps in plan | Not performed |
| Independent cold review | TC-005 | Finding reproduced, fixed, independently closed | Runtime limits remain |

## Coverage ledger

| Case | Scenario | Status | Strongest evidence |
| --- | --- | --- | --- |
| TC-001 | Operator CLI | passed | 8 unit tests |
| TC-002 | Relay and generated config | passed | 13 real OpenSSH integration groups |
| TC-003 | Windows parser/config | passed | 4 scripts; 3 accepted / 25 rejected inputs |
| TC-004 | Physical Windows lifecycle | blocked | No fresh spare Windows target available |
| TC-005 | Review/publication hygiene | passed | P2 fixed; no evidenced P0/P1; source scan clear |
| TC-006 | Hosted CI | passed | All five jobs succeeded on the final implementation |
| TC-007 | Disposable Windows installation | passed | Fresh Windows Server 2022 VMs, standard and admin modes |

## Execution records

### TC-001 - Operator CLI - passed

Ran `python3 -m unittest discover -s tests -v`. The initial repository-output rejection test failed because the test fixture did not resolve a macOS temporary-directory alias. Resolving the fixture root corrected the test; production SOURCE_ROOT was already resolved. All eight operator tests pass. Tests exercise separate private identities, restrictive modes, strict pins, injection-shaped inputs, refusal to overwrite an enrollment, refusal to replace a different pinned host, and native `ssh -G` parsing. Temporary directories are automatically removed. Five Windows static checks also pass; the macOS run explicitly skips the unavailable native PowerShell test.

### TC-002 - Relay and generated configuration - passed

The disposable Debian/OpenSSH test passed 13 groups, including Bash syntax and ShellCheck. It verifies input/account/config/listener collisions, idempotence, effective sshd restrictions, loopback-only listening, denial of shell/SFTP on relay users, wrong identities, lateral TCP forwarding and Unix-socket forwarding, failure handling, and active-session revocation without interrupting a second device or restarting the sshd master.

The final added group uses unmodified `kit.py` to generate enrollment in a path containing spaces. With the generated two-hop configuration, `hostname` succeeds and SCP upload/download compares equal. An unpinned target and separately substituted relay/target host keys are rejected. This closes the generated ProxyCommand/identity composition path using a Linux target fixture, not Windows ACLs. The test container and image were removed.

### TC-003 - Native Windows parser/config - passed

Transferred only the four scripts and test script into a temporary diagnostic directory. Windows PowerShell 5.1 returned four PARSE OK lines and CONFIG OK: 3 valid and 25 invalid inputs. The extra trailing-dot DNS case was rerun after review. No install/uninstall function, service, account, or live tunnel configuration was invoked. The temporary JSON and transfer directory were removed; Test-Path readback was False. See evidence/windows-native.txt.

### TC-004 - Physical Windows lifecycle - blocked

Not performed. Existing connected computers have unrelated SSH deployments and active access; taking them over for this test would violate the refusal boundary. README and SECURITY.md state this limit. Hosted disposable Windows installation testing is being added separately; it cannot establish reboot, sleep, battery or real network-loss behavior.

### TC-005 - Review and publication scan - passed

Independent security/correctness review found no evidenced P0/P1. One P2 was reproduced: Python accepted trailing-dot DNS names while Windows rejected them. The generator now rejects them before creating material; both validation suites gained a case. The reviewer independently closed the finding and native Windows retest passed. Reviewed relay.sh SHA256: d4022e43b0974d4dc426e0658ed81f04ea2a77806a7a73af626289edc3899d31.

Scanned prospective tracked content for private deployment addresses/domains, personal host/user/path identifiers, private-key headers, and token-shaped literals. No findings. Generated enrollment locations are excluded from the source tree by the CLI and gitignore. Final commit/history will be rescanned before public visibility.

### TC-006 - Hosted CI - passed

Initial three-job CI succeeded at c9fe005. The final five-job run 35503097910 at code commit 2f546dde9e00d087b77875a72845c2c840e620f6 succeeded, including both real Windows install modes. Evidence: https://github.com/ylxmf2005/reverse-ssh-kit/actions/runs/35503097910 . Final publication changes are documentation only; implementation and test sources are identical to this run.

### TC-007 - Disposable hosted Windows installation - passed

Added a strongly gated hosted-Windows-only integration fixture for ordinary-user and AdminAccess cases on separate fresh VMs. It includes real installation, ACL/effective settings, SSH/SFTP, refused-relay retry behavior, idempotence and uninstall readback. First run 35502076678 failed in both privilege modes: New-LocalUser rejected the 50-character description (maximum 48). The ownership marker now uses an unhyphenated GUID, preserving its identity entropy in 46 characters; the state validator matches that format. Rollback completed in the failed runs. The next run 35502193913 progressed past account creation but CreateProfile returned 0x800706f7 with a 1024-character buffer. The buffer is now MAX_PATH (260), matching the Win32-OpenSSH reference usage, with capacity passed directly. Run 35502343042 successfully completed installation in both modes, then an assertion about the optional keyboard-interactive field failed; accepting a legacy alias also did not match. The fixture now prints the actual authentication policy and verifies the meaningful boundary directly: AuthenticationMethods=publickey, PasswordAuthentication=no, successful key login, and a real denied password/keyboard-interactive-only SSH attempt. Run 35502765593 then passed installation, ACLs, real key login, rejected non-key authentication and SFTP in both modes. It failed only because the retry assertion required an English stderr phrase that the SYSTEM child did not emit. Retry verification now requires two observed failed SSH exits and fresh launches against a port verified to have no listener; localized/absent wording is not used as the behavioral proof. Run 35503097910 then passed the full fixture in both modes, including idempotence and final cleanup. Actual effective output on this Windows build retains keyboard-interactive fields as yes despite the option; AuthenticationMethods=publickey and PasswordAuthentication=no are the enforced boundary, verified together with successful key auth and a denied non-key-only attempt. The latter uses BatchMode and is not treated alone as proof of server policy.

## Failures, gaps and retest scope

- Historical red: TC-001 temporary-path test fixture, corrected and rerun.
- Review finding: trailing-dot DNS contract mismatch, fixed and independently closed.
- Proven on hosted Windows Server 2022: first installation, effective policy/ACLs, key login, SFTP, refused-relay retries, task settings, idempotence and ownership-checked uninstall in both privilege modes.
- Unproven: physical Windows 10/11 first enrollment and actual reboot, network restoration, battery transitions and sleep recovery.
- Historical runtime failures: account-description length and oversized CreateProfile buffer; both fixed and complete fixtures now pass.
- Fixture corrections: optional authentication-field presentation and stderr wording assertions were replaced with the relevant effective-policy and observed runtime boundaries; complete fixtures now pass.

## Cleanup proof

Python temporary directories were removed. Linux test containers/images were removed. The Windows transfer directory was removed with a False existence readback. Hosted Windows fixture finally blocks completed, temporary key directories and owned registrations were cleaned, and the runners were disposed. No changes were made to existing production SSH configurations.

## Replay entrypoints

See [TestPlan](test-plan.md), tests/, and .github/workflows/ci.yml. Public evidence intentionally excludes private deployment identifiers and credentials.

## Handoff

Current scope supports publishing an initial test release with all five CI jobs passing. Use a spare Windows target for physical lifecycle acceptance before relying on unattended recovery for critical work.
