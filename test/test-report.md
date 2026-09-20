# Test Report: reverse-ssh-kit initial release

## Overall conclusion

- Status: partial.
- Delivery: suitable as an explicitly limited initial test release after hosted CI passes; physical Windows lifecycle reliability is not yet accepted.
- Evidence: operator tests, 13 groups of real Linux SSH integration, native Windows parser/config validation, and independent review have passed.
- Object: the initial repository implementation, with the DNS-contract fix included. The initial hosted CI passed Python, relay, and native Windows jobs. A deeper Windows install fixture is being added.

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
| TC-006 | Hosted CI | passed | Initial Python/relay/Windows jobs all succeeded |
| TC-007 | Disposable Windows installation | partial | New two-VM matrix submitted; result pending |

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

The initial private staging commit c9fe005 passed all three GitHub Actions jobs: Python, relay, and native Windows parser/config. Run: https://github.com/ylxmf2005/reverse-ssh-kit/actions/runs/35501817415 . Further runtime test changes must receive their own CI evidence.

### TC-007 - Disposable hosted Windows installation - partial

Added a strongly gated hosted-Windows-only integration fixture for ordinary-user and AdminAccess cases on separate fresh VMs. It includes real installation, ACL/effective settings, SSH/SFTP, refused-relay retry behavior, idempotence and uninstall readback. First run 35502076678 failed in both privilege modes: New-LocalUser rejected the 50-character description (maximum 48). The ownership marker now uses an unhyphenated GUID, preserving its identity entropy in 46 characters; the state validator matches that format. Rollback completed in the failed runs. The next run 35502193913 progressed past account creation but CreateProfile returned 0x800706f7 with a 1024-character buffer. The buffer is now MAX_PATH (260), matching the Win32-OpenSSH reference usage, with capacity passed directly. Run 35502343042 successfully completed installation in both modes, then an assertion about the optional keyboard-interactive field failed; accepting a legacy alias also did not match. The fixture now prints the actual authentication policy and verifies the meaningful boundary directly: AuthenticationMethods=publickey, PasswordAuthentication=no, successful key login, and a real denied password/keyboard-interactive-only SSH attempt. Runtime authentication/retry/uninstall assertions are being rerun.

## Failures, gaps and retest scope

- Historical red: TC-001 temporary-path test fixture, corrected and rerun.
- Review finding: trailing-dot DNS contract mismatch, fixed and independently closed.
- Unproven: Windows first installation/runtime ACLs and physical reboot, network loss, battery and sleep recovery.
- Historical runtime failure: Windows account description length, fixed; awaiting rerun.
- Pending: disposable Windows installation fixture CI.

## Cleanup proof

Python temporary directories were removed. Linux test containers/images were removed. The Windows transfer directory was removed with a False existence readback. No changes were made to existing production SSH configurations.

## Replay entrypoints

See [TestPlan](test-plan.md), tests/, and .github/workflows/ci.yml. Public evidence intentionally excludes private deployment identifiers and credentials.

## Handoff

Current scope supports publishing an initial test release after CI. Use a spare Windows target for physical lifecycle acceptance before relying on unattended recovery for critical work.
