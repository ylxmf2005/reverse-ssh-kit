# Security scope

The relay administrator, operator computer, and target Windows administrators are trusted. Each device receives separate identities. The Windows installer grants ordinary-user maintenance access by default; `-AdminAccess` deliberately grants administrative access. SSH endpoints are authenticated independently: a trusted relay host key is supplied during preparation, and the Windows host fingerprint is verified on the target before pinning.

Generated enrollment directories contain unencrypted private keys for unattended use. File permissions do not protect against a compromised owner/admin account, insecure backups, or public uploads. Keep bundles outside the repository, transfer them privately, and remove transfer copies after deployment. Never include keys or real deployment data in issues, Actions artifacts or logs.

Relay loopback binding prevents remote direct access, but processes already on the relay can reach loopback ports. Windows still requires a valid operator key. The dedicated relay users cannot open a shell or forward to arbitrary destinations. Revocation terminates existing connections as well as disabling new authentication; revoke on both sides when retiring a device.

The v1 Windows installer requires a fresh or already-managed OpenSSH setup. It refuses to take over an unrelated sshd configuration, account or scheduled task. Do not disable those checks to "fix" installation. The relay sets GatewayPorts=no; use a dedicated relay if existing deployments require publicly bound SSH reverse forwards.

Do not publish an exploit with credentials or target addresses. Report a reproducible issue using documentation IPs and disposable devices. Hosted Windows Server 2022 installation/authentication/cleanup tests pass in standard and administrator modes. This initial release has not yet completed a physical Windows 10/11 reboot/sleep/power-loss acceptance cycle; see the test report before relying on it for unattended critical maintenance.
