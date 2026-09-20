# Agent Note: Native OpenSSH for a small Windows maintenance fleet

Status: implemented

## Problem

A few NATed Windows computers need SSH/SFTP maintenance through a reachable Linux relay, including startup and network-recovery behavior. Enrollment must be repeatable without placing machine credentials into source code or exposing a public Windows SSH port.

## Decision

OpenSSH owns encryption, host authentication and TCP forwarding. Windows services and Task Scheduler own local process startup. A small Python stdlib CLI generates per-device materials; a Bash relay installer enforces per-device forwarding boundaries. The Windows scripts own only a dedicated fresh/managed sshd configuration, maintenance account, protected state and startup task.

Each device has separate tunnel and operator keys. The operator key can authenticate to that device's restricted relay access user and Windows maintenance user. The Windows bundle contains only the tunnel private key and operator public key. Both relay and target host identities are pinned through explicit trusted input. Files containing credentials are generated outside the repository.

The relay creates distinct tunnel/access accounts per device. This adds OS accounts but gives established-session revocation an exact uid boundary and avoids killing another device's SSH process. Windows registration is intentionally one per computer; the implementation refuses an unrelated SSH deployment instead of silently taking it over.

## Alternatives considered

- **frp:** useful for multiple proxy types, but SSH-only maintenance does not justify deploying and securing another client/server protocol here.
- **rathole:** a focused reverse proxy with heartbeat/retry, still another binary and encrypted-transport configuration to maintain.
- **Tailscale:** useful for a multi-service private network, but introduces clients, a control plane and device-policy lifecycle beyond this SSH-only requirement.
- **A custom tunnel service or web control panel:** adds a network-facing security surface without solving an unmet transport need.
- **One shared relay account/key:** simpler initially, but weakens device-specific revocation and isolation. Separate per-device users and keys are worth the small setup cost.
- **Taking over an existing Windows SSH configuration:** risks breaking the owner's other access. Explicit refusal is the v1 boundary.

## Consequences

The project has no third-party Python runtime dependency and preserves standard ssh/scp operation. Reliability follows identifiable layers: SSH keepalives detect failure, the Windows loop reconnects, and the scheduled task restores the process at startup. A machine must remain powered on and awake; there is no zero-downtime claim.

The relay needs root administration and supported OpenSSH Include semantics. GatewayPorts=no also constrains other SSH reverse forwards on that relay, so shared-server users must assess that effect. Generated unattended keys require private storage and careful transfer. Windows capability installation may depend on Windows Update availability; v1 fails explicitly rather than shipping an opaque MSI fallback.

Unit, native parser and isolated Linux SSH integration tests cover the implemented boundaries. Real Windows service installation, reboot, sleep and battery recovery require a disposable target acceptance run; transport tests do not substitute for those observations. The current evidence is recorded in test/test-report.md.
