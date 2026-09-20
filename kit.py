#!/usr/bin/env python3
"""Prepare private enrollment files for native OpenSSH reverse tunnels.

Design: .agents/notes/implemented/architecture/2026-09-20-native-openssh.md
"""
import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile

SOURCE_ROOT = Path(__file__).resolve().parent
WINDOWS_SCRIPTS = ('install.ps1', 'run-tunnel.ps1', 'status.ps1', 'uninstall.ps1')
DEVICE_RE = re.compile(r'[a-z][a-z0-9-]{0,15}\Z')
PUBLIC_KEY_TYPES = {'ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'}


def device_name(value):
    if not DEVICE_RE.fullmatch(value):
        raise ValueError('device must start with a lowercase letter and contain 1-16 lowercase letters, digits or hyphens')
    return value


def hostname(value):
    if not value or len(value) > 253 or any(c in value for c in '\r\n\t %/\\:@"\''):
        raise ValueError('relay host must be an IPv4 address or ASCII DNS name, without a URL, port or shell syntax')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in value.split('.')):
            raise ValueError('invalid relay DNS name')
        if re.fullmatch(r'[0-9.]+', value):
            raise ValueError('invalid IPv4 address')
    else:
        if address.version != 4:
            raise ValueError('v1 supports IPv4/DNS relay addresses only')
    return value


def port(value, minimum=1):
    if isinstance(value, bool):
        raise ValueError('invalid port')
    number = int(value)
    if not minimum <= number <= 65535:
        raise ValueError('port must be between %d and 65535' % minimum)
    return number


def safe_path(path):
    path = Path(path).expanduser().resolve()
    if any(ord(c) < 32 or c in '"%\\' for c in str(path)):
        raise ValueError('paths containing control characters, quotes, percent signs or backslashes are unsupported')
    return path


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
        stream.write(text)


def public_key(path):
    lines = [line.strip() for line in Path(path).read_text(encoding='utf-8').splitlines() if line.strip()]
    if len(lines) != 1:
        raise ValueError('supply exactly one bare OpenSSH public key, not a private key, known_hosts file or authorized_keys options')
    fields = lines[0].split()
    if len(fields) < 2 or fields[0] not in PUBLIC_KEY_TYPES:
        raise ValueError('unsupported or non-bare SSH public key')
    try:
        blob = base64.b64decode(fields[1], validate=True)
        length = struct.unpack('>I', blob[:4])[0]
        embedded_type = blob[4:4 + length].decode('ascii')
    except (ValueError, struct.error, UnicodeError) as exc:
        raise ValueError('invalid public-key encoding') from exc
    if embedded_type != fields[0]:
        raise ValueError('public-key type does not match its wire encoding')
    normalized = fields[0] + ' ' + fields[1]
    with tempfile.TemporaryDirectory(prefix='rsk-key-check-') as directory:
        candidate = Path(directory) / 'public.key'
        candidate.write_text(normalized + '\n', encoding='ascii')
        result = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', str(candidate)], capture_output=True, text=True)
        if result.returncode:
            raise ValueError('ssh-keygen rejected the public key')
    fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode('ascii').rstrip('=')
    return normalized, fingerprint


def config_for(device, host, relay_port, remote_port):
    device_name(device)
    return dict(schema_version=1, device_name=device, relay_host=hostname(host),
                relay_port=port(relay_port), remote_port=port(remote_port, 1024),
                tunnel_user='rsk-t-' + device, access_user='rsk-a-' + device,
                windows_user='rskremote')


def read_config(directory):
    raw = json.loads((directory / 'device.json').read_text(encoding='utf-8'))
    expected = config_for(raw['device_name'], raw['relay_host'], raw['relay_port'], raw['remote_port'])
    if raw != expected:
        raise ValueError('device.json does not match the supported schema; refusing to use changed identities')
    return expected


def ssh_config(directory, cfg):
    device = cfg['device_name']
    # -F is explicit in the subprocess too; a jump must not fall back to ~/.ssh/config.
    proxy = 'ssh -F %s -W %%h:%%p rsk-relay-%s' % (shlex.quote(str(directory / 'ssh_config')), device)
    identity = str(directory / 'operator_key')
    return '''# Generated private configuration. Both SSH host identities must be verified.
Host rsk-relay-{device}
    HostName {host}
    Port {relay_port}
    User {access_user}
    IdentityFile "{identity}"
    UserKnownHostsFile "{relay_hosts}"
    GlobalKnownHostsFile /dev/null
    StrictHostKeyChecking yes
    UpdateHostKeys no
    IdentitiesOnly yes
    BatchMode yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    ConnectTimeout 10
    ServerAliveInterval 15
    ServerAliveCountMax 3

Host {device}
    HostName 127.0.0.1
    Port {remote_port}
    User {windows_user}
    HostKeyAlias rsk-device-{device}
    IdentityFile "{identity}"
    UserKnownHostsFile "{device_hosts}"
    GlobalKnownHostsFile /dev/null
    StrictHostKeyChecking yes
    UpdateHostKeys no
    IdentitiesOnly yes
    BatchMode yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    ConnectTimeout 10
    ServerAliveInterval 15
    ServerAliveCountMax 3
    ProxyCommand {proxy}
'''.format(device=device, host=cfg['relay_host'], relay_port=cfg['relay_port'],
           access_user=cfg['access_user'], identity=identity,
           relay_hosts=directory / 'relay_known_hosts', device_hosts=directory / 'device_known_hosts',
           remote_port=cfg['remote_port'], windows_user=cfg['windows_user'], proxy=proxy)


def prepare(args):
    cfg = config_for(args.device, args.relay_host, args.relay_port, args.remote_port)
    relay_key, fingerprint = public_key(args.relay_host_key)
    output = safe_path(args.output)
    if output == SOURCE_ROOT or SOURCE_ROOT in output.parents:
        raise ValueError('private enrollment files must be created outside the source repository')
    for name in WINDOWS_SCRIPTS:
        if not (SOURCE_ROOT / 'windows' / name).is_file():
            raise ValueError('missing Windows script: ' + name)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(mode=0o700)  # Never overwrite another enrollment or reuse its keys.
    try:
        bundle = output / 'windows-bundle'
        bundle.mkdir(mode=0o700)
        for name, target in [('operator', output / 'operator_key'), ('tunnel', bundle / 'tunnel_key')]:
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'rsk-%s-%s' % (args.device, name), '-f', str(target)], check=True)
            target.chmod(0o600)
            target.with_suffix('.pub').chmod(0o600)
        shutil.copyfile(bundle / 'tunnel_key.pub', output / 'tunnel_key.pub')
        (output / 'tunnel_key.pub').chmod(0o600)
        for directory, name in [(output, 'device.json'), (bundle, 'config.json')]:
            write_private(directory / name, json.dumps(cfg, indent=2) + '\n')
        target_host = cfg['relay_host'] if cfg['relay_port'] == 22 else '[%s]:%s' % (cfg['relay_host'], cfg['relay_port'])
        hosts = '%s %s\n' % (target_host, relay_key)
        write_private(output / 'relay-host-key.pub', relay_key + '\n')
        write_private(output / 'relay_known_hosts', hosts)
        write_private(bundle / 'relay_known_hosts', hosts)
        write_private(output / 'device_known_hosts', '')
        write_private(bundle / 'operator_key.pub', (output / 'operator_key.pub').read_text())
        for name in WINDOWS_SCRIPTS:
            shutil.copyfile(SOURCE_ROOT / 'windows' / name, bundle / name)
            (bundle / name).chmod(0o600)
        write_private(output / 'ssh_config', ssh_config(output, cfg))
        write_private(output / 'ENROLLMENT.txt',
            'Confidential enrollment directory: never commit, upload publicly, or share operator_key.\n'
            'Relay host key fingerprint: %s\n'
            '1. On the relay, run relay.sh install with device %s, port %s, tunnel_key.pub and operator_key.pub. Only copy PUBLIC files there.\n'
            '2. Securely transfer windows-bundle to the intended Windows PC. Inspect install.ps1 and run it in elevated PowerShell. Add -AdminAccess only if administrative maintenance is intended.\n'
            '3. Verify the Windows host key fingerprint on that PC; copy the public key back and run kit.py trust with its expected fingerprint.\n'
            '4. ssh -F %s %s hostname\n'
            '5. Remove the transfer copy of windows-bundle after installation; keep operator_key protected for access.\n' %
            (fingerprint, cfg['device_name'], cfg['remote_port'], shlex.quote(str(output / 'ssh_config')), cfg['device_name']))
    except BaseException:
        shutil.rmtree(output)
        raise
    print('Private enrollment:', output)
    print('Relay host fingerprint:', fingerprint)
    print('Next steps:', output / 'ENROLLMENT.txt')


def trust(args):
    directory = safe_path(args.directory)
    cfg = read_config(directory)
    key, fingerprint = public_key(args.host_key)
    if not hmac.compare_digest(fingerprint, args.fingerprint):
        raise ValueError('Windows host key fingerprint does not match the fingerprint verified on the target computer')
    path = directory / 'device_known_hosts'
    entry = 'rsk-device-%s %s\n' % (cfg['device_name'], key)
    if path.is_symlink():
        raise ValueError('host key file must not be a symbolic link')
    old = path.read_text(encoding='utf-8')
    if old and old != entry:
        raise ValueError('a different Windows host key is already pinned; investigate host identity rather than overwriting it')
    fd, temporary = tempfile.mkstemp(prefix='.host-key-', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(entry)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print('Pinned Windows host key:', fingerprint)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('prepare', help='create a new private enrollment outside the repository')
    p.add_argument('device')
    p.add_argument('--relay-host', required=True)
    p.add_argument('--relay-host-key', type=Path, required=True, help='bare public host key obtained through a trusted relay-admin channel')
    p.add_argument('--relay-port', type=int, default=22)
    p.add_argument('--remote-port', type=int, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.set_defaults(run=prepare)
    p = sub.add_parser('trust', help='pin a Windows host public key whose fingerprint was verified on that PC')
    p.add_argument('directory', type=Path)
    p.add_argument('--host-key', type=Path, required=True)
    p.add_argument('--fingerprint', required=True)
    p.set_defaults(run=trust)
    args = parser.parse_args(argv)
    try:
        args.run(args)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        parser.exit(1, 'error: %s\n' % exc)
    return 0


if __name__ == '__main__':
    sys.exit(main())
