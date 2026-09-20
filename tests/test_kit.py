import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import kit


class KitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        (self.source / 'windows').mkdir(parents=True)
        for script in kit.WINDOWS_SCRIPTS:
            (self.source / 'windows' / script).write_text('# test fixture\n')
        self.patch = mock.patch.object(kit, 'SOURCE_ROOT', self.source.resolve())
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.addCleanup(self.temp.cleanup)
        self.host = self.root / 'relay-host'
        self.make_key(self.host)
        self.output = self.root / 'private enrollment'

    def make_key(self, path):
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)], check=True)
        return path.with_suffix('.pub')

    def enroll(self, **changes):
        options = dict(device='desk', relay_host='relay.example.test', relay_host_key=self.host.with_suffix('.pub'),
                       relay_port=2222, remote_port=22024, output=self.output)
        options.update(changes)
        with contextlib.redirect_stdout(io.StringIO()):
            kit.prepare(argparse.Namespace(**options))

    def pin(self, public, expected):
        with contextlib.redirect_stdout(io.StringIO()):
            kit.trust(argparse.Namespace(directory=self.output, host_key=public, fingerprint=expected))

    def test_generated_bundle_separates_identities_and_pins_relay(self):
        self.enroll()
        bundle = self.output / 'windows-bundle'
        self.assertTrue((bundle / 'tunnel_key').exists())
        self.assertFalse((bundle / 'operator_key').exists())
        self.assertEqual((self.output / 'device_known_hosts').read_text(), '')
        self.assertEqual(kit.public_key(bundle / 'operator_key.pub')[1], kit.public_key(self.output / 'operator_key.pub')[1])
        self.assertNotEqual(kit.public_key(bundle / 'tunnel_key.pub')[1], kit.public_key(bundle / 'operator_key.pub')[1])
        self.assertTrue((bundle / 'relay_known_hosts').read_text().startswith('[relay.example.test]:2222 ssh-ed25519 '))
        if os.name != 'nt':
            self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
            self.assertEqual((self.output / 'operator_key').stat().st_mode & 0o777, 0o600)
        parsed = subprocess.run(['ssh', '-G', '-F', str(self.output / 'ssh_config'), 'desk'], check=True, capture_output=True, text=True).stdout
        self.assertIn('hostname 127.0.0.1\n', parsed)
        self.assertIn('port 22024\n', parsed)
        self.assertIn('user rskremote\n', parsed)
        self.assertIn('stricthostkeychecking true\n', parsed)
        self.assertIn('hostkeyalias rsk-device-desk\n', parsed)
        self.assertIn('proxycommand ssh -F ', parsed)
        self.assertIn('rsk-relay-desk', parsed)

    def test_cannot_overwrite_enrollment(self):
        self.enroll()
        original = (self.output / 'operator_key').read_bytes()
        with self.assertRaises(FileExistsError):
            self.enroll()
        self.assertEqual((self.output / 'operator_key').read_bytes(), original)

    def test_private_output_must_not_be_under_repository(self):
        with self.assertRaisesRegex(ValueError, 'outside the source'):
            self.enroll(output=self.source / 'bundle')
        self.assertFalse((self.source / 'bundle').exists())

    def test_trust_requires_verified_fingerprint_and_refuses_rotation(self):
        self.enroll()
        target = self.make_key(self.root / 'target-host')
        fingerprint = kit.public_key(target)[1]
        with self.assertRaisesRegex(ValueError, 'does not match'):
            self.pin(target, 'SHA256:not-the-verified-value')
        self.assertEqual((self.output / 'device_known_hosts').read_text(), '')
        self.pin(target, fingerprint)
        self.pin(target, fingerprint)
        self.assertTrue((self.output / 'device_known_hosts').read_text().startswith('rsk-device-desk ssh-ed25519 '))
        other = self.make_key(self.root / 'other-host')
        with self.assertRaisesRegex(ValueError, 'already pinned'):
            self.pin(other, kit.public_key(other)[1])

    def test_modified_config_rejected(self):
        self.enroll()
        path = self.output / 'device.json'
        cfg = json.loads(path.read_text())
        cfg['windows_user'] = 'administrator'
        path.write_text(json.dumps(cfg))
        with self.assertRaisesRegex(ValueError, 'changed identities'):
            kit.read_config(self.output)

    def test_rejects_authorized_key_options_private_and_multiple_keys(self):
        key = self.host.with_suffix('.pub').read_text()
        for text in ['restrict ' + key, key + key, self.host.read_text(), 'ssh-ed25519 not-valid-base64!']:
            file = self.root / 'bad.pub'
            file.write_text(text)
            with self.subTest(text=text[:24]), self.assertRaises(ValueError):
                kit.public_key(file)

    def test_rejects_shell_syntax_names_and_ports(self):
        for host in ['https://example.test', 'host;id', '-oProxyCommand=x', '127.0.0.1:22', 'a b', 'a\nb', '999.1.1.1', '::1', 'a..b', 'relay.example.test.']:
            with self.subTest(host=host), self.assertRaises(ValueError):
                kit.hostname(host)
        for name in ['../desk', '-desk', 'Desk', 'desk;id', 'a'*17, '']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                kit.device_name(name)
        for value in [0, 65536, True]:
            with self.subTest(port=value), self.assertRaises(ValueError):
                kit.port(value)
        with self.assertRaises(ValueError):
            kit.port(22, 1024)
        for path in ['bad\npath', 'bad%hpath', 'bad"path']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                kit.safe_path(self.root / path)

    def test_symlink_cannot_replace_another_hosts_file(self):
        self.enroll()
        public = self.make_key(self.root / 'target-host')
        target = self.root / 'unrelated-file'
        target.write_text('')
        hosts = self.output / 'device_known_hosts'
        hosts.unlink()
        hosts.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'symbolic link'):
            self.pin(public, kit.public_key(public)[1])
        self.assertEqual(target.read_text(), '')


if __name__ == '__main__':
    unittest.main()
