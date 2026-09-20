"""Windows-only contract checks; no deployment or network side effects.

Run: python3 -m unittest discover -s tests -p test_windows.py -v
Run the companion .ps1 with Windows PowerShell 5.1 for actual parser/validator
coverage. These source checks are not a substitute for Windows acceptance.
"""
from pathlib import Path
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / 'windows'


class WindowsContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = {p.stem: p.read_text() for p in WINDOWS.glob('*.ps1')}

    def test_ps51_ascii_and_four_entrypoints(self):
        self.assertEqual(set(self.source), {'install', 'run-tunnel', 'uninstall', 'status'})
        for source in self.source.values():
            source.encode('ascii')  # Windows PowerShell 5.1 reads BOM-less files as ANSI.
            self.assertIn('#requires -Version 5.1', source)
            self.assertNotRegex(source, r'\?\?|ForEach-Object\s+-Parallel|ConvertFrom-Json\s+-AsHashtable')

    def test_sshd_effective_single_global_policy(self):
        install = self.source['install']
        config = install.split('$configText = @"\n', 1)[1].split('\n"@', 1)[0]
        settings = {}
        for line in config.splitlines():
            if not line or line.startswith('#'):
                continue
            name, value = line.split(' ', 1)
            self.assertNotIn(name, settings, 'No override/Match escape from the global policy')
            settings[name] = value
        self.assertNotIn('Match', settings)
        self.assertNotIn('Include', settings)
        for name, value in {
            'Port': '22', 'ListenAddress': '127.0.0.1', 'AddressFamily': 'inet',
            'AllowUsers': 'rskremote', 'AuthenticationMethods': 'publickey',
            'PubkeyAuthentication': 'yes', 'StrictModes': 'yes',
            'PasswordAuthentication': 'no', 'KbdInteractiveAuthentication': 'no',
            'DisableForwarding': 'yes', 'AllowAgentForwarding': 'no', 'AllowTcpForwarding': 'no',
            'GatewayPorts': 'no', 'X11Forwarding': 'no', 'PermitTunnel': 'no',
        }.items():
            self.assertEqual(settings[name], value)
        self.assertIn('Subsystem', settings, 'scp/SFTP must remain usable')
        self.assertLess(install.index('-t -f $stageConfig'), install.index('Start-Service sshd'))

    def test_secret_storage_precedes_copy_and_no_password_output(self):
        install, shared = self.source['install'], self.source['status']
        self.assertLess(install.index('New-PrivateDirectory $script:Root'), install.index('[IO.File]::WriteAllBytes'))
        self.assertLess(shared.index('$acl.SetAccessRuleProtection($true, $false)'), shared.index('[IO.Directory]::CreateDirectory($Path, $acl)'))
        self.assertIn('RandomNumberGenerator', install)
        self.assertIn('$password.Dispose()', install)
        self.assertNotRegex(install, r'(?im)^\s*(?:Write-(?:Output|Host|Verbose)|Save-State).*\$password')
        self.assertNotIn('operator_key\'', install)
        self.assertNotRegex(install, r'(?i)Invoke-WebRequest|Invoke-RestMethod|msiexec|Set-NetFirewall|Set-MpPreference')

    def test_reconnect_and_task_contract(self):
        install, run = self.source['install'], self.source['run-tunnel']
        for value in ('-AtStartup', "-UserId 'SYSTEM'", '-ExecutionTimeLimit ([TimeSpan]::Zero)',
                      '-MultipleInstances IgnoreNew', '-AllowStartIfOnBatteries', '-DontStopIfGoingOnBatteries'):
            self.assertIn(value, install)
        for value in ('-F NUL', 'GlobalKnownHostsFile=NUL', 'StrictHostKeyChecking=yes',
                      'ExitOnForwardFailure=yes', 'ServerAliveInterval=15', 'ServerAliveCountMax=3',
                      'ConnectTimeout=15', 'BatchMode=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none',
                      'while ($true)', '[Math]::Min(60, $delay * 2)', '-R 127.0.0.1:',
                      'ReadLineAsync()', '65536', 'CONFIGURATION: operator action required'):
            self.assertIn(value, run)
        self.assertNotIn('accept-new', run)
        self.assertNotRegex(install, r'(?m)^\s*\$settings\s*=.*-RunOnlyIfNetworkAvailable')

    def test_refuse_collisions_and_guarded_revocation(self):
        install, remove, shared = self.source['install'], self.source['uninstall'], self.source['status']
        for phrase in ('Refusing pre-existing unmanaged rskremote', 'Refusing pre-existing unmanaged scheduled task', 'Refusing unmanaged OpenSSH'):
            self.assertIn(phrase, install)
        for guard in ('Assert-OwnedTask $s', 'Assert-OwnedUser $s', 'Assert-FileHash $script:SshConfig'):
            self.assertLess(remove.index(guard), remove.index('Stop-OwnedTunnel $s'))
        self.assertIn('$p.CommandLine.Contains($keyToken)', shared)
        self.assertIn('$p.ExecutablePath -ieq', shared)
        self.assertIn('$p.ParentProcessId -eq $ids[$i]', remove)
        self.assertNotRegex(remove, r'Remove-WindowsCapability|Remove-Item[^\n]*-Recurse|Stop-Process\s+-Name')
        self.assertIn('service_start_mode', remove)
        self.assertIn('service_delayed_auto', remove)
        self.assertIn('User profile retained', remove)

    @unittest.skipUnless(shutil.which('powershell') or shutil.which('pwsh'), 'PowerShell unavailable; run test_windows.ps1 on Windows')
    def test_native_parser_and_config_validation(self):
        executable = shutil.which('powershell') or shutil.which('pwsh')
        command = [executable, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(ROOT / 'tests' / 'test_windows.ps1')]
        if not shutil.which('powershell'):
            # Linux/macOS do not have ProgramData/SystemRoot. Parsing is still safe.
            command.append('-ParseOnly')
        subprocess.run(command, check=True, capture_output=True, text=True)


if __name__ == '__main__':
    unittest.main()
