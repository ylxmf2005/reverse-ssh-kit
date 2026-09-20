#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$BundlePath, [switch]$AdminAccess)
. (Join-Path $PSScriptRoot 'status.ps1') -Library
Assert-Administrator
$bundle = (Resolve-Path -LiteralPath $BundlePath).Path
Assert-NoReparse $bundle
$c = Get-BundleConfig (Join-Path $bundle 'config.json')
$files = @('config.json', 'tunnel_key', 'relay_known_hosts', 'operator_key.pub', 'install.ps1', 'run-tunnel.ps1', 'uninstall.ps1', 'status.ps1')
$hashes = [ordered]@{}
foreach ($name in $files) {
    $path = Join-Path $bundle $name
    Assert-NoReparse $path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Bundle file missing: $name" }
    $hashes[$name] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}
# A single registration is deliberate: the dedicated sshd serves one account.
if (Test-Path -LiteralPath $script:Root) {
    $old = Get-KitState
    if ($old.phase -ne 'installed') { throw 'Incomplete managed installation. Run uninstall.ps1 before retrying.' }
    if ([bool]$old.admin_access -ne [bool]$AdminAccess) { throw 'AdminAccess differs. Uninstall before changing registration.' }
    foreach ($name in $files) {
        if ($old.bundle_hashes.$name -ne $hashes[$name]) { throw "Bundle differs ($name). Uninstall before changing registration." }
        Assert-FileHash (Join-Path $script:Root $name) $hashes[$name]
    }
    Assert-FileHash $script:SshConfig $old.sshd_config_hash
    if (-not (Assert-OwnedTask $old) -or -not (Assert-OwnedUser $old)) { throw 'Managed resource missing; uninstall before reinstalling.' }
    & (Join-Path $PSScriptRoot 'status.ps1')
    return
}
Assert-NoReparse $script:Root
Assert-NoReparse $script:SshDir
if (Get-LocalUser -Name 'rskremote' -ErrorAction SilentlyContinue) { throw 'Refusing pre-existing unmanaged rskremote account.' }
if (Get-ScheduledTask -TaskName $script:TaskName -TaskPath '\' -ErrorAction SilentlyContinue) { throw 'Refusing pre-existing unmanaged scheduled task.' }
foreach ($path in @($script:SshConfig, (Join-Path $script:SshDir 'administrators_authorized_keys'))) {
    if (Test-Path -LiteralPath $path) { throw "Refusing unmanaged OpenSSH configuration/keys: $path" }
}
$existingService = Get-Service sshd -ErrorAction SilentlyContinue
if ($existingService -and $existingService.Status -ne 'Stopped') { throw 'Refusing a running unmanaged sshd service.' }
if (@(Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue).Count) { throw 'TCP port 22 is already in use.' }

New-PrivateDirectory $script:Root
$s = [ordered]@{
    schema_version = 1; owner = ('ReverseSshKit:' + [guid]::NewGuid().ToString()); phase = 'installing'
    admin_access = [bool]$AdminAccess; bundle_hashes = $hashes; user_sid = ''; profile = ''
    authorized_keys = ''; authorized_keys_hash = ''; sshd_config_hash = ''; host_public_hash = ''
    service_start_mode = ''; service_delayed_auto = $null; service_changed = $false; ssh_dir_created = $false
}
try {
    Save-State $s
    foreach ($name in $files) {
        # Destination is protected before the first copy, including on failure.
        [IO.File]::WriteAllBytes((Join-Path $script:Root $name), [IO.File]::ReadAllBytes((Join-Path $bundle $name)))
        Set-KeyAcl (Join-Path $script:Root $name)
        Assert-FileHash (Join-Path $script:Root $name) $hashes[$name]
    }
    foreach ($kind in @('Server', 'Client')) {
        try {
            $cap = Get-WindowsCapability -Online -Name "OpenSSH.$kind~~~~0.0.1.0" -ErrorAction Stop
            if ($cap.State -ne 'Installed') {
                $result = Add-WindowsCapability -Online -Name "OpenSSH.$kind~~~~0.0.1.0" -ErrorAction Stop
                if ($result.RestartNeeded) { throw 'Windows reports that a restart is required; restart manually before retrying.' }
                if ((Get-WindowsCapability -Online -Name "OpenSSH.$kind~~~~0.0.1.0").State -ne 'Installed') { throw 'Capability is not installed.' }
            }
        } catch {
            throw "OpenSSH $kind capability installation failed. No MSI was downloaded. Use official Microsoft instructions: https://learn.microsoft.com/windows-server/administration/openssh/openssh_install_firstuse . $($_.Exception.Message)"
        }
    }
    foreach ($exe in @('sshd.exe', 'ssh.exe', 'ssh-keygen.exe', 'sftp-server.exe')) {
        if (-not (Test-Path -LiteralPath (Join-Path $script:OpenSsh $exe))) { throw "Missing Windows OpenSSH executable: $exe" }
    }
    $service = Get-CimInstance Win32_Service -Filter "Name = 'sshd'"
    if (-not $service -or [Environment]::ExpandEnvironmentVariables($service.PathName).Trim('"') -ine (Join-Path $script:OpenSsh 'sshd.exe') -or $service.StartName -ne 'LocalSystem') {
        throw 'sshd service is not the supported Windows capability service.'
    }
    if ($service.State -ne 'Stopped') { throw 'sshd became active during installation; refusing takeover.' }
    $s.service_start_mode = $service.StartMode
    $s.service_delayed_auto = (Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd').GetValue('DelayedAutoStart', $null)
    Save-State $s
    if (Test-Path -LiteralPath $script:SshConfig) { throw 'A configuration appeared during capability installation; refusing takeover.' }
    if (-not (Test-Path -LiteralPath $script:SshDir)) {
        $s.ssh_dir_created = $true; Save-State $s
        New-PrivateDirectory $script:SshDir
    }
    Assert-SafeAcl $script:SshDir

    $keygen = Join-Path $script:OpenSsh 'ssh-keygen.exe'
    $operator = [IO.File]::ReadAllText((Join-Path $script:Root 'operator_key.pub')).Trim()
    if ($operator -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]*)?$') { throw 'Expected one bare Ed25519 operator public key.' }
    & $keygen -lf (Join-Path $script:Root 'operator_key.pub') -E sha256 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Invalid operator public key.' }
    $relayIdentity = [string]$c.relay_host
    if ($c.relay_port -ne 22) { $relayIdentity = "[$($c.relay_host)]:$($c.relay_port)" }
    $known = [IO.File]::ReadAllText((Join-Path $script:Root 'relay_known_hosts')).Trim()
    if ($known -notmatch ('^' + [regex]::Escape($relayIdentity) + ' (ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/]+={0,2}(?: [^\r\n]*)?$')) {
        throw 'Expected exactly one pinned relay host key for the configured host and port.'
    }
    & $keygen -lf (Join-Path $script:Root 'relay_known_hosts') -E sha256 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Invalid pinned relay host key.' }
    # -y with empty passphrase validates the bundle key without printing it.
    $check = New-Object Diagnostics.ProcessStartInfo
    $check.FileName = $keygen
    $check.Arguments = '-y -P "" -f "' + (Join-Path $script:Root 'tunnel_key') + '"'
    $check.UseShellExecute = $false; $check.CreateNoWindow = $true
    $check.RedirectStandardOutput = $true; $check.RedirectStandardError = $true
    $p = [Diagnostics.Process]::Start($check)
    $null = $p.StandardOutput.ReadToEnd(); $null = $p.StandardError.ReadToEnd(); $p.WaitForExit()
    $exitCode = $p.ExitCode; $p.Dispose()
    if ($exitCode -ne 0) { throw 'Invalid tunnel private key or nonempty passphrase.' }

    $random = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($random) } finally { $rng.Dispose() }
    $password = ConvertTo-SecureString ('aA1!' + [Convert]::ToBase64String($random)) -AsPlainText -Force
    [Array]::Clear($random, 0, $random.Length)
    try {
        $user = New-LocalUser -Name 'rskremote' -Password $password -Description $s.owner -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword
    } finally { $password.Dispose(); $password = $null }
    $s.user_sid = $user.SID.Value; Save-State $s
    $groupSid = 'S-1-5-32-545'
    if ($AdminAccess) { $groupSid = 'S-1-5-32-544' }
    $group = Get-LocalGroup -SID $groupSid
    Add-LocalGroupMember -Group $group -Member $user

    # CreateProfile uses the configured Windows profile root (not a guessed C:\Users path).
    if (-not ('RskUserProfile' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class RskUserProfile {
    [DllImport("userenv.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int CreateProfile(string sid, string name, StringBuilder path, uint size);
}
'@
    }
    $profileBuffer = New-Object Text.StringBuilder 1024
    $hr = [RskUserProfile]::CreateProfile($s.user_sid, 'rskremote', $profileBuffer, 1024)
    if ($hr -ne 0) { throw "Could not create a fresh user profile (HRESULT $hr)." }
    $s.profile = $profileBuffer.ToString(); Save-State $s
    if ($AdminAccess) {
        $authorized = Join-Path $script:SshDir 'administrators_authorized_keys'
    } else {
        $sshHome = Join-Path $s.profile '.ssh'
        New-PrivateDirectory $sshHome $s.user_sid
        $authorized = Join-Path $sshHome 'authorized_keys'
    }
    if (Test-Path -LiteralPath $authorized) { throw 'Refusing existing authorized_keys.' }
    $s.authorized_keys = $authorized
    # Record expected content before publishing, so rollback also handles partial installs.
    $keyStage = Join-Path $script:Root 'authorized_keys.stage'
    Write-Utf8 $keyStage ($operator + "`n")
    $s.authorized_keys_hash = (Get-FileHash -LiteralPath $keyStage).Hash; Save-State $s
    [IO.File]::Copy($keyStage, $authorized, $false)
    if ($AdminAccess) { Set-KeyAcl $authorized } else { Set-KeyAcl $authorized $s.user_sid }

    $hostKey = Join-Path $script:Root 'ssh_host_ed25519_key'
    $generate = New-Object Diagnostics.ProcessStartInfo
    $generate.FileName = $keygen
    $generate.Arguments = '-q -t ed25519 -N "" -f "' + $hostKey + '"'
    $generate.UseShellExecute = $false; $generate.CreateNoWindow = $true
    $p = [Diagnostics.Process]::Start($generate); $p.WaitForExit()
    $exitCode = $p.ExitCode; $p.Dispose()
    if ($exitCode -ne 0) { throw 'Host-key generation failed.' }
    Set-KeyAcl $hostKey
    Set-KeyAcl ($hostKey + '.pub')
    $s.host_public_hash = (Get-FileHash -LiteralPath ($hostKey + '.pub')).Hash
    $hostKeyConfig = $hostKey.Replace('\', '/')
    $authorizedConfig = $authorized.Replace('\', '/')
    $sftp = (Join-Path $script:OpenSsh 'sftp-server.exe').Replace('\', '/')
    $configText = @"
# $($s.owner)
Port 22
AddressFamily inet
ListenAddress 127.0.0.1
HostKey "$hostKeyConfig"
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
StrictModes yes
AllowUsers rskremote
AuthorizedKeysFile "$authorizedConfig"
DisableForwarding yes
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
X11Forwarding no
PermitTunnel no
Subsystem sftp "$sftp"
"@
    $stageConfig = Join-Path $script:Root 'sshd_config.stage'
    Write-Utf8 $stageConfig ($configText + "`n")
    & (Join-Path $script:OpenSsh 'sshd.exe') -t -f $stageConfig
    if ($LASTEXITCODE -ne 0) { throw 'sshd rejected the hardened configuration.' }
    $s.sshd_config_hash = (Get-FileHash -LiteralPath $stageConfig).Hash; Save-State $s
    [IO.File]::Copy($stageConfig, $script:SshConfig, $false)
    Set-KeyAcl $script:SshConfig
    Assert-SafeAcl $script:SshConfig
    # Do not alter SCM failure actions. The task supervises stopped sshd; only
    # StartupType changes, with its exact previous StartMode saved for rollback.
    $s.service_changed = $true; Save-State $s
    Set-Service sshd -StartupType Automatic
    Start-Service sshd

    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $script:Root 'run-tunnel.ps1') + '"'
    $action = New-ScheduledTaskAction -Execute $powershell -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
    # No RunOnlyIfNetworkAvailable: offline boot enters the bounded reconnect loop.
    Register-ScheduledTask -TaskName $script:TaskName -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $s.owner | Out-Null
    $s.phase = 'installed'; Save-State $s
    Start-ScheduledTask -TaskName $script:TaskName -TaskPath '\'
    & (Join-Path $PSScriptRoot 'status.ps1')
    Write-Output 'Installation complete. Export the PUBLIC host key using status.ps1 -ExportHostKey PATH and explicitly pin it on the operator.'
} catch {
    $failure = $_
    try {
        # Reuse the same ownership-checked rollback as explicit removal.
        if (Test-Path -LiteralPath $script:StatePath) { & (Join-Path $PSScriptRoot 'uninstall.ps1') }
        else { Write-Warning "No state was published; protected staging directory remains at $script:Root." }
    } catch { Write-Warning "Rollback incomplete: $($_.Exception.Message). Protected state is retained for manual review." }
    throw $failure
}
