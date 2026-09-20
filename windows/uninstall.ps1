#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding()]
param()
. (Join-Path $PSScriptRoot 'status.ps1') -Library
Assert-Administrator
if (-not (Test-Path -LiteralPath $script:Root)) { Write-Output 'No ReverseSshKit installation directory exists.'; return }
$s = Get-KitState
$task = Assert-OwnedTask $s
$user = Assert-OwnedUser $s
# Preflight before removing anything. A hash mismatch means somebody changed the
# resource since installation; ownership must be resolved rather than guessed.
if ($s.sshd_config_hash -and (Test-Path -LiteralPath $script:SshConfig)) { Assert-FileHash $script:SshConfig $s.sshd_config_hash }
if ($s.authorized_keys -and (Test-Path -LiteralPath $s.authorized_keys)) { Assert-FileHash $s.authorized_keys $s.authorized_keys_hash }
if ($s.service_changed) {
    $definition = Get-CimInstance Win32_Service -Filter "Name = 'sshd'"
    if (-not $definition -or [Environment]::ExpandEnvironmentVariables($definition.PathName).Trim('"') -ine (Join-Path $script:OpenSsh 'sshd.exe') -or $definition.StartName -ne 'LocalSystem') {
        throw 'sshd service ownership changed; refusing service modification.'
    }
    # Missing config plus a running service could now be somebody else's sshd.
    if (-not (Test-Path -LiteralPath $script:SshConfig) -and $definition.State -ne 'Stopped') { throw 'Running sshd has no managed configuration; manual review required.' }
}
Stop-OwnedTunnel $s
if ($s.service_changed) {
    # This was a dedicated, stopped service at installation. Stop only that
    # service, including its accepted sessions, before withdrawing the keys.
    # Revoke accepted sessions as well as the listening service. Limit termination
    # to sshd descendants of this service's PID and the supported executable.
    $definition = Get-CimInstance Win32_Service -Filter "Name = 'sshd'"
    $rootPid = [uint32]$definition.ProcessId
    if ($rootPid -ne 0) {
        $processes = @(Get-CimInstance Win32_Process -Filter "Name = 'sshd.exe'")
        $ids = New-Object 'System.Collections.Generic.List[uint32]'
        $ids.Add($rootPid)
        for ($i = 0; $i -lt $ids.Count; $i++) {
            foreach ($p in $processes) {
                if ($p.ParentProcessId -eq $ids[$i] -and $p.ExecutablePath -ieq (Join-Path $script:OpenSsh 'sshd.exe') -and -not $ids.Contains([uint32]$p.ProcessId)) {
                    $ids.Add([uint32]$p.ProcessId)
                }
            }
        }
        for ($i = $ids.Count - 1; $i -gt 0; $i--) {
            $p = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $ids[$i])
            $original = $processes | Where-Object { $_.ProcessId -eq $ids[$i] }
            if ($p -and $p.CreationDate -eq $original.CreationDate -and $p.ExecutablePath -ieq (Join-Path $script:OpenSsh 'sshd.exe')) {
                $result = Invoke-CimMethod -InputObject $p -MethodName Terminate
                if ($result.ReturnValue -ne 0) { throw 'Could not revoke a managed sshd session; state retained.' }
            }
        }
    }
    Stop-Service sshd -Force
    $mode = @{ Auto = 'Automatic'; Manual = 'Manual'; Disabled = 'Disabled' }[$s.service_start_mode]
    if (-not $mode) { throw 'Unknown previous sshd startup mode; retaining state.' }
    Set-Service sshd -StartupType $mode
    $serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\sshd'
    if ($null -eq $s.service_delayed_auto) {
        if ('DelayedAutoStart' -in (Get-Item -LiteralPath $serviceKey).GetValueNames()) {
            Remove-ItemProperty -LiteralPath $serviceKey -Name DelayedAutoStart
        }
    } else {
        Set-ItemProperty -LiteralPath $serviceKey -Name DelayedAutoStart -Value $s.service_delayed_auto -Type DWord
    }
}
if ($task) { Unregister-ScheduledTask -TaskName $script:TaskName -TaskPath '\' -Confirm:$false }
if ($s.authorized_keys -and (Test-Path -LiteralPath $s.authorized_keys)) {
    Remove-Item -LiteralPath $s.authorized_keys -Force
    if (-not $s.admin_access) {
        $sshHome = Split-Path -Parent $s.authorized_keys
        if (@(Get-ChildItem -Force -LiteralPath $sshHome).Count -eq 0) { Remove-Item -LiteralPath $sshHome -Force }
    }
}
if ($user) { Remove-LocalUser -SID $user.SID }
if ($s.sshd_config_hash -and (Test-Path -LiteralPath $script:SshConfig)) { Remove-Item -LiteralPath $script:SshConfig -Force }
if ($s.ssh_dir_created -and (Test-Path -LiteralPath $script:SshDir) -and @(Get-ChildItem -Force -LiteralPath $script:SshDir).Count -eq 0) {
    Remove-Item -LiteralPath $script:SshDir -Force
}
# Only delete known kit files. Preserve unexpected administrator-added content.
$ownedFiles = @('config.json', 'tunnel_key', 'relay_known_hosts', 'operator_key.pub', 'install.ps1', 'run-tunnel.ps1', 'uninstall.ps1', 'status.ps1',
    'ssh_host_ed25519_key', 'ssh_host_ed25519_key.pub', 'authorized_keys.stage', 'sshd_config.stage', 'tunnel.log', 'tunnel.previous.log', 'state.new')
foreach ($name in $ownedFiles) {
    $path = Join-Path $script:Root $name
    Assert-NoReparse $path
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
}
Remove-Item -LiteralPath $script:StatePath -Force
if (@(Get-ChildItem -Force -LiteralPath $script:Root).Count -eq 0) { Remove-Item -LiteralPath $script:Root -Force }
else { Write-Warning "Unexpected files preserved in $script:Root; directory left protected." }
Write-Output 'Owned task, tunnel, account, keys and configuration removed. OpenSSH capabilities retained; previous service startup mode restored.'
if ($s.profile) { Write-Output "User profile retained to protect any maintenance data: $($s.profile)" }
