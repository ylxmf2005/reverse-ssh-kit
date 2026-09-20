#requires -Version 5.1
#requires -RunAsAdministrator
# Destructive integration test: one invocation per fresh GitHub-hosted Windows VM.
[CmdletBinding()]
param([switch]$AdminAccess)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows' -or
    $env:ImageOS -notmatch '^win(22|25)$' -or -not $env:ImageVersion -or $env:GITHUB_RUN_ID -notmatch '^\d+$' -or
    -not $env:GITHUB_WORKSPACE -or -not $env:RUNNER_TEMP) { throw 'BLOCKED: requires a fresh GitHub-hosted Windows 2022/2025 runner; never run on a personal/self-hosted machine.' }
$repo = Split-Path -Parent $PSScriptRoot
if (-not $repo.StartsWith([IO.Path]::GetFullPath($env:GITHUB_WORKSPACE).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -and
    $repo -ine [IO.Path]::GetFullPath($env:GITHUB_WORKSPACE).TrimEnd('\')) { throw 'BLOCKED: test must run from the checked-out GitHub workspace.' }
. (Join-Path $repo 'windows\status.ps1') -Library
Assert-Administrator
Assert-NoReparse $env:RUNNER_TEMP
if ((Test-Path $script:Root) -or (Get-LocalUser rskremote -ErrorAction SilentlyContinue) -or
    (Get-ScheduledTask -TaskName ReverseSshKit -TaskPath '\' -ErrorAction SilentlyContinue)) { throw 'BLOCKED: VM is not fresh.' }
$sentinel = [IO.File]::Open((Join-Path $env:RUNNER_TEMP 'rsk-install-test.started'), [IO.FileMode]::CreateNew); $sentinel.Dispose()
function Check([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Run([string]$Exe, [string]$Arguments, [bool]$ExpectAuthDenial = $false) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Exe; $info.Arguments = $Arguments; $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true; $info.RedirectStandardError = $true
    $p = [Diagnostics.Process]::Start($info)
    try {
        $out = $p.StandardOutput.ReadToEndAsync(); $err = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit(300000)) { $p.Kill(); $p.WaitForExit(); throw "Timed out: $Exe" }
        $text = $out.GetAwaiter().GetResult(); $errorText = $err.GetAwaiter().GetResult()
        if ($ExpectAuthDenial) {
            Check ($p.ExitCode -ne 0 -and $errorText -match 'Permission denied') "Expected authentication denial: $errorText $text"
            return $errorText
        }
        Check ($p.ExitCode -eq 0) "$Exe exited $($p.ExitCode): $errorText $text"
        return $text
    } finally { $p.Dispose() }
}
function CheckAcl([string]$Path, [string[]]$Allowed) {
    $acl = Get-Acl -LiteralPath $Path
    Check $acl.AreAccessRulesProtected "ACL inherits permissions: $Path"
    Check ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544') "Unexpected owner: $Path"
    $grants = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | Where-Object { $_.AccessControlType -eq 'Allow' })
    foreach ($rule in $grants) { Check ($rule.IdentityReference.Value -in $Allowed) "Unexpected ACL principal on $Path" }
    foreach ($sid in $Allowed) { Check ($sid -in @($grants | ForEach-Object { $_.IdentityReference.Value })) "Missing ACL principal on $Path" }
}
$work = Join-Path $env:RUNNER_TEMP ('rsk-ci-' + [guid]::NewGuid().ToString('N'))
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$uninstall = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $repo 'windows\uninstall.ps1') + '"'
$armed = $false
try {
    try {
        foreach ($kind in @('Server', 'Client')) {
            $name = "OpenSSH.$kind~~~~0.0.1.0"
            if ((Get-WindowsCapability -Online -Name $name).State -ne 'Installed') {
                $cap = Add-WindowsCapability -Online -Name $name
                Check (-not $cap.RestartNeeded) 'Capability requires a reboot.'
            }
            Check ((Get-WindowsCapability -Online -Name $name).State -eq 'Installed') 'Capability unavailable.'
        }
    } catch { throw "BLOCKED: Windows capability provisioning failed; integration NOT passed. $($_.Exception.Message)" }
    $service = Get-CimInstance Win32_Service -Filter "Name = 'sshd'"
    Check ($service -and $service.StartName -eq 'LocalSystem' -and [Environment]::ExpandEnvironmentVariables($service.PathName).Trim('"') -ieq (Join-Path $script:OpenSsh 'sshd.exe')) 'BLOCKED: unsupported sshd service path/account.'
    Stop-Service sshd -Force
    Assert-NoReparse $script:SshConfig
    # Only the stock default config is disposable on this gated ephemeral VM.
    if (Test-Path $script:SshConfig) {
        $default = Join-Path $script:OpenSsh 'sshd_config_default'
        Check ((Test-Path $default) -and (Get-FileHash $script:SshConfig).Hash -eq (Get-FileHash $default).Hash) 'BLOCKED: existing sshd_config is not the capability default.'
        Remove-Item -LiteralPath $script:SshConfig
    }
    Check (-not (Test-Path (Join-Path $script:SshDir 'administrators_authorized_keys'))) 'BLOCKED: existing administrator keys.'
    Check (@(Get-NetTCPConnection -State Listen -LocalPort 22,65432 -ErrorAction SilentlyContinue).Count -eq 0) 'BLOCKED: test ports are occupied.'
    New-PrivateDirectory $work
    $bundle = Join-Path $work 'bundle'; New-PrivateDirectory $bundle
    Copy-Item (Join-Path $repo 'windows\*.ps1') $bundle
    foreach ($key in @('operator_key', 'tunnel_key')) {
        $null = Run (Join-Path $script:OpenSsh 'ssh-keygen.exe') ('-q -t ed25519 -N "" -f "' + (Join-Path $work $key) + '"')
        Set-KeyAcl (Join-Path $work $key)
    }
    Copy-Item (Join-Path $work 'tunnel_key'),(Join-Path $work 'operator_key.pub') $bundle
    $config = @{ schema_version = 1; device_name = 'ci-test'; relay_host = '127.0.0.1'; relay_port = 65432; remote_port = 22222; tunnel_user = 'rsk-t-ci-test'; access_user = 'rsk-a-ci-test'; windows_user = 'rskremote' }
    Write-Utf8 (Join-Path $bundle 'config.json') ($config | ConvertTo-Json)
    Write-Utf8 (Join-Path $bundle 'relay_known_hosts') "[127.0.0.1]:65432 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`n"
    $install = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $bundle 'install.ps1') + '" -BundlePath "' + $bundle + '"'
    if ($AdminAccess) { $install += ' -AdminAccess' }
    $armed = $true; Write-Output (Run $ps $install)
    $state = Get-KitState; $before = (Get-FileHash $script:StatePath).Hash
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 22)
    Check ($listeners.Count -eq 1 -and $listeners[0].LocalAddress -eq '127.0.0.1') 'sshd is not exclusively loopback.'
    $effective = Run (Join-Path $script:OpenSsh 'sshd.exe') ('-T -f "' + $script:SshConfig + '" -C user=rskremote,host=localhost,addr=127.0.0.1')
    foreach ($setting in @('authenticationmethods publickey', 'pubkeyauthentication yes', 'passwordauthentication no', 'allowusers rskremote', 'disableforwarding yes')) {
        Check ($effective -match ('(?m)^' + [regex]::Escape($setting) + '\r?$')) "Unexpected effective setting: $setting"
    }
    Write-Output ($effective -split "`n" | Where-Object { $_ -match 'authentication|allowusers|disableforwarding' })
    $allowed = @('S-1-5-18', 'S-1-5-32-544')
    foreach ($path in @($script:Root, $script:StatePath, (Join-Path $script:Root 'tunnel_key'), (Join-Path $script:Root 'ssh_host_ed25519_key'))) { CheckAcl $path $allowed }
    if (-not $AdminAccess) { $allowed += $state.user_sid }; CheckAcl $state.authorized_keys $allowed
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
    Check (($state.user_sid -in $admins) -eq [bool]$AdminAccess) 'Unexpected administrator membership.'
    $known = Join-Path $work 'known_hosts'; Write-Utf8 $known ('127.0.0.1 ' + (Get-Content -Raw (Join-Path $script:Root 'ssh_host_ed25519_key.pub')).Trim() + "`n")
    $options = '-F NUL -o BatchMode=yes -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=NUL -o IdentitiesOnly=yes -o IdentityAgent=none -o ConnectTimeout=10 -o "UserKnownHostsFile=' + $known + '" -i "' + (Join-Path $work 'operator_key') + '"'
    Check ((Run (Join-Path $script:OpenSsh 'ssh.exe') ($options + ' rskremote@127.0.0.1 hostname')).Trim() -ieq $env:COMPUTERNAME) 'Key-authenticated hostname failed.'
    $null = Run (Join-Path $script:OpenSsh 'ssh.exe') ($options + ' -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password -o NumberOfPasswordPrompts=0 rskremote@127.0.0.1 hostname') $true
    Write-Utf8 (Join-Path $work 'input.txt') ('round-trip-' + [guid]::NewGuid()); $unix = $work.Replace('\', '/')
    $batch = Join-Path $work 'sftp.batch'; Write-Utf8 $batch "put `"$unix/input.txt`" rsk-ci-probe.txt`nget rsk-ci-probe.txt `"$unix/output.txt`"`nrm rsk-ci-probe.txt`n"
    $null = Run (Join-Path $script:OpenSsh 'sftp.exe') ($options + ' -b "' + $batch + '" rskremote@127.0.0.1')
    Check ((Get-FileHash (Join-Path $work 'input.txt')).Hash -eq (Get-FileHash (Join-Path $work 'output.txt')).Hash) 'SFTP round-trip differs.'
    $deadline = (Get-Date).AddSeconds(90); $log = ''
    do { Start-Sleep 2; if (Test-Path (Join-Path $script:Root 'tunnel.log')) { $log = Get-Content -Raw (Join-Path $script:Root 'tunnel.log') } } while (([regex]::Matches($log, '\[ATTEMPT\]').Count -lt 2) -and (Get-Date) -lt $deadline)
    Check ($log -match 'Connection refused|Connection timed out' -and $log -match 'ssh exited with code 255' -and [regex]::Matches($log, '\[ATTEMPT\]').Count -ge 2 -and $log -notmatch 'CONFIGURATION') "Negative reconnect not demonstrated: $log"
    Check ((Get-ScheduledTask ReverseSshKit).State -eq 'Running') 'Task is not running.'
    [xml]$task = Export-ScheduledTask ReverseSshKit
    Check ($task.Task.Settings.ExecutionTimeLimit -eq 'PT0S' -and $task.Task.Settings.MultipleInstancesPolicy -eq 'IgnoreNew') 'Task runtime/single-instance policy differs.'
    Check ($task.Task.Principals.Principal.UserId -in @('SYSTEM', 'S-1-5-18') -and $null -ne $task.Task.Triggers.BootTrigger) 'Task lacks SYSTEM/boot settings.'
    Check ($task.Task.Settings.DisallowStartIfOnBatteries -eq 'false' -and $task.Task.Settings.StopIfGoingOnBatteries -eq 'false') 'Battery policy differs.'
    Write-Output (Run $ps $install)
    Check ((Get-FileHash $script:StatePath).Hash -eq $before -and (Get-LocalUser rskremote).SID.Value -eq $state.user_sid) 'Identical installation is not idempotent.'
    Write-Output (Run $ps $uninstall)
    Check (-not (Get-LocalUser rskremote -ErrorAction SilentlyContinue) -and -not (Get-ScheduledTask ReverseSshKit -ErrorAction SilentlyContinue) -and -not (Test-Path $script:Root)) 'Owned user/task/state survived uninstall.'
    Check ((Get-Service sshd).Status -eq 'Stopped' -and -not (Test-Path $script:SshConfig) -and -not (Test-Path $state.authorized_keys)) 'sshd/config/authorized key survived uninstall.'
    Check (@(Get-CimInstance Win32_Process -Filter "Name = 'ssh.exe'" | Where-Object { $_.CommandLine -like ('*' + $script:Root + '\tunnel_key*') }).Count -eq 0) 'Managed tunnel process survived uninstall.'
} finally {
    try { if ($armed -and (Test-Path $script:StatePath)) { Write-Output (Run $ps $uninstall) } }
    finally {
        if ($armed) {
            $task = Get-ScheduledTask ReverseSshKit -ErrorAction SilentlyContinue
            if ($task -and $task.Description -like 'ReverseSshKit:*') { Stop-ScheduledTask ReverseSshKit; Unregister-ScheduledTask ReverseSshKit -Confirm:$false }
            Stop-Service sshd -Force
            foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name = 'ssh.exe'")) {
                if ($p.ExecutablePath -ieq (Join-Path $script:OpenSsh 'ssh.exe') -and $p.CommandLine -like ('*' + $script:Root + '\tunnel_key*')) { $r = Invoke-CimMethod -InputObject $p -MethodName Terminate; Check ($r.ReturnValue -eq 0) 'Emergency tunnel cleanup failed.' }
            }
        }
        if (Test-Path $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    }
}
Write-Output "PASS: install, effective policy/ACL, SSH/SFTP, offline retries, idempotence, uninstall; AdminAccess=$AdminAccess. No reboot/sleep or successful relay forwarding tested."
