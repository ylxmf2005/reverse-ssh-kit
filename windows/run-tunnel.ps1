#requires -Version 5.1
[CmdletBinding()]
param()
. (Join-Path $PSScriptRoot 'status.ps1') -Library
Assert-Administrator
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'Tunnel runner must execute as SYSTEM through its scheduled task.' }
$mutex = New-Object Threading.Mutex($false, 'Global\ReverseSshKit.Tunnel')
$locked = $false
$child = $null
function Write-TunnelLog([string]$Kind, [string]$Message) {
    $path = Join-Path $script:Root 'tunnel.log'
    Assert-NoReparse $path
    $line = $Message.Replace("`r", ' ').Replace("`n", ' ')
    if ($line.Length -gt 2048) { $line = $line.Substring(0, 2048) }
    if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -ge 65536) {
        $previous = Join-Path $script:Root 'tunnel.previous.log'
        Assert-NoReparse $previous
        Move-Item -LiteralPath $path -Destination $previous -Force
    }
    [IO.File]::AppendAllText($path, ((Get-Date -Format o) + " [$Kind] $line`r`n"), (New-Object Text.UTF8Encoding($false)))
}
function Ensure-Sshd($State) {
    $service = Get-Service sshd
    if ($service.Status -ne 'Running') {
        Assert-FileHash $script:SshConfig $State.sshd_config_hash
        $definition = Get-CimInstance Win32_Service -Filter "Name = 'sshd'"
        if ([Environment]::ExpandEnvironmentVariables($definition.PathName).Trim('"') -ine (Join-Path $script:OpenSsh 'sshd.exe') -or $definition.StartName -ne 'LocalSystem') { throw 'sshd service definition changed.' }
        & (Join-Path $script:OpenSsh 'sshd.exe') -t -f $script:SshConfig
        if ($LASTEXITCODE -ne 0) { throw 'sshd configuration validation failed.' }
        Start-Service sshd
        Write-TunnelLog 'SERVICE' 'Restarted stopped managed sshd.'
    }
}
try {
    try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { return }
    $s = Get-KitState
    if ($s.phase -ne 'installed') { throw 'Installation is incomplete.' }
    foreach ($name in @('config.json', 'tunnel_key', 'relay_known_hosts')) {
        Assert-SafeAcl (Join-Path $script:Root $name) -Private
        Assert-FileHash (Join-Path $script:Root $name) $s.bundle_hashes.$name
    }
    Assert-FileHash $script:SshConfig $s.sshd_config_hash
    if (-not (Assert-OwnedTask $s) -or -not (Assert-OwnedUser $s)) { throw 'Managed account/task is absent.' }
    $c = Get-BundleConfig (Join-Path $script:Root 'config.json')
    $ssh = Join-Path $script:OpenSsh 'ssh.exe'
    $key = Join-Path $script:Root 'tunnel_key'
    $knownHosts = Join-Path $script:Root 'relay_known_hosts'
    # -F NUL also excludes ambient system/user configuration, proxies and identities.
    $arguments = '-F NUL -N -T -i "' + $key + '" -p ' + $c.relay_port +
        ' -o "UserKnownHostsFile=' + $knownHosts + '" -o GlobalKnownHostsFile=NUL' +
        ' -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o BatchMode=yes' +
        ' -o IdentitiesOnly=yes -o IdentityAgent=none -o PreferredAuthentications=publickey' +
        ' -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no' +
        ' -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3' +
        ' -o ConnectTimeout=15 -o ConnectionAttempts=1 -o LogLevel=ERROR' +
        ' -R 127.0.0.1:' + $c.remote_port + ':127.0.0.1:22 ' + $c.tunnel_user + '@' + $c.relay_host
    $delay = 5
    while ($true) {
        Ensure-Sshd $s
        $start = Get-Date
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = $ssh; $info.Arguments = $arguments
        $info.UseShellExecute = $false; $info.CreateNoWindow = $true
        $info.RedirectStandardError = $true
        $child = [Diagnostics.Process]::Start($info)
        Write-TunnelLog 'ATTEMPT' 'Started ssh; this does not confirm remote forwarding readiness.'
        $read = $child.StandardError.ReadLineAsync()
        $checkService = Get-Date
        while ($null -ne $read) {
            if ($read.IsCompleted) {
                $line = $read.GetAwaiter().GetResult()
                if ($null -eq $line) { $read = $null; break }
                $kind = 'SSH'
                if ($line -match 'Permission denied|Host key verification failed|REMOTE HOST IDENTIFICATION|Bad configuration|Bad owner|invalid format|UNPROTECTED PRIVATE KEY|remote port forwarding failed|unknown option|Unsupported option') {
                    $kind = 'CONFIGURATION: operator action required'
                }
                Write-TunnelLog $kind $line
                $read = $child.StandardError.ReadLineAsync()
            } else { Start-Sleep -Milliseconds 250 }
            if (((Get-Date) - $checkService).TotalSeconds -ge 15) {
                Ensure-Sshd $s
                $checkService = Get-Date
            }
        }
        $child.WaitForExit()
        $code = $child.ExitCode
        $child.Dispose(); $child = $null
        if (((Get-Date) - $start).TotalSeconds -ge 120) { $delay = 5 }
        Write-TunnelLog 'RETRY' "ssh exited with code $code; reconnect in $delay seconds."
        Start-Sleep -Seconds $delay
        $delay = [Math]::Min(60, $delay * 2)
    }
} catch {
    if (Test-Path -LiteralPath $script:StatePath) {
        Write-TunnelLog 'CONFIGURATION/SERVICE FAILURE' $_.Exception.Message
    }
    throw
} finally {
    if ($child) {
        if (-not $child.HasExited) { $child.Kill(); $child.WaitForExit() }
        $child.Dispose()
    }
    if ($locked) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
