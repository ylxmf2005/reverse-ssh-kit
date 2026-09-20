#requires -Version 5.1
[CmdletBinding()]
param([switch]$Library, [string]$ExportHostKey)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Root = Join-Path $env:ProgramData 'ReverseSshKit'
$script:StatePath = Join-Path $script:Root 'state.json'
$script:TaskName = 'ReverseSshKit'
$script:SshDir = Join-Path $env:ProgramData 'ssh'
$script:SshConfig = Join-Path $script:SshDir 'sshd_config'
$script:OpenSsh = Join-Path $env:SystemRoot 'System32\OpenSSH'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run from an elevated 64-bit Windows PowerShell session.'
    }
    if (-not [Environment]::Is64BitProcess) { throw '64-bit PowerShell is required.' }
}

function Assert-NoReparse([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -Force -LiteralPath $current).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Refusing reparse point: $current"
            }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
}

function New-PrivateDirectory([string]$Path, [string]$UserSid = '') {
    Assert-NoReparse $Path
    if (Test-Path -LiteralPath $Path) { throw "Refusing existing directory: $Path" }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $owner = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $acl.SetOwner($owner)
    $sids = @('S-1-5-18', 'S-1-5-32-544')
    if ($UserSid) { $sids += $UserSid }
    foreach ($sid in $sids) {
        $principal = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($principal, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    # Apply the DACL at creation, before any private bytes are written.
    [void][IO.Directory]::CreateDirectory($Path, $acl)
}

function Assert-SafeAcl([string]$Path, [switch]$Private) {
    Assert-NoReparse $Path
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18', 'S-1-5-32-544')) { throw "Untrusted owner: $Path" }
    $write = [Security.AccessControl.FileSystemRights]'WriteData,AppendData,WriteExtendedAttributes,WriteAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544')) {
            if ($Private -or ($rule.FileSystemRights -band $write)) { throw "Unsafe ACL: $Path" }
        }
    }
}

function Set-KeyAcl([string]$Path, [string]$UserSid = '') {
    Assert-NoReparse $Path
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    $sids = @('S-1-5-18', 'S-1-5-32-544')
    if ($UserSid) { $sids += $UserSid }
    foreach ($sid in $sids) {
        $principal = New-Object Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($principal, 'FullControl', 'Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Write-Utf8([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}

function Save-State($State) {
    $temp = Join-Path $script:Root 'state.new'
    Write-Utf8 $temp ($State | ConvertTo-Json -Depth 8)
    Set-KeyAcl $temp
    Move-Item -LiteralPath $temp -Destination $script:StatePath -Force
}

function Get-KitState {
    Assert-NoReparse $script:Root
    if (-not (Test-Path -LiteralPath $script:StatePath)) { throw 'No managed installation state. Refusing to take over existing resources.' }
    Assert-SafeAcl $script:Root -Private
    Assert-SafeAcl $script:StatePath -Private
    $state = Get-Content -Raw -LiteralPath $script:StatePath | ConvertFrom-Json
    if ($state.schema_version -ne 1 -or $state.owner -notmatch '^ReverseSshKit:[0-9a-f-]{36}$') { throw 'Invalid installation ownership record.' }
    return $state
}

function Get-BundleConfig([string]$Path) {
    $c = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    if (($c.schema_version -isnot [int] -and $c.schema_version -isnot [long]) -or $c.schema_version -ne 1 -or $c.device_name -cnotmatch '^[a-z][a-z0-9-]{0,15}$' -or
        $c.windows_user -cne 'rskremote' -or $c.tunnel_user -cne "rsk-t-$($c.device_name)" -or
        $c.access_user -cne "rsk-a-$($c.device_name)") { throw 'Invalid bundle schema or account names.' }
    foreach ($field in @('relay_port', 'remote_port')) {
        if ($c.$field -isnot [int] -and $c.$field -isnot [long]) { throw "Invalid $field." }
        $minimum = 1
        if ($field -eq 'remote_port') { $minimum = 1024 }
        if ($c.$field -lt $minimum -or $c.$field -gt 65535) { throw "Invalid $field." }
    }
    $hostName = [string]$c.relay_host
    if ($hostName.Length -gt 253 -or $hostName -cnotmatch '^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$') { throw 'Invalid relay DNS/IPv4 host.' }
    foreach ($label in $hostName.Split('.')) {
        if ($label -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$') { throw 'Invalid relay DNS label.' }
    }
    if ($hostName -match '^[0-9.]+$') {
        $parts = $hostName.Split('.')
        if ($parts.Count -ne 4) { throw 'Invalid IPv4 address.' }
        foreach ($part in $parts) { if ($part -notmatch '^(0|[1-9][0-9]{0,2})$' -or [int]$part -gt 255) { throw 'Invalid IPv4 address.' } }
    }
    return $c
}

function Assert-FileHash([string]$Path, [string]$Hash) {
    Assert-NoReparse $Path
    if (-not (Test-Path -LiteralPath $Path) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash -ne $Hash) {
        throw "Managed file missing or modified; manual review required: $Path"
    }
}

function Assert-OwnedTask($State) {
    $task = Get-ScheduledTask -TaskName $script:TaskName -TaskPath '\' -ErrorAction SilentlyContinue
    if ($task) {
        $expected = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + (Join-Path $script:Root 'run-tunnel.ps1') + '"'
        if ($task.Description -ne $State.owner -or @($task.Actions).Count -ne 1 -or
            $task.Actions[0].Arguments -cne $expected -or
            $task.Actions[0].Execute -ine (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')) {
            throw 'Scheduled task ownership mismatch; refusing to modify it.'
        }
    }
    return $task
}

function Assert-OwnedUser($State) {
    $user = Get-LocalUser -Name 'rskremote' -ErrorAction SilentlyContinue
    if ($user -and ($user.Description -ne $State.owner -or ($State.user_sid -and $user.SID.Value -ne $State.user_sid))) {
        throw 'Local account ownership mismatch; refusing to modify it.'
    }
    return $user
}

function Stop-OwnedTunnel($State) {
    $task = Assert-OwnedTask $State
    if ($task) {
        Disable-ScheduledTask -TaskName $script:TaskName -TaskPath '\' | Out-Null
        Stop-ScheduledTask -TaskName $script:TaskName -TaskPath '\'
        $wait = [Diagnostics.Stopwatch]::StartNew()
        while ((Get-ScheduledTask -TaskName $script:TaskName -TaskPath '\').State -eq 'Running') {
            if ($wait.Elapsed.TotalSeconds -ge 15) { throw 'Scheduled task did not stop; retaining state.' }
            Start-Sleep -Milliseconds 200
        }
    }
    # Task termination may leave ssh.exe behind. Match its dedicated private-key
    # path as well as executable, never kill ssh processes by image name alone.
    $keyToken = '-i "' + (Join-Path $script:Root 'tunnel_key') + '"'
    foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name = 'ssh.exe'")) {
        if ($p.ExecutablePath -ieq (Join-Path $script:OpenSsh 'ssh.exe') -and
            $p.CommandLine -and $p.CommandLine.Contains($keyToken)) {
            $result = Invoke-CimMethod -InputObject $p -MethodName Terminate
            if ($result.ReturnValue -ne 0) { throw "Could not stop managed tunnel process $($p.ProcessId)." }
        }
    }
}

if ($Library) { return }
Assert-Administrator
$s = Get-KitState
$task = Assert-OwnedTask $s
$user = Assert-OwnedUser $s
$service = Get-Service sshd -ErrorAction SilentlyContinue
$taskState = 'Absent'
if ($task) { $taskState = [string]$task.State }
$serviceState = 'Absent'
if ($service) { $serviceState = [string]$service.Status }
Write-Output "Install phase: $($s.phase); task: $taskState; sshd: $serviceState; managed user present: $([bool]$user)"
Write-Output 'A running task is not proof of a reachable reverse port. Check the operator connection after pinning the host key.'
if ($s.phase -eq 'installed') {
    Assert-FileHash $script:SshConfig $s.sshd_config_hash
    Assert-FileHash $s.authorized_keys $s.authorized_keys_hash
    $pub = Join-Path $script:Root 'ssh_host_ed25519_key.pub'
    Assert-FileHash $pub $s.host_public_hash
    & (Join-Path $script:OpenSsh 'ssh-keygen.exe') -lf $pub -E sha256
    if ($LASTEXITCODE -ne 0) { throw 'Host-key fingerprint command failed.' }
    if ($ExportHostKey) {
        $dest = [IO.Path]::GetFullPath($ExportHostKey)
        Assert-NoReparse $dest
        $stream = [IO.File]::Open($dest, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
        try { $bytes = [IO.File]::ReadAllBytes($pub); $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
        Write-Output "Public host key exported to $dest. Verify the displayed fingerprint through the Windows console before operator trust."
    }
}
$log = Join-Path $script:Root 'tunnel.log'
if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 15 }
