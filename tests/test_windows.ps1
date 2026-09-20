#requires -Version 5.1
# Safe on an operator/CI host: parse only, or run pure bundle validation.
# Never invokes install/uninstall, changes services, or starts a connection.
[CmdletBinding()]
param([switch]$ParseOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$windows = Join-Path (Split-Path -Parent $PSScriptRoot) 'windows'
foreach ($name in @('install.ps1', 'run-tunnel.ps1', 'uninstall.ps1', 'status.ps1')) {
    $tokens = $null; $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile((Join-Path $windows $name), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw ($name + ': ' + (($errors | ForEach-Object { $_.Message }) -join '; ')) }
    Write-Output "PARSE OK: $name"
}
if ($ParseOnly) { return }
. (Join-Path $windows 'status.ps1') -Library
$temp = [IO.Path]::GetTempFileName()
try {
    $base = @{ schema_version = 1; device_name = 'test-pc'; relay_host = 'relay.example.com'; relay_port = 22; remote_port = 22222; tunnel_user = 'rsk-t-test-pc'; access_user = 'rsk-a-test-pc'; windows_user = 'rskremote' }
    foreach ($hostName in @('relay.example.com', '192.0.2.1', 'localhost')) {
        $valid = $base.Clone(); $valid.relay_host = $hostName
        Write-Utf8 $temp ($valid | ConvertTo-Json)
        $result = Get-BundleConfig $temp
        if ($result.relay_host -ne $hostName) { throw 'Valid config changed unexpectedly.' }
    }
    $cases = @(
        @('schema_version', '1'), @('schema_version', 2),
        @('device_name', 'UPPER'), @('device_name', '../bad'), @('device_name', 'abcdefghijklmnopq'),
        @('relay_host', '-oProxyCommand=bad'), @('relay_host', 'a b'), @('relay_host', 'a..b'), @('relay_host', 'relay.example.com.'),
        @('relay_host', "a`nb"), @('relay_host', '::1'), @('relay_host', '999.0.0.1'), @('relay_host', '127.1'),
        @('relay_host', '01.2.3.4'), @('relay_host', ('a' * 64 + '.com')),
        @('relay_port', 0), @('relay_port', 65536), @('relay_port', '22'), @('relay_port', 22.5),
        @('remote_port', 1023), @('remote_port', 65536), @('remote_port', $true),
        @('windows_user', 'Administrator'), @('tunnel_user', 'other'), @('access_user', 'other')
    )
    foreach ($case in $cases) {
        $invalid = $base.Clone(); $invalid[$case[0]] = $case[1]
        Write-Utf8 $temp ($invalid | ConvertTo-Json)
        $rejected = $false
        try { $null = Get-BundleConfig $temp } catch { $rejected = $true }
        if (-not $rejected) { throw "Accepted invalid $($case[0]): $($case[1])" }
    }
    Write-Output "CONFIG OK: 3 valid and $($cases.Count) invalid inputs."
} finally { Remove-Item -LiteralPath $temp -Force }
