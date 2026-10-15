# SPDX-License-Identifier: GPL-3.0-or-later

param(
    [string]$Source = 'https://agenttail.mizuame.app/downloads/current',
    [string]$Server = 'https://agenttail-api.mizuame.app',
    [string]$Vpn = '',
    [switch]$Userspace,
    [string]$Socks5 = '',
    [string]$SshPublicKey = '',
    [string]$SshPrivateKey = '',
    [string]$SshExpectedPublicKey = '',
    [switch]$Gui,
    [switch]$NoGui,
    [switch]$NoService
)
$ErrorActionPreference = 'Stop'
if ($Gui -and $NoGui) { throw 'Choose Gui or NoGui' }
if (@(@($Vpn,$SshPublicKey,$SshPrivateKey) | Where-Object { $_ }).Count -gt 1) { throw 'Choose only one installation role' }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$sourceUri = [Uri]$Source
if ($sourceUri.Scheme -ne 'https' -or $sourceUri.UserInfo -or $sourceUri.Query -or $sourceUri.Fragment) { throw 'Release source must use HTTPS without credentials or query' }
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { 'arm64' } else { 'amd64' }
$releaseDir = Join-Path ([IO.Path]::GetTempPath()) ('agenttail-install-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $releaseDir | Out-Null
function Fetch-Artifact([string]$Name) {
    Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 120 -Uri ($Source.TrimEnd('/') + '/' + $Name) -OutFile (Join-Path $releaseDir $Name)
}
try {
    Fetch-Artifact 'manifest.txt'
    Fetch-Artifact 'manifest.sha256'
    $raw = [IO.File]::ReadAllBytes((Join-Path $releaseDir 'manifest.txt'))
    if ($raw.Length -gt 65536) { throw 'Manifest too large' }
    $checksum = [IO.File]::ReadAllBytes((Join-Path $releaseDir 'manifest.sha256'))
    $manifestHash = (Get-FileHash -Algorithm SHA256 (Join-Path $releaseDir 'manifest.txt')).Hash.ToLowerInvariant()
    if ([Text.Encoding]::ASCII.GetString($checksum) -cne "$manifestHash  manifest.txt`n") { throw 'Release manifest SHA-256 mismatch' }
    $lines = [Text.Encoding]::ASCII.GetString($raw).TrimEnd("`n").Split("`n")
    if ($lines[0] -ne 'agenttail-manifest-v1') { throw 'Unsupported release manifest' }
    $created = @($lines | Where-Object { $_ -match '^created [0-9]+$' })
    $expires = @($lines | Where-Object { $_ -match '^expires [0-9]+$' })
    if ($created.Count -ne 1 -or $expires.Count -ne 1) { throw 'Invalid manifest dates' }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $c = [long]$created[0].Split(' ')[1]; $e = [long]$expires[0].Split(' ')[1]
    if ($c -gt $now+300 -or $e -le $now -or $e -le $c -or $e-$c -gt 31622400) { throw 'Expired or invalid release manifest' }
    $artifacts = @{}
    foreach ($role in @('vpn', 'wintun', 'license')) {
        $records = @($lines | Where-Object { $_ -match "^file windows $arch $role " })
        if ($records.Count -ne 1) { throw "Missing or duplicate artifact: $role" }
        $p = $records[0].Split(' ')
        if ($p.Length -ne 8 -or $p[4] -notmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$' -or $p[5] -notmatch '^[0-9]+$' -or [long]$p[5] -lt 1 -or [long]$p[5] -gt 67108864 -or $p[6] -notmatch '^[a-f0-9]{64}$' -or $p[7] -ne '-') { throw 'Invalid artifact metadata' }
        Fetch-Artifact $p[4]
        $path = Join-Path $releaseDir $p[4]
        if ((Get-Item $path).Length -ne [long]$p[5] -or (Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant() -ne $p[6]) { throw 'Artifact digest or size mismatch' }
        $artifacts[$role] = $path
    }
    if ($SshPublicKey) {
        & $artifacts['vpn'] --server $Server ssh install-public --public-key $SshPublicKey
        if ($LASTEXITCODE -ne 0) { throw "SSH registration failed: $LASTEXITCODE" }
        return
    }
    if ($SshPrivateKey) {
        $sshArguments = @('--server', $Server, 'ssh', 'install-private', '--key', $SshPrivateKey)
        if ($SshExpectedPublicKey) { $sshArguments += @('--public-key', $SshExpectedPublicKey) }
        & $artifacts['vpn'] @sshArguments
        if ($LASTEXITCODE -ne 0) { throw "SSH registration failed: $LASTEXITCODE" }
        return
    }
    # The Go client requests UAC elevation. This script remains the invoking
    # user so skill installation uses that user's profile and privileges.
    $arguments = @('install','--https-checksums','--bundle',$releaseDir,'--source',$Source,'--server',$Server)
    if ($NoService) { $arguments += '--no-service' }
    if ($Gui) { $arguments += '--gui=true' }
    if ($NoGui) { $arguments += '--gui=false' }
    & $artifacts['vpn'] @arguments
    if ($LASTEXITCODE -ne 0) { throw "Installation failed: $LASTEXITCODE" }
    & $artifacts['vpn'] skills install
    if ($LASTEXITCODE -ne 0) { throw "Skill installation failed: $LASTEXITCODE" }
    Write-Host 'AgentTail installed. Open a new terminal to use the agenttail command.'
    if ($Vpn) {
        $installedCli = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AgentTail\agenttail.cmd'
        $loginArguments = @('--server', $Server, 'vpn', 'join', '--name', $Vpn)
        if ($Userspace -or $Socks5) { $loginArguments += '--userspace' }
        if ($Socks5) { $loginArguments += @('--socks5', $Socks5) }
        if ($NoService) { $loginArguments += '--up=false' }
        Write-Host 'Joining the VPN. If approval is needed, open the link printed below.'
        & $installedCli @loginArguments
        if ($LASTEXITCODE -ne 0) { throw "Device authorization or connection failed: $LASTEXITCODE" }
        if ($NoService) { Write-Host 'Authorized. Start agenttail agent run, then agenttail vpn up --name <vpn-name>.' }
    } else {
        if ($Userspace -or $Socks5) {
            $proxyAddress = if ($Socks5) { $Socks5 } else { '127.0.0.1:1080' }
            Write-Host "Run agenttail vpn join --name <vpn-name> --userspace --socks5 $proxyAddress to connect a device."
        } else {
            Write-Host 'Run agenttail vpn join --name <vpn-name> to connect a device.'
        }
    }
} finally {
    Remove-Item -Recurse -Force $releaseDir
}
