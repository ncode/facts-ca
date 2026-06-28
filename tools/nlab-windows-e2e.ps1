$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Server = Join-Path $Root "facts-ca-server.exe"
$Cli = Join-Path $Root "facts-ca-cli.exe"
$HostName = "127.0.0.1"
$Port = $null
function Test-PortAvailable {
    param([int]$Candidate)
    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($HostName), $Candidate)
        $listener.Start()
        return $true
    }
    catch {
        return $false
    }
    finally {
        if ($listener) { $listener.Stop() }
    }
}
if ($env:PORT) {
    $Port = [int]$env:PORT
    if ($Port -lt 1 -or $Port -gt 65535) { throw "invalid PORT: $Port" }
    if (-not (Test-PortAvailable $Port)) { throw "PORT is not available: $Port" }
}
else {
    for ($i = 0; $i -lt 20; $i++) {
        $Candidate = Get-Random -Minimum 18000 -Maximum 28000
        if (Test-PortAvailable $Candidate) {
            $Port = $Candidate
            break
        }
    }
if ($null -eq $Port) { throw "could not find an available test port" }
}
$ServerAddr = "${HostName}:$Port"
$UUID = "ED803750-E3C7-44F5-BB08-41A04433FE2E"
$Tmp = Join-Path $env:TEMP ("facts-ca-e2e-" + [guid]::NewGuid().ToString("N"))
$Cadir = Join-Path $Tmp "cadir"
$QuotedCadir = "`"$Cadir`""
$SSLDir = Join-Path $Tmp "ssl"
$ServerOut = Join-Path $Tmp "server.out"
$ServerErr = Join-Path $Tmp "server.err"

function Run-Cli {
    param([string[]]$CliArgs)
    $errFile = [IO.Path]::GetTempFileName()
    $old = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    try {
        $out = & $Cli @CliArgs 2>$errFile | Out-String
        $code = $LASTEXITCODE
        $err = Get-Content -Raw -ErrorAction SilentlyContinue $errFile
        [pscustomobject]@{ Code = $code; Output = ($err + $out) }
    }
    finally {
        $ErrorActionPreference = $old
        Remove-Item -Force -ErrorAction SilentlyContinue $errFile
    }
}

New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
$proc = $null
try {
    Write-Output "== start server (autosign) =="
    $proc = Start-Process -FilePath $Server -ArgumentList @(
        "-init", "-cadir", $QuotedCadir,
        "-listen", "127.0.0.1:$Port",
        "-hostname", $HostName,
        "-autosign"
    ) -PassThru -RedirectStandardOutput $ServerOut -RedirectStandardError $ServerErr

    Write-Output "== bootstrap node1.test (with Puppet trusted-fact extensions) =="
    $boot = $null
    $firstBootFailure = $null
    for ($i = 0; $i -lt 30; $i++) {
        if ($proc.HasExited) {
            Get-Content -ErrorAction SilentlyContinue $ServerOut, $ServerErr | Write-Output
            throw "server exited before bootstrap"
        }
        $boot = Run-Cli @(
            "bootstrap", "--server", $ServerAddr,
            "--certname", "node1.test",
            "--ssldir", $SSLDir,
            "--onetime",
            "--ext", "pp_role=web",
            "--ext", "pp_uuid=$UUID"
        )
        if ($boot.Code -eq 0) { break }
        if ($null -eq $firstBootFailure) { $firstBootFailure = $boot.Output }
        Start-Sleep -Seconds 1
    }
    if ($boot.Code -ne 0) {
        if ($firstBootFailure) {
            "first bootstrap failure:" | Write-Output
            $firstBootFailure | Write-Output
            "last bootstrap failure:" | Write-Output
        }
        $boot.Output | Write-Output
        throw "bootstrap failed"
    }
    $boot.Output | Write-Output
    if ($boot.Output -notmatch "ext pp_role = web") { throw "missing pp_role extension" }
    if ($boot.Output -notmatch "ext pp_uuid = $UUID") { throw "missing pp_uuid extension" }

    Write-Output "== mTLS admin: ca list =="
    $list = Run-Cli @("ca", "list", "--server", $ServerAddr, "--ssldir", $SSLDir)
    if ($list.Code -ne 0 -or $list.Output -notmatch "node1.test") {
        $list.Output | Write-Output
        throw "admin list failed"
    }

    Write-Output "== mTLS data path =="
    $mtls = Run-Cli @(
        "mtls", "--server", $ServerAddr,
        "--ssldir", $SSLDir,
        "--url", "https://$ServerAddr/puppet-ca/v1/certificate/ca"
    )
    if ($mtls.Code -ne 0 -or $mtls.Output -notmatch "HTTP 200") {
        $mtls.Output | Write-Output
        throw "mtls failed"
    }

    Write-Output "ALL WINDOWS E2E CHECKS PASSED"
}
finally {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force
        Wait-Process -Id $proc.Id -ErrorAction SilentlyContinue
    }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $Tmp
}
