# Start the rf daemon on Windows, reach it from a second process over the per-user named pipe,
# check that a second daemon on the same data root is refused, and stop it.
param(
    [Parameter(Mandatory = $true)][string]$Rf
)
$ErrorActionPreference = 'Stop'

$rf = (Resolve-Path $Rf).Path
$work = Join-Path $env:RUNNER_TEMP ("rf-smoke-" + [Guid]::NewGuid().ToString('N'))
$root = Join-Path $work 'data'
$socket = Join-Path $work 'rfd.sock'
New-Item -ItemType Directory -Force -Path $work | Out-Null

$daemon = Start-Process -FilePath $rf -PassThru -NoNewWindow `
    -ArgumentList @('--socket', $socket, 'daemon', 'start', '--data-root', $root) `
    -RedirectStandardOutput (Join-Path $work 'daemon.out') `
    -RedirectStandardError (Join-Path $work 'daemon.err')

function Show-DaemonLog {
    Get-Content (Join-Path $work 'daemon.err') -ErrorAction SilentlyContinue | Select-Object -Last 40
}

try {
    $ready = $false
    foreach ($attempt in 1..60) {
        if ($daemon.HasExited) { break }
        & $rf --socket $socket daemon status *> $null
        if ($LASTEXITCODE -eq 0) { $ready = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) {
        Show-DaemonLog
        throw 'the daemon did not answer a second process over the named pipe'
    }

    # The data root lock: a second daemon on the same root must refuse to start.
    $second = Start-Process -FilePath $rf -PassThru -NoNewWindow -Wait `
        -ArgumentList @('--socket', (Join-Path $work 'second.sock'), 'daemon', 'start', '--data-root', $root) `
        -RedirectStandardOutput (Join-Path $work 'second.out') `
        -RedirectStandardError (Join-Path $work 'second.err')
    if ($second.ExitCode -eq 0) { throw 'a second daemon started on a data root in use' }

    # The data root and the name file belong to the user who runs the job.
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($path in @($root, $socket)) {
        $owner = (Get-Acl -LiteralPath $path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($owner -ne $me) { throw "$path is owned by $owner, not by $me" }
    }

    & $rf --socket $socket daemon stop
    if ($LASTEXITCODE -ne 0) { throw 'daemon stop failed' }
    if (-not $daemon.WaitForExit(30000)) { throw 'the daemon did not exit after stop' }
}
finally {
    if (-not $daemon.HasExited) { Stop-Process -Id $daemon.Id -Force -ErrorAction SilentlyContinue }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
Write-Output 'windows daemon smoke: ok'
