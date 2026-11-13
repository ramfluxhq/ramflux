# Start the rf daemon on Windows, reach it from a second process over the per-user named pipe,
# check that a second daemon on the same data root is refused, and stop it.
# Every CLI child has an exit deadline. A timeout kills that process tree.
param(
    [Parameter(Mandatory = $true)][string]$Rf
)
$ErrorActionPreference = 'Stop'

function Stop-Tree([int]$ProcessId) {
    & taskkill.exe /F /T /PID $ProcessId 2>$null | Out-Null
    Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
}

function Invoke-Bounded {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][int]$DeadlineMs,
        [Parameter(Mandatory = $true)][string]$StdoutPath,
        [Parameter(Mandatory = $true)][string]$StderrPath
    )
    $proc = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru -NoNewWindow `
        -RedirectStandardOutput $StdoutPath -RedirectStandardError $StderrPath
    try {
        if (-not $proc.WaitForExit($DeadlineMs)) {
            throw "child exceeded ${DeadlineMs}ms: $FilePath"
        }
        return $proc.ExitCode
    }
    finally {
        if (-not $proc.HasExited) {
            Stop-Tree $proc.Id
            $null = $proc.WaitForExit(5000)
        }
    }
}

$rf = (Resolve-Path $Rf).Path
$work = Join-Path $env:RUNNER_TEMP ("rf-smoke-" + [Guid]::NewGuid().ToString('N'))
$root = Join-Path $work 'data'
$socket = Join-Path $work 'rfd.sock'
New-Item -ItemType Directory -Force -Path $work | Out-Null

$marker = 'rf-smoke-stall-' + [Guid]::NewGuid().ToString('N')
$stallWatch = [Diagnostics.Stopwatch]::StartNew()
$stalled = $false
try {
    Invoke-Bounded -FilePath 'powershell.exe' `
        -ArgumentList @('-NoProfile', '-Command', "Start-Sleep -Seconds 300; Write-Output $marker") `
        -DeadlineMs 3000 `
        -StdoutPath (Join-Path $work 'stall.out') `
        -StderrPath (Join-Path $work 'stall.err') | Out-Null
}
catch {
    $stalled = $true
}
$stallWatch.Stop()
if (-not $stalled) { throw 'a stalled child was not refused' }
if ($stallWatch.ElapsedMilliseconds -gt 10000) {
    throw "stalled-child cleanup took $($stallWatch.ElapsedMilliseconds)ms"
}
$left = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" |
    Where-Object { $_.CommandLine -like "*$marker*" })
if ($left.Count -ne 0) { throw 'the stalled child was still running' }

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
        $code = Invoke-Bounded -FilePath $rf `
            -ArgumentList @('--socket', $socket, 'daemon', 'status') `
            -DeadlineMs 15000 `
            -StdoutPath (Join-Path $work 'status.out') `
            -StderrPath (Join-Path $work 'status.err')
        if ($code -eq 0) { $ready = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) {
        Show-DaemonLog
        throw 'the daemon did not answer a second process over the named pipe'
    }

    # The data root lock: a second daemon on the same root must refuse to start.
    $secondCode = Invoke-Bounded -FilePath $rf `
        -ArgumentList @('--socket', (Join-Path $work 'second.sock'), 'daemon', 'start', '--data-root', $root) `
        -DeadlineMs 20000 `
        -StdoutPath (Join-Path $work 'second.out') `
        -StderrPath (Join-Path $work 'second.err')
    if ($secondCode -eq 0) { throw 'a second daemon started on a data root in use' }

    # The data root and the name file belong to the user who runs the job.
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($path in @($root, $socket)) {
        $owner = (Get-Acl -LiteralPath $path).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        if ($owner -ne $me) { throw "$path is owned by $owner, not by $me" }
    }

    $stopCode = Invoke-Bounded -FilePath $rf `
        -ArgumentList @('--socket', $socket, 'daemon', 'stop') `
        -DeadlineMs 20000 `
        -StdoutPath (Join-Path $work 'stop.out') `
        -StderrPath (Join-Path $work 'stop.err')
    if ($stopCode -ne 0) { throw 'daemon stop failed' }
    if (-not $daemon.WaitForExit(15000)) { throw 'the daemon did not exit after stop' }
}
finally {
    if (-not $daemon.HasExited) {
        Stop-Tree $daemon.Id
        $null = $daemon.WaitForExit(5000)
    }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
Write-Output 'windows daemon smoke: ok'
