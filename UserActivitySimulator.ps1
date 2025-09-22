<#
.SYNOPSIS
  Simulate benign user activity on Windows (fast run for every-15-min schedule):
  - bounded file I/O with timeouts + heartbeats
  - simple HTTP + DNS
  - optional short-lived GUI app launches (off by default)
  - auto-rotation + cleanup to avoid growth

.NOTES
  Adjust the configuration block as needed. Defaults target a ~tens-of-seconds run.
#>

#region Configuration (quick-run defaults)
# Base temp for all activity
$TempBase = Join-Path -Path $env:TEMP -ChildPath "UserActivitySimulator"

# I/O budget (kept small for quick runs)
$MaxCreateMB       = 20      # total bytes to create this run (approx)
$MaxFileKB         = 512     # max single-file size (~0.5 MB)
$TargetFileCount   = 40      # upper bound; capped by $MaxCreateMB

# Network checks (short timeouts)
$HttpEndpoints     = @("https://example.com/","https://www.bing.com/")
$DnsNames          = @("example.com","microsoft.com")
$HttpTimeoutSec    = 6

# Optional GUI app launches (disabled for headless Task Scheduler runs)
$LaunchGuiApps     = $false
$GuiApps           = @("notepad.exe","calc.exe")
$GuiAppRuntimeSec  = 5

# Logging and retention
$LogPath           = Join-Path -Path $TempBase -ChildPath "logs"
$LogRetentionDays  = 3
$SimFolderRetentionDays = 1

# Hard run cap (guards against unexpected stalls)
$MaxRunSeconds     = 240     # 4 minutes
#endregion

#region Helpers
function Write-Log {
    param([Parameter(Mandatory)][string]$Message,[string]$Level="INFO")
    $t = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "$t [$Level] $Message"
    $logfile = Join-Path $LogPath "simulator.log"
    $null = New-Item -ItemType Directory -Path $LogPath -Force
    Add-Content -Path $logfile -Value $line
    Write-Output $line
}

function Get-RandomBytesFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][long]$SizeBytes,
        [int]$TimeoutSec = 20,     # per-file timeout
        [int]$ChunkSize  = 65536,  # 64 KiB
        [int]$HeartbeatSec = 3
    )
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buffer = New-Object byte[] $ChunkSize
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $nextBeat = (Get-Date).AddSeconds($HeartbeatSec)
    $remaining = [long]$SizeBytes
    $written = 0L

    $fs = [System.IO.File]::Open($Path,[System.IO.FileMode]::Create,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
    try {
        while ($remaining -gt 0) {
            if ((Get-Date) -gt $deadline) { throw "Per-file timeout after $TimeoutSec s writing $Path (wrote $written of $SizeBytes bytes)" }
            $chunk = [Math]::Min($buffer.Length, $remaining)
            if ($chunk -ne $buffer.Length) { $buffer = New-Object byte[] $chunk } # shrink for last chunk
            $rng.GetBytes($buffer)
            $fs.Write($buffer,0,$chunk)
            $remaining -= $chunk
            $written   += $chunk

            if ((Get-Date) -gt $nextBeat) {
                Write-Log "…writing ${Path}: $([math]::Round($written/1KB,0)) / $([math]::Round($SizeBytes/1KB,0)) KB"
                $nextBeat = (Get-Date).AddSeconds($HeartbeatSec)
            }
        }
    } finally {
        $fs.Close()
        $rng.Dispose()
    }
}

function Safe-RemoveFolderIfEmpty {
    param([Parameter(Mandatory)][string]$dir)
    if (Test-Path $dir) {
        try {
            $items = Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue
            if (-not $items) { Remove-Item -LiteralPath $dir -Force -Recurse -ErrorAction SilentlyContinue }
        } catch { }
    }
}
#endregion

#region Start
$runStart   = Get-Date
$runDeadline= $runStart.AddSeconds($MaxRunSeconds)
New-Item -Path $TempBase -ItemType Directory -Force | Out-Null
Write-Log "Starting simulation run in $TempBase"

$ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
$RunFolder = Join-Path $TempBase ("run_$ts")
New-Item -Path $RunFolder -ItemType Directory -Force | Out-Null
Write-Log "Run folder: $RunFolder"
#endregion

#region File creation (bounded + fast)
$maxBytes       = [math]::Floor($MaxCreateMB * 1KB * 1KB)
$createdBytes   = 0L
$createdFiles   = 0
$maxFileBytes   = [math]::Floor($MaxFileKB * 1KB)

for ($i = 1; $i -le $TargetFileCount; $i++) {
    if ((Get-Date) -gt $runDeadline) { Write-Log "Runtime cap reached during file creation"; break }
    $remainingBytes = $maxBytes - $createdBytes
    if ($remainingBytes -le 1024) { break }

    $maxThis = [math]::Min($maxFileBytes, $remainingBytes)
    $size    = Get-Random -Minimum 8192 -Maximum ($maxThis + 1)  # min 8KB
    $fname   = "doc_$([System.Guid]::NewGuid().ToString('N').Substring(0,8)).bin"
    $fpath   = Join-Path $RunFolder $fname

    try {
        Get-RandomBytesFile -Path $fpath -SizeBytes $size -TimeoutSec 20
        $len = (Get-Item $fpath).Length
        $createdBytes += $len
        $createdFiles++
        Write-Log "Created file $fname size $([math]::Round($len/1KB,2)) KB"
        Start-Sleep -Milliseconds (Get-Random -Minimum 30 -Maximum 120)
    } catch {
        Write-Log "Error creating ${fpath} : $_" "WARN"
        # best-effort cleanup of partial file
        try { if (Test-Path $fpath) { Remove-Item -LiteralPath $fpath -Force -ErrorAction SilentlyContinue } } catch {}
    }
}
Write-Log "File creation done. Files=$createdFiles, Bytes=$createdBytes"
#endregion

#region Quick edit/rename pass
$files = Get-ChildItem -Path $RunFolder -File -ErrorAction SilentlyContinue
if ($files) {
    $sample = $files | Get-Random -Count ([math]::Min($files.Count, [int]([math]::Max(6,[math]::Ceiling($files.Count*0.3)))))  # ~30% up to min 6
    foreach ($f in $sample) {
        if ((Get-Date) -gt $runDeadline) { Write-Log "Runtime cap reached during file ops"; break }
        try {
            $null = Get-Content -Path $f.FullName -TotalCount 1 -ErrorAction SilentlyContinue
            Add-Content -Path $f.FullName -Value "Edited by UserActivitySimulator at $((Get-Date).ToString())"
            if ((Get-Random -Minimum 0 -Maximum 100) -lt 15) {
                $newName = "ren_$($f.BaseName)_$([System.Guid]::NewGuid().ToString('N').Substring(0,6))$($f.Extension)"
                Rename-Item -Path $f.FullName -NewName $newName -ErrorAction SilentlyContinue
                Write-Log "Renamed $($f.Name) -> $newName"
            } else {
                Write-Log "Edited $($f.Name)"
            }
            Start-Sleep -Milliseconds (Get-Random -Minimum 40 -Maximum 160)
        } catch {
            Write-Log "File op error on $($f.Name): $_" "WARN"
        }
    }
}
#endregion

#region Network (short timeouts)
foreach ($url in $HttpEndpoints) {
    if ((Get-Date) -gt $runDeadline) { Write-Log "Runtime cap reached during HTTP"; break }
    try {
        $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec $HttpTimeoutSec -ErrorAction Stop
        Write-Log "HTTP GET $url => $($resp.StatusCode) (len $($resp.Content.Length))"
        $tmpSnap = Join-Path $RunFolder ("snap_" + ([System.Guid]::NewGuid().ToString('N').Substring(0,6)) + ".html")
        $resp.Content | Out-File -FilePath $tmpSnap -Encoding utf8
        Remove-Item -Path $tmpSnap -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Log "HTTP failed for $url : $_" "WARN"
    }
}

foreach ($name in $DnsNames) {
    if ((Get-Date) -gt $runDeadline) { break }
    try {
        # Resolve-DnsName has no timeout; this is usually instant. If it occasionally stalls, it's caught by $MaxRunSeconds.
        $r = Resolve-DnsName -Name $name -ErrorAction Stop
        $ips = ($r | Where-Object { $_.IPAddress } | Select-Object -First 3 | ForEach-Object { $_.IPAddress }) -join ","
        Write-Log "DNS $name => $ips"
    } catch {
        Write-Log "DNS failed $name : $_" "WARN"
    }
}
#endregion

#region Optional GUI activity (disabled by default)
if ($LaunchGuiApps) {
    foreach ($app in $GuiApps) {
        if ((Get-Date) -gt $runDeadline) { Write-Log "Runtime cap during GUI apps"; break }
        try {
            $p = Start-Process -FilePath $app -PassThru -ErrorAction SilentlyContinue
            if ($p) {
                Write-Log "Launched $app (PID $($p.Id))"
                Start-Sleep -Seconds $GuiAppRuntimeSec
                try { $p.CloseMainWindow() | Out-Null; Start-Sleep -Milliseconds 500 } catch {}
                try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
                Write-Log "Closed $app (PID $($p.Id))"
            } else {
                Write-Log "Failed to launch $app (no process)" "WARN"
            }
        } catch {
            Write-Log "Error launching ${app}: $_" "WARN"
        }
    }
}
#endregion

#region Cleanup to avoid growth
try {
    $allFiles = Get-ChildItem -Path $RunFolder -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime
    if ($allFiles) {
        $keepRatio = 0.6 # keep 60%
        $keepCount = [math]::Ceiling($allFiles.Count * $keepRatio)
        $toDelete  = $allFiles | Select-Object -First ($allFiles.Count - $keepCount)
        foreach ($d in $toDelete) {
            try {
                Remove-Item -LiteralPath $d.FullName -Force -ErrorAction SilentlyContinue
                Write-Log "Deleted temp file $($d.Name)"
            } catch {
                Write-Log "Delete failed $($d.Name): $_" "WARN"
            }
        }
    }
} catch {
    Write-Log "Cleanup error: $_" "WARN"
}
#endregion

#region Sweep old runs + rotate logs
try {
    $cutoff = (Get-Date).AddDays(-$SimFolderRetentionDays)
    Get-ChildItem -Path $TempBase -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -like "run_*" -and $_.CreationTime -lt $cutoff } |
      ForEach-Object {
          try {
              Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
              Write-Log "Removed old run folder: $($_.FullName)"
          } catch {
              Write-Log "Failed removing old run folder $($_.FullName): $_" "WARN"
          }
      }

    Get-ChildItem -Path $LogPath -File -ErrorAction SilentlyContinue |
      Where-Object { $_.CreationTime -lt (Get-Date).AddDays(-$LogRetentionDays) } |
      ForEach-Object {
          try {
              Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
              Write-Log "Rotated old log $($_.Name)"
          } catch {
              Write-Log "Log rotate failed $($_.Name): $_" "WARN"
          }
      }
} catch {
    Write-Log "Sweep error: $_" "WARN"
}
#endregion

#region Final tidy
try {
    $remaining = Get-ChildItem -Path $RunFolder -Force -ErrorAction SilentlyContinue
    if (-not $remaining) {
        Remove-Item -LiteralPath $RunFolder -Force -Recurse -ErrorAction SilentlyContinue
        Write-Log "Removed empty run folder $RunFolder"
    } else {
        Write-Log "Leaving run folder $RunFolder with $($remaining.Count) items"
    }
} catch {
    Write-Log "Final tidy error: $_" "WARN"
}
#endregion

# Done
$elapsedSec = [math]::Round(((Get-Date) - $runStart).TotalSeconds, 2)
Write-Log "Simulation run completed in $elapsedSec sec"
