<#
.SYNOPSIS
  Simulate user activity on Windows: file IO, simple network calls, process launches, directory listing.
.DESCRIPTION
  Intended to be run periodically (e.g., every 15 minutes via Task Scheduler).
  All created files/folders are kept under a single base temp folder and are cleaned up.
.PARAMETER None - configure via the variables in the Configuration section.
#>

#region Configuration - edit as needed
# Base location to create temp simulation data (defaults to user TEMP)
$TempBase = Join-Path -Path $env:TEMP -ChildPath "UserActivitySimulator"

# Maximum total disk usage (MB) this run should create (script will not exceed this)
$MaxCreateMB = 150          # e.g., 150 MB

# Maximum size of any single file created (KB)
$MaxFileKB = 5120           # 5 MB per file

# Approx number of files to try to create (script will cap based on MaxCreateMB)
$TargetFileCount = 60

# Endpoints for simple HTTP checks (change to trusted, internal endpoints if desired)
$HttpEndpoints = @("https://example.com/", "https://www.bing.com/")

# DNS names to resolve (safe)
$DnsNames = @("example.com", "microsoft.com")

# Processes to briefly open to simulate user activity. If you prefer headless only, set $LaunchGuiApps = $false
$LaunchGuiApps = $true
$GuiApps = @("notepad.exe", "calc.exe")

# How long (seconds) to keep a launched GUI app running before closing it
$GuiAppRuntimeSec = 6

# Path for log files
$LogPath = Join-Path -Path $TempBase -ChildPath "logs"
# Rotate logs older than N days
$LogRetentionDays = 3

# Clean up simulation folders older than this (days)
$SimFolderRetentionDays = 1

# Run duration guard (optional) - max seconds this script will run
$MaxRunSeconds = 600   # 10 minutes
#endregion

#region Helper Functions
function Write-Log {
    param($Message, $Level = "INFO")
    $t = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "$t [$Level] $Message"
    $logfile = Join-Path $LogPath "simulator.log"
    $null = New-Item -ItemType Directory -Path $LogPath -Force
    Add-Content -Path $logfile -Value $line
    Write-Output $line
}

function Get-RandomBytesFile {
    param($Path, $SizeBytes)
    # Create a file with random bytes up to SizeBytes. Uses .NET crypto RNG for quality and speed.
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bufferSize = 65536  # 64 KiB chunk
    $buffer = New-Object byte[] $bufferSize
    $remaining = $SizeBytes
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        while ($remaining -gt 0) {
            $chunk = [Math]::Min($buffer.Length, $remaining)
            if ($chunk -ne $buffer.Length) {
                $tmp = New-Object byte[] $chunk
                $rng.GetBytes($tmp)
                $fs.Write($tmp, 0, $chunk)
            } else {
                $rng.GetBytes($buffer)
                $fs.Write($buffer, 0, $chunk)
            }
            $remaining -= $chunk
        }
    } finally {
        $fs.Close()
        $rng.Dispose()
    }
}

function Safe-RemoveFolderIfEmpty {
    param($dir)
    if (Test-Path $dir) {
        try {
            $items = Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue
            if (-not $items) {
                Remove-Item -LiteralPath $dir -Force -Recurse -ErrorAction SilentlyContinue
            }
        } catch {
            # ignore
        }
    }
}
#endregion

#region Start run
$runStart = Get-Date
$runDeadline = $runStart.AddSeconds($MaxRunSeconds)
New-Item -Path $TempBase -ItemType Directory -Force | Out-Null
Write-Log "Starting simulation run in $TempBase"

# Create a timestamped run folder
$ts = (Get-Date).ToString("yyyyMMdd_HHmmss")
$RunFolder = Join-Path $TempBase ("run_$ts")
New-Item -Path $RunFolder -ItemType Directory -Force | Out-Null
Write-Log "Run folder: $RunFolder"
#endregion

#region File creation (bounded)
# Compute approximate bytes allowed
$maxBytes = [math]::Floor($MaxCreateMB * 1KB * 1KB)  # MB -> bytes
$createdBytes = 0
$createdFiles = 0

# Determine max file size in bytes
$maxFileBytes = [math]::Floor($MaxFileKB * 1KB)

for ($i = 1; $i -le $TargetFileCount; $i++) {
    if ((Get-Date) -gt $runDeadline) { Write-Log "Reached runtime deadline during file creation"; break }
    $remainingBytes = $maxBytes - $createdBytes
    if ($remainingBytes -le 1024) { break }

    # choose a file size: random between 1KB and min(maxFileBytes, remainingBytes)
    $maxThis = [math]::Min($maxFileBytes, $remainingBytes)
    $size = Get-Random -Minimum 1024 -Maximum ($maxThis + 1)
    $fname = "doc_$i_$([System.Guid]::NewGuid().ToString('N').Substring(0,8)).bin"
    $fpath = Join-Path $RunFolder $fname

    try {
        Get-RandomBytesFile -Path $fpath -SizeBytes $size
        $createdBytes += (Get-Item $fpath).Length
        $createdFiles++
        Write-Log "Created file $fname size $([math]::Round((Get-Item $fpath).Length/1KB,2)) KB"
        Start-Sleep -Milliseconds (Get-Random -Minimum 50 -Maximum 200)
    } catch {
        Write-Log "Error creating $fpath : $_" "WARN"
    }
}
Write-Log "File creation done. Files created: $createdFiles. Bytes created: $createdBytes"
#endregion

#region File read/modify / simulate user editing
# Read random files, append a small line, rename some
$files = Get-ChildItem -Path $RunFolder -File -ErrorAction SilentlyContinue
if ($files) {
    $shuffle = $files | Get-Random -Count ([math]::Min($files.Count, 20))
    foreach ($f in $shuffle) {
        if ((Get-Date) -gt $runDeadline) { Write-Log "Reached runtime deadline during file ops"; break }
        try {
            # read small chunk (may fail on binary; that's OK)
            $null = Get-Content -Path $f.FullName -TotalCount 2 -ErrorAction SilentlyContinue
            # append a tiny metadata line
            Add-Content -Path $f.FullName -Value "Edited by UserActivitySimulator at $((Get-Date).ToString())"
            Write-Log "Read & appended to $($f.Name)"
            # rename occasionally
            if ((Get-Random -Minimum 0 -Maximum 100) -lt 12) {
                $newName = "ren_$($f.BaseName)_$([System.Guid]::NewGuid().ToString('N').Substring(0,6))$($f.Extension)"
                Rename-Item -Path $f.FullName -NewName $newName -ErrorAction SilentlyContinue
                Write-Log "Renamed $($f.Name) -> $newName"
            }
            Start-Sleep -Milliseconds (Get-Random -Minimum 80 -Maximum 400)
        } catch {
            Write-Log "File op error on $($f.Name): $_" "WARN"
        }
    }
}
#endregion

#region Network interactions (HTTP + DNS + small downloads)
foreach ($url in $HttpEndpoints) {
    if ((Get-Date) -gt $runDeadline) { Write-Log "Reached runtime deadline during network ops"; break }
    try {
        $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 12 -ErrorAction Stop
        Write-Log "HTTP GET $url => $($resp.StatusCode) (len $($resp.Content.Length))"
        # save a tiny snapshot then delete it to simulate download+cleanup
        $tmpSnap = Join-Path $RunFolder ("snap_" + ([System.Guid]::NewGuid().ToString('N').Substring(0,6)) + ".html")
        $resp.Content | Out-File -FilePath $tmpSnap -Encoding utf8
        Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 300)
        Remove-Item -Path $tmpSnap -Force -ErrorAction SilentlyContinue
        Write-Log "Downloaded+deleted snapshot for $url"
    } catch {
        Write-Log "HTTP check failed for $url : $_" "WARN"
    }
}

foreach ($name in $DnsNames) {
    if ((Get-Date) -gt $runDeadline) { break }
    try {
        $r = Resolve-DnsName -Name $name -ErrorAction Stop
        $ips = ($r | Where-Object { $_.IPAddress } | Select-Object -First 3 | ForEach-Object { $_.IPAddress }) -join ","
        Write-Log "DNS resolve $name => $ips"
    } catch {
        Write-Log "DNS resolve failed $name : $_" "WARN"
    }
}
#endregion

#region Process launches to simulate interactive apps (optional)
if ($LaunchGuiApps) {
    foreach ($app in $GuiApps) {
        if ((Get-Date) -gt $runDeadline) { Write-Log "Reached runtime deadline during GUI app ops"; break }
        try {
            $p = Start-Process -FilePath $app -PassThru -ErrorAction SilentlyContinue
            if ($p) {
                Write-Log "Launched $app (PID $($p.Id)). Will close in $GuiAppRuntimeSec s"
                Start-Sleep -Seconds $GuiAppRuntimeSec
                try { $p.CloseMainWindow() | Out-Null; Start-Sleep -Seconds 1 } catch {}
                try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
                Write-Log "Closed $app (PID $($p.Id))"
            } else {
                Write-Log "Failed to launch $app (Start-Process returned nothing)" "WARN"
            }
        } catch {
            # FIXED: brace variable to avoid "$app:" parse issue
            Write-Log "Error launching ${app}: $_" "WARN"
        }
        Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 800)
    }
}
#endregion

#region Cleanup - delete a portion of created files to simulate tidy-up and avoid growth
try {
    $allFiles = Get-ChildItem -Path $RunFolder -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime
    if ($allFiles) {
        # delete older half of files (or keep at most 40%)
        $keepRatio = 0.6
        $keepCount = [math]::Ceiling($allFiles.Count * $keepRatio)
        $toDelete = $allFiles | Select-Object -First ($allFiles.Count - $keepCount)
        foreach ($d in $toDelete) {
            try {
                Remove-Item -LiteralPath $d.FullName -Force -ErrorAction SilentlyContinue
                Write-Log "Deleted temp file $($d.Name) during cleanup"
            } catch {
                Write-Log "Failed to delete $($d.Name): $_" "WARN"
            }
        }
    }
} catch {
    Write-Log "Cleanup error: $_" "WARN"
}
#endregion

#region Sweep old runs and rotate logs
try {
    # Sweep run folders older than retention
    $cutoff = (Get-Date).AddDays(-$SimFolderRetentionDays)
    Get-ChildItem -Path $TempBase -Directory -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like "run_*" -and $_.CreationTime -lt $cutoff
    } | ForEach-Object {
        try {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Removed old run folder: $($_.FullName)"
        } catch {
            Write-Log "Failed to remove old run folder $($_.FullName): $_" "WARN"
        }
    }

    # Rotate logs: remove logs older than retention
    Get-ChildItem -Path $LogPath -File -ErrorAction SilentlyContinue | Where-Object {
        $_.CreationTime -lt (Get-Date).AddDays(-$LogRetentionDays)
    } | ForEach-Object {
        try {
            Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
            Write-Log "Rotated old log $($_.Name)"
        } catch {
            Write-Log "Failed to rotate log $($_.Name): $_" "WARN"
        }
    }
} catch {
    Write-Log "Sweep error: $_" "WARN"
}
#endregion

#region Final tidy: if run folder is tiny or empty, remove it
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

# FIXED: ensure the timespan is expanded inside the string
$elapsedSec = [math]::Round(((Get-Date) - $runStart).TotalSeconds, 2)
Write-Log "Simulation run completed in $elapsedSec sec"
