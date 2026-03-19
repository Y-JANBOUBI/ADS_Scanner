<#
.SYNOPSIS
    ADS Scanner - Efficiently scans for Alternate Data Streams.

.DESCRIPTION
    Recursively scans a target directory for files with ADS. Outputs details 
    to console and optionally to CSV. Includes progress tracking and a summary report.
#>

param(
    [Parameter(Mandatory=$false, Position=0)]
    [string]$Path,

    [Parameter(Mandatory=$false)]
    [string]$csv,

    [Parameter(Mandatory=$false)]
    [switch]$content,

    [Parameter(Mandatory=$false)]
    [ValidateSet("Table", "List")]
    [string]$format = "Table"
)


#region Help & usage
function Write-Usage {
    Write-Host @"
Usage: .\ADS_Scanner.ps1 -Path <path> [-Csv <path>] [-Content] [-Format <Table|List>]

Parameters:
  -Path        : The directory path to scan (required)
  -Csv         : Path to export results (optional)
                 - If directory: creates ADS_YYYYMMDD_HHMMSS.csv
                 - If file path: uses that filename
  -Content     : Read and preview ADS content (optional)
  -Format      : Output format - Table (default) or List (optional)

Examples:
  .\ADS_Scanner.ps1 -Path "C:\Temp" 
  .\ADS_Scanner.ps1 -Path "C:\Temp" -Content -Csv "C:\Reports"
  .\ADS_Scanner.ps1 -Path "C:\Temp" -Format List -Csv ".\results.csv"
"@ -ForegroundColor Yellow
}   

if ([string]::IsNullOrEmpty($Path)) {
    Write-Usage
    exit 1
}
#endregion



# 1. Validate Input Path
if (-not (Test-Path -Path $Path -PathType Container)) {
    Write-Error "The path '$Path' is invalid or not a directory."
    exit
}

# 2. Determine CSV Export Path
 $csvFilePath = $null
if ($csv) {
    if ([System.IO.Path]::HasExtension($csv)) {
        $csvFilePath = $csv
    }
    else {
        if (-not (Test-Path $csv)) {
            Write-Error "The output directory '$csv' does not exist."
            exit
        }
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $defaultFileName = "ADS_$timestamp.csv"
        $csvFilePath = Join-Path -Path $csv -ChildPath $defaultFileName
    }
    
    $parentDir = Split-Path $csvFilePath -Parent
    if ($parentDir -and -not (Test-Path $parentDir)) {
        Write-Error "The directory '$parentDir' for the CSV output does not exist."
        exit
    }
}

# 3. Initialize Counters and Timer
 $startTime = Get-Date
 $processedCount = 0
 $filesWithAdsCount = 0

Write-Host "Initializing scan on '$Path'..." -ForegroundColor Cyan

# 4. Pre-enumerate files for accurate Progress Bar
Write-Host "Enumerating files for progress tracking... (Please wait)" -ForegroundColor Gray
 $files = Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue
 $totalFiles = $files.Count

if ($totalFiles -eq 0) {
    Write-Warning "No files found to scan."
    exit
}

if ($csv) { Write-Host "CSV export enabled. Target: $csvFilePath" -ForegroundColor Yellow }
if ($content) { Write-Host "Content preview enabled (-content switch)." -ForegroundColor Yellow }

# 5. Process files
 $results = foreach ($file in $files) {
    $processedCount++

    # Update Progress every 100 files
    if ($processedCount % 100 -eq 0 -or $processedCount -eq $totalFiles) {
        $percentComplete = ($processedCount / $totalFiles) * 100
        Write-Progress -Activity "Scanning for ADS" `
                       -Status "Processed $processedCount of $totalFiles files" `
                       -PercentComplete $percentComplete `
                       -CurrentOperation $file.FullName
    }

    try {
        $streams = Get-Item -LiteralPath $file.FullName -Stream * -ErrorAction Stop
        $streamCount = $streams.Count
        
        if ($streamCount -gt 1) {
            $filesWithAdsCount++
            $adsList = $streams | Where-Object { $_.Stream -ne ':$DATA' }

            foreach ($ads in $adsList) {
                
                # --- Content Preview Logic ---
                $contentPreview = $null
                if ($content) {
                    $adsPath = "$($file.FullName):$($ads.Stream)"
                    try {
                        # Check for PE Header (MZ) - EXE/DLL
                        # We read the first 2 bytes.
                        if ($PSVersionTable.PSVersion.Major -ge 6) {
                            $bytes = Get-Content -LiteralPath $adsPath -AsByteStream -TotalCount 2 -ErrorAction Stop
                        } else {
                            $bytes = Get-Content -LiteralPath $adsPath -Encoding Byte -TotalCount 2 -ErrorAction Stop
                        }
                        
                        # MZ Header Check (0x4D = 'M', 0x5A = 'Z')
                        if ($bytes.Count -ge 2 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
                            $contentPreview = "[PE_FILE] MZ Header Detected (EXE/DLL)"
                        }
                        else {
                            # Not an EXE, try reading as Text
                            # Get-Content returns an array of lines. 
                            $textLines = Get-Content -LiteralPath $adsPath -ErrorAction Stop
                            if ($textLines) {
                                # FIX: Join lines with a space to ensure it exports to CSV as a single line.
                                # This formats ZoneTransfer data nicely: "[ZoneTransfer] ZoneId=3 ..."
                                $flatString = $textLines -join " "
                                
                                # Truncate if very long (optional, kept at 150 chars for readability)
                                if ($flatString.Length -gt 300) { 
                                    $contentPreview = $flatString.Substring(0, 300) + "..." 
                                } else { 
                                    $contentPreview = $flatString
                                }
                            }
                        }
                    }
                    catch {
                        $contentPreview = "[Error reading content]"
                    }
                }
                # -----------------------------

                # Create ordered dictionary to conditionally add properties
                $props = [ordered]@{
                    File_Name        = $file.Name
                    File_Path        = $file.FullName
                    Stream_Count     = $streamCount
                    Second_ADS_Name  = $ads.Stream
                    Stream_Size_b    = $ads.Length
                }

                if ($content) {
                    $props['Content_Preview'] = $contentPreview
                }

                # Output the object
                [PSCustomObject]$props
            }
        }
    }
    catch {
        # Silent handling for Access Denied/Locked files
    }
}

# 6. Finalize Timer
 $endTime = Get-Date
 $duration = $endTime - $startTime

Write-Progress -Activity "Scanning for ADS" -Completed

# 7. Always Output Results to Console (Using chosen Format)
if ($results) {
    Write-Host "`n[+] FILES WITH ALTERNATE DATA STREAMS FOUND:" -ForegroundColor Green
    
    # Apply formatting based on -format parameter
    switch ($format) {
        "List" { 
            $results | Format-List 
        }
        Default { 
            $results | Format-Table -AutoSize 
        }
    }
} else {
    Write-Host "`nNo Alternate Data Streams found." -ForegroundColor Yellow
}

# 8. Handle CSV Export (if enabled)
if ($csvFilePath) {
    try {
        if ($results) {
            $results | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        }
        else {
            # Create empty CSV with headers (dynamically match columns)
            $emptyHash = [ordered]@{
                File_Name       = $null
                File_Path       = $null
                Stream_Count    = $null
                Second_ADS_Name = $null
                Stream_Size_b   = $null
            }
            if ($content) { $emptyHash['Content_Preview'] = $null }
            
            [PSCustomObject]$emptyHash | Export-Csv -Path $csvFilePath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        }
    }
    catch {
        Write-Error "Failed to write to CSV: $_"
    }
}

# 9. Summary Section
Write-Host "[+] SCAN RESULT SUMMARY:" -ForegroundColor Green
Write-Host "------------------------------------------------------------"
Write-Host "Start Time           : $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "End Time             : $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "Time Spent           : $($duration.ToString('hh\:mm\:ss\.ff'))"
Write-Host "Total Files Scanned  : $totalFiles"
Write-Host "Files with ADS Found : $filesWithAdsCount"

if ($csvFilePath) {
    Write-Host "CSV Result File Path : '$csvFilePath'"
} else {
    Write-Host "CSV Export           : Disabled (use -csv parameter to enable)"
}