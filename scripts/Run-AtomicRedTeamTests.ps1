<#
.SYNOPSIS
    Safe Mock Atomic Red Team Validation Harness for ATT&CK Coverage Mapper
.DESCRIPTION
    This is a SAFE MOCK harness that simulates Atomic Red Team test results WITHOUT
    executing any dangerous payloads. It pulls the 22 detectable technique IDs from the
    ATT&CK Coverage Mapper database, skips the actual shell execution entirely, and
    generates a simulated validation log file (JSON format) that the Streamlit dashboard
    can read for project documentation.

    This script is designed for documentation/CI purposes ONLY. It does NOT:
    - Clone or execute Atomic Red Team tests
    - Run any adversarial commands on the host
    - Require atomic-operator or atomic-red-team to be installed

.NOTES
    Author: ATT&CK Coverage Mapper Project
    Run as: PowerShell 5.1+ or PowerShell 7+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ProjectRoot = "D:\DAV project\attack-coverage-mapper",

    [Parameter(Mandatory=$false)]
    [string]$PythonExe = ".\.venv\Scripts\python.exe",

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\atomic-test-results",

    [Parameter(Mandatory=$false)]
    [string]$ConfigPath = "config.yaml",

    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "HighConfidence", "MediumConfidence")]
    [string]$Mode = "All"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

function Write-Log {
    param([string] $Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = "[$timestamp] [$Level]"
    Write-Host "$prefix $Message"
}

function Get-DetectableTechniquesFromDB {
    param(
        [string]$ProjectRoot,
        [string]$PythonExe,
        [string]$ConfigPath
    )

    Write-Log "Querying detectable techniques from database..."

    $pythonScript = @"
import sys
sys.path.insert(0, 'src')
from config_loader import load_config
from database.session import session_scope
from analysis.coverage_analyzer import load_coverage_rows

with session_scope() as s:
    config = load_config('$ConfigPath')
    rows = load_coverage_rows(s, config)
    detectable = [r for r in rows if r.is_detectable and r.scope_hit]
    seen = set()
    for r in detectable:
        if r.attack_id not in seen:
            seen.add(r.attack_id)
            print(f'{r.attack_id}|{r.name}|{r.best_confidence:.6f}')
"@

    $result = & $PythonExe -c $pythonScript
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to query database for detectable techniques"
        exit 1
    }

    $techniques = @()
    foreach ($line in $result) {
        if ($line -match '^(.+)\|(.+)\|([\d.]+)$') {
            $techniques += @{
                Id = $matches[1]
                Name = $matches[2]
                Confidence = [double]$matches[3]
            }
        }
    }

    return $techniques
}

# ─────────────────────────────────────────────────────────────────────────────
# GET DETECTABLE TECHNIQUES FROM DATABASE
# ─────────────────────────────────────────────────────────────────────────────

Set-Location $ProjectRoot

Write-Log "=== Safe Mock Atomic Red Team Validation Started ==="
Write-Log "Project: $ProjectRoot"
Write-Log "Mode: $Mode"
Write-Log "Output: $OutputPath"

$DetectableTechniques = Get-DetectableTechniquesFromDB -ProjectRoot $ProjectRoot -PythonExe $PythonExe -ConfigPath $ConfigPath

if ($DetectableTechniques.Count -eq 0) {
    Write-Error "No detectable techniques found in database. Run populate_db.py first."
    exit 1
}

Write-Log "Found $($DetectableTechniques.Count) detectable techniques in database"

# Filter based on mode
switch ($Mode) {
    "HighConfidence" {
        $Techniques = $DetectableTechniques | Where-Object { $_.Confidence -ge 0.85 }
    }
    "MediumConfidence" {
        $Techniques = $DetectableTechniques | Where-Object { $_.Confidence -ge 0.70 -and $_.Confidence -lt 0.85 }
    }
    "All" {
        $Techniques = $DetectableTechniques
    }
    default {
        $Techniques = $DetectableTechniques
    }
}

Write-Log "Selected $($Techniques.Count) techniques for mock validation ($Mode mode)"
if ($Verbose) {
    $Techniques | ForEach-Object { Write-Host "  $($_.Id): $($_.Name) (conf=$($_.Confidence))" }
}

# ─────────────────────────────────────────────────────────────────────────────
# GENERATE MOCK VALIDATION RESULTS
# ─────────────────────────────────────────────────────────────────────────────

$ResultsArray = @()
$StartTime = Get-Date

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$SummaryFile = Join-Path $OutputPath "mock-validation-summary-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$DetailFile = Join-Path $OutputPath "mock-validation-details-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"

# CSV Header
"TechniqueId,TechniqueName,Confidence,MockStatus,MockExitCode,MockDurationSeconds,MockOutputFile,MockNotes" | Out-File $SummaryFile -Encoding UTF8

# Simulate validation for each technique
foreach ($Tech in $Techniques) {
    $techId = $Tech.Id
    $techName = $Tech.Name
    $confidence = $Tech.Confidence

    Write-Log "Mock validating ${techId}: ${techName} (conf=${confidence})"

    $testStart = Get-Date

    # Simulate a small processing delay (realistic mock)
    Start-Sleep -Milliseconds (Get-Random -Minimum 10 -Maximum 50)

    $duration = (Get-Date) - $testStart
    $durationSec = [math]::Round($duration.TotalSeconds, 3)

    # Mock result: techniques with confidence >= 0.75 get "DETECTED", others "PARTIAL"
    # This simulates the reality that higher-confidence mappings have better detection coverage
    if ($confidence -ge 0.85) {
        $status = "DETECTED"
        $exitCode = 0
        $notes = "High confidence mapping - strong detection coverage expected"
    }
    elseif ($confidence -ge 0.75) {
        $status = "DETECTED"
        $exitCode = 0
        $notes = "Good confidence mapping - detection coverage expected"
    }
    elseif ($confidence -ge 0.70) {
        $status = "PARTIAL"
        $exitCode = 0
        $notes = "Medium confidence mapping - partial detection coverage"
    }
    else {
        $status = "PARTIAL"
        $exitCode = 0
        $notes = "Lower confidence mapping - limited detection coverage"
    }

    $color = if ($status -eq "DETECTED") { "Green" } else { "Yellow" }
    Write-Host "  $status (mock, ${durationSec}s)" -ForegroundColor $color

    $result = @{
        TechniqueId     = $techId
        TechniqueName   = $techName
        Confidence      = $confidence
        MockStatus      = $status
        MockExitCode    = $exitCode
        MockDurationSeconds = $durationSec
        MockOutputFile  = ""
        MockNotes       = $notes
    }

    $ResultsArray += $result

    # Append to CSV
    $escapedNotes = $notes -replace '"', '""' -replace "`r", "" -replace "`n", " "
    $csvLine = $techId + "," + $techName + "," + $confidence + "," + $status + "," + $exitCode + "," + $durationSec + ",," + "`"" + $escapedNotes + "`""
    $csvLine | Out-File $SummaryFile -Encoding UTF8 -Append
}

$EndTime = Get-Date
$TotalDuration = $EndTime - $StartTime

# ─────────────────────────────────────────────────────────────────────────────
# GENERATE REPORTS
# ─────────────────────────────────────────────────────────────────────────────

Write-Log "=== Generating Mock Validation Reports ==="

$detected = ($ResultsArray | Where-Object { $_.MockStatus -eq "DETECTED" }).Count
$partial = ($ResultsArray | Where-Object { $_.MockStatus -eq "PARTIAL" }).Count

# Write detailed JSON
$report = @{
    RunInfo = @{
        Timestamp         = $StartTime.ToString("o")
        EndTime           = $EndTime.ToString("o")
        TotalDurationSec  = [math]::Round($TotalDuration.TotalSeconds, 2)
        Mode              = $Mode
        TotalTechniques   = $Techniques.Count
        ProjectRoot       = $ProjectRoot
        ConfigPath        = $ConfigPath
        IsMockValidation  = $true
        Disclaimer        = "This is a MOCK validation for documentation purposes only. No actual Atomic Red Team tests were executed."
    }
    Summary = @{
        Total           = $Techniques.Count
        Detected        = $detected
        Partial         = $partial
        DetectionRate   = if ($Techniques.Count -gt 0) { [math]::Round(($detected / $Techniques.Count) * 100, 1) } else { 0 }
    }
    Results = $ResultsArray
}

$report | ConvertTo-Json -Depth 10 | Out-File $DetailFile -Encoding UTF8

# Print summary
Write-Host "`n=== MOCK VALIDATION SUMMARY ===" -ForegroundColor Green
Write-Host "Total Techniques: $($Techniques.Count)"
Write-Host "  Detected (High Confidence): $detected" -ForegroundColor Green
Write-Host "  Partial (Medium/Low Conf):  $partial" -ForegroundColor Yellow
Write-Host "Detection Rate: $([math]::Round(($detected / $Techniques.Count) * 100, 1))%"
Write-Host "Total Duration: $([math]::Round($TotalDuration.TotalSeconds, 1))s"
Write-Host "`nReports saved to:"
Write-Host "  Summary CSV: $SummaryFile"
Write-Host "  Detail JSON: $DetailFile"
Write-Host ""
Write-Host "⚠  IMPORTANT: This is a MOCK validation for documentation purposes only." -ForegroundColor Yellow
Write-Host "   No actual Atomic Red Team tests were executed." -ForegroundColor Yellow
Write-Host "   For real validation, run atomic-operator in a controlled sandbox environment." -ForegroundColor Yellow

# Exit successfully
exit 0