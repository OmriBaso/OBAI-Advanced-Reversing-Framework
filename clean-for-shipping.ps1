<#
.SYNOPSIS
    Clean the OBAI Reverse Engineering Platform for shipping (hand-off to a friend
    or pushing to GitHub). Removes user data + build artifacts and sanitizes secrets.
    The bundled Ghidra install is KEPT on disk (you need it to run) but is gitignored,
    so it is not pushed to GitHub - recipients download Ghidra themselves.

.DESCRIPTION
    Cleared (folder kept, contents wiped, .gitkeep added):
        uploads, analysis_db, ghidra_projects, symbol_cache, symbols, libraries
    Deleted (regenerated automatically):
        every __pycache__ , *.pyc , agent/bin , agent/obj , agent/.vs ,
        frontend/node_modules (unless -KeepNodeModules) , static/dist (unless -KeepBuiltFrontend)
    Sanitized:
        re_config.json  -> API keys blanked (models kept). re_config.example.json written.
    Samples removed unless -KeepSamples:
        Base, Base.zip, hman.dll
    Always kept on disk (ghidra_12.0_PUBLIC is gitignored, not pushed to GitHub):
        ghidra_12.0_PUBLIC , ghidra_scripts , all source

.PARAMETER DryRun
    Show what WOULD be removed/changed. Touches nothing.

.PARAMETER Force
    Skip the confirmation prompt.

.PARAMETER KeepSamples
    Keep the sample binaries (Base, Base.zip, hman.dll).

.PARAMETER KeepBuiltFrontend
    Keep static/dist (the built React app). Default removes it; rebuild with 'npm run build'.

.PARAMETER KeepNodeModules
    Keep frontend/node_modules. Default removes it; restore with 'npm install'.

.PARAMETER NoGitignore
    Do not write/overwrite .gitignore.

.EXAMPLE
    .\clean-for-shipping.ps1 -DryRun
    Preview everything that would be cleaned.

.EXAMPLE
    .\clean-for-shipping.ps1
    Clean in place (prompts once before deleting).
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Force,
    [switch]$KeepSamples,
    [switch]$KeepBuiltFrontend,
    [switch]$KeepNodeModules,
    [switch]$NoGitignore
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

# --- Safety: make sure we are in the OBAI repo root ---
$markers = @("run.py", "app", "setup.py")
foreach ($m in $markers) {
    if (-not (Test-Path (Join-Path $root $m))) {
        Write-Host "ERROR: '$m' not found in $root - this does not look like the OBAI repo root. Aborting." -ForegroundColor Red
        exit 1
    }
}

function Get-SizeMB($path) {
    if (-not (Test-Path $path)) { return 0 }
    try {
        $sum = (Get-ChildItem $path -Recurse -Force -File -ErrorAction SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
    } catch { $sum = 0 }
    if ($null -eq $sum) { return 0 }
    return [math]::Round($sum / 1MB, 1)
}

$script:Freed = 0.0
function Report($label, $path) {
    $mb = Get-SizeMB $path
    $script:Freed += $mb
    $verb = "cleaned"
    if ($DryRun) { $verb = "would clean" }
    Write-Host ("  {0,-44} {1,8:N1} MB  ({2})" -f $label, $mb, $verb) -ForegroundColor Gray
}

function Clear-DirContents($dir, $label) {
    Report $label $dir
    if ($DryRun) { return }
    if (Test-Path $dir) {
        Get-ChildItem $dir -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne ".gitkeep" } |
            ForEach-Object { Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue }
    } else {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $keep = Join-Path $dir ".gitkeep"
    if (-not (Test-Path $keep)) { New-Item -ItemType File -Path $keep | Out-Null }
}

function Remove-Target($path, $label) {
    if (-not (Test-Path $path)) { return }
    Report $label $path
    if (-not $DryRun) { Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ""
Write-Host "OBAI - clean for shipping" -ForegroundColor Cyan
Write-Host "Root: $root" -ForegroundColor DarkGray
if ($DryRun) { Write-Host "DRY RUN - nothing will be modified." -ForegroundColor Yellow }
Write-Host ""

if (-not $DryRun -and -not $Force) {
    Write-Host "This will permanently delete uploaded binaries, saved analyses, Ghidra projects," -ForegroundColor Yellow
    Write-Host "caches and build artifacts, and BLANK the API keys in re_config.json." -ForegroundColor Yellow
    Write-Host "Ghidra (ghidra_12.0_PUBLIC) is kept on disk but is gitignored (not pushed)." -ForegroundColor Yellow
    $ans = Read-Host "Proceed? (y/N)"
    if ($ans -notin @("y", "Y", "yes", "Yes")) {
        Write-Host "Aborted." -ForegroundColor Red
        exit 0
    }
    Write-Host ""
}

# --- 1) User-data directories: wipe contents, keep folder + .gitkeep ---
Write-Host "User data (folder kept, contents wiped):" -ForegroundColor White
Clear-DirContents (Join-Path $root "uploads")         "uploads"
Clear-DirContents (Join-Path $root "analysis_db")     "analysis_db"
Clear-DirContents (Join-Path $root "ghidra_projects") "ghidra_projects"
Clear-DirContents (Join-Path $root "symbol_cache")    "symbol_cache"
Clear-DirContents (Join-Path $root "symbols")         "symbols"
Clear-DirContents (Join-Path $root "libraries")       "libraries"
Write-Host ""

# --- 2) Build / cache artifacts: delete entirely ---
Write-Host "Build and cache artifacts (regenerated automatically):" -ForegroundColor White

# __pycache__ everywhere except inside Ghidra or node_modules
$pycache = Get-ChildItem $root -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notlike "*ghidra_12.0_PUBLIC*" -and $_.FullName -notlike "*node_modules*" }
$pycacheMB = 0.0
foreach ($d in $pycache) {
    $pycacheMB += (Get-SizeMB $d.FullName)
    if (-not $DryRun) { Remove-Item $d.FullName -Recurse -Force -ErrorAction SilentlyContinue }
}
$script:Freed += $pycacheMB
$verb = "cleaned"
if ($DryRun) { $verb = "would clean" }
$pycacheLabel = "__pycache__ x" + $pycache.Count
Write-Host ("  {0,-44} {1,8:N1} MB  ({2})" -f $pycacheLabel, $pycacheMB, $verb) -ForegroundColor Gray

# stray .pyc
if (-not $DryRun) {
    Get-ChildItem $root -Recurse -Filter "*.pyc" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notlike "*ghidra_12.0_PUBLIC*" } |
        ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue }
}

Remove-Target (Join-Path $root "agent\bin") "agent/bin"
Remove-Target (Join-Path $root "agent\obj") "agent/obj"
Remove-Target (Join-Path $root "agent\.vs") "agent/.vs"

if (-not $KeepNodeModules) {
    Remove-Target (Join-Path $root "frontend\node_modules") "frontend/node_modules"
} else {
    Write-Host "  frontend/node_modules                        (kept: -KeepNodeModules)" -ForegroundColor DarkGray
}

if (-not $KeepBuiltFrontend) {
    Remove-Target (Join-Path $root "static\dist") "static/dist"
} else {
    Write-Host "  static/dist                                  (kept: -KeepBuiltFrontend)" -ForegroundColor DarkGray
}
Write-Host ""

# --- 3) Samples ---
Write-Host "Sample binaries:" -ForegroundColor White
if (-not $KeepSamples) {
    Remove-Target (Join-Path $root "Base")     "Base"
    Remove-Target (Join-Path $root "Base.zip") "Base.zip"
    Remove-Target (Join-Path $root "hman.dll") "hman.dll"
} else {
    Write-Host "  (kept: -KeepSamples)" -ForegroundColor DarkGray
}
Write-Host ""

# --- 4) Sanitize re_config.json (blank API keys, keep models) ---
Write-Host "Secrets:" -ForegroundColor White
$cfgPath = Join-Path $root "re_config.json"
$examplePath = Join-Path $root "re_config.example.json"
if (Test-Path $cfgPath) {
    try {
        $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
        $blanked = 0
        foreach ($prov in $cfg.providers.PSObject.Properties) {
            if ($prov.Value.PSObject.Properties.Name -contains "api_key") {
                if ($prov.Value.api_key) { $blanked++ }
                $prov.Value.api_key = ""
            }
        }
        $json = $cfg | ConvertTo-Json -Depth 8
        if (-not $DryRun) {
            $json | Set-Content $cfgPath -Encoding UTF8
            $json | Set-Content $examplePath -Encoding UTF8
        }
        $verb = "blanked"
        if ($DryRun) { $verb = "would blank" }
        Write-Host ("  re_config.json API keys {0} ({1} found); wrote re_config.example.json" -f $verb, $blanked) -ForegroundColor Gray
    } catch {
        Write-Host "  WARNING: could not parse re_config.json - leaving it untouched. Blank the api_key fields manually." -ForegroundColor Red
    }
} else {
    Write-Host "  re_config.json not present - skipping." -ForegroundColor DarkGray
}
Write-Host ""

# --- 5) .gitignore ---
if (-not $NoGitignore) {
    $gi = @'
# Python
__pycache__/
*.pyc
*.pyo
venv/
.venv/
env/

# Frontend
frontend/node_modules/
static/dist/

# .NET remote agent build artifacts
agent/bin/
agent/obj/
agent/.vs/

# OBAI runtime data (user-generated)
uploads/*
!uploads/.gitkeep
analysis_db/*
!analysis_db/.gitkeep
ghidra_projects/*
!ghidra_projects/.gitkeep
symbol_cache/*
!symbol_cache/.gitkeep
symbols/*
!symbols/.gitkeep
libraries/*
!libraries/.gitkeep

# Secrets - never commit real API keys. Ship re_config.example.json instead.
re_config.json

# Internal dev notes - not shipped to clients / public GitHub
CLAUDE.md

# Samples (uncomment if you do not want to ship them)
# Base/
# Base.zip
# hman.dll

# Bundled Ghidra install - 826 MB, too heavy for GitHub. Not committed.
# Download Ghidra separately and set GHIDRA_HOME, or unzip it into
# ./ghidra_12.0_PUBLIC (the default location app/config.py looks for).
ghidra_12.0_PUBLIC/
'@
    $giPath = Join-Path $root ".gitignore"
    Write-Host "Git:" -ForegroundColor White
    if ($DryRun) {
        Write-Host "  would write .gitignore" -ForegroundColor Gray
    } else {
        $gi | Set-Content $giPath -Encoding UTF8
        Write-Host "  wrote .gitignore" -ForegroundColor Gray
    }
    Write-Host ""
}

# --- Summary ---
$summaryVerb = "freed"
if ($DryRun) { $summaryVerb = "that would be freed" }
Write-Host ("Total {0}: {1:N1} MB" -f $summaryVerb, $script:Freed) -ForegroundColor Green
Write-Host ""
Write-Host "Reminders before shipping:" -ForegroundColor Cyan
Write-Host "  * re_config.json keys are blanked - recipients set their own in the Settings UI." -ForegroundColor DarkGray
Write-Host "  * Frontend: cd frontend; npm install; npm run build   (regenerates static/dist)" -ForegroundColor DarkGray
Write-Host "  * Backend:  python setup.py   then   python run.py" -ForegroundColor DarkGray
Write-Host "  * Ghidra (ghidra_12.0_PUBLIC) is gitignored - it stays on your disk but is not pushed." -ForegroundColor DarkGray
Write-Host "    Recipients download Ghidra themselves and set GHIDRA_HOME (see README)." -ForegroundColor DarkGray
Write-Host ""
