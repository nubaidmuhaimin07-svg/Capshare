# CapShare - one-time setup for Windows 10/11.
#
# What it does (no administrator rights needed):
#   1. finds a usable Python (python.org 3.10-3.13, or MSYS2 UCRT64 Python)
#   2. creates a private virtual environment in  %USERPROFILE%\.capshare-venv
#   3. installs the packages from requirements.txt into it
#   4. creates the demo accounts and runs a quick self-test
#
# How to run it:  right-click this file -> "Run with PowerShell"
#            or:  powershell -ExecutionPolicy Bypass -File .\setup_windows.ps1
#
# Windows limitation: Linux POSIX ACLs (setfacl/getfacl) do not exist on Windows, so that
# one feature is switched off here. Everything else (capabilities, delegation, revoke,
# expiry, transfers, the lab) works the same.

$ErrorActionPreference = "Stop"
$Here  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Venv  = Join-Path $env:USERPROFILE ".capshare-venv"

function Say($text, $color = "Gray") { Write-Host $text -ForegroundColor $color }

function Test-Python($exe) {
    # returns @{ Exe; Major; Minor; Msys2 } or $null
    if (-not $exe -or -not (Test-Path -LiteralPath $exe)) { return $null }
    if ($exe -like "*\WindowsApps\*") { return $null }          # Microsoft Store stub, not a real Python
    try {
        $out = & $exe -c "import sys; print(sys.version_info[0], sys.version_info[1], sys.executable)" 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
        $parts = ($out | Select-Object -First 1).ToString().Split(" ", 3)
        return @{ Exe = $exe; Major = [int]$parts[0]; Minor = [int]$parts[1]
                  Msys2 = ($exe -like "*msys64*") }
    } catch { return $null }
}

function Find-Python {
    $found = @()
    # 1. the "py" launcher with versions PySide6 supports
    foreach ($v in "3.13", "3.12", "3.11", "3.10") {
        try {
            $exe = (& py "-$v" -c "import sys; print(sys.executable)" 2>$null | Select-Object -First 1)
            $p = Test-Python $exe
            if ($p) { $found += $p }
        } catch { }
    }
    # 2. python on PATH
    foreach ($cmd in (Get-Command python, python3 -All -ErrorAction SilentlyContinue)) {
        $p = Test-Python $cmd.Source
        if ($p) { $found += $p }
    }
    # 3. MSYS2 UCRT64 Python (has no PySide6 wheels on pip, but pacman provides the packages)
    $p = Test-Python "C:\msys64\ucrt64\bin\python.exe"
    if ($p) { $found += $p }

    $good = $found | Where-Object { -not $_.Msys2 -and $_.Major -eq 3 -and $_.Minor -ge 10 -and $_.Minor -le 13 }
    if ($good) { return $good | Select-Object -First 1 }
    $msys = $found | Where-Object { $_.Msys2 }
    if ($msys) { return $msys | Select-Object -First 1 }
    return $found | Select-Object -First 1
}

Say "== CapShare setup for Windows ==" Cyan
$py = Find-Python
if (-not $py) {
    Say "No Python found." Red
    Say "Install Python 3.12 from https://www.python.org/downloads/ (tick 'Add python.exe to PATH')," Yellow
    Say "then run this script again." Yellow
    Read-Host "Press Enter to close"
    exit 1
}
Say "Using Python $($py.Major).$($py.Minor): $($py.Exe)"

if ($py.Msys2) {
    # pip cannot build pydantic-core / PySide6 on MSYS2, but pacman ships them.
    & $py.Exe -c "import fastapi, PySide6, requests" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Say "MSYS2 Python needs three packages. Open the 'MSYS2 UCRT64' shell and run:" Yellow
        Say "  pacman -S --needed mingw-w64-ucrt-x86_64-python-fastapi mingw-w64-ucrt-x86_64-python-requests mingw-w64-ucrt-x86_64-pyside6" White
        Say "then run this script again." Yellow
        Read-Host "Press Enter to close"
        exit 1
    }
}
elseif ($py.Minor -gt 13) {
    Say "Python $($py.Major).$($py.Minor) is very new; PySide6 may not have a build for it yet." Yellow
    Say "If the install below fails, install Python 3.12 from python.org and re-run." Yellow
}

# --- virtual environment -------------------------------------------------------------
$venvPy = $null
foreach ($candidate in "$Venv\Scripts\python.exe", "$Venv\bin\python.exe") {
    if (Test-Path -LiteralPath $candidate) { $venvPy = $candidate }
}
if (-not $venvPy) {
    Say "Creating the environment in $Venv ..."
    if ($py.Msys2) { & $py.Exe -m venv --system-site-packages $Venv }
    else           { & $py.Exe -m venv $Venv }
    foreach ($candidate in "$Venv\Scripts\python.exe", "$Venv\bin\python.exe") {
        if (Test-Path -LiteralPath $candidate) { $venvPy = $candidate }
    }
}
if (-not $venvPy) { throw "could not create the virtual environment" }

Say "Installing packages (this can take a few minutes the first time) ..."
& $venvPy -m pip install --disable-pip-version-check -r (Join-Path $Here "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "pip install failed - see the messages above" }

# --- demo accounts + self test ---------------------------------------------------------
Push-Location $Here
try {
    Say "Creating demo accounts ..."
    & $venvPy -m capshare seed
    Say "Self-test (runs the five KO-13 challenges) ..."
    & $venvPy -m capshare lab | Select-String -Pattern "^==" | ForEach-Object { Say "  $($_.Line)" }
    if ($LASTEXITCODE -ne 0) { throw "self-test failed" }
} finally { Pop-Location }

Say ""
Say "Setup finished." Green
Say "  Start CapShare : double-click CapShare.bat"
Say "  Run all checks : double-click run_checks.bat"
Say "  Sign in as     : olivia / capshare-demo   (alice, bob, carol, dave use the same password)"
Say "  Other devices  : if they cannot connect, run open_firewall_windows.ps1 as administrator"
Read-Host "Press Enter to close"
