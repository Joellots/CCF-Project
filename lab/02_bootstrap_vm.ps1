# Run INSIDE the Azure VM, in an Administrator PowerShell.
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\02_bootstrap_vm.ps1
#
# Installs everything the collection needs. The VM both captures and analyses
# its own memory, so dumps never leave it: only a small CSV does.

$ErrorActionPreference = 'Stop'
$Lab = 'C:\lab'
New-Item -ItemType Directory -Force -Path $Lab, "$Lab\tools", "$Lab\out" | Out-Null

Write-Host '[*] Defender exclusions for the lab directory' -ForegroundColor Cyan
# WinPMEM loads a kernel driver and Atomic tests perform real process
# injection. Both are flagged by default. Scope the exclusion to C:\lab only.
Add-MpPreference -ExclusionPath $Lab
Set-MpPreference -DisableRealtimeMonitoring $true

Write-Host '[*] Python 3.12' -ForegroundColor Cyan
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    $py = "$env:TEMP\python-installer.exe"
    Invoke-WebRequest -UseBasicParsing `
        'https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe' -OutFile $py
    Start-Process $py -Wait -ArgumentList '/quiet InstallAllUsers=1 PrependPath=1'
    $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine')
}
python --version

Write-Host '[*] Volatility3' -ForegroundColor Cyan
python -m pip install --quiet --upgrade pip
python -m pip install --quiet volatility3
# volatility3 exposes no __version__ attribute, so ask the CLI instead.
python -m volatility3.cli --help 2>&1 | Select-Object -First 1
Write-Host '    volatility3 importable' -ForegroundColor Green

Write-Host '[*] WinPMEM' -ForegroundColor Cyan
Invoke-WebRequest -UseBasicParsing `
  'https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe' `
  -OutFile "$Lab\tools\winpmem.exe"

Write-Host '[*] Atomic Red Team' -ForegroundColor Cyan
# Fresh Server 2022 defaults to TLS 1.0/1.1, which the PowerShell Gallery
# refuses, and PowerShellGet prompts for both the NuGet provider and PSGallery
# trust. All three must be settled up front or the install blocks on a prompt.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    Install-Module -Name invoke-atomicredteam -Scope AllUsers -Force -AllowClobber -Confirm:$false
    Write-Host '    module installed' -ForegroundColor Green
} catch {
    Write-Warning "  invoke-atomicredteam module failed: $_"
    Write-Warning "  the atomics themselves still download below; you can retry the module later"
}

# The atomics folder is a plain zip and does not depend on the module, so fetch
# it separately rather than letting a gallery failure take it down too.
$zip = "$env:TEMP\atomics.zip"
Invoke-WebRequest -UseBasicParsing `
  'https://github.com/redcanaryco/atomic-red-team/archive/refs/heads/master.zip' -OutFile $zip
Expand-Archive $zip -DestinationPath "$env:TEMP\art" -Force
if (Test-Path "$Lab\atomics") { Remove-Item "$Lab\atomics" -Recurse -Force }
Move-Item "$env:TEMP\art\atomic-red-team-master\atomics" "$Lab\atomics" -Force

Write-Host ''
Write-Host 'Ready. Next:' -ForegroundColor Green
Write-Host "  1. copy extract_features_v2.py and collect_paired.ps1 into $Lab"
Write-Host "  2. smoke test:  $Lab\tools\winpmem.exe C:\dumps\test.raw"
Write-Host "  3. preflight :  python $Lab\preflight.py C:\dumps\test.raw"
Write-Host ''
Write-Host 'Dumps go to C:\dumps and are deleted right after each extraction.' -ForegroundColor Yellow
Write-Host 'Only the feature CSV is kept, so the disk never fills.' -ForegroundColor Yellow
