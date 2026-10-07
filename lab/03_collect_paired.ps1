# Paired capture, run INSIDE the lab VM as Administrator.
#
#   .\03_collect_paired.ps1 -Trials 10
#
# Each trial captures the machine CLEAN, then runs one injection technique and
# captures it again. Same boot, same workload, minutes apart. The only thing
# that differs between the pair is the technique, so any change in the memory
# artefacts is attributable to it. That is the property CIC-MalMem-2022 lacks.

param(
    [int]$Trials = 10,
    [string]$Lab = 'C:\lab',
    [string]$DumpDir = '',                 # auto: D:\ on Azure, C:\dumps on AWS
    [int]$SettleSec = 90,
    [int]$DetonateSec = 120
)

$ErrorActionPreference = 'Stop'

# Azure gives every VM a free ephemeral SSD at D:. AWS t3 instances are EBS-only
# and have no such disk, so fall back to the root volume there.
if (-not $DumpDir) {
    $DumpDir = if (Test-Path 'D:\') { 'D:\' } else { 'C:\dumps' }
}
New-Item -ItemType Directory -Force -Path $DumpDir | Out-Null
Write-Host "[*] dumps -> $DumpDir (each is deleted right after extraction)" -ForegroundColor Cyan

$Out     = Join-Path $Lab 'out\paired_dataset.csv'
$Pmem    = Join-Path $Lab 'tools\winpmem.exe'
$Extract = Join-Path $Lab 'extract_features_v2.py'
# Invoke-AtomicTest defaults to C:\AtomicRedTeam\atomics. The bootstrap installs
# them under C:\lab, so every call must be told where they are or each technique
# silently does nothing and both captures in the pair come out identical.
$Atomics = Join-Path $Lab 'atomics'

foreach ($p in @($Pmem, $Extract, $Atomics)) {
    if (-not (Test-Path $p)) { throw "missing prerequisite: $p" }
}
if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
    Import-Module invoke-atomicredteam -ErrorAction Stop
}
New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null

# Injection and hiding techniques. These produce the artefacts the detector
# reads: malfind regions, unlinked modules, hidden threads.
$Techniques = @('T1055.001','T1055.002','T1055.003','T1055.004','T1055.012')

# Varying workload gives the clean baseline realistic spread. Without it the
# baseline has near-zero dispersion and everything looks anomalous.
$Workloads = @('idle','browser','office','mixed','busy')

function Start-Workload($name) {
    switch ($name) {
        'idle'    { }
        'browser' { Start-Process notepad; Start-Process mspaint }
        'office'  { Start-Process notepad; Start-Process calc; Start-Process explorer }
        'mixed'   { Start-Process notepad; Start-Process mspaint; Start-Process calc }
        'busy'    { 1..4 | ForEach-Object { Start-Process powershell '-NoExit','-Command','1..1e7|Measure-Object' } }
    }
}
function Stop-Workload {
    'notepad','mspaint','calc','explorer','powershell' | ForEach-Object {
        Get-Process $_ -EA SilentlyContinue |
            Where-Object { $_.Id -ne $PID } | Stop-Process -Force -EA SilentlyContinue
    }
    Start-Process explorer   # keep the shell alive
}

function Capture($label, $tag, $trial) {
    $img = Join-Path $DumpDir "$($label)_$trial.raw"
    Write-Host "    capturing $label ..." -ForegroundColor Cyan
    & $Pmem $img | Out-Null
    if (-not (Test-Path $img)) { throw "WinPMEM produced no image at $img" }
    python $Extract $img --output $Out --append --label $label `
           --host $env:COMPUTERNAME --tag $tag
    Remove-Item $img -Force           # a 4 GB image per capture: do not keep them
}

Write-Host "[*] $Trials trials -> $Out" -ForegroundColor Green
for ($i = 1; $i -le $Trials; $i++) {
    $wl   = $Workloads[($i - 1) % $Workloads.Count]
    $tech = $Techniques[($i - 1) % $Techniques.Count]
    Write-Host "[=] trial $i/$Trials  workload=$wl  technique=$tech" -ForegroundColor Green

    Stop-Workload
    Start-Workload $wl
    Start-Sleep -Seconds $SettleSec

    Capture 'clean' "workload=$wl" $i

    Write-Host "    running $tech" -ForegroundColor Yellow
    try {
        Invoke-AtomicTest $tech -PathToAtomicsFolder $Atomics -GetPrereqs -ErrorAction SilentlyContinue
        Invoke-AtomicTest $tech -PathToAtomicsFolder $Atomics
        Start-Sleep -Seconds $DetonateSec
        Capture 'infected' "workload=$wl|technique=$tech" $i
    }
    catch { Write-Warning "  $tech failed: $_  (clean capture for trial $i is still valid)" }
    finally { Invoke-AtomicTest $tech -PathToAtomicsFolder $Atomics -Cleanup -ErrorAction SilentlyContinue }
}

Write-Host ''
Write-Host "[+] done. Copy $Out off the VM, then on your Ubuntu box:" -ForegroundColor Green
Write-Host '    python3 pipeline/baseline_diff.py fit   paired_dataset.csv --out baseline.json'
Write-Host '    python3 pipeline/baseline_diff.py score paired_dataset.csv --model baseline.json'
