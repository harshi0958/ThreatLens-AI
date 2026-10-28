param(
    [switch]$RetrainModel
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$FrontendRoot = Join-Path $ProjectRoot 'frontend'
$VenvPath = Join-Path $ProjectRoot '.venv'
$PythonExe = Join-Path $VenvPath 'Scripts\python.exe'
$Requirements = Join-Path $ProjectRoot 'backend\requirements.txt'
$SampleDataset = Join-Path $ProjectRoot 'datasets\sample\network_traffic_sample.csv'
$ModelArtifact = Join-Path $ProjectRoot 'backend\artifacts\demo_model.joblib'

Set-Location -LiteralPath $ProjectRoot

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw 'Node.js and npm are required. Install a supported Node.js LTS release and rerun start.ps1.'
}

foreach ($port in @(8000, 5173)) {
    $listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($listener) {
        throw "Port $port is already in use (PID $($listener.OwningProcess)). Stop that service or configure a different port before starting ThreatLens AI."
    }
}

if (-not (Test-Path $PythonExe)) {
    $PythonLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($PythonLauncher) {
        & py -3 -m venv $VenvPath
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        & python -m venv $VenvPath
    } else {
        throw 'Python 3 is required. Install Python and ensure the py launcher or python command is on PATH.'
    }
    if ($LASTEXITCODE -ne 0) {
        throw 'Virtual environment creation failed.'
    }
}

Write-Host 'Installing backend dependencies...'
& $PythonExe -m pip install -r $Requirements
if ($LASTEXITCODE -ne 0) {
    throw 'Backend dependency installation failed.'
}

if (-not (Test-Path (Join-Path $ProjectRoot '.env'))) {
    Copy-Item (Join-Path $ProjectRoot '.env.example') (Join-Path $ProjectRoot '.env')
    Write-Host 'Created .env from .env.example. Review it before using a MongoDB service.'
}

if (-not (Test-Path $SampleDataset) -or $RetrainModel) {
    Write-Host 'Generating deterministic synthetic sample traffic...'
    & $PythonExe (Join-Path $ProjectRoot 'backend\scripts\generate_demo_dataset.py')
    if ($LASTEXITCODE -ne 0) {
        throw 'Sample dataset generation failed.'
    }
}

if (-not (Test-Path $ModelArtifact) -or $RetrainModel) {
    Write-Host 'Training the synthetic demo classifier...'
    & $PythonExe (Join-Path $ProjectRoot 'backend\scripts\train_demo_model.py')
    if ($LASTEXITCODE -ne 0) {
        throw 'Demo model training failed.'
    }
}

Write-Host 'Installing frontend dependencies...'
Push-Location $FrontendRoot
try {
    & npm install
    if ($LASTEXITCODE -ne 0) {
        throw 'Frontend dependency installation failed.'
    }
} finally {
    Pop-Location
}

$FrontendForCommand = $FrontendRoot.Replace("'", "''")
$PythonForCommand = $PythonExe.Replace("'", "''")

Write-Host 'Starting backend and frontend in separate PowerShell windows...'
Start-Process -FilePath 'powershell.exe' -WorkingDirectory $ProjectRoot -ArgumentList @(
    '-NoExit',
    '-Command',
    "& '$PythonForCommand' -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload"
) | Out-Null
Start-Process -FilePath 'powershell.exe' -WorkingDirectory $FrontendRoot -ArgumentList @(
    '-NoExit',
    '-Command',
    "Set-Location -LiteralPath '$FrontendForCommand'; npm run dev -- --host 127.0.0.1 --port 5173"
) | Out-Null

Write-Host 'Dashboard: http://localhost:5173'
Write-Host 'API health: http://127.0.0.1:8000/api/health'
Write-Host 'Swagger docs: http://127.0.0.1:8000/docs'
