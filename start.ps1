$ErrorActionPreference = "Stop"

function Load-DotEnv {
  param([string]$Path)

  Get-Content $Path | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith("#")) {
      return
    }

    $parts = $line -split "=", 2
    if ($parts.Length -ne 2) {
      return
    }

    $name = $parts[0].Trim()
    $value = $parts[1].Trim()
    [Environment]::SetEnvironmentVariable($name, $value, "Process")
  }
}

function Resolve-DockerCli {
  $dockerCommand = Get-Command "docker" -ErrorAction SilentlyContinue
  if ($dockerCommand) {
    return $dockerCommand.Source
  }

  $candidatePaths = @(
    "D:\Docker\DockerDesktop\resources\bin\docker.exe",
    "C:\Program Files\Docker\Docker\resources\bin\docker.exe"
  )

  foreach ($candidatePath in $candidatePaths) {
    if (Test-Path $candidatePath) {
      $dockerBin = Split-Path -Parent $candidatePath
      if (($env:Path -split ";") -notcontains $dockerBin) {
        $env:Path = "$dockerBin;$env:Path"
      }
      return $candidatePath
    }
  }

  throw "Docker CLI not found. Start Docker Desktop or add docker.exe to PATH."
}

function Invoke-Checked {
  param(
    [string]$FilePath,
    [string[]]$Arguments
  )

  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
  }
}

function Invoke-BestEffort {
  param(
    [string]$FilePath,
    [string[]]$Arguments
  )

  $previousErrorActionPreference = $ErrorActionPreference
  $hasNativePreference = Test-Path Variable:\PSNativeCommandUseErrorActionPreference
  if ($hasNativePreference) {
    $previousNativePreference = $PSNativeCommandUseErrorActionPreference
    $script:PSNativeCommandUseErrorActionPreference = $false
  }

  try {
    $ErrorActionPreference = "Continue"
    & $FilePath @Arguments *>$null
  } catch {
  } finally {
    $ErrorActionPreference = $previousErrorActionPreference
    if ($hasNativePreference) {
      $script:PSNativeCommandUseErrorActionPreference = $previousNativePreference
    }
    $global:LASTEXITCODE = 0
  }
}

function Wait-Port {
  param(
    [string]$HostName,
    [int]$Port,
    [int]$TimeoutSeconds = 60
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    try {
      $client = New-Object System.Net.Sockets.TcpClient
      $async = $client.BeginConnect($HostName, $Port, $null, $null)
      $ok = $async.AsyncWaitHandle.WaitOne(1000)
      if ($ok -and $client.Connected) {
        $client.EndConnect($async)
        $client.Close()
        return
      }
      $client.Close()
    } catch {
    }
    Start-Sleep -Seconds 1
  }

  throw "Timed out waiting for ${HostName}:$Port"
}

function Wait-HttpOk {
  param(
    [string]$Url,
    [int]$TimeoutSeconds = 90
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    try {
      $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
      if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500) {
        return
      }
    } catch {
    }
    Start-Sleep -Seconds 2
  }

  throw "Timed out waiting for HTTP endpoint: $Url"
}

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
}

Load-DotEnv ".env"

$docker = Resolve-DockerCli

Write-Host "Starting infrastructure..."
Invoke-BestEffort -FilePath $docker -Arguments @("compose", "-f", ".\docker\docker-compose.yml", "stop", "api", "worker")
Invoke-Checked -FilePath $docker -Arguments @("compose", "-f", ".\docker\docker-compose.yml", "up", "-d", "postgres", "redis", "localstack")

Wait-Port -HostName "127.0.0.1" -Port 5432
Wait-Port -HostName "127.0.0.1" -Port 6379
Wait-Port -HostName "127.0.0.1" -Port 4566
Wait-HttpOk -Url "http://127.0.0.1:4566/_localstack/health"

Write-Host "Ensuring Python dependencies..."
$dependencyCheck = "import importlib.util, sys; missing=[m for m in ('fastapi','sqlalchemy','redis','rq','boto3','alembic') if importlib.util.find_spec(m) is None]; print('Missing Python packages: ' + ', '.join(missing)) if missing else None; sys.exit(1 if missing else 0)"
& py -3.12 -c $dependencyCheck
if ($LASTEXITCODE -ne 0) {
  Invoke-Checked -FilePath "py" -Arguments @("-3.12", "-m", "pip", "install", "-e", ".[dev]")
}

Write-Host "Ensuring Playwright browser..."
Invoke-Checked -FilePath "py" -Arguments @("-3.12", "-m", "playwright", "install", "chromium")

Write-Host "Bootstrapping LocalStack resources..."
Invoke-Checked -FilePath "py" -Arguments @("-3.12", ".\scripts\bootstrap_localstack.py")

Write-Host "Applying migrations..."
Invoke-Checked -FilePath "py" -Arguments @("-3.12", "-m", "alembic", "upgrade", "head")

$runtimeDir = ".\.runtime"
$logDir = Join-Path $runtimeDir "logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$workerOutLog = Join-Path $logDir "worker.out.log"
$workerErrLog = Join-Path $logDir "worker.err.log"

Write-Host "Starting RQ worker in background..."
if ($false) {
}
<#
  throw "rq.exe not found — run: pip install rq"
}
$workerProcess = Start-Process `
#>
$workerProcess = Start-Process `
  -FilePath "py" `
  -ArgumentList @("-3.12", "-m", "rq.cli", "worker", "--worker-class", "rq.SimpleWorker", "auth_bootstrap", "recon", "attack_planning", "attack_tasks", "finding_scorer") `
  -WorkingDirectory $projectRoot `
  -RedirectStandardOutput $workerOutLog `
  -RedirectStandardError $workerErrLog `
  -PassThru

Set-Content -Path (Join-Path $runtimeDir "worker.pid") -Value $workerProcess.Id

Write-Host "Worker PID: $($workerProcess.Id)"
Write-Host "Worker stdout log: $workerOutLog"
Write-Host "Worker stderr log: $workerErrLog"
Write-Host "API starting on http://127.0.0.1:8000"

Invoke-Checked -FilePath "py" -Arguments @("-3.12", "-m", "uvicorn", "api.main:app", "--reload")
