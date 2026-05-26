param(
    [int]$From = 48,
    [int]$To   = 56,
    [int]$Only = 0
)

$ProjectDir = $PSScriptRoot

if ($Only -gt 0) {
    $sprints = @($Only)
} else {
    $sprints = $From..$To
}

$failed = @()

foreach ($n in $sprints) {
    Write-Host ""
    Write-Host ("=" * 50) -ForegroundColor Cyan
    Write-Host "  SPRINT $n - starting" -ForegroundColor Cyan
    Write-Host ("=" * 50) -ForegroundColor Cyan

    $prompt = "Implement sprint $n for ProofScan. Read docs/sprints/sprint-$n-*.md for the full plan and acceptance criteria. Follow CLAUDE.md workflow: you are the orchestrator, dispatch to Codex and Gemini workers, do not write code directly. Run pytest after implementation. Update WORK.md with ship decision."

    Push-Location $ProjectDir
    claude --dangerously-skip-permissions -p $prompt
    $exitCode = $LASTEXITCODE
    Pop-Location

    if ($exitCode -ne 0) {
        Write-Host ""
        Write-Host ("=" * 50) -ForegroundColor Red
        Write-Host "  SPRINT $n FAILED (exit $exitCode)" -ForegroundColor Red
        Write-Host ("=" * 50) -ForegroundColor Red
        Write-Host "Resume with: .\run-sprints.ps1 -From $n" -ForegroundColor Yellow
        $failed += $n
        break
    }

    Write-Host ""
    Write-Host ("=" * 50) -ForegroundColor Green
    Write-Host "  SPRINT $n COMPLETE" -ForegroundColor Green
    Write-Host ("=" * 50) -ForegroundColor Green
}

Write-Host ""
if ($failed.Count -eq 0) {
    Write-Host ("=" * 50) -ForegroundColor Green
    Write-Host "  ALL SPRINTS DONE ($From-$To)" -ForegroundColor Green
    Write-Host ("=" * 50) -ForegroundColor Green
} else {
    Write-Host "Failed sprints: $($failed -join ', ')" -ForegroundColor Red
}
