# dev_setup.ps1 - Run this before working on FileGuard

Write-Host ""
Write-Host "Setting FileGuard development environment..." -ForegroundColor Cyan
Write-Host ""

$env:FILEGUARD_TESTING = "true"
$env:FILEGUARD_SANDBOX = "C:\FileGuardTest\mock_system"
$env:FILEGUARD_READONLY = "true"

Write-Host "[OK] FILEGUARD_TESTING = true" -ForegroundColor Green
Write-Host "[OK] FILEGUARD_SANDBOX = C:\FileGuardTest\mock_system" -ForegroundColor Green
Write-Host "[OK] FILEGUARD_READONLY = true" -ForegroundColor Green
Write-Host ""
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "  SAFETY MODE ENABLED" -ForegroundColor Yellow
Write-Host "  All file operations sandboxed" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "You can now safely develop FileGuard!" -ForegroundColor Cyan
Write-Host ""
