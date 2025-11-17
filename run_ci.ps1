# sushCore Local CI Check
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "sushCore Local CI Check" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$ErrorActionPreference = "Continue"
$results = @()

# Step 1: Check merge conflicts
Write-Host "`n[1/4] Checking for merge conflicts..." -ForegroundColor Yellow
try {
    python scripts/check_merge_conflicts.py
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ PASSED: Merge conflicts check" -ForegroundColor Green
        $results += $true
    } else {
        Write-Host "✗ FAILED: Merge conflicts check" -ForegroundColor Red
        $results += $false
    }
} catch {
    Write-Host "✗ ERROR: Merge conflicts check failed" -ForegroundColor Red
    $results += $false
}

# Step 2: Ruff format check
Write-Host "`n[2/4] Running Ruff format check..." -ForegroundColor Yellow
try {
    ruff format --check .
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ PASSED: Ruff format check" -ForegroundColor Green
        $results += $true
    } else {
        Write-Host "✗ FAILED: Ruff format check" -ForegroundColor Red
        Write-Host "  Run 'ruff format .' to fix formatting issues" -ForegroundColor Yellow
        $results += $false
    }
} catch {
    Write-Host "✗ ERROR: Ruff not found. Install with: pip install ruff" -ForegroundColor Red
    $results += $false
}

# Step 3: Ruff lint check
Write-Host "`n[3/4] Running Ruff lint check..." -ForegroundColor Yellow
try {
    ruff check .
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ PASSED: Ruff lint check" -ForegroundColor Green
        $results += $true
    } else {
        Write-Host "✗ FAILED: Ruff lint check" -ForegroundColor Red
        Write-Host "  Run 'ruff check --fix .' to auto-fix some issues" -ForegroundColor Yellow
        $results += $false
    }
} catch {
    Write-Host "✗ ERROR: Ruff not found. Install with: pip install ruff" -ForegroundColor Red
    $results += $false
}

# Step 4: Black check
Write-Host "`n[4/4] Running Black format check..." -ForegroundColor Yellow
try {
    black --check .
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ PASSED: Black format check" -ForegroundColor Green
        $results += $true
    } else {
        Write-Host "✗ FAILED: Black format check" -ForegroundColor Red
        Write-Host "  Run 'black .' to fix formatting issues" -ForegroundColor Yellow
        $results += $false
    }
} catch {
    Write-Host "✗ ERROR: Black not found. Install with: pip install black" -ForegroundColor Red
    $results += $false
}

# Summary
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "CI Check Summary" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$passed = ($results | Where-Object { $_ -eq $true }).Count
$total = $results.Count

Write-Host "`nOverall: $passed/$total checks passed" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Yellow" })

if ($passed -eq $total) {
    Write-Host "`n✓ All CI checks passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n✗ Some CI checks failed" -ForegroundColor Red
    exit 1
}

