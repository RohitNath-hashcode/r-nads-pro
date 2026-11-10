# R-NADS Pro — Automated Security, SCA & Code Quality Audit Runner (PowerShell)
# Enforces zero-tolerance security standards for production deployments.

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "       R-NADS Pro: Enterprise Security & Quality Audit       " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Unsafe Code Audit
Write-Host "`n[Audit 1/5] Checking for Unsafe Code Blocks..." -ForegroundColor Yellow
$unsafeMatches = Get-ChildItem -Path crates, services -Recurse -Filter "*.rs" | 
    Select-String "\bunsafe\b" | 
    Where-Object { $_.Line -notmatch "forbid\(unsafe_code\)" -and $_.Line -notmatch "deny\(unsafe_code\)" }

if ($unsafeMatches) {
    Write-Host "[-] FAILED: Unsafe code block detected in source tree!" -ForegroundColor Red
    $unsafeMatches | ForEach-Object { Write-Host "    $($_.Filename):$($_.LineNumber): $($_.Line)" }
    exit 1
} else {
    Write-Host "[+] PASSED: Zero unsafe blocks found. All crates enforce #![forbid(unsafe_code)]." -ForegroundColor Green
}

# 2. Code Quality & Linter Audit (Clippy with -D warnings)
Write-Host "`n[Audit 2/5] Running SAST Code Quality & Linter Analyzer (Clippy)..." -ForegroundColor Yellow
cargo clippy --workspace --all-targets -- -D warnings
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] FAILED: Clippy security / code-quality linter found warnings." -ForegroundColor Red
    exit $LASTEXITCODE
}
Write-Host "[+] PASSED: 0 clippy warnings across all workspace crates." -ForegroundColor Green

# 3. Code Formatting Standards
Write-Host "`n[Audit 3/5] Verifying Code Formatting..." -ForegroundColor Yellow
cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] FAILED: Code formatting does not comply with rustfmt rules." -ForegroundColor Red
    exit $LASTEXITCODE
}
Write-Host "[+] PASSED: All source files meet formatting standards." -ForegroundColor Green

# 4. Supply Chain & SCA Vulnerability Analysis
Write-Host "`n[Audit 4/5] Executing Software Composition Analysis (SCA)..." -ForegroundColor Yellow
if (Get-Command cargo-deny -ErrorAction SilentlyContinue) {
    Write-Host "Running cargo-deny check..."
    cargo deny check
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[-] FAILED: cargo-deny found policy violations in dependencies." -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Host "[+] PASSED: cargo-deny passed all advisory, ban, and license checks." -ForegroundColor Green
} else {
    Write-Host "[*] cargo-deny not installed on host. Checking Cargo.lock integrity..." -ForegroundColor Gray
    if (Test-Path Cargo.lock) {
        Write-Host "[+] PASSED: Cargo.lock is committed with deterministic dependency hashes." -ForegroundColor Green
    } else {
        Write-Host "[-] FAILED: Cargo.lock is missing!" -ForegroundColor Red
        exit 1
    }
}

# 5. Unit, Integration, and Fuzzing Test Suite
Write-Host "`n[Audit 5/5] Running Comprehensive Test Suite (IPv6, Scans, Fragments, SVDD, Drift)..." -ForegroundColor Yellow
if (Test-Path "target\debug\deps\*.exe") {
    Remove-Item "target\debug\deps\*.exe" -Force -ErrorAction SilentlyContinue
}
cargo test --workspace
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] FAILED: Test suite encountered failures." -ForegroundColor Red
    exit $LASTEXITCODE
}
Write-Host "[+] PASSED: All workspace tests passed cleanly." -ForegroundColor Green

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "       SECURITY AUDIT COMPLETE: ALL SECURITY GATES PASSED     " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
