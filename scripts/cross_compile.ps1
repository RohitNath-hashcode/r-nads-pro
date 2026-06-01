# R-NADS Cross-Compilation Script for Windows (Powershell)
# Cross-compiles the R-NADS engine for Raspberry Pi (AArch64 Linux) using `cross` (Docker).

Write-Host "=== R-NADS Raspberry Pi Cross-Compiler ===" -ForegroundColor Cyan

# 1. Check if Docker is running
Write-Host "[1/3] Checking Docker daemon status..." -ForegroundColor Yellow
& docker info > $null 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker daemon is not running. Please start Docker Desktop and try again."
    Exit 1
}
Write-Host "Docker is running." -ForegroundColor Green

# 2. Check if cargo-cross is installed
Write-Host "[2/3] Checking if 'cross' tool is installed..." -ForegroundColor Yellow
$crossVersion = & cargo cross --version > $null 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "'cross' is not installed. Installing via cargo..." -ForegroundColor Cyan
    & cargo install cross --git https://github.com/cross-rs/cross
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to install cargo-cross."
        Exit 1
    }
}
Write-Host "'cross' tool is ready." -ForegroundColor Green

# 3. Compile for target aarch64-unknown-linux-gnu
Write-Host "[3/3] Cross-compiling for aarch64-unknown-linux-gnu..." -ForegroundColor Yellow
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
& cross build --target aarch64-unknown-linux-gnu --release

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n=== Success! ===" -ForegroundColor Green
    Write-Host "Binary built at: target\aarch64-unknown-linux-gnu\release\r-nads-bin" -ForegroundColor Green
} else {
    Write-Error "Cross-compilation failed."
    Exit 1
}
