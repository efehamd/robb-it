$installDir = "$env:LOCALAPPDATA\RobbIT"
$exePath    = "$installDir\robbit.exe"
$url        = "https://github.com/efehamd/robb-it/releases/latest/download/RobbIT.exe"

Write-Host ""
Write-Host "  Robb-IT Security Installer" -ForegroundColor Magenta
Write-Host "  --------------------------" -ForegroundColor DarkMagenta

# Create install directory
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

# Download
Write-Host "  Downloading..." -ForegroundColor Gray
Invoke-WebRequest $url -OutFile $exePath -UseBasicParsing

# Add to user PATH permanently (for future terminals)
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$userPath;$installDir", "User")
    Write-Host "  Added to PATH." -ForegroundColor Green
}

# Add to current session PATH immediately (so robbit works right now)
if ($env:PATH -notlike "*$installDir*") {
    $env:PATH += ";$installDir"
}

Write-Host "  Installed to: $exePath" -ForegroundColor Green
Write-Host ""
Write-Host "  Done! Type 'robbit' to launch." -ForegroundColor Magenta
Write-Host ""
