param(
    [string]$Target = "x86_64-pc-windows-msvc",
    [string]$Configuration = "release",
    [string]$AppVersion = "0.1.0",
    [string]$InnoSetupCompiler
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw "The release installer must be built on Windows."
}

function Resolve-InnoSetupCompiler {
    param([string]$ConfiguredPath)

    if ($ConfiguredPath) {
        if (-not (Test-Path $ConfiguredPath)) {
            throw "Inno Setup compiler not found: $ConfiguredPath"
        }
        return (Resolve-Path $ConfiguredPath).Path
    }

    $command = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    throw "Install Inno Setup 6 or pass -InnoSetupCompiler <path-to-ISCC.exe>."
}

cargo build --release --target $Target

$artifactsDir = Join-Path "target\$Target" $Configuration
$requiredArtifacts = @(
    "otpuac-admin.exe",
    "otpuac-service.exe",
    "otpuac-setup.exe",
    "otpuac_provider_rs.dll"
)

foreach ($artifact in $requiredArtifacts) {
    $path = Join-Path $artifactsDir $artifact
    if (-not (Test-Path $path)) {
        throw "Missing release artifact: $path"
    }
}

New-Item -ItemType Directory -Force -Path "dist" | Out-Null

$iscc = Resolve-InnoSetupCompiler -ConfiguredPath $InnoSetupCompiler
$resolvedArtifacts = (Resolve-Path $artifactsDir).Path
$script = (Resolve-Path "installer\otpuac.iss").Path

& $iscc "/DAppVersion=$AppVersion" "/DArtifactsDir=$resolvedArtifacts" $script
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup compiler failed with exit code $LASTEXITCODE"
}

Write-Host "Built dist\OTPUAC-Setup-$AppVersion-x64.exe"
