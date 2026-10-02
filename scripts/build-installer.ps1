param(
    [string]$Target = "x86_64-pc-windows-msvc",
    [string]$Configuration = "release",
    [string]$AppVersion = "0.1.0",
    [string]$WixVersion = "5.0.2",
    [switch]$Locked
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw "The release installer must be built on Windows."
}

function Assert-LastExitCode {
    param([string]$Step)

    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE"
    }
}

function Resolve-Wix {
    $command = Get-Command "wix.exe" -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    throw "Install the WiX Toolset with 'dotnet tool install --global wix --version $WixVersion'."
}

function Install-WixExtensions {
    param([string]$Wix)

    # Adding an extension that is already in the global cache is a no-op.
    foreach ($extension in @("WixToolset.UI.wixext", "WixToolset.Util.wixext")) {
        & $Wix extension add -g "$extension/$WixVersion"
        Assert-LastExitCode "wix extension add $extension"
    }
}

# Windows Installer versions are numeric major.minor.patch, so SemVer
# pre-release and build suffixes only appear in the file name.
$msiVersion = ($AppVersion -split '[-+]', 2)[0]
if ($msiVersion -notmatch '^\d+\.\d+\.\d+$') {
    throw "AppVersion '$AppVersion' does not start with a major.minor.patch version."
}

$cargoArgs = @("build", "--release", "--target", $Target)
if ($Locked) {
    $cargoArgs += "--locked"
}

cargo @cargoArgs
Assert-LastExitCode "cargo build"

$artifactsDir = Join-Path "target\$Target" $Configuration
$requiredArtifacts = @(
    "otpuac-admin.exe",
    "otpuac-service.exe",
    "otpuac-setup.exe",
    "otpuac_provider.dll"
)

foreach ($artifact in $requiredArtifacts) {
    $path = Join-Path $artifactsDir $artifact
    if (-not (Test-Path $path)) {
        throw "Missing release artifact: $path"
    }
}

New-Item -ItemType Directory -Force -Path "dist" | Out-Null

$wix = Resolve-Wix
Install-WixExtensions -Wix $wix

$resolvedArtifacts = (Resolve-Path $artifactsDir).Path
$output = "dist\OTPUAC-$AppVersion-x64.msi"

& $wix build `
    -arch x64 `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext `
    -d "Version=$msiVersion" `
    -d "ArtifactsDir=$resolvedArtifacts" `
    -out $output `
    installer\otpuac.wxs `
    installer\OtpuacUI.wxs
Assert-LastExitCode "wix build"

Write-Host "Built $output"
