Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $target = "x86_64-pc-windows-msvc"
} else {
    $target = "x86_64-pc-windows-gnu"
}

cargo build --release --target $target

Write-Host "Built release artifacts under target\$target\release"
