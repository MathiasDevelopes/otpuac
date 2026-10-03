# Installs the MSI silently, checks every piece it should put on the machine,
# uninstalls it, and checks that everything is gone again. This changes the
# machine (a local administrator account, a service, a Credential Provider),
# so run it only on a disposable VM or CI runner.
param(
    [Parameter(Mandatory = $true)]
    [string]$Msi,
    [string]$AccountName = "OTPUACSmokeTest",
    [string]$LogDir = "dist\installer-logs"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$serviceName = "OTPUAC"
$providerClsid = "{B6B6F0C2-4CCB-487E-9B58-681099865B10}"
$installDir = Join-Path $env:ProgramFiles "OTPUAC"
$programData = Join-Path $env:ProgramData "OTPUAC"
$enrollmentFile = Join-Path $env:RUNNER_TEMP "otpuac-enrollment.txt"
if (-not $env:RUNNER_TEMP) {
    $enrollmentFile = Join-Path $env:TEMP "otpuac-enrollment.txt"
}

$registryChecks = @(
    "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$providerClsid\InprocServer32",
    "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$providerClsid",
    "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application\$serviceName"
)

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$msiPath = (Resolve-Path $Msi).Path

function Invoke-Msiexec {
    param([string[]]$Arguments, [string]$Log)

    $process = Start-Process msiexec.exe -Wait -PassThru -ArgumentList (
        $Arguments + @("/qn", "/norestart", "/l*v", "`"$Log`"")
    )
    if ($process.ExitCode -ne 0) {
        throw "msiexec $($Arguments -join ' ') failed with exit code $($process.ExitCode); see $Log"
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)

    if (-not $Condition) {
        throw "Check failed: $Message"
    }
    Write-Host "ok: $Message"
}

Write-Host "Installing $msiPath"
Invoke-Msiexec -Log (Join-Path $LogDir "install.log") -Arguments @(
    "/i", "`"$msiPath`"",
    "OTPUACACCOUNTNAME=$AccountName",
    "OTPUACENROLLMENTFILE=`"$enrollmentFile`""
)

foreach ($file in @("otpuac-admin.exe", "otpuac-service.exe", "otpuac-setup.exe", "otpuac_provider.dll")) {
    Assert-True (Test-Path (Join-Path $installDir $file)) "$file is installed"
}
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
Assert-True ($null -ne $service) "service $serviceName exists"
Assert-True ($service.Status -eq "Running") "service $serviceName is running"
Assert-True ($service.StartType -eq "Automatic") "service $serviceName starts automatically"
foreach ($key in $registryChecks) {
    Assert-True (Test-Path $key) "$key exists"
}
$inproc = (Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\$providerClsid\InprocServer32").'(default)'
Assert-True ($inproc -eq (Join-Path $installDir "otpuac_provider.dll")) "provider InprocServer32 points at the installed DLL"
$user = Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue
Assert-True ($null -ne $user) "managed account $AccountName exists"
$admins = Get-LocalGroupMember -SID "S-1-5-32-544" | Where-Object { $_.Name -like "*\$AccountName" }
Assert-True ($null -ne $admins) "managed account is a local administrator"
Assert-True (Test-Path (Join-Path $programData "vault.json")) "vault is provisioned"
Assert-True (Test-Path (Join-Path $programData "setup.json")) "setup metadata is written"
Assert-True ((Get-Content $enrollmentFile -Raw) -match "otpauth://totp/") "enrollment file holds an otpauth URI"
Remove-Item $enrollmentFile -Force

Write-Host "Uninstalling $msiPath"
Invoke-Msiexec -Log (Join-Path $LogDir "uninstall.log") -Arguments @("/x", "`"$msiPath`"")

Assert-True (-not (Test-Path $installDir)) "install directory is removed"
Assert-True ($null -eq (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) "service is removed"
foreach ($key in $registryChecks) {
    Assert-True (-not (Test-Path $key)) "$key is removed"
}
Assert-True ($null -eq (Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue)) "managed account is removed"
Assert-True (-not (Test-Path $programData)) "ProgramData\OTPUAC is removed"

Write-Host "MSI install and uninstall smoke test passed"
