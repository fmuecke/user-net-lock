# Copyright (C) 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-only
# Project: https://github.com/fmuecke/user-net-lock.git

# Uses the shared Windows Sandbox helper to run elevated tests without messing up the dev system.
#
# Flow:
# 1. Refuse to use an existing sandbox, then start a fresh unconfigured one.
# 2. Share a unique writable host directory with the guest and copy the test binary there.
# 3. Run the elevated lifecycle test as SYSTEM, redirecting guest output to result.txt.
# 4. Require both the command success code and its success marker, then stop the guest.

[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [ValidateRange(30, 600)]
    [int]$StartupTimeoutSeconds = 120
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$buildScript = Join-Path $repositoryRoot 'build.ps1'
$powerShell = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
if (-not $powerShell) {
    $powerShell = (Get-Command powershell -ErrorAction Stop).Source
}
& $powerShell -NoProfile -File $buildScript -Configuration $Configuration
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$integrationExecutable = Join-Path $repositoryRoot 'out\build\user-net-lock-integration-tests.exe'
if (-not (Test-Path -LiteralPath $integrationExecutable -PathType Leaf)) {
    throw "The integration executable was not built: $integrationExecutable"
}
$trafficIntegrationExecutable = Join-Path $repositoryRoot 'out\build\user-net-lock-traffic-integration-tests.exe'
if (-not (Test-Path -LiteralPath $trafficIntegrationExecutable -PathType Leaf)) {
    throw "The traffic integration executable was not built: $trafficIntegrationExecutable"
}

$runRoot = Join-Path $repositoryRoot 'out\windows-sandbox-integration'
# Update the immutable raw revision and SHA-256 together when publishing a new
# WindowsSandboxTest module version.
$windowsSandboxTestModuleUri = 'https://gist.githubusercontent.com/fmuecke/2a53528dba05cd208c2cfbef2c547e2a/raw/894855d0810861b90c4333dd4caba352d6b27d32/WindowsSandboxTest.psm1'
$windowsSandboxTestModuleSha256 = 'B13C8BC805C4FD57F6AFCDA5DB65B2470A4F545BA33AA5CA43D43DD5FB508AB7'
$windowsSandboxTestModulePath = Join-Path $runRoot 'WindowsSandboxTest-1.0.0.psm1'
$windowsSandboxTestDownloadPath = "$windowsSandboxTestModulePath.download"
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
try {
    Invoke-WebRequest -Uri $windowsSandboxTestModuleUri -OutFile $windowsSandboxTestDownloadPath
    $downloadedHash = (Get-FileHash -LiteralPath $windowsSandboxTestDownloadPath -Algorithm SHA256).Hash
    if ($downloadedHash -ne $windowsSandboxTestModuleSha256) {
        throw "WindowsSandboxTest 1.0.0 hash mismatch. Expected $windowsSandboxTestModuleSha256, got $downloadedHash."
    }
    Move-Item -LiteralPath $windowsSandboxTestDownloadPath -Destination $windowsSandboxTestModulePath -Force
}
finally {
    if (Test-Path -LiteralPath $windowsSandboxTestDownloadPath) {
        Remove-Item -LiteralPath $windowsSandboxTestDownloadPath -Force
    }
}
Import-Module $windowsSandboxTestModulePath -Force

$testAccounts = @('WfpSandboxTestA', 'WfpSandboxTestB')
Invoke-WindowsSandboxTest `
    -RunRoot $runRoot `
    -ArtifactPath @($integrationExecutable, $trafficIntegrationExecutable) `
    -StartupTimeoutSeconds $StartupTimeoutSeconds `
    -TestScript {
    param($sandbox)

    $resultPath = Join-Path $sandbox.HostDirectory 'result.txt'
    $trafficResultPath = Join-Path $sandbox.HostDirectory 'traffic-result.txt'
    $provisionCommand = 'cmd.exe /d /c "(net user {0} "" /add && net user {1} "" /add)"' -f $testAccounts[0], $testAccounts[1]
    $provision = & $sandbox.InvokeCommand `
        -Command $provisionCommand `
        -Phase 'Guest test-account provisioning' `
        -CaptureFailure
    if ($provision.ExitCode -ne 0) {
        throw "The sandbox test-account provisioning failed with exit code $($provision.ExitCode).`n$($provision.Output)"
    }

    $testCommand = 'cmd.exe /d /c "user-net-lock-integration-tests.exe {0} {1} > {2}\result.txt 2>&1"' -f $testAccounts[0], $testAccounts[1], $sandbox.GuestMountPath
    $execution = & $sandbox.InvokeCommand `
        -Command $testCommand `
        -Phase 'Guest integration tests' `
        -CaptureFailure

    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        throw "The sandbox test did not create $resultPath.`n$($execution.Output)"
    }
    $result = Get-Content -LiteralPath $resultPath -Raw
    if ($execution.ExitCode -ne 0) {
        throw "The sandbox test command failed with exit code $($execution.ExitCode).`n$result"
    }
    if ($result -notmatch '(?m)^WFP integration tests passed\s*$') {
        throw "The sandbox test did not report success.`n$result"
    }

    $trafficCommand = 'cmd.exe /d /c "user-net-lock-traffic-integration-tests.exe {0} {1} > {2}\traffic-result.txt 2>&1"' -f $testAccounts[0], $testAccounts[1], $sandbox.GuestMountPath
    $trafficExecution = & $sandbox.InvokeCommand `
        -Command $trafficCommand `
        -Phase 'Guest traffic-enforcement integration test' `
        -CaptureFailure

    if (-not (Test-Path -LiteralPath $trafficResultPath -PathType Leaf)) {
        throw "The sandbox traffic test did not create $trafficResultPath.`n$($trafficExecution.Output)"
    }
    $trafficResult = Get-Content -LiteralPath $trafficResultPath -Raw
    if ($trafficExecution.ExitCode -ne 0) {
        throw "The sandbox traffic test command failed with exit code $($trafficExecution.ExitCode).`n$trafficResult"
    }
    if ($trafficResult -notmatch '(?m)^WFP traffic enforcement integration tests passed\s*$') {
        throw "The sandbox traffic test did not report success.`n$trafficResult"
    }

    return @($result, $trafficResult)
}
