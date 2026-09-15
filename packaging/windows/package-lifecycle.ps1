# SPDX-License-Identifier: GPL-3.0-only
param([Parameter(Mandatory=$true)][ValidateSet('prepare','install','remove')][string]$Action)
$ErrorActionPreference = 'Stop'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator authorization is required' }
    $root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'OpenConnect GUI'
    $helper = Join-Path $root 'ocvpn-installer.exe'
    if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Install directory is a reparse point' }
    if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) { throw 'Native service manager is missing; cannot prove safe update/removal' }
    function Invoke-Manager([string]$Command) {
        $result = & $helper $Command
        if ($LASTEXITCODE -ne 0) { throw 'Native service operation failed; files must be preserved. Run ocvpn service repair.' }
        return ($result | ConvertFrom-Json)
    }
    if ($Action -eq 'install') {
        # No HKCU changes from the elevated installer. Login registration and
        # callback choice belong to the actual user and remain explicit opt-ins.
        & "$env:SystemRoot\System32\icacls.exe" $root /setowner '*S-1-5-32-544' /T /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Unable to set administrator ownership' }
        & "$env:SystemRoot\System32\icacls.exe" $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /T /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Unable to protect installed files' }
        $state = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'OpenConnectGUI'
        if (Test-Path -LiteralPath $state) {
            if ((Get-Item -LiteralPath $state).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'State directory is a reparse point' }
        } else { New-Item -ItemType Directory -Path $state | Out-Null }
        & "$env:SystemRoot\System32\icacls.exe" $state /setowner '*S-1-5-32-544' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Unable to own service state' }
        & "$env:SystemRoot\System32\icacls.exe" $state /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Unable to protect service state' }
        $result = Invoke-Manager install
        if ($result.registered -ne $true -or $result.approval_required -ne $false) { throw 'Service was not registered' }
    } else {
        $result = Invoke-Manager uninstall
        if ($result.registered -ne $false -or $result.approval_required -ne $false) { throw 'Service/worker/recovery remains unresolved; files preserved' }
        $result = Invoke-Manager status
        if ($result.registered -ne $false -or $result.approval_required -ne $false) { throw 'Service unregister was not confirmed; files preserved' }
    }
    exit 0
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
}
