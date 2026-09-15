# SPDX-License-Identifier: GPL-3.0-only
# Run from an extracted standalone package in an Administrator PowerShell.
param([Parameter(Mandatory=$true)][ValidateSet('install','uninstall')][string]$Action)
$ErrorActionPreference = 'Stop'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run in an Administrator PowerShell' }
    $source = Split-Path -Parent $PSScriptRoot
    $root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'OpenConnect GUI'
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $lifecycle = Join-Path $root 'resources\package-lifecycle.ps1'
    $existing = Test-Path -LiteralPath $root
    & $powershell -NoProfile -NonInteractive -File (Join-Path $PSScriptRoot 'check-install-root.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Unsafe existing installation; no installed helper was executed' }
    if ($Action -eq 'install') {
        $manifest = Get-Content -Raw -LiteralPath (Join-Path $source 'payload-manifest.json') | ConvertFrom-Json
        foreach ($entry in $manifest.PSObject.Properties) {
            $file = Join-Path $source $entry.Name
            if ($entry.Name.Contains('..') -or [IO.Path]::IsPathRooted($entry.Name)) { throw 'Unsafe package manifest' }
            if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ine $entry.Value) { throw 'Package integrity check failed' }
        }
        if ($existing) {
            if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unsafe install path' }
            & $powershell -NoProfile -NonInteractive -File $lifecycle prepare
            if ($LASTEXITCODE -ne 0) { throw 'Old service cleanup failed; files preserved' }
        }
        foreach ($entry in $manifest.PSObject.Properties) {
            $destination = Join-Path $root $entry.Name
            New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $source $entry.Name) -Destination $destination -Force
        }
        Copy-Item -LiteralPath (Join-Path $source 'payload-manifest.json') -Destination $root -Force
        & $powershell -NoProfile -NonInteractive -File $lifecycle install
        if ($LASTEXITCODE -ne 0) { throw 'Service installation failed; preserve files and repair' }
    } else {
        $manifest = Get-Content -Raw -LiteralPath (Join-Path $root 'payload-manifest.json') | ConvertFrom-Json
        & $powershell -NoProfile -NonInteractive -File $lifecycle remove
        if ($LASTEXITCODE -ne 0) { throw 'Service cleanup failed; files preserved' }
        foreach ($entry in $manifest.PSObject.Properties) {
            if ($entry.Name.Contains('..') -or [IO.Path]::IsPathRooted($entry.Name)) { throw 'Unsafe installed manifest' }
            $file = Join-Path $root $entry.Name
            if ((Test-Path -LiteralPath $file) -and (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ine $entry.Value) { throw 'Modified installed file; preserve and reconcile before uninstall' }
        }
        foreach ($entry in $manifest.PSObject.Properties) {
            Remove-Item -LiteralPath (Join-Path $root $entry.Name) -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath (Join-Path $root 'payload-manifest.json')
        # Empty directories may remain; no unrelated files or profiles are deleted.
    }
    exit 0
} catch { Write-Error $_ -ErrorAction Continue; exit 1 }
