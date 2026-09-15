# SPDX-License-Identifier: GPL-3.0-only
param([Parameter(Mandatory=$true)][ValidateSet('add','remove')][string]$Action)
$ErrorActionPreference = 'Stop'
try {
    $root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'OpenConnect GUI'
    $key = 'HKLM:\SOFTWARE\OpenConnectGUI\Package'
    $current = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $parts = @($current -split ';' | Where-Object { $_ -ne '' })
    $present = @($parts | Where-Object { $_.TrimEnd('\') -ieq $root }).Count -gt 0
    if ($Action -eq 'add' -and -not $present) {
        [Environment]::SetEnvironmentVariable('Path', ($parts + $root) -join ';', 'Machine')
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name PathAdded -Value $root -PropertyType String -Force | Out-Null
    } elseif ($Action -eq 'remove' -and (Test-Path $key)) {
        $owned = (Get-ItemProperty -Path $key -Name PathAdded -ErrorAction SilentlyContinue).PathAdded
        if ($owned -eq $root) {
            [Environment]::SetEnvironmentVariable('Path', (@($parts | Where-Object { $_ -ine $root }) -join ';'), 'Machine')
            Remove-ItemProperty -Path $key -Name PathAdded
        }
    }
    # New processes after the next sign-in observe the updated machine PATH.
    exit 0
} catch { Write-Error $_ -ErrorAction Continue; exit 1 }
