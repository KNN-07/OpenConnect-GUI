# SPDX-License-Identifier: GPL-3.0-only
# Embedded into NSIS, never executed from an unvalidated existing install.
$ErrorActionPreference = 'Stop'
try {
    $root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'OpenConnect GUI'
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    if (-not (Test-Path -LiteralPath $root)) {
        New-Item -ItemType Directory -Path $root | Out-Null
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetOwner($admins)
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @($admins, $system)) {
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        }
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
        Set-Acl -LiteralPath $root -AclObject $acl
    }
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($root)
    $write = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    while ($pending.Count) {
        $path = $pending.Pop()
        $item = Get-Item -LiteralPath $path -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Existing install contains a reparse point; preserve and repair it before updating' }
        $acl = Get-Acl -LiteralPath $path
        $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin @($admins.Value, $system.Value)) { throw 'Existing install is not owned by Administrators/SYSTEM; do not execute its helpers' }
        foreach ($rule in $acl.Access) {
            if ($rule.AccessControlType -ne 'Allow' -or ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if (($rule.FileSystemRights -band $write) -and $sid -notin @($admins.Value, $system.Value)) { throw 'Existing installation is writable by an unprivileged account; files preserved' }
        }
        if ($item.PSIsContainer) {
            foreach ($child in Get-ChildItem -LiteralPath $path -Force) { $pending.Push($child.FullName) }
        }
    }
    exit 0
} catch { Write-Error $_ -ErrorAction Continue; exit 1 }
