# Installed with an Administrators/SYSTEM-only writable ACL. Never invoked with -Command.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevation required' }
    $buffer = [char[]]::new(131073)
    $length = 0
    while ($length -lt $buffer.Length) {
        $count = [Console]::In.Read($buffer, $length, $buffer.Length - $length)
        if ($count -eq 0) { break }
        $length += $count
    }
    if ($length -gt 131072) { throw 'Request too large' }
    $request = (-join $buffer[0..($length - 1)]) | ConvertFrom-Json
    if ($request.operation -notin @('check', 'read', 'set', 'remove', 'observe')) { throw 'Invalid operation' }
    Import-Module DnsClient -ErrorAction Stop
    function Assert-Tag([string] $tag) {
        if ($tag -notmatch '^ocvpn:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { throw 'Invalid owner' }
    }
    function Assert-Suffixes($suffixes) {
        if (@($suffixes).Count -eq 0 -or @($suffixes).Count -gt 256) { throw 'Invalid suffix count' }
        foreach ($suffix in $suffixes) {
            if ($suffix.Length -gt 253 -or $suffix -notmatch '^(?=.{1,253}\.?$)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$') { throw 'Invalid suffix' }
        }
    }
    function Assert-Value($value) {
        Assert-Tag $value.tag
        Assert-Suffixes $value.suffixes
        if (@($value.servers).Count -eq 0 -or @($value.servers).Count -gt 256) { throw 'Invalid server count' }
        foreach ($server in $value.servers) {
            $parsed = $null
            if (-not [Net.IPAddress]::TryParse($server, [ref]$parsed)) { throw 'Invalid DNS address' }
            if ($parsed.Equals([Net.IPAddress]::Any) -or $parsed.Equals([Net.IPAddress]::IPv6Any) -or $parsed.IsIPv6Multicast) { throw 'Invalid DNS address' }
        }
    }
    function Namespaces($suffixes) { @($suffixes | ForEach-Object { '.' + $_.TrimEnd('.').ToLowerInvariant() } | Sort-Object -Unique) }
    function Same-Set($a, $b) { @(Compare-Object @($a | Sort-Object -Unique) @($b | Sort-Object -Unique)).Count -eq 0 }
    $local = @(Get-DnsClientNrptRule -ErrorAction Stop)
    function Owned([string] $tag) { @($local | Where-Object { $_.DisplayName -eq $tag }) }
    function Read-Owned([string] $tag) {
        $rules = @(Owned $tag)
        if ($rules.Count -eq 0) { return $null }
        # A transaction owns exactly one rule containing all negotiated suffixes.
        if ($rules.Count -ne 1) { throw 'Ambiguous ownership' }
        $rule = $rules[0]
        if ($rule.Comment -ne $tag) { throw 'Rule changed externally' }
        $value = @{ tag = $tag; suffixes = @($rule.Namespace | ForEach-Object { ([string]$_).TrimStart('.').TrimEnd('.').ToLowerInvariant() } | Sort-Object -Unique); servers = @($rule.NameServers | ForEach-Object { ([Net.IPAddress]::Parse([string]$_)).ToString().ToLowerInvariant() } | Sort-Object -Unique) }
        Assert-Value $value
        return @{ tag = $tag; suffixes = $value.suffixes; servers = $value.servers; names = @([string]$rule.Name) }
    }
    function Check-Policy($value) {
        Assert-Value $value
        $wanted = @(Namespaces $value.suffixes)
        # Inspect both effective GPO policy and local persistent rules. Never override either.
        $policies = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop) + $local
        foreach ($policy in $policies) {
            foreach ($namespace in @($policy.Namespace)) {
                $candidate = ([string]$namespace).TrimStart('.').TrimEnd('.').ToLowerInvariant()
                foreach ($suffix in $wanted) {
                    $domain = $suffix.TrimStart('.')
                    if ($candidate -eq '' -or $candidate -eq $domain -or $candidate.EndsWith('.' + $domain) -or $domain.EndsWith('.' + $candidate)) { throw 'Conflicting administrator DNS policy' }
                }
            }
        }
    }
    $result = $null
    switch ($request.operation) {
        'check' { Check-Policy $request.value }
        'read' { Assert-Tag $request.tag; $result = Read-Owned $request.tag }
        'set' {
            Assert-Tag $request.tag
            Assert-Value $request.value
            if ($request.value.tag -ne $request.tag) { throw 'Owner mismatch' }
            $existing = Read-Owned $request.tag
            if ($null -ne $existing) { throw 'Rule already exists' }
            Check-Policy $request.value
            $metadata = @{ tag = $request.tag; suffixes = @($request.value.suffixes); servers = @($request.value.servers) }
            $rule = Add-DnsClientNrptRule -Namespace (Namespaces $metadata.suffixes) -NameServers $metadata.servers -DisplayName $request.tag -Comment $request.tag -PassThru -ErrorAction Stop
            $result = @{ tag = $metadata.tag; suffixes = $metadata.suffixes; servers = $metadata.servers; names = @([string]$rule.Name) }
        }
        'remove' {
            Assert-Tag $request.tag
            $existing = Read-Owned $request.tag
            if ($null -ne $existing) {
                Assert-Value $request.expected
                if (-not (Same-Set $existing.names $request.expected.names) -or -not (Same-Set $existing.suffixes $request.expected.suffixes) -or -not (Same-Set $existing.servers $request.expected.servers)) { throw 'Rule changed externally' }
                foreach ($name in $request.expected.names) { Remove-DnsClientNrptRule -Name $name -Force -ErrorAction Stop }
            }
        }
        'observe' {
            Assert-Suffixes $request.suffixes
            $wanted = @(Namespaces $request.suffixes)
            $servers = @()
            $found = @()
            foreach ($policy in @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)) {
                foreach ($namespace in @($policy.Namespace)) {
                    if ($namespace -in $wanted) {
                        $found += ([string]$namespace).TrimStart('.')
                        $servers += @($policy.NameServers)
                    }
                }
            }
            if (-not (Same-Set $wanted (Namespaces $found))) { throw 'Split DNS is not effective' }
            $result = @{ suffixes = @($found | Sort-Object -Unique); servers = @($servers | Sort-Object -Unique) }
        }
    }
    $json = ConvertTo-Json -InputObject $result -Compress -Depth 8
    if ($json.Length -gt 262144) { throw 'Response too large' }
    [Console]::Out.Write($json)
    exit 0
} catch {
    # Native/policy text is not exposed to callers.
    [Console]::Error.WriteLine('NRPT operation failed')
    exit 1
}
