[CmdletBinding()]
param(
    [switch]$Plan,
    [switch]$Yes,
    [switch]$NoRun,
    [string]$Root = $(if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'TechnocoreOnboard' } else { '' }),
    [string]$PayloadPath,
    [string]$PayloadSha256
)
$ErrorActionPreference = 'Stop'
$AppVersion = '1.0.0'
$UvVersion = '0.13.1'
$ReleaseUrl = 'https://github.com/0xMamareza/technocore-onboard/releases/download/v1.0.0/technocore-onboard.zip'
$ReleaseSha256 = '9b99c535f8b9c969cbba283568eb80409cae2576b5069a48babe37c5c6b8368a'
if ($Plan) {
    Write-Output "Technocore Onboard $AppVersion; root: $Root"
    Write-Output "Download checksum-pinned private uv $UvVersion, managed Python 3.12; isolated .venv; cryptography==50.0.0. No system/PATH/profile changes."
    Write-Output 'Explicit consent is required before downloads. Setup separately asks before identity creation or public posting.'
    exit 0
}
# BEGIN SAFE ARCHIVE
function Expand-SafePayload([string]$Archive, [string]$Destination) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $required = @('onboard.py', 'vendor/technocore_agent.py', 'vendor/LICENSE', 'requirements.txt', 'README.md', 'LICENSE', 'SECURITY.md')
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        if ($zip.Entries.Count -eq 0 -or $zip.Entries.Count -gt 200) { throw 'Unsafe payload: entry limit' }
        $seen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        [long]$size = 0
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            $parts = $name.TrimEnd('/').Split('/')
            if (!$name -or $name.Contains('\')) { throw "Unsafe payload path: $name" }
            foreach ($part in $parts) {
                if ($part -notmatch '^[A-Za-z0-9_.-]+$' -or $part -in @('.', '..') -or $part.EndsWith('.') -or $part -match '^(?i:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)') { throw "Unsafe payload path: $name" }
            }
            if (!$seen.Add($name)) { throw 'Unsafe payload: case collision' }
            $mode = ($entry.ExternalAttributes -shr 16) -band 61440
            $directory = $name.EndsWith('/')
            if ($mode -notin @(0, 32768, 16384) -or ($mode -eq 16384 -and !$directory) -or ($mode -eq 32768 -and $directory)) { throw 'Unsafe payload: symlink or special entry' }
            $allowed = $name -cin $required -or ($parts.Length -eq 2 -and $parts[0] -ceq 'docs' -and $name.EndsWith('.md', [StringComparison]::Ordinal)) -or $name -cin @('vendor/', 'docs/')
            if (!$allowed) { throw "Unexpected payload entry: $name" }
            $size += $entry.Length
            if ($size -gt 20971520) { throw 'Unsafe payload: size limit' }
        }
        foreach ($name in $required) {
            if (!$zip.GetEntry($name) -or $zip.GetEntry($name).FullName.EndsWith('/')) { throw 'Incomplete payload' }
        }
        $requirementsStream = $zip.GetEntry('requirements.txt').Open()
        $requirementsBytes = New-Object IO.MemoryStream
        try {
            $requirementsStream.CopyTo($requirementsBytes)
            $expected = 'cryptography==50.0.0; sys_platform != "darwin" or platform_machine == "arm64"' + "`n" + 'cryptography==48.0.1; sys_platform == "darwin" and platform_machine == "x86_64"' + "`n"
            if ([Convert]::ToBase64String($requirementsBytes.ToArray()) -cne [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($expected))) { throw 'Unexpected dependency requirements' }
        } finally { $requirementsStream.Dispose(); $requirementsBytes.Dispose() }
        foreach ($entry in $zip.Entries) {
            if ($entry.FullName.EndsWith('/')) { continue }
            $scan = New-Object IO.StreamReader($entry.Open())
            try {
                if ($scan.ReadToEnd() -cmatch '-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?m:^-----BEGIN ENCRYPTED PRIVATE KEY-----)|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,}|AKIA[A-Z0-9]{16}') { throw "Potential secret in payload: $($entry.FullName)" }
            } finally { $scan.Dispose() }
        }
        if (Test-Path -LiteralPath $Destination) { throw 'Extraction destination already exists' }
        # Expand-Archive is used only after checking every path and external file mode.
    } finally { $zip.Dispose() }
    Expand-Archive -LiteralPath $Archive -DestinationPath $Destination -ErrorAction Stop
}
# END SAFE ARCHIVE
function Assert-SafePath([string]$Path) {
    $current = $Path
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Unsafe symlink/reparse path: $current" }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
}
if (!$NoRun -and ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected)) { throw 'Setup requires a real terminal; use -Yes -NoRun only for an installation audit.' }
if ([string]::IsNullOrWhiteSpace($Root) -or $Root -notmatch '^[A-Za-z]:[\\/]' -or $Root -match '[\x00-\x1f<>"|?*]' -or $Root.Substring(2).Contains(':')) { throw 'Unsafe install root; choose an absolute local Windows path.' }
# Validate the supplied spelling before GetFullPath can strip trailing dots/spaces.
foreach ($part in ($Root.Substring(3) -split '[\\/]')) {
    if ($part.EndsWith('.') -or $part.EndsWith(' ') -or $part -match '^(?i:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)') { throw 'Unsafe Windows root path component.' }
}
$Root = [IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
if ($Root.Length -le 3) { throw 'Unsafe install root.' }
if ($Root.Length -le 3 -or $Root -eq $env:USERPROFILE -or $Root -eq $env:LOCALAPPDATA -or ($env:WINDIR -and $Root.StartsWith($env:WINDIR, [StringComparison]::OrdinalIgnoreCase))) { throw 'Unsafe install root.' }
Assert-SafePath $Root
$ownerPath = Join-Path $Root '.bootstrap-owner'
if (Test-Path -LiteralPath $Root) {
    if (!(Test-Path -LiteralPath $ownerPath -PathType Leaf)) { throw 'Refusing unmanaged existing root. Choose a new private directory.' }
    Assert-SafePath $ownerPath
    if ([IO.File]::ReadAllText($ownerPath).Trim() -cne 'technocore-onboard-v1') { throw 'Refusing unmanaged existing root.' }
}
if ([bool]$PayloadPath -ne [bool]$PayloadSha256) { throw '-PayloadPath and -PayloadSha256 must be supplied together for a local audit artifact.' }
if ($PayloadPath) {
    if (![IO.Path]::IsPathRooted($PayloadPath) -or !(Test-Path -LiteralPath $PayloadPath -PathType Leaf)) { throw 'Local payload must be an explicit existing absolute file path.' }
    Assert-SafePath $PayloadPath
    if ($PayloadSha256 -notmatch '^[a-fA-F0-9]{64}$' -or (Get-FileHash -LiteralPath $PayloadPath -Algorithm SHA256).Hash -ine $PayloadSha256) { throw 'Payload checksum mismatch; nothing installed.' }
}
function Download-Verified([string]$Url, [string]$Destination, [string]$Hash) {
    if ($Hash -notmatch '^[a-fA-F0-9]{64}$') { throw 'Release checksum is not finalized. Use the published release installer or explicit local audit artifact flags.' }
    if (!$Url.StartsWith('https://', [StringComparison]::Ordinal)) { throw 'Downloads require HTTPS.' }
    try { Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Destination -TimeoutSec 120 -ErrorAction Stop | Out-Null }
    catch { throw "Download failed for $Url. Check HTTPS connectivity/proxy and retry. $($_.Exception.Message)" }
    if ((Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash -ine $Hash) { throw "Download checksum mismatch for $Url; refusing execution." }
}
function Assert-ManagedTree([string]$Path, [bool]$AllowInternalLinks = $false) {
    Assert-SafePath $Path
    if (!(Test-Path -LiteralPath $Path -PathType Container)) { return }
    $pending = New-Object 'Collections.Generic.Queue[string]'
    $pending.Enqueue($Path)
    while ($pending.Count) {
        foreach ($item in Get-ChildItem -LiteralPath $pending.Dequeue() -Force) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                # uv creates a private unversioned Python junction; permit only a direct internal target.
                if (!$AllowInternalLinks -or !$item.Target -or @($item.Target).Count -ne 1) { throw "Unsafe managed-tree reparse point: $($item.FullName)" }
                $target = [string]@($item.Target)[0]
                if ($target.StartsWith('\??\')) { $target = $target.Substring(4) }
                if (![IO.Path]::IsPathRooted($target)) { $target = Join-Path $item.DirectoryName $target }
                $target = [IO.Path]::GetFullPath($target)
                if (!$target.StartsWith($Path.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe runtime link target outside private runtime.' }
                Assert-SafePath $target
            } elseif ($item.PSIsContainer) { $pending.Enqueue($item.FullName) }
        }
    }
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'This installer requires native Windows PowerShell. Use install.sh on POSIX.' }
$arch = $env:PROCESSOR_ARCHITEW6432
if (!$arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
switch ($arch.ToUpperInvariant()) {
    'AMD64' { }
    'ARM64' {
        if ([Environment]::OSVersion.Version.Build -lt 22000) { throw 'Unsupported Windows ARM64 host: Windows 11 (build 22000+) with x64 emulation is required; native ARM64 cryptography wheels are unavailable.' }
        Write-Output 'Windows ARM64 compatibility: using private Windows x64 uv and CPython under Windows 11 x64 emulation because cryptography has no native Windows ARM64 wheel. If x64 emulation is unavailable, installation stops; no native ARM fallback.'
    }
    default { throw "Unsupported Windows architecture: $arch. Supported: x64 or Windows 11 ARM64 with x64 emulation." }
}
$asset = 'uv-x86_64-pc-windows-msvc.zip'
$uvHash = '3b2661a463a5baea7f5076ea2b25ab71d77f36a6c0d809e5350651792f80a672'
$PythonRequest = 'cpython-3.12-windows-x86_64-none'
Write-Output "Technocore Onboard installs only inside: $Root"
Write-Output 'Downloads: checksum-pinned private uv 0.13.1 (GitHub), managed Python 3.12 (GitHub), cryptography==50.0.0 and binary dependencies (PyPI).'
Write-Output 'No system Python, administrator rights, PATH/profile or policy changes. No identity creation or public posting by the installer.'
if (!$Yes) {
    if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { throw 'Dependency download consent requires a terminal; audit use: -Yes -NoRun.' }
    if ((Read-Host 'Allow these private dependency downloads? Type yes to continue') -cne 'yes') { Write-Output 'Cancelled; nothing installed.'; return }
}
if (!$PayloadPath -and $ReleaseSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Release checksum is not finalized. Use the published release installer or explicit local audit artifact flags.' }
# BEGIN PRIVATE ACL
function Set-PrivateTree([string]$Path) {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'
    $items = New-Object 'Collections.Generic.List[object]'
    $pending = New-Object 'Collections.Generic.Queue[string]'
    $pending.Enqueue($Path)
    # Preflight the whole tree before changing any ACL or installation content.
    while ($pending.Count) {
        $item = Get-Item -LiteralPath $pending.Dequeue() -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            # Only the runtime subtree has already passed direct-target containment validation.
            if (!$item.FullName.StartsWith((Join-Path $Path 'runtime') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe private-tree reparse point.' }
            continue
        }
        $acl = Get-Acl -LiteralPath $item.FullName
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $user.Value) { throw "Unsafe private owner: $($item.FullName)" }
        foreach ($rule in $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])) {
            if ($rule.IdentityReference.Value -notin @($user.Value, $system.Value)) { throw "Unsafe private DACL: explicit foreign grant/deny on $($item.FullName)" }
        }
        $items.Add($item)
        if ($item.PSIsContainer) { foreach ($child in Get-ChildItem -LiteralPath $item.FullName -Force) { $pending.Enqueue($child.FullName) } }
    }
    foreach ($item in $items) {
        if ($item.PSIsContainer) { $acl = New-Object Security.AccessControl.DirectorySecurity; $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' }
        else { $acl = New-Object Security.AccessControl.FileSecurity; $inherit = [Security.AccessControl.InheritanceFlags]::None }
        $acl.SetOwner($user)
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @($user, $system)) {
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        # Set-Acl in Windows PowerShell 5.1 can request SACL privileges on protected trees.
        if ($item.PSIsContainer) { [IO.Directory]::SetAccessControl($item.FullName, $acl) }
        else { [IO.File]::SetAccessControl($item.FullName, $acl) }
        $actual = Get-Acl -LiteralPath $item.FullName
        $rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        if (!$actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $user.Value -or $rules.Count -ne 2) { throw 'Cannot verify private owner/DACL.' }
        foreach ($rule in $rules) {
            if ($rule.IdentityReference.Value -notin @($user.Value, $system.Value) -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl') { throw 'Cannot verify private DACL.' }
        }
    }
}
# END PRIVATE ACL
$utf8 = New-Object Text.UTF8Encoding($false)
foreach ($name in @('runtime', '.venv', 'bin', "app-v$AppVersion", 'identity', 'receipts')) { Assert-ManagedTree (Join-Path $Root $name) ($name -eq 'runtime') }
[IO.Directory]::CreateDirectory($Root) | Out-Null
Set-PrivateTree $Root
if (!(Test-Path -LiteralPath $ownerPath)) { [IO.File]::WriteAllText($ownerPath, "technocore-onboard-v1`n", $utf8) }
$lockPath = Join-Path $Root '.install.lock'
Assert-SafePath $lockPath
$lock = $null
$stage = $null
$oldEnv = @{}
$envValues = @{
    UV_PYTHON_INSTALL_DIR = (Join-Path $Root 'runtime\python')
    UV_CACHE_DIR = (Join-Path $Root 'runtime\cache')
    UV_PYTHON_PREFERENCE = 'only-managed'
    UV_PYTHON_DOWNLOADS = 'automatic'
    UV_NO_CONFIG = '1'
    UV_NO_PROGRESS = '1'
    UV_SYSTEM_CERTS = 'true'
}
$oldTls = [Net.ServicePointManager]::SecurityProtocol
$setupError = $null
try {
    try { $lock = [IO.File]::Open($lockPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None) }
    catch { throw 'Installation lock already exists. Ensure no other installer is running; remove only .install.lock after an interrupted install.' }
    foreach ($name in @('runtime', '.venv', 'bin', "app-v$AppVersion")) { Assert-ManagedTree (Join-Path $Root $name) ($name -eq 'runtime') }
    $stage = Join-Path $Root ('.stage-' + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    $payload = Join-Path $stage 'payload.zip'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ($PayloadPath) { [IO.File]::Copy($PayloadPath, $payload); $hash = $PayloadSha256.ToLowerInvariant() }
    else { Download-Verified $ReleaseUrl $payload $ReleaseSha256; $hash = $ReleaseSha256.ToLowerInvariant() }
    if ((Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash -ine $hash) { throw 'Payload checksum mismatch after staging.' }
    $stagedApp = Join-Path $stage 'app'
    Expand-SafePayload $payload $stagedApp
    $app = Join-Path $Root "app-v$AppVersion"
    if (Test-Path -LiteralPath $app) {
        $actual = @(Get-ChildItem -LiteralPath $app -Recurse -File -Force)
        $expected = @(Get-ChildItem -LiteralPath $stagedApp -Recurse -File -Force)
        if ($actual.Count -ne $expected.Count) { throw 'Existing versioned app differs; refusing to overwrite it.' }
        foreach ($file in $expected) {
            $relative = $file.FullName.Substring($stagedApp.Length + 1)
            $target = Join-Path $app $relative
            if (!(Test-Path -LiteralPath $target -PathType Leaf) -or (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash) { throw 'Existing versioned app differs; refusing to overwrite it.' }
        }
    }
    $uvZip = Join-Path $stage 'uv.zip'
    Download-Verified "https://github.com/astral-sh/uv/releases/download/$UvVersion/$asset" $uvZip $uvHash
    $uvDir = Join-Path $stage 'uv'
    Expand-Archive -LiteralPath $uvZip -DestinationPath $uvDir
    $uv = Join-Path $uvDir 'uv.exe'
    if (!(Test-Path -LiteralPath $uv -PathType Leaf)) { throw 'Verified uv archive did not contain uv.exe.' }
    $version = & $uv --version
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '^uv 0\.13\.1(?: |$)') { throw 'Unexpected private uv version.' }
    foreach ($key in $envValues.Keys) { $oldEnv[$key] = [Environment]::GetEnvironmentVariable($key, 'Process'); [Environment]::SetEnvironmentVariable($key, $envValues[$key], 'Process') }
    $venv = Join-Path $Root '.venv'
    $python = Join-Path $venv 'Scripts\python.exe'
    if (!(Test-Path -LiteralPath $python -PathType Leaf)) {
        if (Test-Path -LiteralPath $venv) { throw 'Incomplete .venv exists; move only that directory aside and retry. Identity/data are unaffected.' }
        & $uv venv --python $PythonRequest $venv
        if ($LASTEXITCODE -ne 0) { throw 'Private Python/venv setup failed; check download connectivity.' }
    }
    & $python -I -c "import sys, sysconfig; assert sys.version_info[:2] == (3,12) and sys.prefix != sys.base_prefix and sysconfig.get_platform() == 'win-amd64'; print('Private runtime:', sys.version.split()[0], sysconfig.get_platform())"
    if ($LASTEXITCODE -ne 0) { throw 'Private venv must be isolated Windows x64 Python 3.12 (win-amd64); native ARM64/32-bit runtimes are not supported.' }
    & $uv pip install --python $python --index-url https://pypi.org/simple --only-binary :all: -r (Join-Path $stagedApp 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Private dependency installation failed; no wizard started.' }
    & $python -I -c "import cryptography; assert cryptography.__version__ == '50.0.0'"
    if ($LASTEXITCODE -ne 0) { throw 'cryptography version verification failed.' }
    if (!(Test-Path -LiteralPath $app)) { [IO.Directory]::Move($stagedApp, $app) }
    $bin = Join-Path $Root 'bin'
    [IO.Directory]::CreateDirectory($bin) | Out-Null
    $wrapper = Join-Path $bin 'tcproof.ps1'
    Assert-SafePath $wrapper
    $qPython = $python.Replace("'", "''")
    $qApp = (Join-Path $app 'onboard.py').Replace("'", "''")
    $qRoot = $Root.Replace("'", "''")
    $body = "# Technocore Onboard: explicit private interpreter; no activation or PATH edits.`r`n& '$qPython' -B -E -s '$qApp' --data-dir '$qRoot' @args`r`nexit `$LASTEXITCODE`r`n"
    $tempWrapper = Join-Path $stage 'tcproof.ps1'
    [IO.File]::WriteAllText($tempWrapper, $body, (New-Object Text.UTF8Encoding($true)))
    if (Test-Path -LiteralPath $wrapper) { [IO.File]::Replace($tempWrapper, $wrapper, [NullString]::Value) } else { [IO.File]::Move($tempWrapper, $wrapper) }
    Write-Output "Installed. No identity or public post was created."
    $qWrapper = $wrapper.Replace("'", "''")
    Write-Output "Contribute: powershell.exe -NoProfile -ExecutionPolicy Bypass -File '$qWrapper' contribute"
    Write-Output "Doctor: powershell.exe -NoProfile -ExecutionPolicy Bypass -File '$qWrapper' doctor"
} catch {
    $setupError = $_
    throw
} finally {
    try {
        try {
            foreach ($key in $oldEnv.Keys) { [Environment]::SetEnvironmentVariable($key, $oldEnv[$key], 'Process') }
            [Net.ServicePointManager]::SecurityProtocol = $oldTls
            if ($stage -and (Test-Path -LiteralPath $stage)) {
                # Windows may briefly retain an image mapping after uv exits.
                for ($attempt = 1; $attempt -le 20; $attempt++) {
                    try { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction Stop; break }
                    catch {
                        if ($attempt -eq 20) { throw }
                        Start-Sleep -Milliseconds 250
                    }
                }
            }
        } finally {
            if ($lock) {
                try { $lock.Dispose() }
                finally { Remove-Item -LiteralPath $lockPath -Force -ErrorAction Stop }
            }
        }
    } catch {
        if (!$setupError) { throw }
        Write-Warning -WarningAction Continue "Installer cleanup also failed: $($_.Exception.Message)"
    }
}
if (!$NoRun) {
    & $python -B -E -s (Join-Path $app 'onboard.py') --data-dir $Root setup
    if ($LASTEXITCODE -ne 0) { throw "Setup ended with exit code $LASTEXITCODE; installation remains available for doctor/setup." }
}
