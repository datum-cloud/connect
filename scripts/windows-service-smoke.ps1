param(
    [Parameter(Mandatory = $true)] [string] $Plugin,
    [Parameter(Mandatory = $true)] [string] $Daemon,
    [ValidateRange(1, 65535)] [int] $Port = 47881,
    [ValidateRange(1, 600)] [int] $TimeoutSeconds = 45
)

$ErrorActionPreference = "Stop"
$serviceName = "datum-connect-daemon"
$programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$vendorDir = Join-Path $programData "Datum"
$stateDir = Join-Path $vendorDir "Connect"
$stageDir = Join-Path $programFiles "DatumConnectSmoke"
$stagedDaemon = Join-Path $stageDir "datum-connect-daemon.exe"
$credentials = Join-Path ([IO.Path]::GetTempPath()) ("datum-connect-smoke-{0}.json" -f [guid]::NewGuid())
$installed = $false
$stageOwned = $false
$stateOwned = $false
$vendorDirExisted = Test-Path -LiteralPath $vendorDir

function Assert-Administrator {
	if ($PSVersionTable.PSVersion.Major -lt 7) {
		throw "This smoke test requires PowerShell 7 or newer (pwsh)."
	}
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this smoke test from an elevated PowerShell session."
    }
}

function Invoke-Plugin([string[]] $Arguments, [int] $Limit = $TimeoutSeconds) {
    $process = [Diagnostics.Process]::new()
    $process.StartInfo.FileName = $Plugin
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.CreateNoWindow = $true
    $process.StartInfo.RedirectStandardOutput = $true
    $process.StartInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) { [void] $process.StartInfo.ArgumentList.Add($argument) }
    $cancellation = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($Limit))
    try {
        if (-not $process.Start()) { throw "Could not start $Plugin." }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        try {
            [void] $process.WaitForExitAsync($cancellation.Token).GetAwaiter().GetResult()
        } catch {
            # PowerShell can wrap the .NET cancellation in a method-invocation
            # exception. Check the token rather than relying on exception type.
            if ($cancellation.IsCancellationRequested) {
                try { $process.Kill($true); [void] $process.WaitForExit(5000) } catch { }
                throw "Timed out after ${Limit}s: $Plugin $($Arguments -join ' ')"
            }
            throw
        }
        $out = $stdout.GetAwaiter().GetResult()
        $err = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "Command failed ($($process.ExitCode)): $Plugin $($Arguments -join ' ')`n$out`n$err"
        }
        return $out
    } finally {
        $cancellation.Dispose()
        $process.Dispose()
    }
}

function Assert-PortAvailable {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    try {
        $listener.Start()
    } catch {
        throw "Loopback port $Port is already occupied; refusing a health check that could reach an unrelated process."
    } finally {
        $listener.Stop()
    }
}

function Wait-Health {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/v1/health" -TimeoutSec 2
            if ($health.status -eq "ok") { return }
        } catch { }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Daemon health did not become ready on port $Port within ${TimeoutSeconds}s."
}

function Get-SmokeServiceState {
    try {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) { return $null }
        throw
    }
    try { return $service.Status.ToString() } finally { $service.Dispose() }
}

function Assert-Stopped {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ((Get-SmokeServiceState) -eq "Stopped") { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Service did not stop within ${TimeoutSeconds}s."
}

function Wait-ServiceRunning {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ((Get-SmokeServiceState) -eq "Running") { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "SCM did not report the service running within ${TimeoutSeconds}s."
}

function Wait-ServiceAbsent {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ($null -eq (Get-SmokeServiceState)) { return }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "SCM still reports the service after uninstall; preserving artifacts for diagnosis."
}

function Assert-PrivateAcl([string] $Path) {
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { throw "$Path still inherits its DACL." }
    $allowed = @("S-1-5-18", "S-1-5-32-544")
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($allowed -notcontains $owner) { throw "$Path has an unexpected owner $owner." }
    $grants = @()
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -eq "Allow" -and $allowed -notcontains $sid) {
            throw "$Path grants access to unexpected principal $sid."
        }
        if ($rule.AccessControlType -eq "Allow" -and
            ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
            [Security.AccessControl.FileSystemRights]::FullControl) { $grants += $sid }
    }
    foreach ($sid in $allowed) {
        if ($grants -notcontains $sid) { throw "$Path lacks the expected full-control grant for $sid." }
    }
}

function Assert-ApiAuthentication {
    $response = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/v1/status?project=windows-service-smoke" `
        -SkipHttpErrorCheck -TimeoutSec 5
    if ($response.StatusCode -ne 401) { throw "Unauthenticated project status did not return HTTP 401." }
    $tokenFile = Join-Path $stateDir "daemon_auth\setup.token"
    $status = Invoke-Plugin -Arguments @("status", "--project", "windows-service-smoke", `
        "--token-file", $tokenFile, "--daemon-url", "http://127.0.0.1:$Port", "--output", "json")
    $parsed = $status | ConvertFrom-Json
    if ($parsed.project -ne "windows-service-smoke" -or $parsed.enrolled -ne $false) {
        throw "Authenticated status did not report the expected unenrolled project."
    }
}

function Set-SmokeArtifactAcl([string] $Path, [bool] $Directory) {
    $acl = Get-Acl -LiteralPath $Path
    $admins = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $acl.SetOwner($admins)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void] $acl.RemoveAccessRuleAll($rule) }
    $inheritance = if ($Directory) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [Security.AccessControl.InheritanceFlags]::None }
    foreach ($sid in @("S-1-5-18", "S-1-5-32-544")) {
        $identity = [Security.Principal.SecurityIdentifier]::new($sid)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity, "FullControl", $inheritance,
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

Assert-Administrator
Assert-PortAvailable
if (-not (Test-Path -LiteralPath $Plugin -PathType Leaf)) { throw "Plugin not found: $Plugin" }
if (-not (Test-Path -LiteralPath $Daemon -PathType Leaf)) { throw "Daemon not found: $Daemon" }
if (Get-SmokeServiceState) {
    throw "Refusing to touch existing service $serviceName."
}
if (Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$serviceName") {
    throw "Refusing to replace an existing Event Log source for $serviceName."
}
if (Test-Path -LiteralPath $stateDir) { throw "Refusing to touch existing state $stateDir." }
if (Test-Path -LiteralPath $stageDir) { throw "Refusing to touch existing staging directory $stageDir." }

try {
    New-Item -ItemType Directory -Path $stageDir | Out-Null
    $stageOwned = $true
    Set-SmokeArtifactAcl $stageDir $true
    Copy-Item -LiteralPath $Daemon -Destination $stagedDaemon
    Set-SmokeArtifactAcl $stagedDaemon $false
    $credentialJson = @{
        type = "datum_service_account"
        project_id = "windows-service-smoke"
        client_id = "windows-service-smoke"
        client_email = "windows-service-smoke@invalid.example"
        private_key = "not-used-without-up"
    } | ConvertTo-Json
    [IO.File]::WriteAllText($credentials, $credentialJson, [Text.UTF8Encoding]::new($false))

    Invoke-Plugin @("daemon", "install", "--system", "--port", "$Port", "--executable", $stagedDaemon, "--credentials-file", $credentials) | Out-Host
    $installed = $true
    $stateOwned = $true
    Invoke-Plugin @("daemon", "start", "--system", "--daemon-url", "http://127.0.0.1:$Port") | Out-Host
    Wait-ServiceRunning
    Wait-Health

    Assert-PrivateAcl $stateDir
    Assert-PrivateAcl (Join-Path $stateDir "credentials.json")
    Assert-PrivateAcl (Join-Path $stateDir "daemon_auth\setup.token")
    Assert-ApiAuthentication

    Invoke-Plugin @("daemon", "stop", "--system") | Out-Host
    Assert-Stopped
    Invoke-Plugin @("daemon", "start", "--system", "--daemon-url", "http://127.0.0.1:$Port") | Out-Host
    Wait-ServiceRunning
    Wait-Health
    Assert-ApiAuthentication
    Invoke-Plugin @("daemon", "stop", "--system") | Out-Host
    Assert-Stopped
    Invoke-Plugin @("daemon", "uninstall", "--system") | Out-Host
    Wait-ServiceAbsent
    $installed = $false
    Write-Host "Windows native service smoke test passed."
} finally {
    if ($installed) {
        try { Invoke-Plugin -Arguments @("daemon", "stop", "--system") -Limit 45 | Out-Null } catch { Write-Warning $_ }
        try { Invoke-Plugin -Arguments @("daemon", "uninstall", "--system") -Limit 30 | Out-Null } catch { Write-Warning $_ }
    }
    Remove-Item -LiteralPath $credentials -Force -ErrorAction SilentlyContinue
    # Unknown SCM state is not proof of absence. Never remove a live service's
    # executable or state because a diagnostic query itself failed.
    $serviceRemains = $true
    try { $serviceRemains = $null -ne (Get-SmokeServiceState) } catch { Write-Warning $_ }
    if ($serviceRemains) {
        Write-Warning "Service $serviceName still exists; preserving $stateDir and $stageDir for safe diagnosis."
    } else {
        if ($stateOwned) { Remove-Item -LiteralPath $stateDir -Recurse -Force -ErrorAction SilentlyContinue }
        if (-not $vendorDirExisted -and $stateOwned -and (Test-Path -LiteralPath $vendorDir)) {
            $children = @(Get-ChildItem -LiteralPath $vendorDir -Force)
            if ($children.Count -eq 0) { Remove-Item -LiteralPath $vendorDir -Force }
        }
        if ($stageOwned) { Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
