package bruecke

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

const windowsWireGuardInstallerURL = "https://download.wireguard.com/windows-client/wireguard-installer.exe"
const windowsActuatorVersion = "2026-07-30.1"

type windowsBootstrapConfig struct {
	ServiceBaseURL string
	TunnelName     string
	LogUploadToken string
}

func (s *Server) handleAdminWindowsBootstrap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	name := defaultWindowsTunnelName(s.cfg.WGEndpoint)
	logUploadToken, err := s.bootstrapLogToken()
	if err != nil {
		if s.logger != nil {
			s.logger.Printf("bootstrap log token failed: %v", err)
		}
		http.Error(w, "bootstrap log token failed", http.StatusInternalServerError)
		return
	}
	script := renderWindowsBootstrapScript(windowsBootstrapConfig{
		ServiceBaseURL: s.bootstrapServiceBaseURL(r),
		TunnelName:     name,
		LogUploadToken: logUploadToken,
	})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/x-powershell; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+"-startup.ps1"))
	_, _ = w.Write([]byte(script))
}

func (s *Server) bootstrapServiceBaseURL(r *http.Request) string {
	if configured := strings.TrimRight(strings.TrimSpace(s.cfg.PublicURL), "/"); configured != "" {
		return configured
	}
	return publicBaseURL(r)
}

func renderWindowsBootstrapScript(cfg windowsBootstrapConfig) string {
	tunnelName := strings.TrimSpace(cfg.TunnelName)
	if tunnelName == "" {
		tunnelName = "bruecke"
	}
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.ServiceBaseURL), "/")
	template := windowsBootstrapTemplate
	replacer := strings.NewReplacer(
		"__SERVICE_BASE_URL__", psSingleQuoted(baseURL),
		"__WIREGUARD_INSTALLER_URL__", psSingleQuoted(windowsWireGuardInstallerURL),
		"__TUNNEL_NAME__", psSingleQuoted(tunnelName),
		"__BOOTSTRAP_LOG_TOKEN__", psSingleQuoted(strings.TrimSpace(cfg.LogUploadToken)),
		"__WINDOWS_ACTUATOR_VERSION__", windowsActuatorVersion,
	)
	return replacer.Replace(template)
}

func publicBaseURL(r *http.Request) string {
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		proto = strings.ToLower(strings.TrimSpace(strings.Split(forwarded, ",")[0]))
	}
	host := strings.TrimSpace(r.Host)
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwarded != "" {
		host = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	return proto + "://" + host
}

func defaultWindowsTunnelName(endpoint string) string {
	host, err := hostFromEndpoint(endpoint)
	if err != nil {
		host = "bruecke"
	}
	host = strings.ToLower(host)
	name := regexp.MustCompile(`[^a-z0-9-]+`).ReplaceAllString(host, "-")
	name = strings.Trim(name, "-")
	if name == "" {
		name = "bruecke"
	}
	if !strings.HasPrefix(name, "bruecke-") {
		name = "bruecke-" + name
	}
	if len(name) > 64 {
		name = name[:64]
		name = strings.TrimRight(name, "-")
	}
	return name
}

func psSingleQuoted(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

const windowsBootstrapTemplate = `# bruecke Windows startup bootstrap
# Run as LocalSystem or Administrator. Installs WireGuard, fetches fresh config via machine cert enrollment,
# rewrites the actuator, registers its network-change task, then runs it. Deploy this script via GPO as a computer startup script.

$ErrorActionPreference = 'Stop'
$ServiceBaseUrl = __SERVICE_BASE_URL__
$WireGuardInstallerUrl = __WIREGUARD_INSTALLER_URL__
$TunnelName = __TUNNEL_NAME__
$BootstrapLogToken = __BOOTSTRAP_LOG_TOKEN__
$script:LocalNetworkJson = '[]'
$script:BootstrapRunId = [guid]::NewGuid().ToString('N')
$script:BootstrapStatus = 'running'
$script:BootstrapHostname = ''
$script:BootstrapClientId = ''
$script:CertificateSubject = ''
$script:CertificateIssuer = ''
$script:CertificateThumbprint = ''
$script:LogSeq = 0
$script:LogQueue = New-Object 'System.Collections.Generic.List[object]'

$ProgramDataDir = Join-Path $env:ProgramData 'bruecke'
$ConfigPath = Join-Path $ProgramDataDir ($TunnelName + '.conf')
$ActuatorPath = Join-Path $ProgramDataDir ($TunnelName + '-actuator.ps1')
$LocalNetworkPath = Join-Path $ProgramDataDir ($TunnelName + '-local-network.json')
$BootstrapLogPath = Join-Path $ProgramDataDir 'bootstrap.log'
$WireGuardExe = 'C:\Program Files\WireGuard\wireguard.exe'

function ConvertTo-LogString($Value, [int]$MaxLength = 4096) {
    if ($null -eq $Value) { return '' }
    $text = [string]$Value
    if ($text.Length -gt $MaxLength) { return $text.Substring(0, $MaxLength) }
    return $text
}

function Redact-BrueckeLogMessage([string]$Message) {
    $text = ConvertTo-LogString $Message 4096
    $text = [regex]::Replace($text, '(?i)(Authorization:\s*Bearer\s+)[^\s]+', '$1[redacted]')
    $text = [regex]::Replace($text, '(?i)(bootstrap_log_token\s*[=:]\s*)[^\s,;]+', '$1[redacted]')
    $text = [regex]::Replace($text, '(?is)PrivateKey\s*=\s*[^\r\n]+', 'PrivateKey = [redacted]')
    $text = [regex]::Replace($text, '(?is)signature"?\s*[:=]\s*"?[^"\s,}]+' , 'signature:[redacted]')
    return $text
}

function Write-BrueckeLocalLog([string]$Line) {
    try {
        New-Item -ItemType Directory -Force -Path $ProgramDataDir | Out-Null
        Add-Content -LiteralPath $BootstrapLogPath -Value $Line -Encoding UTF8
    } catch {}
}

function ConvertTo-BrueckeJsonBytes($Value, [int]$Depth = 12) {
    $json = $Value | ConvertTo-Json -Depth $Depth -Compress
    return [System.Text.Encoding]::UTF8.GetBytes($json)
}

function Get-BrueckeJsonProperty($Value, [string]$Name) {
    if ($null -eq $Value) { return $null }
    $property = $Value.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function ConvertTo-BrueckeProcessArgument([string]$Value) {
    if ($null -eq $Value) { return '""' }
    if ($Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    $quote = [string][char]34
    $result = $quote
    $slashes = 0
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq '\') {
            $slashes++
            continue
        }
        if ($ch -eq [char]34) {
            if ($slashes -gt 0) {
                $result += ('\' * ($slashes * 2))
                $slashes = 0
            }
            $result += '\'
            $result += $quote
            continue
        }
        if ($slashes -gt 0) {
            $result += ('\' * $slashes)
            $slashes = 0
        }
        $result += [string]$ch
    }
    if ($slashes -gt 0) { $result += ('\' * ($slashes * 2)) }
    $result += $quote
    return $result
}

function Split-BrueckeProcessLines([string]$Text) {
    $lines = New-Object 'System.Collections.Generic.List[string]'
    if ([string]::IsNullOrEmpty($Text)) { return @() }
    foreach ($line in ($Text -split '\r?\n')) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            $lines.Add($line) | Out-Null
        }
    }
    return @($lines.ToArray())
}

function Invoke-BrueckeNativeCommand([string]$FilePath, [string[]]$Arguments) {
    $escaped = New-Object 'System.Collections.Generic.List[string]'
    foreach ($arg in @($Arguments)) {
        $escaped.Add((ConvertTo-BrueckeProcessArgument ([string]$arg))) | Out-Null
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = [string]::Join(' ', $escaped.ToArray())
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    try {
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    } catch {}
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    try {
        if (-not $process.Start()) { throw "failed to start $FilePath" }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        return [pscustomobject]@{
            ExitCode = [int]$process.ExitCode
            StdoutLines = @(Split-BrueckeProcessLines $stdout)
            StderrLines = @(Split-BrueckeProcessLines $stderr)
        }
    } finally {
        $process.Dispose()
    }
}

function Send-BrueckeLogs([string]$Status = 'running') {
    if ([string]::IsNullOrWhiteSpace($BootstrapLogToken)) { return }
    if ($script:LogQueue.Count -eq 0) { return }
    $events = @($script:LogQueue.ToArray())
    $body = @{
        run_id = $script:BootstrapRunId
        computer_name = [string]$env:COMPUTERNAME
        hostname = [string]$script:BootstrapHostname
        client_id = [string]$script:BootstrapClientId
        certificate_subject = [string]$script:CertificateSubject
        certificate_issuer = [string]$script:CertificateIssuer
        certificate_thumbprint = [string]$script:CertificateThumbprint
        service_base_url = [string]$ServiceBaseUrl
        tunnel_name = [string]$TunnelName
        powershell_version = [string]$PSVersionTable.PSVersion
        status = [string]$Status
        events = $events
    }
    try {
        [byte[]]$bodyBytes = @(ConvertTo-BrueckeJsonBytes $body 10)
        Invoke-WebRequest -Uri ($ServiceBaseUrl + '/api/bootstrap-logs') -Method Post -Body $bodyBytes -ContentType 'application/json; charset=utf-8' -Headers @{ Authorization = ('Bearer ' + $BootstrapLogToken) } -UseBasicParsing -TimeoutSec 15 | Out-Null
        $script:LogQueue.Clear()
    } catch {
        $stamp = (Get-Date).ToUniversalTime().ToString('o')
        Write-BrueckeLocalLog "[$stamp] [warn] [log-upload] upload failed: $($_.Exception.Message)"
    }
}

function Add-BrueckeLogEvent([string]$Stamp, [string]$Level, [string]$Phase, [string]$Message) {
    $safeMessage = Redact-BrueckeLogMessage $Message
    $safeLevel = ConvertTo-LogString $Level 32
    $safePhase = ConvertTo-LogString $Phase 80
    $script:LogSeq++
    $script:LogQueue.Add([pscustomobject]@{
        seq = $script:LogSeq
        time = $Stamp
        level = $safeLevel
        phase = $safePhase
        message = $safeMessage
    })
    if ($script:LogQueue.Count -gt 200) {
        $script:LogQueue.RemoveRange(0, $script:LogQueue.Count - 200)
    }
    if ($script:LogQueue.Count -ge 10) {
        Send-BrueckeLogs -Status $script:BootstrapStatus
    }
}

function Write-BrueckeLog([string]$Message, [string]$Level = 'info', [string]$Phase = 'bootstrap') {
    $stamp = (Get-Date).ToUniversalTime().ToString('o')
    $safeMessage = Redact-BrueckeLogMessage $Message
    $safeLevel = ConvertTo-LogString $Level 32
    $safePhase = ConvertTo-LogString $Phase 80
    Write-BrueckeLocalLog "[$stamp] [$safeLevel] [$safePhase] $safeMessage"
    Add-BrueckeLogEvent $stamp $safeLevel $safePhase $safeMessage
}

function Write-BrueckeNativeCommandOutput($Result, [string]$Phase = 'process') {
    foreach ($line in @($Result.StdoutLines)) {
        Write-BrueckeLog ([string]$line) 'info' $Phase
    }
    foreach ($line in @($Result.StderrLines)) {
        Write-BrueckeLog ([string]$line) 'warn' $Phase
    }
}

function Get-BrueckeLocalLogLength {
    try {
        if (Test-Path -LiteralPath $BootstrapLogPath) {
            return [int64](Get-Item -LiteralPath $BootstrapLogPath).Length
        }
    } catch {}
    return [int64]0
}

function Import-BrueckeLocalLogSince([int64]$Offset) {
    if (-not (Test-Path -LiteralPath $BootstrapLogPath)) { return }
    $stream = $null
    $reader = $null
    try {
        $stream = [System.IO.File]::Open($BootstrapLogPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        if ($Offset -ge $stream.Length) { return }
        if ($Offset -gt 0) { $stream.Seek($Offset, [System.IO.SeekOrigin]::Begin) | Out-Null }
        $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8, $true)
        while ($null -ne ($line = $reader.ReadLine())) {
            if ($line -match '^\[(?<time>[^\]]+)\]\s+\[(?<level>[^\]]+)\]\s+\[(?<phase>[^\]]+)\]\s+(?<message>.*)$') {
                Add-BrueckeLogEvent $Matches['time'] $Matches['level'] $Matches['phase'] $Matches['message']
            }
        }
    } catch {
        Write-BrueckeLog "Failed to import actuator logs: $($_.Exception.Message)" 'warn' 'actuator'
    } finally {
        if ($null -ne $reader) {
            $reader.Close()
        } elseif ($null -ne $stream) {
            $stream.Close()
        }
    }
}

function Rotate-BrueckeLog {
    try {
        if (Test-Path $BootstrapLogPath) {
            $item = Get-Item -LiteralPath $BootstrapLogPath
            if ($item.Length -gt 1048576) {
                Move-Item -LiteralPath $BootstrapLogPath -Destination ($BootstrapLogPath + '.1') -Force
            }
        }
    } catch {}
}

function ConvertTo-PowerShellLiteral([string]$Value) {
    return "'" + $Value.Replace("'", "''") + "'"
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'bruecke bootstrap must run as Administrator or LocalSystem'
    }
}

function Ensure-WireGuardInstalled {
    if (Test-Path $WireGuardExe) {
        Write-BrueckeLog 'WireGuard already installed'
        return
    }
    Write-BrueckeLog 'WireGuard missing; downloading installer'
    $installerPath = Join-Path $env:TEMP 'wireguard-installer.exe'
    Invoke-WebRequest -Uri $WireGuardInstallerUrl -OutFile $installerPath -UseBasicParsing
    try {
        $process = Start-Process -FilePath $installerPath -ArgumentList '/install /quiet' -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "WireGuard installer exited with $($process.ExitCode)"
        }
    } finally {
        Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path $WireGuardExe)) {
        throw 'WireGuard install finished but wireguard.exe was not found'
    }
}

function Get-BrueckeTunnelServices {
    return @(Get-Service -Name 'WireGuardTunnel$bruecke*' -ErrorAction SilentlyContinue)
}

function Disconnect-BrueckeTunnelsForNetworkRecovery {
    if (-not (Test-Path -LiteralPath $WireGuardExe)) { return $false }
    $services = @(Get-BrueckeTunnelServices)
    if ($services.Count -eq 0) { return $false }
    $prefix = 'WireGuardTunnel$'
    foreach ($service in $services) {
        $name = $service.Name.Substring($prefix.Length)
        Write-BrueckeLog "Temporarily removing tunnel $name to restore bootstrap HTTP access" 'warn' 'network-recovery'
        $result = Invoke-BrueckeNativeCommand $WireGuardExe @('/uninstalltunnelservice', $name)
        Write-BrueckeNativeCommandOutput $result 'network-recovery'
        if ($result.ExitCode -ne 0) {
            Write-BrueckeLog "Tunnel removal for $name exited $($result.ExitCode)" 'warn' 'network-recovery'
        }
    }
    $deadline = (Get-Date).AddSeconds(12)
    while ((Get-Date) -lt $deadline) {
        if (@(Get-BrueckeTunnelServices).Count -eq 0) { return $true }
        Start-Sleep -Milliseconds 500
    }
    Write-BrueckeLog 'One or more bruecke tunnel services remained after recovery wait' 'warn' 'network-recovery'
    return $true
}

function Test-BrueckeServiceReachable([int]$TimeoutSeconds = 8) {
    try {
        $response = Invoke-WebRequest -Uri ($ServiceBaseUrl + '/healthz') -Method Get -UseBasicParsing -TimeoutSec $TimeoutSeconds
        if ([int]$response.StatusCode -eq 200) {
            Write-BrueckeLog "Service health check succeeded at $ServiceBaseUrl" 'info' 'network'
            return $true
        }
        Write-BrueckeLog "Service health check returned HTTP $([int]$response.StatusCode)" 'warn' 'network'
    } catch {
        Write-BrueckeLog "Service health check failed: $($_.Exception.Message)" 'warn' 'network'
    }
    return $false
}

function Assert-BrueckeServiceReachable {
    if (Test-BrueckeServiceReachable) { return }
    $recoveredTunnel = Disconnect-BrueckeTunnelsForNetworkRecovery
    if ($recoveredTunnel) {
        Write-BrueckeLog 'Retrying bootstrap HTTP without the existing WireGuard tunnel' 'warn' 'network-recovery'
    } else {
        Write-BrueckeLog 'Waiting for startup networking before retrying bootstrap HTTP' 'warn' 'network-recovery'
    }
    for ($attempt = 1; $attempt -le 5; $attempt++) {
        Start-Sleep -Seconds 3
        if (Test-BrueckeServiceReachable) { return }
    }
    throw "bruecke service is unreachable at $ServiceBaseUrl after network recovery"
}

function Convert-CertificateToPem([Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
    $body = [Convert]::ToBase64String($Cert.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
    $newline = [Environment]::NewLine
    return '-----BEGIN CERTIFICATE-----' + $newline + $body + $newline + '-----END CERTIFICATE-----' + $newline
}

function Get-CertificateChainPem([Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.VerificationFlags = [Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreWrongUsage
    [void]$chain.Build($Cert)
    $items = @()
    foreach ($element in $chain.ChainElements) {
        $item = $element.Certificate
        if ($item.Thumbprint -eq $Cert.Thumbprint) { continue }
        if ($item.Subject -eq $item.Issuer) { continue }
        $items += Convert-CertificateToPem $item
    }
    return $items
}

function Test-ClientAuthCertificate([Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
    $clientAuthOid = '1.3.6.1.5.5.7.3.2'
    $eku = @($Cert.EnhancedKeyUsageList)
    if ($eku.Count -eq 0) { return $true }
    return [bool]($eku | Where-Object { $_.ObjectId -eq $clientAuthOid })
}

function Test-MicrosoftOrganizationCertificate([Security.Cryptography.X509Certificates.X509Certificate2]$Cert) {
    $identity = "$($Cert.Subject) $($Cert.Issuer)"
    return ($identity -match 'MS-Organization')
}

function Get-CandidateMachineCertificates {
    $now = Get-Date
    $all = @(Get-ChildItem Cert:\LocalMachine\My)
    Write-BrueckeLog "Scanning $($all.Count) LocalMachine\My certificates" 'info' 'certificate'
    $usable = @()
    foreach ($cert in $all) {
        $label = "$($cert.Subject) / $($cert.Issuer) / $($cert.Thumbprint) / notAfter=$($cert.NotAfter.ToString('o'))"
        if (-not $cert.HasPrivateKey) {
            Write-BrueckeLog "Skipping certificate without private key: $label" 'warn' 'certificate'
            continue
        }
        if ($cert.NotBefore -gt $now) {
            Write-BrueckeLog "Skipping certificate not yet valid: $label" 'warn' 'certificate'
            continue
        }
        if ($cert.NotAfter -le $now) {
            Write-BrueckeLog "Skipping expired certificate: $label" 'warn' 'certificate'
            continue
        }
        if (-not (Test-ClientAuthCertificate $cert)) {
            Write-BrueckeLog "Skipping certificate without ClientAuth EKU: $label" 'warn' 'certificate'
            continue
        }
        if (Test-MicrosoftOrganizationCertificate $cert) {
            Write-BrueckeLog "Skipping Microsoft Entra device certificate: $label" 'warn' 'certificate'
            continue
        }
        Write-BrueckeLog "Usable enrollment certificate candidate: $label" 'info' 'certificate'
        $usable += $cert
    }
    return $usable | Sort-Object @{ Expression = { if ($_.Subject -match '\.') { 0 } else { 1 } } }, @{ Expression = { $_.NotAfter }; Descending = $true }
}

function Get-BrueckeErrorBody($ErrorRecord) {
    try {
        if ($null -ne $ErrorRecord.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
            return ConvertTo-LogString (Redact-BrueckeLogMessage $ErrorRecord.ErrorDetails.Message) 1024
        }
        $response = $ErrorRecord.Exception.Response
        if ($null -eq $response) { return '' }
        $stream = $response.GetResponseStream()
        if ($null -eq $stream) { return '' }
        $reader = New-Object System.IO.StreamReader($stream)
        return ConvertTo-LogString (Redact-BrueckeLogMessage $reader.ReadToEnd()) 1024
    } catch {
        return ''
    }
}

function Invoke-BrueckeJson([string]$Path, [hashtable]$Body) {
    [byte[]]$bodyBytes = @(ConvertTo-BrueckeJsonBytes $Body 12)
    Write-BrueckeLog "POST $Path" 'info' 'http'
    try {
        $response = Invoke-WebRequest -Uri ($ServiceBaseUrl + $Path) -Method Post -Body $bodyBytes -ContentType 'application/json; charset=utf-8' -UseBasicParsing -TimeoutSec 45
        Write-BrueckeLog "POST $Path returned HTTP $([int]$response.StatusCode)" 'info' 'http'
        return $response.Content | ConvertFrom-Json
    } catch {
        $err = $_
        $status = ''
        try { if ($null -ne $err.Exception.Response) { $status = [string][int]$err.Exception.Response.StatusCode } } catch {}
        $body = Get-BrueckeErrorBody $err
        if ([string]::IsNullOrWhiteSpace($body)) {
            Write-BrueckeLog "POST $Path failed status=$status error=$($err.Exception.Message)" 'error' 'http'
        } else {
            Write-BrueckeLog "POST $Path failed status=$status body=$body error=$($err.Exception.Message)" 'error' 'http'
        }
        throw
    }
}

function Sign-BrueckeChallenge([Security.Cryptography.X509Certificates.X509Certificate2]$Cert, [byte[]]$Payload) {
    $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
    if ($null -ne $rsa) {
        $signature = $rsa.SignData($Payload, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
        return @{ algorithm = 'sha256-rsa'; signature = [Convert]::ToBase64String($signature) }
    }
    $ecdsa = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Cert)
    if ($null -ne $ecdsa) {
        $signature = $ecdsa.SignData($Payload, [Security.Cryptography.HashAlgorithmName]::SHA256)
        return @{ algorithm = 'sha256-ecdsa'; signature = [Convert]::ToBase64String($signature) }
    }
    throw 'certificate private key is neither RSA nor ECDSA'
}

function Update-WireGuardConfig {
    $lastError = $null
    $certificates = @(Get-CandidateMachineCertificates)
    foreach ($cert in $certificates) {
      for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $script:CertificateSubject = [string]$cert.Subject
            $script:CertificateIssuer = [string]$cert.Issuer
            $script:CertificateThumbprint = [string]$cert.Thumbprint
            Write-BrueckeLog "Trying certificate $($cert.Subject) / issuer=$($cert.Issuer) / thumbprint=$($cert.Thumbprint) attempt=$attempt" 'info' 'enrollment'
            $chainPem = @(Get-CertificateChainPem $cert)
            Write-BrueckeLog "Certificate chain contains $($chainPem.Count) intermediate certificate(s)" 'info' 'certificate'
            $start = Invoke-BrueckeJson '/enroll/start' @{
                certificate = Convert-CertificateToPem $cert
                chain = $chainPem
            }
            $startHostname = [string](Get-BrueckeJsonProperty $start 'hostname')
            $startExpiresAt = [string](Get-BrueckeJsonProperty $start 'expires_at')
            $startChallenge = [string](Get-BrueckeJsonProperty $start 'challenge')
            $startHandshakeID = [string](Get-BrueckeJsonProperty $start 'handshake_id')
            $script:BootstrapHostname = $startHostname
            Write-BrueckeLog "Enrollment handshake started for hostname=$startHostname expires_at=$startExpiresAt" 'info' 'enrollment'
            $payload = [Convert]::FromBase64String($startChallenge)
            $signed = Sign-BrueckeChallenge $cert $payload
            Write-BrueckeLog "Challenge signed with $($signed.algorithm)" 'info' 'enrollment'
            $finish = Invoke-BrueckeJson '/enroll/finish' @{
                handshake_id = $startHandshakeID
                algorithm = [string]$signed.algorithm
                signature = [string]$signed.signature
                response_format = 'json'
            }
            $finishHostname = [string](Get-BrueckeJsonProperty $finish 'hostname')
            $finishClientID = [string](Get-BrueckeJsonProperty $finish 'client_id')
            $finishAddress = [string](Get-BrueckeJsonProperty $finish 'address')
            if (-not [string]::IsNullOrWhiteSpace($finishHostname)) {
                $script:BootstrapHostname = $finishHostname
            }
            if (-not [string]::IsNullOrWhiteSpace($finishClientID)) {
                $script:BootstrapClientId = $finishClientID
            }
            $config = [string](Get-BrueckeJsonProperty $finish 'config')
            if ([string]::IsNullOrWhiteSpace($config)) {
                throw 'empty WireGuard config returned'
            }
            $localNetworks = Get-BrueckeJsonProperty $finish 'local_networks'
            if ($null -eq $localNetworks) {
                $localNetworks = Get-BrueckeJsonProperty $finish 'local_network'
            }
            if ($null -ne $localNetworks) {
                $script:LocalNetworkJson = ConvertTo-Json -InputObject @($localNetworks) -Depth 6 -Compress
            } else {
                $script:LocalNetworkJson = '[]'
            }
            $configuredNetworks = @($localNetworks).Count
            $networkTempPath = $LocalNetworkPath + '.tmp'
            $utf8NoBOM = New-Object System.Text.UTF8Encoding
            [System.IO.File]::WriteAllText($networkTempPath, $script:LocalNetworkJson, $utf8NoBOM)
            Move-Item -LiteralPath $networkTempPath -Destination $LocalNetworkPath -Force
            Write-BrueckeLog "Local network rules saved path=$LocalNetworkPath configured_networks=$configuredNetworks bytes=$($script:LocalNetworkJson.Length)" 'info' 'enrollment'
            $configTempPath = $ConfigPath + '.tmp'
            [System.IO.File]::WriteAllText($configTempPath, $config, [System.Text.Encoding]::ASCII)
            Move-Item -LiteralPath $configTempPath -Destination $ConfigPath -Force
            Write-BrueckeLog "WireGuard config saved to $ConfigPath for client_id=$($script:BootstrapClientId) address=$finishAddress" 'info' 'enrollment'
            Send-BrueckeLogs -Status $script:BootstrapStatus
            return
        } catch {
            $lastError = $_
            Write-BrueckeLog "Enrollment attempt $attempt failed for $($cert.Subject): $($_.Exception.Message)" 'error' 'enrollment'
            Send-BrueckeLogs -Status 'enrollment_failed'
            if ($attempt -lt 3) { Start-Sleep -Seconds 2 }
        }
      }
    }
    if ($lastError) { throw "no machine certificate could enroll: $($lastError.Exception.Message)" }
    throw 'no usable AD CS machine certificate found in Cert:\LocalMachine\My (Microsoft Entra MS-Organization certificates are ignored)'
}

function Write-ActuatorScript {
    $localNetwork = $script:LocalNetworkJson
    if ([string]::IsNullOrWhiteSpace($localNetwork)) { $localNetwork = '[]' }
    $script = @'
param(
    [ValidateSet('bootstrap', 'scheduled-task', 'manual')]
    [string]$TriggerSource = 'manual'
)

$ErrorActionPreference = 'Stop'
$TunnelName = __TUNNEL_NAME_LITERAL__
$ConfigPath = __CONFIG_PATH_LITERAL__
$WireGuardExe = __WIREGUARD_EXE_LITERAL__
$LocalNetworkPath = __LOCAL_NETWORK_PATH_LITERAL__
$ServiceBaseUrl = __ACTUATOR_SERVICE_BASE_URL_LITERAL__
$EventUploadToken = __ACTUATOR_EVENT_UPLOAD_TOKEN_LITERAL__
$ClientId = __ACTUATOR_CLIENT_ID_LITERAL__
$ClientHostname = __ACTUATOR_CLIENT_HOSTNAME_LITERAL__
$ActuatorVersion = __ACTUATOR_VERSION_LITERAL__
$VPNEventOutboxPath = Join-Path (Split-Path -Parent $ConfigPath) ($TunnelName + '-vpn-event-outbox.json')
$VPNEventOutboxLimit = 5000
$VPNEventUploadBatchLimit = 5
$AppliedConfigHashPath = $ConfigPath + '.applied.sha256'
$ActuatorMutexName = 'Global\bruecke-actuator-' + $TunnelName
$script:ActuatorMutex = $null
$script:ActuatorMutexOwned = $false
$script:CidrSelfTestPassed = $null
$EmbeddedLocalNetworkJson = __LOCAL_NETWORK_JSON_LITERAL__
$localNetworkJson = $EmbeddedLocalNetworkJson
$localNetworkSource = 'embedded'
$localNetworkLoadWarning = ''
$decodedLocalNetwork = $null
try {
    if (Test-Path -LiteralPath $LocalNetworkPath) {
        $localNetworkJson = [System.IO.File]::ReadAllText($LocalNetworkPath, [System.Text.Encoding]::UTF8)
        $localNetworkSource = 'cached-file'
    }
    $decodedLocalNetwork = $localNetworkJson | ConvertFrom-Json -ErrorAction Stop
} catch {
    $localNetworkLoadWarning = $_.Exception.Message
    $localNetworkSource = 'embedded-fallback'
    $decodedLocalNetwork = $EmbeddedLocalNetworkJson | ConvertFrom-Json -ErrorAction Stop
}
$LocalNetworks = @()
if ($null -ne $decodedLocalNetwork) {
    foreach ($item in $decodedLocalNetwork) {
        if ($null -eq $item) { continue }
        if ($null -ne $item.PSObject.Properties['type']) {
            $LocalNetworks += $item
        }
    }
    if ($LocalNetworks.Count -eq 0) {
        $wifiConfigured = -not [string]::IsNullOrWhiteSpace(([string]$decodedLocalNetwork.wifi_name + [string]$decodedLocalNetwork.wifi_gateway + [string]$decodedLocalNetwork.wifi_subnet + [string]$decodedLocalNetwork.wifi_search_domain))
        if ($wifiConfigured) {
            $LocalNetworks += [pscustomobject]@{ type = 'wifi'; name = 'Migrated Wi-Fi'; ssid = $decodedLocalNetwork.wifi_name; gateway = $decodedLocalNetwork.wifi_gateway; subnet = $decodedLocalNetwork.wifi_subnet; search_domain = $decodedLocalNetwork.wifi_search_domain }
        }
        $ethernetConfigured = -not [string]::IsNullOrWhiteSpace(([string]$decodedLocalNetwork.eth_gateway + [string]$decodedLocalNetwork.eth_subnet + [string]$decodedLocalNetwork.eth_search_domain))
        if ($ethernetConfigured) {
            $LocalNetworks += [pscustomobject]@{ type = 'ethernet'; name = 'Migrated Ethernet'; ssid = ''; gateway = $decodedLocalNetwork.eth_gateway; subnet = $decodedLocalNetwork.eth_subnet; search_domain = $decodedLocalNetwork.eth_search_domain }
        }
    }
}
$ActuatorLogPath = Join-Path (Split-Path -Parent $ConfigPath) 'bootstrap.log'

function ConvertTo-ActuatorLogString($Value, [int]$MaxLength = 4096) {
    if ($null -eq $Value) { return '' }
    $text = [string]$Value
    if ($text.Length -gt $MaxLength) { return $text.Substring(0, $MaxLength) }
    return $text
}

function Redact-ActuatorLogMessage([string]$Message) {
    $text = ConvertTo-ActuatorLogString $Message 4096
    $text = [regex]::Replace($text, '(?i)(Authorization:\s*Bearer\s+)[^\s]+', '$1[redacted]')
    $text = [regex]::Replace($text, '(?is)PrivateKey\s*=\s*[^\r\n]+', 'PrivateKey = [redacted]')
    return $text
}

function Write-ActuatorLog([string]$Message, [string]$Level = 'info') {
    $stamp = (Get-Date).ToUniversalTime().ToString('o')
    $safeLevel = ConvertTo-ActuatorLogString $Level 32
    $safeMessage = Redact-ActuatorLogMessage $Message
    $line = "[$stamp] [$safeLevel] [actuator] $safeMessage"
    try { Add-Content -LiteralPath $ActuatorLogPath -Value $line -Encoding UTF8 } catch {}
}
function ConvertTo-ActuatorJsonBytes($Value, [int]$Depth = 12) {
    $json = ConvertTo-Json -InputObject $Value -Depth $Depth -Compress
    return [System.Text.Encoding]::UTF8.GetBytes($json)
}

function Read-VPNEventOutbox {
    if (-not (Test-Path -LiteralPath $VPNEventOutboxPath)) { return @() }
    try {
        $json = [System.IO.File]::ReadAllText($VPNEventOutboxPath, [System.Text.Encoding]::UTF8)
        if ([string]::IsNullOrWhiteSpace($json)) { return @() }
        return @($json | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        Write-ActuatorLog "Could not read VPN event outbox path=$VPNEventOutboxPath error=$($_.Exception.Message)" 'warn'
        return @()
    }
}

function Write-VPNEventOutbox($Events) {
    $items = @($Events)
    $tempPath = $VPNEventOutboxPath + '.' + $PID + '.tmp'
    try {
        $json = ConvertTo-Json -InputObject $items -Depth 12 -Compress
        $utf8NoBOM = New-Object System.Text.UTF8Encoding
        [System.IO.File]::WriteAllText($tempPath, $json, $utf8NoBOM)
        Move-Item -LiteralPath $tempPath -Destination $VPNEventOutboxPath -Force
    } finally {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }

}

function Add-VPNEventToOutbox($Event) {
    $cutoff = (Get-Date).ToUniversalTime().AddDays(-7)
    $kept = New-Object 'System.Collections.Generic.List[object]'
    foreach ($existing in @(Read-VPNEventOutbox)) {
        if ($null -eq $existing) { continue }
        if ([string]$existing.event_id -eq [string]$Event.event_id) { continue }
        $occurredAt = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse([string]$existing.occurred_at, [ref]$occurredAt)) { continue }
        if ($occurredAt.UtcDateTime -lt $cutoff) { continue }
        $kept.Add($existing) | Out-Null
    }
    $kept.Add($Event) | Out-Null
    $items = @($kept.ToArray())
    if ($items.Count -gt $VPNEventOutboxLimit) {
        $items = @($items | Select-Object -Last $VPNEventOutboxLimit)
    }
    Write-VPNEventOutbox $items
    Write-ActuatorLog "Queued VPN decision event event_id=$($Event.event_id) outbox_count=$($items.Count) path=$VPNEventOutboxPath"
}

function Flush-VPNEventOutbox {
    if ([string]::IsNullOrWhiteSpace($EventUploadToken)) { return }
    for ($uploadBatch = 1; $uploadBatch -le $VPNEventUploadBatchLimit; $uploadBatch++) {
        $events = @(Read-VPNEventOutbox)
        if ($events.Count -eq 0) { return }
        $batch = @($events | Select-Object -First 100)
        try {
            [byte[]]$bodyBytes = @(ConvertTo-ActuatorJsonBytes @{ events = $batch } 12)
            Invoke-WebRequest -Uri ($ServiceBaseUrl + '/api/vpn-events') -Method Post -Body $bodyBytes -ContentType 'application/json; charset=utf-8' -Headers @{ Authorization = ('Bearer ' + $EventUploadToken) } -UseBasicParsing -TimeoutSec 5 | Out-Null
            $remaining = @($events | Select-Object -Skip $batch.Count)
            Write-VPNEventOutbox $remaining
            Write-ActuatorLog "Uploaded VPN decision events count=$($batch.Count) remaining=$($remaining.Count)"
        } catch {
            Write-ActuatorLog "VPN decision event upload deferred queued=$($events.Count) error=$($_.Exception.Message)" 'warn'
            return
        }
    }
}

function Publish-VPNDecisionEvent([string]$Decision, [string]$DesiredState, [string]$StateBefore, [string]$StateAfter, [string]$Outcome, [string]$Reason, $Evaluations) {
    $eventClientId = ([string]$ClientId).Trim()
    if (-not $eventClientId) { $eventClientId = ([string]$ClientHostname).Trim() }
    if (-not $eventClientId) { $eventClientId = ([string]$env:COMPUTERNAME).Trim() }
    $event = [pscustomobject]@{
        event_id = [guid]::NewGuid().ToString('N')
        occurred_at = (Get-Date).ToUniversalTime().ToString('o')
        client_id = $eventClientId
        computer_name = [string]$env:COMPUTERNAME
        hostname = [string]$ClientHostname
        tunnel_name = [string]$TunnelName
        actuator_version = [string]$ActuatorVersion
        trigger_source = [string]$TriggerSource
        decision = [string]$Decision
        desired_state = [string]$DesiredState
        state_before = [string]$StateBefore
        state_after = [string]$StateAfter
        outcome = [string]$Outcome
        reason = Redact-ActuatorLogMessage $Reason
        evaluations = @($Evaluations)
    }
    try {
        Add-VPNEventToOutbox $event
    } catch {
        Write-ActuatorLog "Could not persist VPN decision event event_id=$($event.event_id) error=$($_.Exception.Message)" 'error'
        return
    }
    Flush-VPNEventOutbox
}

function ConvertTo-ActuatorProcessArgument([string]$Value) {
    if ($null -eq $Value) { return '""' }
    if ($Value.Length -eq 0) { return '""' }
    if ($Value -notmatch '[\s"]') { return $Value }
    $quote = [string][char]34
    $result = $quote
    $slashes = 0
    foreach ($ch in $Value.ToCharArray()) {
        if ($ch -eq '\') {
            $slashes++
            continue
        }
        if ($ch -eq [char]34) {
            if ($slashes -gt 0) {
                $result += ('\' * ($slashes * 2))
                $slashes = 0
            }
            $result += '\'
            $result += $quote
            continue
        }
        if ($slashes -gt 0) {
            $result += ('\' * $slashes)
            $slashes = 0
        }
        $result += [string]$ch
    }
    if ($slashes -gt 0) { $result += ('\' * ($slashes * 2)) }
    $result += $quote
    return $result
}

function Split-ActuatorProcessLines([string]$Text) {
    $lines = New-Object 'System.Collections.Generic.List[string]'
    if ([string]::IsNullOrEmpty($Text)) { return @() }
    foreach ($line in ($Text -split '\r?\n')) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            $lines.Add($line) | Out-Null
        }
    }
    return @($lines.ToArray())
}

function Invoke-ActuatorNativeCommand([string]$FilePath, [string[]]$Arguments) {
    $escaped = New-Object 'System.Collections.Generic.List[string]'
    foreach ($arg in @($Arguments)) {
        $escaped.Add((ConvertTo-ActuatorProcessArgument ([string]$arg))) | Out-Null
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = [string]::Join(' ', $escaped.ToArray())
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    try {
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    } catch {}
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    try {
        if (-not $process.Start()) { throw "failed to start $FilePath" }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        return [pscustomobject]@{
            ExitCode = [int]$process.ExitCode
            StdoutLines = @(Split-ActuatorProcessLines $stdout)
            StderrLines = @(Split-ActuatorProcessLines $stderr)
        }
    } finally {
        $process.Dispose()
    }
}

function Write-ActuatorNativeCommandOutput($Result) {
    foreach ($line in @($Result.StdoutLines)) {
        Write-ActuatorLog ([string]$line)
    }
    foreach ($line in @($Result.StderrLines)) {
        Write-ActuatorLog ([string]$line) 'warn'
    }
}

function Test-IPv4InCidr([string]$IPAddress, [string]$CIDR) {
    try {
        $parts = $CIDR.Split('/')
        if ($parts.Count -ne 2) { return $false }
        $bits = [int]$parts[1]
        if ($bits -lt 0 -or $bits -gt 32) { return $false }
        $ipBytes = [Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
        $networkBytes = [Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
        if ($ipBytes.Length -ne 4 -or $networkBytes.Length -ne 4) { return $false }

        $wholeBytes = [int][Math]::Floor($bits / 8)
        for ($index = 0; $index -lt $wholeBytes; $index++) {
            if ($ipBytes[$index] -ne $networkBytes[$index]) { return $false }
        }
        $remainingBits = $bits % 8
        if ($remainingBits -gt 0) {
            $divisor = [int][Math]::Pow(2, 8 - $remainingBits)
            $ipPrefix = [int][Math]::Floor(([int]$ipBytes[$wholeBytes]) / $divisor)
            $networkPrefix = [int][Math]::Floor(([int]$networkBytes[$wholeBytes]) / $divisor)
            if ($ipPrefix -ne $networkPrefix) { return $false }
        }
        return $true
    } catch {
        return $false
    }
}

function Test-IPv4CidrImplementation {
    if ($null -ne $script:CidrSelfTestPassed) { return [bool]$script:CidrSelfTestPassed }
    $vectors = @(
        [pscustomobject]@{ Address = '10.30.2.65'; CIDR = '10.30.0.0/21'; Expected = $true },
        [pscustomobject]@{ Address = '10.30.8.1'; CIDR = '10.30.0.0/21'; Expected = $false },
        [pscustomobject]@{ Address = '203.0.113.9'; CIDR = '0.0.0.0/0'; Expected = $true },
        [pscustomobject]@{ Address = '192.0.2.10'; CIDR = '192.0.2.10/32'; Expected = $true },
        [pscustomobject]@{ Address = '192.0.2.11'; CIDR = '192.0.2.10/32'; Expected = $false }
    )
    foreach ($vector in $vectors) {
        $actual = Test-IPv4InCidr $vector.Address $vector.CIDR
        if ($actual -ne $vector.Expected) {
            $script:CidrSelfTestPassed = $false
            Write-ActuatorLog "CIDR runtime self-test failed address=$($vector.Address) cidr=$($vector.CIDR) expected=$($vector.Expected) actual=$actual" 'error'
            return $false
        }
    }
    $script:CidrSelfTestPassed = $true
    Write-ActuatorLog 'CIDR runtime self-test passed'
    return $true
}

function Join-AdapterValues($Values) {
    $items = @($Values | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if ($items.Count -eq 0) { return '-' }
    return [string]::Join(',', [string[]]$items)
}

function Get-AdapterSSIDObservation($Adapter) {
    $names = New-Object 'System.Collections.Generic.List[string]'
    $ssidErrors = New-Object 'System.Collections.Generic.List[string]'
    $adapterGuid = $null
    try {
        $adapterGuid = [guid]$Adapter.NetAdapter.InterfaceGuid
    } catch {
        $ssidErrors.Add("adapter GUID unavailable: $($_.Exception.Message)") | Out-Null
    }
    if ($null -ne $adapterGuid) {
        try {
            $profiles = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetConnectionProfiles()
            $matchingProfileFound = $false
            foreach ($profile in @($profiles)) {
                try {
                    if ($null -eq $profile.NetworkAdapter -or $profile.NetworkAdapter.NetworkAdapterId -ne $adapterGuid) { continue }
                    $matchingProfileFound = $true
                    if ($null -eq $profile.WlanConnectionProfileDetails) { continue }
                    $ssid = ([string]$profile.WlanConnectionProfileDetails.GetConnectedSsid()).Trim()
                    if ($ssid -and -not $names.Contains($ssid)) {
                        $names.Add($ssid) | Out-Null
                    }
                } catch {
                    $ssidErrors.Add("connected SSID lookup failed: $($_.Exception.Message)") | Out-Null
                }
            }
            if (-not $matchingProfileFound) {
                $ssidErrors.Add('no WinRT connection profile matched the adapter GUID') | Out-Null
            } elseif ($names.Count -eq 0 -and $ssidErrors.Count -eq 0) {
                $ssidErrors.Add('matching WinRT profile did not expose a connected SSID') | Out-Null
            }
        } catch {
            $ssidErrors.Add("WinRT connection-profile enumeration failed: $($_.Exception.Message)") | Out-Null
        }
    }
    $status = 'unavailable'
    if ($names.Count -gt 0) { $status = 'available' }
    return [pscustomobject]@{
        Status = $status
        Names = [string[]]$names.ToArray()
        Errors = [string[]]$ssidErrors.ToArray()
    }
}

function Get-AdapterNetworkProfileObservation($Adapter) {
    $names = New-Object 'System.Collections.Generic.List[string]'
    $profileErrors = New-Object 'System.Collections.Generic.List[string]'
    try {
        foreach ($profile in @(Get-NetConnectionProfile -InterfaceIndex $Adapter.InterfaceIndex -ErrorAction Stop)) {
            $name = ([string]$profile.Name).Trim()
            if ($name -and -not $names.Contains($name)) { $names.Add($name) | Out-Null }
        }
    } catch {
        $profileErrors.Add($_.Exception.Message) | Out-Null
    }
    return [pscustomobject]@{
        Names = [string[]]$names.ToArray()
        Errors = [string[]]$profileErrors.ToArray()
    }
}

function Get-AdapterKind($Adapter) {
    $netAdapter = $Adapter.NetAdapter
    try {
        $mediumNumber = [int]$netAdapter.NdisPhysicalMedium
        if ($mediumNumber -eq 1 -or $mediumNumber -eq 9) { return 'wifi' }
    } catch {}
    $media = "$($netAdapter.NdisPhysicalMedium) $($netAdapter.PhysicalMediaType) $($netAdapter.MediaType)"
    if ($media -match '(?i)wireless|802[._ -]?11|wi-?fi|wlan') { return 'wifi' }
    $identity = "$($Adapter.InterfaceDescription) $($Adapter.InterfaceAlias)"
    if ($identity -match '(?i)wireless|802[._ -]?11|wi-?fi|wlan') { return 'wifi' }
    return 'ethernet'
}

function Test-IgnoredLocalAdapter($Adapter) {
    $identity = "$($Adapter.InterfaceDescription) $($Adapter.InterfaceAlias) $($Adapter.NetAdapter.Name)"
    if ($Adapter.InterfaceAlias -ieq $TunnelName) { return $true }
    return ($identity -match '(?i)wireguard|wintun|openvpn|tap-windows|loopback|isatap|teredo|6to4')
}

function Get-AdapterGateways($Adapter) {
    $gateways = @($Adapter.IPv4DefaultGateway | ForEach-Object { ([string]$_.NextHop).Trim() } | Where-Object { $_ -and $_ -ne '0.0.0.0' })
    if ($gateways.Count -eq 0) {
        try {
            $gateways = @(Get-NetRoute -AddressFamily IPv4 -InterfaceIndex $Adapter.InterfaceIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                ForEach-Object { ([string]$_.NextHop).Trim() } | Where-Object { $_ -and $_ -ne '0.0.0.0' })
        } catch {}
    }
    return @($gateways | Select-Object -Unique)
}

function Get-AdapterDNSSuffixes($Adapter) {
    try {
        return @(Get-DnsClient -InterfaceIndex $Adapter.InterfaceIndex -ErrorAction Stop |
            ForEach-Object { ([string]$_.ConnectionSpecificSuffix).Trim().TrimEnd('.') } |
            Where-Object { $_ } | Select-Object -Unique)
    } catch {
        return @()
    }
}

function Get-AdapterAddressCIDRs($Adapter) {
    $values = New-Object 'System.Collections.Generic.List[string]'
    foreach ($address in @($Adapter.IPv4Address)) {
        $ip = ([string]$address.IPAddress).Trim()
        if (-not $ip) { continue }
        try {
            $prefixLength = [int]$address.PrefixLength
            $values.Add("$ip/$prefixLength") | Out-Null
        } catch {
            $values.Add($ip) | Out-Null
        }
    }
    return [string[]]$values.ToArray()
}

function Test-AdapterAddressMatchesCIDR($Adapter, [string]$CIDR) {
    try {
        $parts = $CIDR.Split('/')
        if ($parts.Count -ne 2) { return $false }
        $wantedPrefixLength = [int]$parts[1]
        foreach ($address in @($Adapter.IPv4Address)) {
            $ip = ([string]$address.IPAddress).Trim()
            if (-not $ip) { continue }
            $actualPrefixLength = [int]$address.PrefixLength
            if ($actualPrefixLength -ne $wantedPrefixLength) { continue }
            if (Test-IPv4InCidr $ip $CIDR) { return $true }
        }
    } catch {}
    return $false
}

function Test-AdapterMatchesLegacy($Adapter, [string]$Kind, $Profile, [int]$ProfileIndex, $SSIDObservation) {
    $gateway = ([string]$Profile.gateway).Trim()
    $subnet = ([string]$Profile.subnet).Trim()
    $searchDomain = ([string]$Profile.search_domain).Trim()
    $wifiName = ([string]$Profile.ssid).Trim()
    $profileName = ([string]$Profile.name).Trim()
    $ruleLabel = "#$ProfileIndex $Kind"
    if ($profileName) { $ruleLabel = "#$ProfileIndex $profileName" }

    $criteria = 0
    $failures = New-Object 'System.Collections.Generic.List[string]'
    $unavailable = New-Object 'System.Collections.Generic.List[string]'
    $gatewayMatched = $false
    $subnetMatched = $false
    $addressCIDRs = @(Get-AdapterAddressCIDRs $Adapter)
    $gateways = @(Get-AdapterGateways $Adapter)
    $dnsSuffixes = @(Get-AdapterDNSSuffixes $Adapter)
    $adapterLabel = "$($Adapter.InterfaceAlias)#$($Adapter.InterfaceIndex)"

    if ($wifiName) {
        $criteria++
        if ($Kind -ne 'wifi') {
            $failures.Add('adapter is not Wi-Fi') | Out-Null
        } elseif ($SSIDObservation.Status -ne 'available') {
            $unavailable.Add("SSID expected=$wifiName actual=unavailable") | Out-Null
        } elseif (@($SSIDObservation.Names | Where-Object { $_ -ieq $wifiName }).Count -eq 0) {
            $failures.Add("SSID expected=$wifiName actual=$(Join-AdapterValues $SSIDObservation.Names)") | Out-Null
        }
    }

    if ($gateway) {
        $criteria++
        if ($gateways.Count -eq 0) {
            $unavailable.Add("gateway expected=$gateway actual=unavailable") | Out-Null
        } elseif (@($gateways | Where-Object { $_ -eq $gateway }).Count -eq 0) {
            $failures.Add("gateway expected=$gateway actual=$(Join-AdapterValues $gateways)") | Out-Null
        } else {
            $gatewayMatched = $true
        }
    }

    if ($subnet) {
        $criteria++
        if ($addressCIDRs.Count -eq 0) {
            $unavailable.Add("subnet expected=$subnet addresses=unavailable") | Out-Null
        } elseif (-not (Test-AdapterAddressMatchesCIDR $Adapter $subnet)) {
            $failures.Add("subnet expected=$subnet addresses=$(Join-AdapterValues $addressCIDRs) (address and prefix length must match)") | Out-Null
        } else {
            $subnetMatched = $true
        }
    }

    if ($searchDomain) {
        $criteria++
        $wantedSuffix = $searchDomain.Trim().TrimEnd('.')
        if ($dnsSuffixes.Count -eq 0) {
            $unavailable.Add("DNS suffix expected=$wantedSuffix actual=unavailable") | Out-Null
        } elseif (@($dnsSuffixes | Where-Object { $_ -ieq $wantedSuffix }).Count -eq 0) {
            $failures.Add("DNS suffix expected=$wantedSuffix actual=$(Join-AdapterValues $dnsSuffixes)") | Out-Null
        }
    }

    if ($criteria -eq 0) {
        return [pscustomobject]@{ Matched = $false; Indeterminate = $false; UsedFallback = $false }
    }
    if ($failures.Count -gt 0) {
        Write-ActuatorLog "Local network profile $ruleLabel did not match adapter=$adapterLabel reasons=$([string]::Join('; ', $failures.ToArray()))"
        return [pscustomobject]@{ Matched = $false; Indeterminate = $false; UsedFallback = $false }
    }
    if ($unavailable.Count -eq 0) {
        Write-ActuatorLog "Local network profile $ruleLabel matched adapter=$adapterLabel criteria=$criteria"
        return [pscustomobject]@{ Matched = $true; Indeterminate = $false; UsedFallback = $false }
    }
    if ($gateway -and $subnet -and $gatewayMatched -and $subnetMatched) {
        Write-ActuatorLog "Local network profile $ruleLabel matched adapter=$adapterLabel using strong topology fallback; gateway and strict subnet matched while observations were unavailable=$([string]::Join('; ', $unavailable.ToArray()))"
        return [pscustomobject]@{ Matched = $true; Indeterminate = $false; UsedFallback = $true }
    }

    Write-ActuatorLog "Local network profile $ruleLabel is indeterminate for adapter=$adapterLabel unavailable=$([string]::Join('; ', $unavailable.ToArray()))"
    return [pscustomobject]@{ Matched = $false; Indeterminate = $true; UsedFallback = $false }
}

function Test-AdapterMatches($Adapter, [string]$Kind, $Profile, [int]$ProfileIndex, $SSIDObservation) {
    $profileKind = ([string]$Profile.type).Trim().ToLowerInvariant()
    $gateway = ([string]$Profile.gateway).Trim()
    $subnet = ([string]$Profile.subnet).Trim()
    $searchDomain = ([string]$Profile.search_domain).Trim().TrimEnd('.')
    $wifiName = ([string]$Profile.ssid).Trim()
    $profileName = ([string]$Profile.name).Trim()
    $ruleLabel = "#$ProfileIndex $profileKind"
    if ($profileName) { $ruleLabel = "#$ProfileIndex $profileName" }

    $failures = New-Object 'System.Collections.Generic.List[string]'
    $unavailable = New-Object 'System.Collections.Generic.List[string]'
    $gatewayMatched = $false
    $subnetMatched = $false
    $addressCIDRs = @(Get-AdapterAddressCIDRs $Adapter)
    $gateways = @(Get-AdapterGateways $Adapter)
    $dnsSuffixes = @(Get-AdapterDNSSuffixes $Adapter)
    $adapterLabel = "$($Adapter.InterfaceAlias)#$($Adapter.InterfaceIndex)"

    if ($Kind -ne $profileKind) {
        $failures.Add("adapter type expected=$profileKind actual=$Kind") | Out-Null
    }

    if ($wifiName) {
        if ($Kind -ne 'wifi') {
            $failures.Add('adapter is not Wi-Fi') | Out-Null
        } elseif ($SSIDObservation.Status -ne 'available') {
            $unavailable.Add("SSID expected=$wifiName actual=unavailable") | Out-Null
        } elseif (@($SSIDObservation.Names | Where-Object { $_ -ieq $wifiName }).Count -eq 0) {
            $failures.Add("SSID expected=$wifiName actual=$(Join-AdapterValues $SSIDObservation.Names)") | Out-Null
        }
    }

    if ($gateway) {
        if ($gateways.Count -eq 0) {
            $unavailable.Add("gateway expected=$gateway actual=unavailable") | Out-Null
        } elseif (@($gateways | Where-Object { $_ -eq $gateway }).Count -eq 0) {
            $failures.Add("gateway expected=$gateway actual=$(Join-AdapterValues $gateways)") | Out-Null
        } else {
            $gatewayMatched = $true
        }
    }

    if ($subnet) {
        if ($addressCIDRs.Count -eq 0) {
            $unavailable.Add("subnet expected=$subnet addresses=unavailable") | Out-Null
        } elseif (-not (Test-AdapterAddressMatchesCIDR $Adapter $subnet)) {
            $failures.Add("subnet expected=$subnet addresses=$(Join-AdapterValues $addressCIDRs) (address and prefix length must match)") | Out-Null
        } else {
            $subnetMatched = $true
        }
    }

    if ($searchDomain) {
        if ($dnsSuffixes.Count -eq 0) {
            $unavailable.Add("DNS suffix expected=$searchDomain actual=unavailable") | Out-Null
        } elseif (@($dnsSuffixes | Where-Object { $_ -ieq $searchDomain }).Count -eq 0) {
            $failures.Add("DNS suffix expected=$searchDomain actual=$(Join-AdapterValues $dnsSuffixes)") | Out-Null
        }
    }


    $matched = $false
    $usedFallback = $false
    $indeterminate = $false
    if ($failures.Count -gt 0) {
        Write-ActuatorLog "Local network profile $ruleLabel did not match adapter=$adapterLabel reasons=$([string]::Join('; ', $failures.ToArray()))"
    } elseif ($unavailable.Count -eq 0) {
        $matched = $true
        Write-ActuatorLog "Local network profile $ruleLabel matched adapter=$adapterLabel"
    } elseif ($gateway -and $subnet -and $gatewayMatched -and $subnetMatched) {
        $matched = $true
        $usedFallback = $true
        Write-ActuatorLog "Local network profile $ruleLabel matched adapter=$adapterLabel using strong topology fallback; gateway and strict subnet matched while observations were unavailable=$([string]::Join('; ', $unavailable.ToArray()))"
    } else {
        $indeterminate = $true
        Write-ActuatorLog "Local network profile $ruleLabel is indeterminate for adapter=$adapterLabel unavailable=$([string]::Join('; ', $unavailable.ToArray()))"
    }

    $expectedSSIDs = @()
    if ($wifiName) { $expectedSSIDs = @($wifiName) }
    $expectedGateways = @()
    if ($gateway) { $expectedGateways = @($gateway) }
    $expectedCIDRs = @()
    if ($subnet) { $expectedCIDRs = @($subnet) }
    $expectedDNS = @()
    if ($searchDomain) { $expectedDNS = @($searchDomain) }
    $evaluation = [pscustomobject]@{
        profile_index = $ProfileIndex
        profile_type = $profileKind
        adapter_alias = [string]$Adapter.InterfaceAlias
        adapter_index = [int]$Adapter.InterfaceIndex
        matched = $matched
        used_fallback = $usedFallback
        expected = [pscustomobject]@{
            kind = $profileKind
            ssids = @($expectedSSIDs)
            gateways = @($expectedGateways)
            address_cidrs = @($expectedCIDRs)
            dns_suffixes = @($expectedDNS)
        }
        actual = [pscustomobject]@{
            kind = $Kind
            ssids = @($SSIDObservation.Names)
            gateways = @($gateways)
            address_cidrs = @($addressCIDRs)
            dns_suffixes = @($dnsSuffixes)
        }
        mismatches = @($failures.ToArray())
        unavailable = @($unavailable.ToArray())
    }
    return [pscustomobject]@{ Matched = $matched; Indeterminate = $indeterminate; UsedFallback = $usedFallback; Evaluation = $evaluation }
}

function Test-InLocalNetwork {
    if (-not (Test-IPv4CidrImplementation)) {
        return [pscustomobject]@{ State = 'Indeterminate'; Summary = 'CIDR runtime self-test failed'; Evaluations = @() }
    }
    $profiles = @($LocalNetworks | Where-Object { $null -ne $_ })
    if ($profiles.Count -eq 0) {
        Write-ActuatorLog 'No local network profiles were supplied by the server'
        return [pscustomobject]@{ State = 'NonLocal'; Summary = 'no local network profiles configured'; Evaluations = @() }
    }
    try {
        $adapters = @(Get-NetIPConfiguration -ErrorAction Stop | Where-Object {
            $null -ne $_.NetAdapter -and
            ($_.NetAdapter.Status -eq 'Up' -or $_.NetAdapter.MediaConnectionState -eq 'Connected') -and
            @($_.IPv4Address).Count -gt 0
        })
    } catch {
        Write-ActuatorLog "Could not enumerate network adapters: $($_.Exception.Message)" 'warn'
        return [pscustomobject]@{ State = 'Indeterminate'; Summary = 'network adapter enumeration failed'; Evaluations = @() }
    }

    $usableAdapters = 0
    $sawIndeterminate = $false
    $evaluations = New-Object 'System.Collections.Generic.List[object]'
    Write-ActuatorLog "Evaluating $($adapters.Count) active IPv4 adapter(s) against $($profiles.Count) local network profile(s)"
    foreach ($adapter in $adapters) {
        if (Test-IgnoredLocalAdapter $adapter) {
            Write-ActuatorLog "Ignoring tunnel adapter $($adapter.InterfaceAlias)#$($adapter.InterfaceIndex)"
            continue
        }
        $usableAdapters++
        $ssidObservation = Get-AdapterSSIDObservation $adapter
        $networkProfileObservation = Get-AdapterNetworkProfileObservation $adapter
        $kind = Get-AdapterKind $adapter
        $addressCIDRs = @(Get-AdapterAddressCIDRs $adapter)
        $gateways = @(Get-AdapterGateways $adapter)
        $suffixes = @(Get-AdapterDNSSuffixes $adapter)
        Write-ActuatorLog "Observed adapter=$($adapter.InterfaceAlias)#$($adapter.InterfaceIndex) kind=$kind description=$($adapter.InterfaceDescription) addresses=$(Join-AdapterValues $addressCIDRs) gateways=$(Join-AdapterValues $gateways) ssid_status=$($ssidObservation.Status) ssids=$(Join-AdapterValues $ssidObservation.Names) network_profiles=$(Join-AdapterValues $networkProfileObservation.Names) dns_suffixes=$(Join-AdapterValues $suffixes)"
        if (@($ssidObservation.Errors).Count -gt 0) {
            Write-ActuatorLog "SSID observation unavailable adapter=$($adapter.InterfaceAlias)#$($adapter.InterfaceIndex) details=$(Join-AdapterValues $ssidObservation.Errors)" 'warn'
        }
        if (@($networkProfileObservation.Errors).Count -gt 0) {
            Write-ActuatorLog "Network profile observation failed adapter=$($adapter.InterfaceAlias)#$($adapter.InterfaceIndex) details=$(Join-AdapterValues $networkProfileObservation.Errors)" 'warn'
        }

        for ($index = 0; $index -lt $profiles.Count; $index++) {
            $profile = $profiles[$index]
            $profileKind = ([string]$profile.type).Trim().ToLowerInvariant()
            if ($profileKind -ne 'wifi' -and $profileKind -ne 'ethernet') {
                Write-ActuatorLog "Ignoring local network profile #$($index + 1) with unsupported type=$profileKind" 'warn'
                continue
            }
            $match = Test-AdapterMatches $adapter $kind $profile ($index + 1) $ssidObservation
            $evaluations.Add($match.Evaluation) | Out-Null
            if ($match.Matched) {
                return [pscustomobject]@{ State = 'Local'; Summary = "profile #$($index + 1) matched adapter $($adapter.InterfaceAlias)"; Evaluations = @($evaluations.ToArray()) }
            }
            if ($match.Indeterminate) { $sawIndeterminate = $true }
        }
    }

    if ($usableAdapters -eq 0) {
        Write-ActuatorLog 'No active physical IPv4 adapter is ready for local-network detection'
        return [pscustomobject]@{ State = 'Indeterminate'; Summary = 'no active physical IPv4 adapter ready'; Evaluations = @($evaluations.ToArray()) }
    }
    if ($sawIndeterminate) {
        Write-ActuatorLog 'No profile matched, but at least one profile still has unavailable observations'
        return [pscustomobject]@{ State = 'Indeterminate'; Summary = 'one or more configured observations unavailable'; Evaluations = @($evaluations.ToArray()) }
    }
    Write-ActuatorLog 'No active adapter matched any configured local network profile'
    return [pscustomobject]@{ State = 'NonLocal'; Summary = 'all observed profiles mismatched'; Evaluations = @($evaluations.ToArray()) }
}

function Get-StableLocalNetworkDecision([int]$TimeoutSeconds = 30, [int]$IntervalSeconds = 2, [int]$RequiredSamples = 2) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $lastState = ''
    $consecutiveSamples = 0
    $sampleNumber = 0
    $lastResult = $null
    do {
        $sampleNumber++
        $result = Test-InLocalNetwork
        $lastResult = $result
        Write-ActuatorLog "Detection sample=$sampleNumber state=$($result.State) summary=$($result.Summary)"
        if ($result.State -eq 'Local' -or $result.State -eq 'NonLocal') {
            if ($result.State -eq $lastState) {
                $consecutiveSamples++
            } else {
                $lastState = $result.State
                $consecutiveSamples = 1
            }
            if ($consecutiveSamples -ge $RequiredSamples) {
                Write-ActuatorLog "Stable local-network decision=$($result.State) samples=$consecutiveSamples"
                return $result
            }
        } else {
            $lastState = ''
            $consecutiveSamples = 0
        }
        if ((Get-Date) -ge $deadline) { break }
        Start-Sleep -Seconds $IntervalSeconds
    } while ($true)

    Write-ActuatorLog "Local-network detection remained indeterminate or unstable for $TimeoutSeconds seconds; forcing VPN on" 'warn'
    $lastEvaluations = @()
    if ($null -ne $lastResult) { $lastEvaluations = @($lastResult.Evaluations) }
    return [pscustomobject]@{ State = 'Indeterminate'; Summary = 'detection timeout; force-on safety policy'; Evaluations = $lastEvaluations }
}

function Enter-ActuatorMutex {
    try {
        $script:ActuatorMutex = New-Object System.Threading.Mutex($false, $ActuatorMutexName)
        try {
            $script:ActuatorMutexOwned = $script:ActuatorMutex.WaitOne([TimeSpan]::FromSeconds(60))
        } catch [System.Threading.AbandonedMutexException] {
            $script:ActuatorMutexOwned = $true
            Write-ActuatorLog "Recovered abandoned actuator mutex $ActuatorMutexName" 'warn'
        }
        if (-not $script:ActuatorMutexOwned) {
            Write-ActuatorLog "Another actuator owns $ActuatorMutexName after 60 seconds; skipping duplicate run" 'warn'
            $script:ActuatorMutex.Dispose()
            $script:ActuatorMutex = $null
            return $false
        }
        return $true
    } catch {
        Write-ActuatorLog "Could not acquire actuator mutex $($ActuatorMutexName): $($_.Exception.Message)" 'error'
        throw
    }
}

function Exit-ActuatorMutex {
    if ($null -eq $script:ActuatorMutex) { return }
    try {
        if ($script:ActuatorMutexOwned) { $script:ActuatorMutex.ReleaseMutex() }
    } catch {
        Write-ActuatorLog "Could not release actuator mutex $($ActuatorMutexName): $($_.Exception.Message)" 'warn'
    } finally {
        $script:ActuatorMutex.Dispose()
        $script:ActuatorMutex = $null
        $script:ActuatorMutexOwned = $false
    }
}

function Get-TunnelService([string]$Name) {
    $serviceName = 'WireGuardTunnel$' + $Name
    return Get-Service -Name $serviceName -ErrorAction SilentlyContinue
}

function Get-TunnelServiceState([string]$Name) {
    $service = Get-TunnelService $Name
    if ($null -eq $service) { return 'not installed' }
    return [string]$service.Status
}

function Get-TunnelNetworkAdapters([string]$Name) {
    try {
        return @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
            $_.Name -ieq $Name -or $_.InterfaceAlias -ieq $Name
        })
    } catch {
        Write-ActuatorLog "Could not enumerate tunnel network adapters while reconciling $($Name): $($_.Exception.Message)" 'warn'
        return @()
    }
}

function Get-TunnelState([string]$Name) {
    $service = Get-TunnelService $Name
    try {
        $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {
            $_.Name -ieq $Name -or $_.InterfaceAlias -ieq $Name
        })
    } catch {
        Write-ActuatorLog "Could not observe tunnel state for $($Name): $($_.Exception.Message)" 'warn'
        return [pscustomobject]@{ State = 'unknown'; ServiceState = 'unknown'; AdapterCount = 0 }
    }
    $serviceState = 'not installed'
    if ($null -ne $service) { $serviceState = [string]$service.Status }
    if (Test-TunnelServiceEnabled $serviceState) { return [pscustomobject]@{ State = 'on'; ServiceState = $serviceState; AdapterCount = $adapters.Count } }
    if ($null -eq $service -and $adapters.Count -eq 0) { return [pscustomobject]@{ State = 'off'; ServiceState = $serviceState; AdapterCount = 0 } }
    return [pscustomobject]@{ State = 'partial'; ServiceState = $serviceState; AdapterCount = $adapters.Count }
}

function Wait-TunnelEnabled([string]$Name, [int]$TimeoutSeconds = 20) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $state = Get-TunnelState $Name
        if ($state.State -eq 'on') { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}


function Wait-TunnelAbsent([string]$Name, [int]$TimeoutSeconds = 20) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ($null -eq (Get-TunnelService $Name) -and @(Get-TunnelNetworkAdapters $Name).Count -eq 0) {
            return $true
        }
        Start-Sleep -Milliseconds 500
    }
    return ($null -eq (Get-TunnelService $Name) -and @(Get-TunnelNetworkAdapters $Name).Count -eq 0)
}

function Stop-Tunnel([string]$Name) {
    $serviceName = 'WireGuardTunnel$' + $Name
    $service = Get-TunnelService $Name
    $adapters = @(Get-TunnelNetworkAdapters $Name)
    if ($null -eq $service -and $adapters.Count -eq 0) {
        Write-ActuatorLog "Tunnel service $serviceName and adapter $Name are absent"
        return $true
    }
    $serviceState = 'not installed'
    if ($null -ne $service) { $serviceState = [string]$service.Status }
    Write-ActuatorLog "Stopping tunnel $Name service_state=$serviceState adapter_count=$($adapters.Count)"
    $result = Invoke-ActuatorNativeCommand $WireGuardExe @('/uninstalltunnelservice', $Name)
    Write-ActuatorNativeCommandOutput $result
    if ($result.ExitCode -ne 0) {
        Write-ActuatorLog "WireGuard uninstall tunnel $Name exited $($result.ExitCode)" 'warn'
    }
    if (Wait-TunnelAbsent $Name 20) {
        Write-ActuatorLog "Tunnel service $serviceName and adapter $Name are absent"
        return $true
    }
    $remainingAdapters = @(Get-TunnelNetworkAdapters $Name)
    Write-ActuatorLog "Tunnel still exists after uninstall wait service_state=$(Get-TunnelServiceState $Name) adapter_count=$($remainingAdapters.Count)" 'warn'
    return $false
}

function Stop-OtherBrueckeTunnels {
    $prefix = 'WireGuardTunnel$'
    $current = $prefix + $TunnelName
    Get-Service -Name 'WireGuardTunnel$bruecke*' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne $current } |
        ForEach-Object { [void](Stop-Tunnel ($_.Name.Substring($prefix.Length))) }
}

function Get-DesiredConfigHash {
    if (-not (Test-Path -LiteralPath $ConfigPath)) { return '' }
    return ([string](Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash).Trim().ToUpperInvariant()
}

function Get-AppliedConfigHash {
    try {
        if (-not (Test-Path -LiteralPath $AppliedConfigHashPath)) { return '' }
        $hash = ([System.IO.File]::ReadAllText($AppliedConfigHashPath, [System.Text.Encoding]::ASCII)).Trim().ToUpperInvariant()
        if ($hash -notmatch '^[0-9A-F]{64}$') {
            Write-ActuatorLog "Ignoring invalid applied-config hash marker path=$AppliedConfigHashPath" 'warn'
            return ''
        }
        return $hash
    } catch {
        Write-ActuatorLog "Could not read applied-config hash marker: $($_.Exception.Message)" 'warn'
        return ''
    }
}

function Set-AppliedConfigHash([string]$Hash) {
    $normalizedHash = $Hash.Trim().ToUpperInvariant()
    if ($normalizedHash -notmatch '^[0-9A-F]{64}$') {
        throw 'refusing to persist an invalid applied-config hash'
    }
    $tempPath = $AppliedConfigHashPath + '.' + $PID + '.tmp'
    try {
        [System.IO.File]::WriteAllText($tempPath, $normalizedHash, [System.Text.Encoding]::ASCII)
        Move-Item -LiteralPath $tempPath -Destination $AppliedConfigHashPath -Force
    } finally {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    }
    Write-ActuatorLog "Recorded applied WireGuard config hash path=$AppliedConfigHashPath sha256=$normalizedHash"
}

function Test-TunnelServiceEnabled([string]$State) {
    return ($State -eq 'Running' -or $State -eq 'StartPending')
}

function Write-WireGuardInstallDiagnostics([string]$DesiredHash, [string]$AppliedHash) {
    if (Test-Path -LiteralPath $WireGuardExe) {
        Write-ActuatorLog "WireGuard executable exists at $WireGuardExe"
    } else {
        Write-ActuatorLog "WireGuard executable is missing at $WireGuardExe" 'warn'
    }
    if (Test-Path -LiteralPath $ConfigPath) {
        $item = Get-Item -LiteralPath $ConfigPath
        $appliedHashLabel = $AppliedHash
        if (-not $appliedHashLabel) { $appliedHashLabel = '-' }
        Write-ActuatorLog "WireGuard config ready path=$ConfigPath bytes=$($item.Length) desired_sha256=$DesiredHash applied_sha256=$appliedHashLabel"
    } else {
        Write-ActuatorLog "WireGuard config path is missing: $ConfigPath" 'warn'
    }
}

function Install-Tunnel {
    $attempts = 2
    $lastExit = 0
    for ($attempt = 1; $attempt -le $attempts; $attempt++) {
        Write-ActuatorLog "Installing WireGuard tunnel service from $ConfigPath attempt=$attempt"
        $result = Invoke-ActuatorNativeCommand $WireGuardExe @('/installtunnelservice', $ConfigPath)
        Write-ActuatorNativeCommandOutput $result
        $lastExit = [int]$result.ExitCode
        if ($lastExit -eq 0) {
            Write-ActuatorLog "WireGuard tunnel service installed"
            return
        }
        $state = Get-TunnelServiceState $TunnelName
        Write-ActuatorLog "WireGuard install attempt $attempt exited $lastExit service_state=$state" 'warn'
        if ($attempt -lt $attempts) {
            [void](Stop-Tunnel $TunnelName)
            Start-Sleep -Seconds 2
        }
    }
    $finalState = Get-TunnelServiceState $TunnelName
    Write-ActuatorLog "WireGuard install failed after $attempts attempt(s) exit=$lastExit service_state=$finalState" 'error'
    throw "WireGuard install tunnel service exited $lastExit after $attempts attempt(s)"
}

function Ensure-Tunnel {
    $desiredHash = Get-DesiredConfigHash
    if (-not $desiredHash) {
        throw "cannot enable tunnel because the desired config is missing or unreadable: $ConfigPath"
    }
    $appliedHash = Get-AppliedConfigHash
    $service = Get-TunnelService $TunnelName
    $tunnelAdapters = @(Get-TunnelNetworkAdapters $TunnelName)
    $serviceState = 'not installed'
    if ($null -ne $service) { $serviceState = [string]$service.Status }
    $serviceEnabled = Test-TunnelServiceEnabled $serviceState

    Write-WireGuardInstallDiagnostics $desiredHash $appliedHash
    if ($serviceEnabled -and $appliedHash -eq $desiredHash) {
        Write-ActuatorLog "Tunnel already enabled with current config; no interface change required service_state=$serviceState sha256=$desiredHash"
        return [pscustomobject]@{ Changed = $false; Reason = 'already enabled with current config' }
    }

    $reason = 'service is not installed'
    if ($null -eq $service -and $tunnelAdapters.Count -gt 0) {
        $reason = "service is not installed but $($tunnelAdapters.Count) tunnel adapter(s) remain"
    } elseif ($null -ne $service -and -not $serviceEnabled) {
        $reason = "service is not enabled (state=$serviceState)"
    } elseif ($serviceEnabled -and -not $appliedHash) {
        $reason = 'applied-config marker is missing'
    } elseif ($serviceEnabled -and $appliedHash -ne $desiredHash) {
        $reason = 'desired config changed'
    }
    Write-ActuatorLog "Tunnel reconciliation requires installation reason=$reason"

    if (($null -ne $service -or $tunnelAdapters.Count -gt 0) -and -not (Stop-Tunnel $TunnelName)) {
        throw "could not remove existing tunnel before installation service_state=$(Get-TunnelServiceState $TunnelName) adapter_count=$(@(Get-TunnelNetworkAdapters $TunnelName).Count)"
    }
    Install-Tunnel
    if (-not (Wait-TunnelEnabled $TunnelName 20)) {
        throw "tunnel service did not reach an enabled state after installation state=$(Get-TunnelServiceState $TunnelName)"
    }
    Set-AppliedConfigHash $desiredHash
    Write-ActuatorLog "Tunnel reconciliation complete service_state=$(Get-TunnelServiceState $TunnelName) sha256=$desiredHash"
    return [pscustomobject]@{ Changed = $true; Reason = $reason }
}
$decision = $null
$decisionName = 'indeterminate'
$desiredState = 'on'
$outcome = 'failed'
$reason = ''
$evaluations = @()
$eventPublished = $false
$stateBefore = [pscustomobject]@{ State = 'unknown'; ServiceState = 'unknown'; AdapterCount = 0 }
$stateAfter = $stateBefore
try {
    Write-ActuatorLog "Actuator starting for tunnel $TunnelName trigger=$TriggerSource configured_profiles=$($LocalNetworks.Count) local_network_source=$localNetworkSource actuator_version=$ActuatorVersion"
    if ($localNetworkLoadWarning) {
        Write-ActuatorLog "Cached local-network rules could not be loaded; using embedded fallback: $localNetworkLoadWarning" 'warn'
    }
    if (-not (Enter-ActuatorMutex)) { exit 0 }

    $stateBefore = Get-TunnelState $TunnelName
    $stateAfter = $stateBefore
    $decision = Get-StableLocalNetworkDecision
    $reason = [string]$decision.Summary
    $evaluations = @($decision.Evaluations)
    if ($decision.State -eq 'Local') {
        $decisionName = 'local'
        $desiredState = 'off'
        if ($stateBefore.State -eq 'off') {
            $outcome = 'no_op'
            Write-ActuatorLog "VPN already disabled on local network; no interface change required reason=$reason"
        } else {
            Write-ActuatorLog "VPN deactivation requested decision=local state_before=$($stateBefore.State) reason=$reason"
            if (-not (Stop-Tunnel $TunnelName)) {
                throw "local network matched but tunnel could not be disabled state=$(Get-TunnelServiceState $TunnelName)"
            }
            $stateAfter = Get-TunnelState $TunnelName
            if ($stateAfter.State -ne 'off') {
                throw "local network matched but tunnel state is $($stateAfter.State) after deactivation"
            }
            $outcome = 'deactivated'
            Write-ActuatorLog "VPN deactivated decision=local state_after=off reason=$reason"
        }
    } else {
        if ($decision.State -eq 'NonLocal') { $decisionName = 'non_local' }
        if ($decision.State -eq 'Indeterminate') {
            $decisionName = 'indeterminate'
            Write-ActuatorLog "Local-network decision is indeterminate; force-on safety policy applies reason=$reason" 'warn'
        }
        $desiredState = 'on'
        if (-not (Test-Path -LiteralPath $ConfigPath)) {
            throw "cannot enforce VPN on because config is missing: $ConfigPath"
        }
        Stop-OtherBrueckeTunnels
        $reconciliation = Ensure-Tunnel
        $stateAfter = Get-TunnelState $TunnelName
        if ($stateAfter.State -ne 'on') {
            throw "VPN should be on but reconciled state is $($stateAfter.State)"
        }
        if ($reconciliation.Changed -or $stateBefore.State -ne 'on') {
            $outcome = 'activated'
            Write-ActuatorLog "VPN activated decision=$decisionName state_after=on reason=$reason"
        } else {
            $outcome = 'no_op'
            Write-ActuatorLog "VPN already enabled; no interface change required decision=$decisionName reason=$reason"
        }
    }

    $stateAfter = Get-TunnelState $TunnelName
    Write-ActuatorLog "VPN decision=$decisionName desired_state=$desiredState outcome=$outcome state_before=$($stateBefore.State) state_after=$($stateAfter.State) reason=$reason"
    Publish-VPNDecisionEvent $decisionName $desiredState $stateBefore.State $stateAfter.State $outcome $reason $evaluations
    $eventPublished = $true
} catch {
    $failureMessage = $_.Exception.Message
    if ($script:ActuatorMutexOwned -and -not $eventPublished) {
        $stateAfter = Get-TunnelState $TunnelName
        $reason = ($reason + '; actuator failure: ' + $failureMessage).Trim(' ', ';')
        Write-ActuatorLog "VPN decision=$decisionName desired_state=$desiredState outcome=failed state_before=$($stateBefore.State) state_after=$($stateAfter.State) reason=$reason" 'error'
        Publish-VPNDecisionEvent $decisionName $desiredState $stateBefore.State $stateAfter.State 'failed' $reason $evaluations
    }
    Write-ActuatorLog "Actuator failed: $failureMessage" 'error'
    throw
} finally {
    Exit-ActuatorMutex
}
'@
    $script = $script.Replace('__TUNNEL_NAME_LITERAL__', (ConvertTo-PowerShellLiteral $TunnelName))
    $script = $script.Replace('__CONFIG_PATH_LITERAL__', (ConvertTo-PowerShellLiteral $ConfigPath))
    $script = $script.Replace('__WIREGUARD_EXE_LITERAL__', (ConvertTo-PowerShellLiteral $WireGuardExe))
    $script = $script.Replace('__LOCAL_NETWORK_PATH_LITERAL__', (ConvertTo-PowerShellLiteral $LocalNetworkPath))
    $script = $script.Replace('__LOCAL_NETWORK_JSON_LITERAL__', (ConvertTo-PowerShellLiteral $localNetwork))
    $script = $script.Replace('__ACTUATOR_SERVICE_BASE_URL_LITERAL__', (ConvertTo-PowerShellLiteral $ServiceBaseUrl))
    $script = $script.Replace('__ACTUATOR_EVENT_UPLOAD_TOKEN_LITERAL__', (ConvertTo-PowerShellLiteral $BootstrapLogToken))
    $script = $script.Replace('__ACTUATOR_CLIENT_ID_LITERAL__', (ConvertTo-PowerShellLiteral $script:BootstrapClientId))
    $script = $script.Replace('__ACTUATOR_CLIENT_HOSTNAME_LITERAL__', (ConvertTo-PowerShellLiteral $script:BootstrapHostname))
    $script = $script.Replace('__ACTUATOR_VERSION_LITERAL__', (ConvertTo-PowerShellLiteral '__WINDOWS_ACTUATOR_VERSION__'))
    $actuatorTokens = $null
    $actuatorParseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($script, [ref]$actuatorTokens, [ref]$actuatorParseErrors)
    if (@($actuatorParseErrors).Count -gt 0) {
        $parseMessages = @($actuatorParseErrors | ForEach-Object {
            "line=$($_.Extent.StartLineNumber) column=$($_.Extent.StartColumnNumber) $($_.Message)"
        })
        throw "generated actuator failed PowerShell parser validation: $([string]::Join('; ', [string[]]$parseMessages))"
    }
    Write-BrueckeLog 'Generated actuator passed PowerShell parser validation' 'info' 'actuator-task'

    $actuatorTempPath = $ActuatorPath + '.' + $script:BootstrapRunId + '.tmp'
    $actuatorBackupPath = $ActuatorPath + '.' + $script:BootstrapRunId + '.bak'
    try {
        [System.IO.File]::WriteAllText($actuatorTempPath, $script, [System.Text.Encoding]::UTF8)
        if (Test-Path -LiteralPath $ActuatorPath) {
            Remove-Item -LiteralPath $actuatorBackupPath -Force -ErrorAction SilentlyContinue
            [System.IO.File]::Replace($actuatorTempPath, $ActuatorPath, $actuatorBackupPath)
        } else {
            [System.IO.File]::Move($actuatorTempPath, $ActuatorPath)
        }
    } finally {
        Remove-Item -LiteralPath $actuatorTempPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $actuatorBackupPath -Force -ErrorAction SilentlyContinue
    }
    Write-BrueckeLog "Actuator updated atomically path=$ActuatorPath" 'info' 'actuator-task'
}

function Set-BrueckeActuatorScheduledTask {
    $taskFolderPath = '\Bruecke'
    $taskName = $TunnelName + '-network-actuator'
    $profiles = @()
    try {
        if (-not [string]::IsNullOrWhiteSpace($script:LocalNetworkJson)) {
            $decodedProfiles = $script:LocalNetworkJson | ConvertFrom-Json -ErrorAction Stop
            foreach ($decodedProfile in $decodedProfiles) {
                if ($null -ne $decodedProfile) { $profiles += $decodedProfile }
            }
        }
    } catch {
        throw "could not decode local network rules before task registration: $($_.Exception.Message)"
    }

    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder = $null
    try { $folder = $service.GetFolder($taskFolderPath) } catch {}

    if ($null -eq $folder) {
        $rootFolder = $service.GetFolder('\')
        $folder = $rootFolder.CreateFolder('Bruecke', $null)
    }

    $definition = $service.NewTask(0)
    $definition.RegistrationInfo.Author = 'bruecke'
    $definition.RegistrationInfo.Description = 'Reevaluate cached bruecke local-network rules and reconcile the WireGuard tunnel.'
    $definition.Settings.Enabled = $true
    $definition.Settings.AllowDemandStart = $true
    $definition.Settings.StartWhenAvailable = $true
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    $definition.Settings.RunOnlyIfNetworkAvailable = $false
    $definition.Settings.MultipleInstances = 2
    $definition.Settings.ExecutionTimeLimit = 'PT5M'

    $definition.Principal.UserId = 'SYSTEM'
    $definition.Principal.LogonType = 5
    $definition.Principal.RunLevel = 1

    $bootTrigger = $definition.Triggers.Create(8)
    $bootTrigger.Delay = 'PT15S'
    $bootTrigger.Enabled = $true

    $eventTrigger = $definition.Triggers.Create(0)
    $eventTrigger.Subscription = "<QueryList><Query Id='0' Path='Microsoft-Windows-NetworkProfile/Operational'><Select Path='Microsoft-Windows-NetworkProfile/Operational'>*[System[Provider[@Name='Microsoft-Windows-NetworkProfile'] and (EventID=10000 or EventID=10001)]]</Select></Query></QueryList>"
    $eventTrigger.Delay = 'PT10S'
    $eventTrigger.Enabled = $true

    $timeTrigger = $definition.Triggers.Create(1)
    $timeTrigger.StartBoundary = (Get-Date).AddMinutes(1).ToString("yyyy-MM-dd'T'HH:mm:ss")
    $timeTrigger.Repetition.Interval = 'PT2M30S'
    $timeTrigger.Repetition.StopAtDurationEnd = $false
    $timeTrigger.Enabled = $true

    $action = $definition.Actions.Create(0)
    $action.Path = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action.Arguments = [string]::Join(' ', [string[]]@(
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        (ConvertTo-BrueckeProcessArgument $ActuatorPath),
        '-TriggerSource',
        'scheduled-task'
    ))
    $action.WorkingDirectory = $ProgramDataDir

    [void]$folder.RegisterTaskDefinition($taskName, $definition, 6, 'SYSTEM', $null, 5, $null)
    Write-BrueckeLog "Registered managed actuator task $taskFolderPath\$taskName triggers=boot+network-profile+2m30s profiles=$($profiles.Count)" 'info' 'actuator-task'
}

try {
    New-Item -ItemType Directory -Force -Path $ProgramDataDir | Out-Null
    Rotate-BrueckeLog
    Write-BrueckeLog "Bootstrap starting run_id=$($script:BootstrapRunId) computer=$($env:COMPUTERNAME) user=$([Security.Principal.WindowsIdentity]::GetCurrent().Name) ps=$($PSVersionTable.PSVersion)" 'info' 'bootstrap'
    Assert-Administrator
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Assert-BrueckeServiceReachable
    Ensure-WireGuardInstalled
    Update-WireGuardConfig
    Write-ActuatorScript
    $taskRegistrationErrorMessage = ''
    try {
        Set-BrueckeActuatorScheduledTask
    } catch {
        $taskRegistrationErrorMessage = $_.Exception.Message
        Write-BrueckeLog "Actuator task registration failed: $taskRegistrationErrorMessage" 'error' 'actuator-task'
    }

    Write-BrueckeLog "Running actuator $ActuatorPath" 'info' 'actuator'
    $actuatorLogOffset = Get-BrueckeLocalLogLength
    $actuatorResult = $null
    try {
        $actuatorResult = Invoke-BrueckeNativeCommand 'powershell.exe' @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $ActuatorPath, '-TriggerSource', 'bootstrap')
    } finally {
        Import-BrueckeLocalLogSince $actuatorLogOffset
    }
    Write-BrueckeNativeCommandOutput $actuatorResult 'actuator-process'
    if ($actuatorResult.ExitCode -ne 0) {
        throw "actuator exited with $($actuatorResult.ExitCode)"
    }
    if ($taskRegistrationErrorMessage) {
        throw "actuator task registration failed after immediate actuator run: $taskRegistrationErrorMessage"
    }
    $script:BootstrapStatus = 'complete'
    Write-BrueckeLog 'Bootstrap complete' 'info' 'bootstrap'
} catch {
    $script:BootstrapStatus = 'failed'
    Write-BrueckeLog "Bootstrap failed: $($_.Exception.Message)" 'error' 'bootstrap'
    if (-not [string]::IsNullOrWhiteSpace($_.ScriptStackTrace)) {
        Write-BrueckeLog $_.ScriptStackTrace 'error' 'bootstrap'
    }
    throw
} finally {
    Send-BrueckeLogs -Status $script:BootstrapStatus
}
`
