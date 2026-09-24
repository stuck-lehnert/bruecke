//go:build windows

package bruecke

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsBootstrapPowerShellSyntax(t *testing.T) {
	script := renderWindowsBootstrapScript(windowsBootstrapConfig{
		ServiceBaseURL: "https://vpn.example.com",
		TunnelName:     "bruecke-vpn-example-com",
		LogUploadToken: "upload-token",
	})
	path := writePowerShellFixture(t, script)
	command := `$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($env:BRUECKE_SCRIPT_PATH, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    $parseErrors | ForEach-Object { [Console]::Error.WriteLine($_.Message) }
    exit 1
}`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command)
	cmd.Env = append(os.Environ(), "BRUECKE_SCRIPT_PATH="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("parse generated PowerShell: %v\n%s", err, output)
	}
}

func TestWindowsActuatorLocalNetworkFixtures(t *testing.T) {
	script := renderWindowsBootstrapScript(windowsBootstrapConfig{
		ServiceBaseURL: "https://vpn.example.com",
		TunnelName:     "bruecke-vpn-example-com",
		LogUploadToken: "upload-token",
	})
	const actuatorStartMarker = "$script = @'\n"
	start := strings.Index(script, actuatorStartMarker)
	if start < 0 {
		t.Fatal("generated bootstrap is missing actuator here-string")
	}
	actuator := script[start+len(actuatorStartMarker):]
	const entrypointMarker = "\ntry {\n    Write-ActuatorLog \"Actuator starting"
	end := strings.Index(actuator, entrypointMarker)
	if end < 0 {
		t.Fatal("generated actuator is missing entrypoint marker")
	}
	actuator = actuator[:end]
	fixtureDir := t.TempDir()
	configPath := filepath.Join(fixtureDir, "bruecke-test.conf")
	localNetworkPath := filepath.Join(fixtureDir, "bruecke-test-local-network.json")
	actuator = strings.NewReplacer(
		"__TUNNEL_NAME_LITERAL__", psSingleQuoted("bruecke-test"),
		"__CONFIG_PATH_LITERAL__", psSingleQuoted(configPath),
		"__WIREGUARD_EXE_LITERAL__", psSingleQuoted(`C:\Program Files\WireGuard\wireguard.exe`),
		"__LOCAL_NETWORK_PATH_LITERAL__", psSingleQuoted(localNetworkPath),
		"__LOCAL_NETWORK_JSON_LITERAL__", "'[]'",
		"__ACTUATOR_SERVICE_BASE_URL_LITERAL__", "'https://vpn.example.com'",
		"__ACTUATOR_EVENT_UPLOAD_TOKEN_LITERAL__", "'upload-token'",
		"__ACTUATOR_CLIENT_ID_LITERAL__", "'pc1|domain:test'",
		"__ACTUATOR_CLIENT_HOSTNAME_LITERAL__", "'pc1.example.com'",
		"__ACTUATOR_VERSION_LITERAL__", "'fixture'",
	).Replace(actuator)

	fixtures := `
function Get-AdapterGateways($Adapter) { return @('10.30.2.1') }
function Get-AdapterDNSSuffixes($Adapter) { return @('ad.internal') }
function Assert-Fixture([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

$adapter = [pscustomobject]@{
    InterfaceAlias = 'WLAN'
    InterfaceIndex = 16
    InterfaceDescription = 'Intel Wi-Fi fixture'
    NetAdapter = [pscustomobject]@{
        Status = 'Up'
        MediaConnectionState = 'Connected'
        NdisPhysicalMedium = 9
        Name = 'WLAN'
    }
    IPv4Address = @([pscustomobject]@{ IPAddress = '10.30.2.65'; PrefixLength = 21 })
}
$ssidUnavailable = [pscustomobject]@{
    Status = 'unavailable'
    Names = [string[]]@()
    Errors = [string[]]@('access denied')
}
$ssidWrong = [pscustomobject]@{
    Status = 'available'
    Names = [string[]]@('OTHER-WIFI')
    Errors = [string[]]@()
}
$profile21 = [pscustomobject]@{
    type = 'wifi'
    name = 'strict /21 fixture'
    ssid = 'STL-INTERN'
    gateway = '10.30.2.1'
    subnet = '10.30.0.0/21'
    search_domain = 'ad.internal'
}
$profile24 = [pscustomobject]@{
    type = 'wifi'
    name = 'wrong /24 fixture'
    ssid = 'STL-INTERN'
    gateway = '10.30.2.1'
    subnet = '10.30.2.0/24'
    search_domain = 'ad.internal'
}
$ssidOnly = [pscustomobject]@{
    type = 'wifi'
    name = 'SSID only'
    ssid = 'STL-INTERN'
    gateway = ''
    subnet = ''
    search_domain = ''
}

$strictMatch = Test-AdapterMatches $adapter 'wifi' $profile21 1 $ssidUnavailable
Assert-Fixture ($strictMatch.Matched -and $strictMatch.UsedFallback) '/21 plus gateway should satisfy strong topology fallback'

function Get-AdapterDNSSuffixes($Adapter) { return @() }
$systemContextMatch = Test-AdapterMatches $adapter 'wifi' $profile21 2 $ssidUnavailable
Assert-Fixture ($systemContextMatch.Matched -and $systemContextMatch.UsedFallback) 'SYSTEM context with unavailable SSID and DNS suffix must match strict /21 plus gateway'
function Get-AdapterDNSSuffixes($Adapter) { return @('ad.internal') }

$prefixMismatch = Test-AdapterMatches $adapter 'wifi' $profile24 3 $ssidUnavailable
Assert-Fixture (-not $prefixMismatch.Matched -and -not $prefixMismatch.Indeterminate) '/21 adapter must not match configured /24'

$observedSSIDMismatch = Test-AdapterMatches $adapter 'wifi' $profile21 4 $ssidWrong
Assert-Fixture (-not $observedSSIDMismatch.Matched -and -not $observedSSIDMismatch.Indeterminate) 'observed wrong SSID must be a hard mismatch'

$ssidIndeterminate = Test-AdapterMatches $adapter 'wifi' $ssidOnly 5 $ssidUnavailable
Assert-Fixture (-not $ssidIndeterminate.Matched -and $ssidIndeterminate.Indeterminate) 'unavailable SSID cannot satisfy an SSID-only profile'

$decodedProfilesFixture = '[{"type":"wifi"},{"type":"ethernet"}]' | ConvertFrom-Json
$loadedProfilesFixture = @()
foreach ($decodedProfileFixture in $decodedProfilesFixture) {
    if ($null -ne $decodedProfileFixture) { $loadedProfilesFixture += $decodedProfileFixture }
}
Assert-Fixture ($loadedProfilesFixture.Count -eq 2) 'PowerShell 5.1 JSON arrays must load as two profiles'

function Get-NetIPConfiguration { param($ErrorAction); return @($adapter) }
function Get-AdapterSSIDObservation($Adapter) { return $ssidUnavailable }
function Get-AdapterNetworkProfileObservation($Adapter) {
    return [pscustomobject]@{ Names = [string[]]@('ad.internal'); Errors = [string[]]@() }
}
$LocalNetworks = @($profile21)
$networkDecision = Test-InLocalNetwork
Assert-Fixture ($networkDecision.State -eq 'Local') 'complete supplied WLAN fixture must classify as Local'

$script:uninstallCalls = 0
function Get-TunnelService([string]$Name) { return $null }
function Get-TunnelNetworkAdapters([string]$Name) { return @() }
function Invoke-ActuatorNativeCommand([string]$FilePath, [string[]]$Arguments) {
    $script:uninstallCalls++
    return [pscustomobject]@{ ExitCode = 0 }
}
function Write-ActuatorNativeCommandOutput($Result) {}
function Wait-TunnelAbsent([string]$Name, [int]$TimeoutSeconds = 20) { return $true }
$alreadyOff = Stop-Tunnel $TunnelName
Assert-Fixture ($alreadyOff -and $script:uninstallCalls -eq 0) 'an absent tunnel must be an off-state no-op'
function Get-TunnelNetworkAdapters([string]$Name) {
    return @([pscustomobject]@{ Name = $Name; Status = 'Up' })
}
$removedOrphanAdapter = Stop-Tunnel $TunnelName
Assert-Fixture ($removedOrphanAdapter -and $script:uninstallCalls -eq 1) 'an existing tunnel adapter must be uninstalled even when service lookup is empty'

$hashA = 'A' * 64
$hashB = 'B' * 64
$script:stopCalls = 0
$script:installCalls = 0
$script:recordedHash = ''
function Get-DesiredConfigHash { return $hashA }
function Get-AppliedConfigHash { return $hashA }
function Get-TunnelService([string]$Name) { return [pscustomobject]@{ Status = 'Running' } }
function Write-WireGuardInstallDiagnostics([string]$DesiredHash, [string]$AppliedHash) {}
function Stop-Tunnel([string]$Name) { $script:stopCalls++; return $true }
function Install-Tunnel { $script:installCalls++ }
function Set-AppliedConfigHash([string]$Hash) { $script:recordedHash = $Hash }
function Wait-TunnelEnabled([string]$Name, [int]$TimeoutSeconds = 20) { return $true }

Ensure-Tunnel
Assert-Fixture ($script:stopCalls -eq 0 -and $script:installCalls -eq 0) 'current running tunnel must be a no-op'

function Get-AppliedConfigHash { return $hashB }
Ensure-Tunnel
Assert-Fixture ($script:stopCalls -eq 1) 'changed config must remove the running service exactly once'
Assert-Fixture ($script:installCalls -eq 1) 'changed config must install the service exactly once'
Assert-Fixture ($script:recordedHash -eq $hashA) 'changed config must record the desired hash'

$script:stopCalls = 0
$script:installCalls = 0
function Get-TunnelService([string]$Name) { return $null }
function Get-AppliedConfigHash { return $hashA }
Ensure-Tunnel
Assert-Fixture ($script:stopCalls -eq 1) 'non-local reconciliation must remove an orphan tunnel adapter before install'
Assert-Fixture ($script:installCalls -eq 1) 'non-local reconciliation must install after removing an orphan tunnel adapter'
`
	path := writePowerShellFixture(t, actuator+fixtures)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run actuator fixtures: %v\n%s", err, output)
	}
}

func writePowerShellFixture(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.ps1")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write PowerShell fixture: %v", err)
	}
	return path
}
