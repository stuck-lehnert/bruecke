package bruecke

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWindowsBootstrapScriptEnrollsAndRunsStartupActuator(t *testing.T) {
	script := renderWindowsBootstrapScript(windowsBootstrapConfig{ServiceBaseURL: "https://vpn.example.com", TunnelName: "bruecke-vpn-example-com", LogUploadToken: "upload-token"})

	for _, want := range []string{
		"$ServiceBaseUrl = 'https://vpn.example.com'",
		"$TunnelName = 'bruecke-vpn-example-com'",
		`C:\Program Files\WireGuard\wireguard.exe`,
		`Cert:\LocalMachine\My`,
		"Test-MicrosoftOrganizationCertificate",
		"Skipping Microsoft Entra device certificate",
		"MS-Organization certificates are ignored",
		"/enroll/start",
		"/enroll/finish",
		"response_format = 'json'",
		"ConvertTo-Json -InputObject @($localNetworks) -Depth 6 -Compress",
		"$localNetworks = Get-BrueckeJsonProperty $finish 'local_networks'",
		"ConvertTo-BrueckeJsonBytes",
		"[byte[]]$bodyBytes = @(ConvertTo-BrueckeJsonBytes $Body 12)",
		"[byte[]]$bodyBytes = @(ConvertTo-BrueckeJsonBytes $body 10)",
		"Get-BrueckeJsonProperty",
		"application/json; charset=utf-8",
		"Get-Service -Name $serviceName -ErrorAction SilentlyContinue",
		"$BootstrapLogToken = 'upload-token'",
		"$BootstrapLogPath = Join-Path $ProgramDataDir 'bootstrap.log'",
		"/api/bootstrap-logs",
		"Redact-BrueckeLogMessage",
		"Send-BrueckeLogs",
		"Invoke-BrueckeNativeCommand",
		"Import-BrueckeLocalLogSince",
		"Write-BrueckeNativeCommandOutput",
		"Invoke-ActuatorNativeCommand",
		"Write-ActuatorNativeCommandOutput",
		"Wait-TunnelAbsent",
		"Get-TunnelNetworkAdapters",
		"Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256",
		"$AppliedConfigHashPath = $ConfigPath + '.applied.sha256'",
		"Get-AppliedConfigHash",
		"Set-AppliedConfigHash $desiredHash",
		"WireGuard config ready path=$ConfigPath bytes=$($item.Length) desired_sha256=$DesiredHash applied_sha256=",
		"Tunnel already enabled with current config; no interface change required",
		"Tunnel reconciliation requires installation reason=$reason",
		"Ensure-Tunnel",
		"configured_profiles=$($LocalNetworks.Count) local_network_source=$localNetworkSource",
		"VPN deactivated decision=local",
		"foreach ($item in $decodedLocalNetwork)",
		"WireGuard install failed after $attempts attempt(s)",
		"actuator-process",
		"actuator exited with",
		"Assert-BrueckeServiceReachable",
		"Disconnect-BrueckeTunnelsForNetworkRecovery",
		"Enrollment attempt $attempt failed",
		"Local network rules saved path=$LocalNetworkPath configured_networks=$configuredNetworks",
		"__LOCAL_NETWORK_PATH_LITERAL__",
		"$LocalNetworks = @()",
		"Get-AdapterSSIDObservation",
		"Get-AdapterNetworkProfileObservation",
		"Test-AdapterAddressMatchesCIDR",
		"$actualPrefixLength -ne $wantedPrefixLength",
		"address and prefix length must match",
		"using strong topology fallback",
		"Get-StableLocalNetworkDecision",
		"Detection sample=$sampleNumber",
		"$ActuatorMutexName = 'Global\\bruecke-actuator-' + $TunnelName",
		"$actuatorBackupPath = $ActuatorPath + '.' + $script:BootstrapRunId + '.bak'",
		"[System.IO.File]::Replace($actuatorTempPath, $ActuatorPath, $actuatorBackupPath)",
		"New-Object -ComObject 'Schedule.Service'",
		"$definition.Principal.UserId = 'SYSTEM'",
		"$definition.Settings.MultipleInstances = 2",
		"$bootTrigger.Delay = 'PT15S'",
		"$eventTrigger.Delay = 'PT10S'",
		"$timeTrigger.Repetition.Interval = 'PT2M30S'",
		"EventID=10000 or EventID=10001",
		"/api/vpn-events",
		"$VPNEventOutboxPath",
		"Publish-VPNDecisionEvent",
		"VPN decision=$decisionName",
		"VPN activated decision=$decisionName",
		"force-on safety policy applies",
		"profile_index = $ProfileIndex",
		"actual = [pscustomobject]",
		"Set-BrueckeActuatorScheduledTask",
		"[System.Management.Automation.Language.Parser]::ParseInput($script",
		"Generated actuator passed PowerShell parser validation",
		"$decodedProfiles = $script:LocalNetworkJson | ConvertFrom-Json -ErrorAction Stop",
		"foreach ($decodedProfile in $decodedProfiles)",
		"'-TriggerSource', 'bootstrap'",
		"NdisPhysicalMedium",
		"Get-NetConnectionProfile -InterfaceIndex",
		"Test-IgnoredLocalAdapter",
		"Observed adapter=",
		"for ($index = 0; $index -lt $profiles.Count; $index++)",
		"Local network profile $ruleLabel matched",
		"No active adapter matched any configured local network profile",
		"@('/installtunnelservice', $ConfigPath)",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"Copy-Item -LiteralPath $PSCommandPath",
		"PrivateKey = private",
		"Write-Output $Line",
		"Write-Output $line",
		"2>&1",
		"$LASTEXITCODE",
		"$installOutput = &",
		"$ActuatorMutexName:",
		"Get-Content -LiteralPath $ConfigPath",
		"$finish.address",
		"$start.challenge",
		"netsh wlan show interfaces",
		"Convert-IPv4ToUInt32",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("script must not contain %q", forbidden)
		}
	}

	ssidStart := strings.Index(script, "function Get-AdapterSSIDObservation")
	profileStart := strings.Index(script, "function Get-AdapterNetworkProfileObservation")
	if ssidStart < 0 || profileStart <= ssidStart {
		t.Fatalf("SSID and network-profile observation functions are missing or out of order")
	}
	if strings.Contains(script[ssidStart:profileStart], "Get-NetConnectionProfile") {
		t.Fatal("Windows network-profile names must not be used as SSID candidates")
	}

	localStart := strings.Index(script, "if ($decision.State -eq 'Local') {")
	if localStart < 0 {
		t.Fatal("generated actuator is missing the local reconciliation branch")
	}
	localEndOffset := strings.Index(script[localStart:], "\n    } else {\n        if ($decision.State -eq 'NonLocal')")
	if localEndOffset < 0 {
		t.Fatal("generated actuator is missing the end of its local reconciliation branch")
	}
	localBlock := script[localStart : localStart+localEndOffset]
	if !strings.Contains(localBlock, "Stop-Tunnel $TunnelName") {
		t.Fatal("local branch must disable the tunnel")
	}
	for _, forbidden := range []string{"Ensure-Tunnel", "Install-Tunnel"} {
		if strings.Contains(localBlock, forbidden) {
			t.Fatalf("local branch must not enable the tunnel through %q", forbidden)
		}
	}

	nonLocalStart := strings.Index(script, "if ($decision.State -eq 'NonLocal') { $decisionName = 'non_local' }")
	if nonLocalStart < 0 {
		t.Fatal("generated actuator is missing the non-local reconciliation branch")
	}
	nonLocalEndOffset := strings.Index(script[nonLocalStart:], "} catch {")
	if nonLocalEndOffset < 0 {
		t.Fatal("generated actuator is missing the end of its reconciliation branch")
	}
	nonLocalBlock := script[nonLocalStart : nonLocalStart+nonLocalEndOffset]
	if !strings.Contains(nonLocalBlock, "Ensure-Tunnel") {
		t.Fatal("non-local branch must use idempotent tunnel reconciliation")
	}
	for _, forbidden := range []string{"[void](Stop-Tunnel $TunnelName)", "Install-Tunnel"} {
		if strings.Contains(nonLocalBlock, forbidden) {
			t.Fatalf("non-local branch must not unconditionally execute %q", forbidden)
		}
	}
}

func TestAdminWindowsBootstrapUsesForwardedPublicURL(t *testing.T) {
	app := NewServer(Config{WGEndpoint: "vpn.example.com:51820"}, ServerDependencies{})
	app.sess["token"] = adminSession{ExpiresAt: time.Now().Add(time.Hour)}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/windows-bootstrap.ps1", nil)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "vpn.example.com")
	req.AddCookie(&http.Cookie{Name: adminCookieName, Value: "token"})
	response := httptest.NewRecorder()

	app.Routes().ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); !strings.Contains(got, "application/x-powershell") {
		t.Fatalf("content type=%q", got)
	}
	if got := response.Header().Get("Content-Disposition"); !strings.Contains(got, "bruecke-vpn-example-com-startup.ps1") {
		t.Fatalf("content disposition=%q", got)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache control=%q", got)
	}
	if !strings.Contains(response.Body.String(), "$ServiceBaseUrl = 'https://vpn.example.com'") {
		t.Fatalf("script did not use forwarded public URL")
	}
}

func TestAdminWindowsBootstrapPrefersConfiguredPublicURL(t *testing.T) {
	app := NewServer(Config{WGEndpoint: "vpn.example.com:51820", PublicURL: "https://enroll.example.com/"}, ServerDependencies{})
	app.sess["token"] = adminSession{ExpiresAt: time.Now().Add(time.Hour)}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/windows-bootstrap.ps1", nil)
	req.Host = "internal.example.com"
	req.AddCookie(&http.Cookie{Name: adminCookieName, Value: "token"})
	response := httptest.NewRecorder()

	app.Routes().ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "$ServiceBaseUrl = 'https://enroll.example.com'") {
		t.Fatalf("script did not use configured public URL")
	}
}
