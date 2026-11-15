package bruecke

import (
	_ "embed"
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
		methodNotAllowed(w, http.MethodGet)
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
	return renderWindowsBootstrapTemplate(windowsBootstrapTemplate, cfg)
}

func renderWindowsBootstrapTemplate(template string, cfg windowsBootstrapConfig) string {
	tunnelName := strings.TrimSpace(cfg.TunnelName)
	if tunnelName == "" {
		tunnelName = "bruecke"
	}
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.ServiceBaseURL), "/")
	// Match the former Go raw string literal: carriage returns were discarded.
	// Embedded files retain CRLF when an editor or checkout converts line endings.
	template = strings.ReplaceAll(template, "\r", "")
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

//go:embed windows/bootstrap.ps1
var windowsBootstrapTemplate string
