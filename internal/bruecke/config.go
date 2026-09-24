package bruecke

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr               string
	ACMEHTTPAddr           string
	DataDir                string
	DatabasePath           string
	SettingsPath           string
	TLSTerminate           bool
	TLSHostname            string
	TLSCacheDir            string
	DomainCAFile           string
	DomainCAFiles          []string
	RootStorePath          string
	RemoteSubnetStorePath  string
	RemoteSubnetRuntimeDir string
	BootstrapLogTokenPath  string
	BootstrapLogDir        string
	VPNEventDir            string
	WebDir                 string
	PublicURL              string
	AdminHash              string
	AdminSessionTTL        time.Duration
	AdminCookieSecure      bool
	WGInterface            string
	WGEndpoint             string
	WGServerPublicKey      string
	WGNetwork              netip.Prefix
	WGServerIP             netip.Addr
	WGIPv6Network          netip.Prefix
	WGIPv6ServerIP         netip.Addr
	WGClientAllowedIPs     string
	WGDNSServers           string
	WGSearchDomain         string
	WGPersistentKeepalive  int
	WGConnectedWithin      time.Duration
	ApplyWireGuard         bool
	ApplyRemoteSubnets     bool
	OpenVPNPath            string
	WGListenPort           int
	WGPrivateKeyFile       string
	WGOutboundInterface    string
	WGUpScript             string
	WGDownScript           string
	ApplyPeerScript        string
	RemovePeerScript       string
	PeerStatusScript       string
}

func LoadConfig() (Config, error) {
	dataDir := getenv("BRUECKE_DATA_DIR", "/data")
	tlsTerminate, err := getenvBool("BRUECKE_TLS_TERMINATE", false)
	if err != nil {
		return Config{}, err
	}
	network, err := netip.ParsePrefix(getenv("BRUECKE_WG_CIDR", "10.44.0.0/24"))
	if err != nil {
		return Config{}, fmt.Errorf("BRUECKE_WG_CIDR: %w", err)
	}
	network = network.Masked()
	if !network.Addr().Is4() {
		return Config{}, fmt.Errorf("BRUECKE_WG_CIDR must be IPv4")
	}
	if network.Bits() > 30 {
		return Config{}, fmt.Errorf("BRUECKE_WG_CIDR must leave room for server and clients")
	}

	serverIP, err := firstUsableIP(network)
	if err != nil {
		return Config{}, err
	}
	if raw := strings.TrimSpace(os.Getenv("BRUECKE_WG_SERVER_IP")); raw != "" {
		serverIP, err = netip.ParseAddr(raw)
		if err != nil {
			return Config{}, fmt.Errorf("BRUECKE_WG_SERVER_IP: %w", err)
		}
	}
	if !isUsableHost(network, serverIP) {
		return Config{}, fmt.Errorf("BRUECKE_WG_SERVER_IP must be a usable host inside %s", network)
	}
	ipv6Network, err := netip.ParsePrefix(getenv("BRUECKE_WG_IPV6_CIDR", "fd44:44:44::/64"))
	if err != nil {
		return Config{}, fmt.Errorf("BRUECKE_WG_IPV6_CIDR: %w", err)
	}
	ipv6Network = ipv6Network.Masked()
	if !ipv6Network.Addr().Is6() || ipv6Network.Addr().Is4() {
		return Config{}, fmt.Errorf("BRUECKE_WG_IPV6_CIDR must be IPv6")
	}
	if ipv6Network.Bits() >= 128 {
		return Config{}, fmt.Errorf("BRUECKE_WG_IPV6_CIDR must leave room for server and clients")
	}
	ipv6ServerIP, err := firstUsableIPv6(ipv6Network)
	if err != nil {
		return Config{}, err
	}
	if raw := strings.TrimSpace(os.Getenv("BRUECKE_WG_IPV6_SERVER_IP")); raw != "" {
		ipv6ServerIP, err = netip.ParseAddr(raw)
		if err != nil {
			return Config{}, fmt.Errorf("BRUECKE_WG_IPV6_SERVER_IP: %w", err)
		}
	}
	if !isUsableIPv6Host(ipv6Network, ipv6ServerIP) {
		return Config{}, fmt.Errorf("BRUECKE_WG_IPV6_SERVER_IP must be a usable host inside %s", ipv6Network)
	}

	endpoint := strings.TrimSpace(os.Getenv("BRUECKE_WG_ENDPOINT"))
	if endpoint == "" {
		return Config{}, fmt.Errorf("BRUECKE_WG_ENDPOINT is required")
	}
	serverPublicKey := strings.TrimSpace(os.Getenv("BRUECKE_WG_SERVER_PUBLIC_KEY"))
	if serverPublicKey == "" {
		return Config{}, fmt.Errorf("BRUECKE_WG_SERVER_PUBLIC_KEY is required")
	}
	tlsHostname := strings.TrimSpace(os.Getenv("BRUECKE_TLS_HOSTNAME"))
	if tlsTerminate {
		if tlsHostname == "" {
			tlsHostname, err = hostFromEndpoint(endpoint)
			if err != nil {
				return Config{}, err
			}
		}
	}

	keepalive, err := getenvInt("BRUECKE_WG_PERSISTENT_KEEPALIVE", 25)
	if err != nil {
		return Config{}, err
	}
	if keepalive < 0 {
		return Config{}, fmt.Errorf("BRUECKE_WG_PERSISTENT_KEEPALIVE must be >= 0")
	}

	applyWG, err := getenvBool("BRUECKE_APPLY_WG", true)
	if err != nil {
		return Config{}, err
	}
	applyRemoteSubnets, err := getenvBool("BRUECKE_APPLY_REMOTE_SUBNETS", applyWG)
	if err != nil {
		return Config{}, err
	}
	adminCookieSecure, err := getenvBool("BRUECKE_ADMIN_COOKIE_SECURE", true)
	if err != nil {
		return Config{}, err
	}
	adminSessionSeconds, err := getenvInt("BRUECKE_ADMIN_SESSION_SECONDS", 43200)
	if err != nil {
		return Config{}, err
	}
	if adminSessionSeconds <= 0 {
		return Config{}, fmt.Errorf("BRUECKE_ADMIN_SESSION_SECONDS must be > 0")
	}
	connectedSeconds, err := getenvInt("BRUECKE_WG_CONNECTED_SECONDS", 180)
	if err != nil {
		return Config{}, err
	}
	if connectedSeconds <= 0 {
		return Config{}, fmt.Errorf("BRUECKE_WG_CONNECTED_SECONDS must be > 0")
	}
	listenPort, err := getenvInt("BRUECKE_WG_LISTEN_PORT", 0)
	if err != nil {
		return Config{}, err
	}
	if listenPort == 0 {
		listenPort, err = listenPortFromEndpoint(endpoint)
		if err != nil {
			return Config{}, err
		}
	}
	if listenPort <= 0 || listenPort > 65535 {
		return Config{}, fmt.Errorf("BRUECKE_WG_LISTEN_PORT must be between 1 and 65535")
	}

	addrDefault := ":8080"
	if tlsTerminate {
		addrDefault = ":443"
	}
	publicURL, err := normalizePublicURL(os.Getenv("BRUECKE_PUBLIC_URL"))
	if err != nil {
		return Config{}, err
	}

	return Config{
		HTTPAddr:               getenv("BRUECKE_ADDR", addrDefault),
		ACMEHTTPAddr:           getenv("BRUECKE_ACME_HTTP_ADDR", ":80"),
		DataDir:                dataDir,
		DatabasePath:           getenv("BRUECKE_DB_PATH", filepath.Join(dataDir, "bruecke.json")),
		SettingsPath:           getenv("BRUECKE_SETTINGS_PATH", filepath.Join(dataDir, "settings.json")),
		TLSTerminate:           tlsTerminate,
		TLSHostname:            tlsHostname,
		TLSCacheDir:            getenv("BRUECKE_TLS_CACHE_DIR", filepath.Join(dataDir, "acme-cache")),
		DomainCAFile:           getenv("BRUECKE_CA_CERT", filepath.Join(dataDir, "domain-root-ca.pem")),
		DomainCAFiles:          getenvList("BRUECKE_CA_CERTS", []string{getenv("BRUECKE_CA_CERT", filepath.Join(dataDir, "domain-root-ca.pem"))}),
		RootStorePath:          getenv("BRUECKE_ROOT_STORE_PATH", filepath.Join(dataDir, "root-certs.json")),
		RemoteSubnetStorePath:  getenv("BRUECKE_REMOTE_SUBNET_STORE_PATH", filepath.Join(dataDir, "remote-subnets.json")),
		RemoteSubnetRuntimeDir: getenv("BRUECKE_REMOTE_SUBNET_RUNTIME_DIR", filepath.Join(dataDir, "remote-subnets-runtime")),
		BootstrapLogTokenPath:  getenv("BRUECKE_BOOTSTRAP_LOG_TOKEN_PATH", filepath.Join(dataDir, "bootstrap-log-token")),
		BootstrapLogDir:        getenv("BRUECKE_BOOTSTRAP_LOG_DIR", filepath.Join(dataDir, "bootstrap-logs")),
		VPNEventDir:            getenv("BRUECKE_VPN_EVENT_DIR", filepath.Join(dataDir, "vpn-events")),
		WebDir:                 getenv("BRUECKE_WEB_DIR", "/usr/local/share/bruecke/web"),
		PublicURL:              publicURL,
		AdminHash:              strings.TrimSpace(os.Getenv("ADMIN_HASH")),
		AdminSessionTTL:        time.Duration(adminSessionSeconds) * time.Second,
		AdminCookieSecure:      adminCookieSecure,
		WGInterface:            getenv("BRUECKE_WG_INTERFACE", "wg0"),
		WGEndpoint:             endpoint,
		WGServerPublicKey:      serverPublicKey,
		WGNetwork:              network,
		WGServerIP:             serverIP,
		WGIPv6Network:          ipv6Network,
		WGIPv6ServerIP:         ipv6ServerIP,
		WGClientAllowedIPs:     getenv("BRUECKE_WG_CLIENT_ALLOWED_IPS", "0.0.0.0/0, ::/0"),
		WGDNSServers:           getenv("BRUECKE_WG_DNS", "9.9.9.9"),
		WGSearchDomain:         strings.TrimSpace(os.Getenv("BRUECKE_WG_SEARCH_DOMAIN")),
		WGPersistentKeepalive:  keepalive,
		WGConnectedWithin:      time.Duration(connectedSeconds) * time.Second,
		ApplyWireGuard:         applyWG,
		ApplyRemoteSubnets:     applyRemoteSubnets,
		OpenVPNPath:            getenv("BRUECKE_OPENVPN_PATH", "openvpn"),
		WGListenPort:           listenPort,
		WGPrivateKeyFile:       getenv("BRUECKE_WG_PRIVATE_KEY_FILE", filepath.Join(dataDir, "wg-server.key")),
		WGOutboundInterface:    getenv("BRUECKE_WG_OUTBOUND_INTERFACE", "auto"),
		WGUpScript:             getenv("BRUECKE_WG_UP_SCRIPT", "/usr/local/bin/bruecke-wg-up"),
		WGDownScript:           getenv("BRUECKE_WG_DOWN_SCRIPT", "/usr/local/bin/bruecke-wg-down"),
		ApplyPeerScript:        getenv("BRUECKE_WG_APPLY_PEER_SCRIPT", "/usr/local/bin/bruecke-wg-apply-peer"),
		RemovePeerScript:       getenv("BRUECKE_WG_REMOVE_PEER_SCRIPT", "/usr/local/bin/bruecke-wg-remove-peer"),
		PeerStatusScript:       getenv("BRUECKE_WG_PEER_STATUS_SCRIPT", "/usr/local/bin/bruecke-wg-peer-status"),
	}, nil
}

func normalizePublicURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return "", fmt.Errorf("BRUECKE_PUBLIC_URL must be an absolute http(s) URL")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", fmt.Errorf("BRUECKE_PUBLIC_URL must not contain a path, query, or fragment")
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func getenv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getenvList(key string, fallback []string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parts := strings.Split(value, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			items = append(items, item)
		}
	}
	return items
}

func getenvBool(key string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return parsed, nil
}

func getenvInt(key string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return parsed, nil
}

func hostFromEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("BRUECKE_WG_ENDPOINT is required for TLS hostname")
	}
	host := endpoint
	if parsedHost, _, err := net.SplitHostPort(endpoint); err == nil {
		host = parsedHost
	} else if strings.HasPrefix(endpoint, "[") {
		end := strings.Index(endpoint, "]")
		if end > 1 {
			host = endpoint[1:end]
		}
	} else if strings.Count(endpoint, ":") == 1 {
		parts := strings.Split(endpoint, ":")
		host = parts[0]
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return "", fmt.Errorf("could not derive TLS hostname from BRUECKE_WG_ENDPOINT")
	}
	return host, nil
}

func listenPortFromEndpoint(endpoint string) (int, error) {
	endpoint = strings.TrimSpace(endpoint)
	if _, port, err := net.SplitHostPort(endpoint); err == nil {
		return parsePort("BRUECKE_WG_ENDPOINT port", port)
	}
	if strings.HasPrefix(endpoint, "[") {
		end := strings.Index(endpoint, "]")
		if end >= 0 && len(endpoint) > end+1 && endpoint[end+1] == ':' {
			return parsePort("BRUECKE_WG_ENDPOINT port", endpoint[end+2:])
		}
		return 51820, nil
	}
	if strings.Count(endpoint, ":") == 1 {
		parts := strings.Split(endpoint, ":")
		return parsePort("BRUECKE_WG_ENDPOINT port", parts[1])
	}
	return 51820, nil
}

func parsePort(label, raw string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("%s must be between 1 and 65535", label)
	}
	return port, nil
}
