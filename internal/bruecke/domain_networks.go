package bruecke

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

type DomainLocalNetwork struct {
	Type         string `json:"type"`
	Name         string `json:"name,omitempty"`
	SSID         string `json:"ssid,omitempty"`
	Gateway      string `json:"gateway,omitempty"`
	Subnet       string `json:"subnet,omitempty"`
	SearchDomain string `json:"search_domain,omitempty"`
}

type legacyDomainLocalNetwork struct {
	WifiName         string `json:"wifi_name,omitempty"`
	WifiGateway      string `json:"wifi_gateway,omitempty"`
	WifiSubnet       string `json:"wifi_subnet,omitempty"`
	WifiSearchDomain string `json:"wifi_search_domain,omitempty"`
	EthGateway       string `json:"eth_gateway,omitempty"`
	EthSubnet        string `json:"eth_subnet,omitempty"`
	EthSearchDomain  string `json:"eth_search_domain,omitempty"`
}

func normalizeDomainLocalNetworks(networks []DomainLocalNetwork) ([]DomainLocalNetwork, error) {
	if len(networks) == 0 {
		return nil, nil
	}
	normalized := make([]DomainLocalNetwork, 0, len(networks))
	for index, network := range networks {
		label := fmt.Sprintf("local network %d", index+1)
		network.Type = strings.ToLower(strings.TrimSpace(network.Type))
		network.Name = strings.TrimSpace(network.Name)
		network.SSID = strings.TrimSpace(network.SSID)
		if network.Name != "" {
			label += " (" + network.Name + ")"
		}
		if network.Type != "wifi" && network.Type != "ethernet" {
			return nil, fmt.Errorf("%s type must be wifi or ethernet", label)
		}
		if network.Type == "ethernet" && network.SSID != "" {
			return nil, fmt.Errorf("%s cannot configure an SSID for ethernet", label)
		}
		var err error
		network.Gateway, err = normalizeLocalIPv4(network.Gateway, label+" gateway")
		if err != nil {
			return nil, err
		}
		network.Subnet, err = normalizeLocalIPv4CIDR(network.Subnet, label+" subnet")
		if err != nil {
			return nil, err
		}
		network.SearchDomain, err = normalizeLocalSearchDomain(network.SearchDomain, label+" search domain")
		if err != nil {
			return nil, err
		}
		if network.SSID == "" && network.Gateway == "" && network.Subnet == "" && network.SearchDomain == "" {
			return nil, fmt.Errorf("%s must configure at least one matching field", label)
		}
		normalized = append(normalized, network)
	}
	return normalized, nil
}

func (legacy legacyDomainLocalNetwork) profiles() []DomainLocalNetwork {
	profiles := make([]DomainLocalNetwork, 0, 2)
	if legacy.WifiName != "" || legacy.WifiGateway != "" || legacy.WifiSubnet != "" || legacy.WifiSearchDomain != "" {
		profiles = append(profiles, DomainLocalNetwork{Type: "wifi", SSID: legacy.WifiName, Gateway: legacy.WifiGateway, Subnet: legacy.WifiSubnet, SearchDomain: legacy.WifiSearchDomain})
	}
	if legacy.EthGateway != "" || legacy.EthSubnet != "" || legacy.EthSearchDomain != "" {
		profiles = append(profiles, DomainLocalNetwork{Type: "ethernet", Gateway: legacy.EthGateway, Subnet: legacy.EthSubnet, SearchDomain: legacy.EthSearchDomain})
	}
	return profiles
}

func legacyLocalNetwork(networks []DomainLocalNetwork) legacyDomainLocalNetwork {
	var legacy legacyDomainLocalNetwork
	for _, network := range networks {
		switch network.Type {
		case "wifi":
			if legacy.WifiName == "" && legacy.WifiGateway == "" && legacy.WifiSubnet == "" && legacy.WifiSearchDomain == "" {
				legacy.WifiName = network.SSID
				legacy.WifiGateway = network.Gateway
				legacy.WifiSubnet = network.Subnet
				legacy.WifiSearchDomain = network.SearchDomain
			}
		case "ethernet":
			if legacy.EthGateway == "" && legacy.EthSubnet == "" && legacy.EthSearchDomain == "" {
				legacy.EthGateway = network.Gateway
				legacy.EthSubnet = network.Subnet
				legacy.EthSearchDomain = network.SearchDomain
			}
		}
	}
	return legacy
}

func (legacy legacyDomainLocalNetwork) empty() bool {
	return len(legacy.profiles()) == 0
}

func (d Domain) MarshalJSON() ([]byte, error) {
	type domainAlias Domain
	legacy := legacyLocalNetwork(d.LocalNetworks)
	var legacyPtr *legacyDomainLocalNetwork
	if !legacy.empty() {
		legacyPtr = &legacy
	}
	return json.Marshal(struct {
		domainAlias
		LocalNetwork *legacyDomainLocalNetwork `json:"local_network,omitempty"`
	}{domainAlias: domainAlias(d), LocalNetwork: legacyPtr})
}

func (d *Domain) UnmarshalJSON(data []byte) error {
	type domainAlias Domain
	wire := struct {
		domainAlias
		LocalNetwork legacyDomainLocalNetwork `json:"local_network,omitempty"`
	}{}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*d = Domain(wire.domainAlias)
	if d.LocalNetworks == nil {
		d.LocalNetworks = wire.LocalNetwork.profiles()
	}
	return nil
}

func normalizeLocalIPv4(raw, label string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil || !addr.Is4() {
		return "", fmt.Errorf("%s must be an IPv4 address", label)
	}
	return addr.String(), nil
}

func normalizeLocalIPv4CIDR(raw, label string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !prefix.Addr().Is4() {
		return "", fmt.Errorf("%s must be an IPv4 CIDR", label)
	}
	return prefix.Masked().String(), nil
}

func normalizeLocalSearchDomain(raw, label string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	normalized, err := normalizeHostname(raw)
	if err != nil {
		return "", fmt.Errorf("%s: %w", label, err)
	}
	return normalized, nil
}
