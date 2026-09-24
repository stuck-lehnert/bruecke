package bruecke

import "time"

type adminSession struct {
	ExpiresAt time.Time
}

type adminLoginRequest struct {
	Password string `json:"password"`
}

type adminSessionResponse struct {
	Authenticated bool `json:"authenticated"`
}

type adminClientsResponse struct {
	Clients     []adminClient `json:"clients"`
	StatusError string        `json:"status_error,omitempty"`
}

type adminRemoteSubnetsResponse struct {
	Subnets []RemoteSubnetView `json:"subnets"`
}

type adminGroupsResponse struct {
	Groups []GroupView `json:"groups"`
}

type adminDomainsResponse struct {
	Domains []Domain `json:"domains"`
}

type adminClient struct {
	ID                  string     `json:"id"`
	Hostname            string     `json:"hostname"`
	DomainID            string     `json:"domain_id,omitempty"`
	DomainName          string     `json:"domain_name,omitempty"`
	IP                  string     `json:"ip"`
	IPv6                string     `json:"ipv6,omitempty"`
	PublicKey           string     `json:"public_key"`
	GroupIDs            []string   `json:"group_ids,omitempty"`
	RemoteSubnetIDs     []string   `json:"remote_subnet_ids,omitempty"`
	Enabled             bool       `json:"enabled"`
	Connected           bool       `json:"connected"`
	LatestHandshake     *time.Time `json:"latest_handshake,omitempty"`
	CertificateSubject  string     `json:"certificate_subject,omitempty"`
	CertificateSerial   string     `json:"certificate_serial,omitempty"`
	CertificateNotAfter time.Time  `json:"certificate_not_after,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type adminUpdateClientRequest struct {
	Enabled         *bool    `json:"enabled,omitempty"`
	RemoteSubnetIDs []string `json:"remote_subnet_ids,omitempty"`
}

type adminRemoteSubnetCreateRequest struct {
	Name           string   `json:"name"`
	ConfigType     string   `json:"config_type"`
	SourceFilename string   `json:"source_filename"`
	Config         string   `json:"config"`
	Subnets        []string `json:"subnets"`
	ClientIDs      []string `json:"client_ids,omitempty"`
	GroupIDs       []string `json:"group_ids,omitempty"`
	FreeForAll     bool     `json:"free_for_all,omitempty"`
}

type adminRemoteSubnetUpdateRequest struct {
	Name       *string   `json:"name,omitempty"`
	Subnets    *[]string `json:"subnets,omitempty"`
	ClientIDs  *[]string `json:"client_ids,omitempty"`
	GroupIDs   *[]string `json:"group_ids,omitempty"`
	FreeForAll *bool     `json:"free_for_all,omitempty"`
	Enabled    *bool     `json:"enabled,omitempty"`
}

type adminCreateGroupRequest struct {
	Name string `json:"name"`
}

type adminUpdateGroupRequest struct {
	Name      *string   `json:"name,omitempty"`
	ClientIDs *[]string `json:"client_ids,omitempty"`
	GroupIDs  *[]string `json:"group_ids,omitempty"`
}

type adminCreateDomainRequest struct {
	Name              string                   `json:"name"`
	PEM               string                   `json:"pem,omitempty"`
	DNSServers        []string                 `json:"dns_servers,omitempty"`
	SearchDomain      string                   `json:"search_domain,omitempty"`
	LocalNetworks     []DomainLocalNetwork     `json:"local_networks,omitempty"`
	LocalNetwork      legacyDomainLocalNetwork `json:"local_network,omitempty"`
	AutoEnrollEnabled bool                     `json:"auto_enroll_enabled,omitempty"`
}

type adminUpdateDomainRequest struct {
	Name              *string                   `json:"name,omitempty"`
	PEM               *string                   `json:"pem,omitempty"`
	DNSServers        *[]string                 `json:"dns_servers,omitempty"`
	SearchDomain      *string                   `json:"search_domain,omitempty"`
	LocalNetworks     *[]DomainLocalNetwork     `json:"local_networks,omitempty"`
	LocalNetwork      *legacyDomainLocalNetwork `json:"local_network,omitempty"`
	AutoEnrollEnabled *bool                     `json:"auto_enroll_enabled,omitempty"`
}

type adminDeleteDomainRequest struct {
	Password string `json:"password"`
}

func (r adminCreateDomainRequest) domainLocalNetworks() []DomainLocalNetwork {
	if r.LocalNetworks != nil {
		return r.LocalNetworks
	}
	return r.LocalNetwork.profiles()
}

func (r adminUpdateDomainRequest) domainLocalNetworks() *[]DomainLocalNetwork {
	if r.LocalNetworks != nil || r.LocalNetwork == nil {
		return r.LocalNetworks
	}
	profiles := r.LocalNetwork.profiles()
	return &profiles
}

type adminManualEnrollRequest struct {
	Hostname string `json:"hostname"`
	DomainID string `json:"domain_id"`
}

type adminManualEnrollResponse struct {
	Hostname string      `json:"hostname"`
	Address  string      `json:"address"`
	Config   string      `json:"config"`
	Client   adminClient `json:"client"`
}
