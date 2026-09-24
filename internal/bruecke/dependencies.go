package bruecke

import (
	"context"
	"crypto/x509"
	"net/netip"
	"time"
)

type Logger interface {
	Printf(format string, args ...any)
}

type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time {
	return f()
}

type systemClock struct{}

func (systemClock) Now() time.Time {
	return time.Now().UTC()
}

type WireGuardKeyGenerator interface {
	GenerateWireGuardKeyPair() (privateKey, publicKey string, err error)
}

type WireGuardKeyGeneratorFunc func() (privateKey, publicKey string, err error)

func (f WireGuardKeyGeneratorFunc) GenerateWireGuardKeyPair() (string, string, error) {
	return f()
}

type ClientRepository interface {
	Clients() []Client
	Client(id string) (Client, error)
	Groups(domains []Domain) []GroupView
	AddGroup(name string, now time.Time) (GroupView, error)
	UpdateGroup(id string, name *string, clientIDs, groupIDs *[]string) (GroupView, error)
	DeleteGroup(id string) error
	Rotate(ctx context.Context, enrollment Enrollment, apply func(oldPublicKey, allowedIP string, enabled bool) error) (Client, error)
	SetClientRemoteSubnetIDs(id string, ids []string) (Client, error)
	SetClientEnabled(ctx context.Context, id string, enabled bool, apply func(client Client) error) (Client, error)
	DeleteClient(ctx context.Context, id string, apply func(client Client) error) (Client, error)
	SetPools(network netip.Prefix, serverIP netip.Addr, ipv6Net netip.Prefix, ipv6IP netip.Addr) error
	NormalizeAssignmentReferences(clientIDs, groupIDs []string) ([]string, []string, error)
}

type RootRepository interface {
	Domains() []Domain
	Domain(id string) (Domain, error)
	AddDomain(name, pem string, dns []string, searchDomain string, localNetworks []DomainLocalNetwork, autoEnroll bool, now time.Time) (Domain, error)
	UpdateDomain(id string, patch DomainPatch) (Domain, error)
	Delete(id string) error
	VerifyClientCertificate(cert *x509.Certificate, chain []*x509.Certificate, now time.Time) (Domain, error)
}

type SettingsRepository interface {
	Get() VPNSettings
	Set(settings VPNSettings) (VPNSettings, error)
}

type RemoteSubnetRepository interface {
	Subnets() []RemoteSubnetView
	Specs() []RemoteSubnetSpec
	Add(name, configType, filename, config string, subnets, clientIDs, groupIDs []string, now time.Time) (RemoteSubnetView, error)
	Update(id string, patch RemoteSubnetUpdate) (RemoteSubnetView, error)
	RemoveClient(id string) error
	Delete(id string) error
	RestrictedIDs(ids []string) ([]string, error)
}

type RemoteSubnetSyncer interface {
	Sync(ctx context.Context, specs []RemoteSubnetSpec, clients []Client) error
}

type BootstrapLogRepository interface {
	Append(req BootstrapLogUploadRequest, now time.Time) (BootstrapLogRun, error)
	Runs(limit int) ([]BootstrapLogRun, error)
	Run(id string, sinceSeq int64) (BootstrapLogRun, []BootstrapLogEvent, error)
}

type VPNEventRepository interface {
	Append(events []VPNEventUpload, now time.Time) (int, error)
	Events(query VPNEventQuery, now time.Time) ([]VPNEvent, string, error)
}

type ServerDependencies struct {
	Clients       ClientRepository
	WireGuard     WireGuard
	Roots         RootRepository
	Settings      SettingsRepository
	RemoteSubnets RemoteSubnetRepository
	RemoteRuntime RemoteSubnetSyncer
	BootstrapLogs BootstrapLogRepository
	VPNEvents     VPNEventRepository
	Logger        Logger
	Clock         Clock
	KeyGenerator  WireGuardKeyGenerator
}

func (d ServerDependencies) withDefaults() ServerDependencies {
	if d.Clock == nil {
		d.Clock = systemClock{}
	}
	if d.KeyGenerator == nil {
		d.KeyGenerator = WireGuardKeyGeneratorFunc(generateWireGuardKeyPair)
	}
	return d
}
