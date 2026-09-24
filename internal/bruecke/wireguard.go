package bruecke

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type WireGuard interface {
	Configure(ctx context.Context, settings VPNSettings) error
	Reconfigure(ctx context.Context, previous, next VPNSettings, clients []Client) error
	RotatePeer(ctx context.Context, oldPublicKey, newPublicKey, allowedIP string, enabled bool) error
	SetPeer(ctx context.Context, publicKey, allowedIP string, enabled bool) error
	Sync(ctx context.Context, clients []Client) error
	PeerStatuses(ctx context.Context) (map[string]PeerStatus, error)
}

type PeerStatus struct {
	LatestHandshake time.Time
}

type ScriptWireGuard struct {
	cfg    Config
	logger *log.Logger
}

func NewScriptWireGuard(cfg Config, logger *log.Logger) *ScriptWireGuard {
	return &ScriptWireGuard{cfg: cfg, logger: logger}
}

func (w *ScriptWireGuard) Configure(ctx context.Context, settings VPNSettings) error {
	if !w.cfg.ApplyWireGuard {
		return nil
	}
	addressCIDRs, networks, ipv6Networks, err := wireGuardInterfaceSettings(settings)
	if err != nil {
		return err
	}
	if err := w.run(ctx, w.cfg.WGUpScript, w.cfg.WGInterface, addressCIDRs, strconv.Itoa(w.cfg.WGListenPort), w.cfg.WGPrivateKeyFile, w.cfg.WGOutboundInterface, strings.Join(networks, ","), strings.Join(ipv6Networks, ",")); err != nil {
		return err
	}
	if w.logger != nil {
		w.logger.Printf("wireguard configured interface=%s addresses=%s ipv4=%s ipv6=%s", w.cfg.WGInterface, addressCIDRs, strings.Join(networks, ","), strings.Join(ipv6Networks, ","))
	}
	return nil
}

func (w *ScriptWireGuard) Reconfigure(ctx context.Context, previous, next VPNSettings, clients []Client) error {
	if !w.cfg.ApplyWireGuard {
		return nil
	}
	if !sameWireGuardInterfaceSettings(previous, next) {
		if err := w.down(ctx, previous); err != nil {
			return err
		}
		if err := w.Configure(ctx, next); err != nil {
			return err
		}
	}
	return w.Sync(ctx, clients)
}

func (w *ScriptWireGuard) RotatePeer(ctx context.Context, oldPublicKey, newPublicKey, allowedIP string, enabled bool) error {
	if !w.cfg.ApplyWireGuard {
		return nil
	}
	if oldPublicKey != "" && (oldPublicKey != newPublicKey || !enabled) {
		if err := w.run(ctx, w.cfg.RemovePeerScript, w.cfg.WGInterface, oldPublicKey); err != nil {
			return err
		}
	}
	if !enabled {
		return nil
	}
	return w.SetPeer(ctx, newPublicKey, allowedIP, enabled)
}

func (w *ScriptWireGuard) SetPeer(ctx context.Context, publicKey, allowedIP string, enabled bool) error {
	if !w.cfg.ApplyWireGuard {
		return nil
	}
	if !enabled {
		return w.run(ctx, w.cfg.RemovePeerScript, w.cfg.WGInterface, publicKey)
	}
	return w.run(ctx, w.cfg.ApplyPeerScript, w.cfg.WGInterface, publicKey, allowedIP)
}

func (w *ScriptWireGuard) Sync(ctx context.Context, clients []Client) error {
	if !w.cfg.ApplyWireGuard {
		return nil
	}
	for _, client := range clients {
		if err := w.SetPeer(ctx, client.PublicKey, clientAllowedIPs(client), !client.Disabled); err != nil {
			return fmt.Errorf("sync %s: %w", client.Hostname, err)
		}
	}
	if w.logger != nil {
		w.logger.Printf("wireguard synced peers=%d", len(clients))
	}
	return nil
}

func (w *ScriptWireGuard) PeerStatuses(ctx context.Context) (map[string]PeerStatus, error) {
	statuses := map[string]PeerStatus{}
	if !w.cfg.ApplyWireGuard {
		return statuses, nil
	}
	output, err := w.output(ctx, w.cfg.PeerStatusScript, w.cfg.WGInterface)
	if err != nil {
		return statuses, err
	}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		epoch, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || epoch <= 0 {
			statuses[fields[0]] = PeerStatus{}
			continue
		}
		statuses[fields[0]] = PeerStatus{LatestHandshake: time.Unix(epoch, 0).UTC()}
	}
	return statuses, nil
}

func (w *ScriptWireGuard) down(ctx context.Context, settings VPNSettings) error {
	_, networks, ipv6Networks, err := wireGuardInterfaceSettings(settings)
	if err != nil {
		return err
	}
	return w.run(ctx, w.cfg.WGDownScript, w.cfg.WGInterface, w.cfg.WGOutboundInterface, strings.Join(networks, ","), strings.Join(ipv6Networks, ","))
}

func wireGuardInterfaceSettings(settings VPNSettings) (string, []string, []string, error) {
	if len(settings.AddressCIDRs) > 0 {
		return strings.Join(settings.AddressCIDRs, ","), append([]string(nil), settings.ClientIPv4CIDRs...), append([]string(nil), settings.ClientIPv6CIDRs...), nil
	}
	network, serverIP, ipv6Network, ipv6ServerIP, err := settings.Pools()
	if err != nil {
		return "", nil, nil, err
	}
	addressCIDRs := fmt.Sprintf("%s/%d,%s/%d", serverIP, network.Bits(), ipv6ServerIP, ipv6Network.Bits())
	return addressCIDRs, []string{network.String()}, []string{ipv6Network.String()}, nil
}

func sameWireGuardInterfaceSettings(a, b VPNSettings) bool {
	aAddressCIDRs, aNetworks, aIPv6Networks, err := wireGuardInterfaceSettings(a)
	if err != nil {
		return false
	}
	bAddressCIDRs, bNetworks, bIPv6Networks, err := wireGuardInterfaceSettings(b)
	if err != nil {
		return false
	}
	return aAddressCIDRs == bAddressCIDRs && strings.Join(aNetworks, ",") == strings.Join(bNetworks, ",") && strings.Join(aIPv6Networks, ",") == strings.Join(bIPv6Networks, ",")
}

func (w *ScriptWireGuard) run(ctx context.Context, script string, args ...string) error {
	_, err := w.output(ctx, script, args...)
	return err
}

func (w *ScriptWireGuard) output(ctx context.Context, script string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, script, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed == "" {
			return "", fmt.Errorf("%s failed: %w", script, err)
		}
		return "", fmt.Errorf("%s failed: %w: %s", script, err, trimmed)
	}
	return string(output), nil
}
