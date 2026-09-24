package bruecke

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type RemoteSubnetRuntime struct {
	cfg       Config
	logger    *log.Logger
	mu        sync.Mutex
	processes map[string]*remoteOpenVPNProcess
	rules     []remoteFirewallRule
}

type remoteOpenVPNProcess struct {
	cmd           *exec.Cmd
	configHash    string
	interfaceName string
}

type remoteFirewallRule struct {
	family string
	table  string
	insert bool
	args   []string
}

func NewRemoteSubnetRuntime(cfg Config, logger *log.Logger) *RemoteSubnetRuntime {
	return &RemoteSubnetRuntime{cfg: cfg, logger: logger, processes: map[string]*remoteOpenVPNProcess{}}
}

func (r *RemoteSubnetRuntime) Sync(ctx context.Context, specs []RemoteSubnetSpec, clients []Client) error {
	if r == nil || !r.cfg.ApplyRemoteSubnets {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := os.MkdirAll(r.cfg.RemoteSubnetRuntimeDir, 0o700); err != nil {
		return fmt.Errorf("create remote subnet runtime dir: %w", err)
	}
	enabled := map[string]RemoteSubnetSpec{}
	for _, spec := range specs {
		if spec.Enabled {
			enabled[spec.ID] = spec
		}
	}
	for id := range r.processes {
		if _, ok := enabled[id]; !ok {
			r.stopLocked(id)
		}
	}
	for id, spec := range enabled {
		hash := remoteOpenVPNConfigHash(spec)
		if process, ok := r.processes[id]; ok && process.configHash == hash && process.cmd.Process != nil {
			continue
		}
		if _, ok := r.processes[id]; ok {
			r.stopLocked(id)
		}
		if err := r.startLocked(ctx, spec, hash); err != nil {
			return err
		}
	}
	return r.applyFirewallLocked(ctx, enabled, clients)
}

func (r *RemoteSubnetRuntime) StopAll(ctx context.Context) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clearFirewallBestEffortLocked(ctx)
	for id := range r.processes {
		r.stopLocked(id)
	}
}

func (r *RemoteSubnetRuntime) startLocked(ctx context.Context, spec RemoteSubnetSpec, hash string) error {
	interfaceName := remoteInterfaceName(spec.ID)
	dir := filepath.Join(r.cfg.RemoteSubnetRuntimeDir, spec.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create remote subnet dir: %w", err)
	}
	configPath := filepath.Join(dir, "client.ovpn")
	if err := os.WriteFile(configPath, []byte(runtimeOpenVPNConfig(spec, interfaceName)), 0o600); err != nil {
		return fmt.Errorf("write OpenVPN config: %w", err)
	}
	if spec.OVPNCreds != "" {
		if err := os.WriteFile(filepath.Join(dir, "creds.txt"), []byte(spec.OVPNCreds), 0o600); err != nil {
			return fmt.Errorf("write OpenVPN creds: %w", err)
		}
	}
	logPath := filepath.Join(dir, "openvpn.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open OpenVPN log: %w", err)
	}
	cmd := exec.Command(r.cfg.OpenVPNPath, "--config", configPath)
	cmd.Dir = dir
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("start OpenVPN %s: %w", spec.Name, err)
	}
	r.processes[spec.ID] = &remoteOpenVPNProcess{cmd: cmd, configHash: hash, interfaceName: interfaceName}
	if r.logger != nil {
		r.logger.Printf("remote subnet started id=%s name=%s interface=%s", spec.ID, spec.Name, interfaceName)
	}
	go func(id, name string, cmd *exec.Cmd, logFile *os.File) {
		err := cmd.Wait()
		_ = logFile.Close()
		if r.logger != nil && err != nil {
			r.logger.Printf("remote subnet exited id=%s name=%s: %v", id, name, err)
		}
		r.mu.Lock()
		if current, ok := r.processes[id]; ok && current.cmd == cmd {
			delete(r.processes, id)
		}
		r.mu.Unlock()
	}(spec.ID, spec.Name, cmd, logFile)
	return nil
}

func (r *RemoteSubnetRuntime) stopLocked(id string) {
	process := r.processes[id]
	if process == nil {
		return
	}
	if process.cmd.Process != nil {
		_ = process.cmd.Process.Kill()
	}
	delete(r.processes, id)
}

func (r *RemoteSubnetRuntime) applyFirewallLocked(ctx context.Context, specs map[string]RemoteSubnetSpec, clients []Client) error {
	if err := r.clearFirewallLocked(ctx); err != nil {
		return err
	}
	var rules []remoteFirewallRule
	for _, spec := range specs {
		process := r.processes[spec.ID]
		if process == nil {
			continue
		}
		for _, cidr := range spec.Subnets {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return err
			}
			family := "ipv4"
			if prefix.Addr().Is6() {
				family = "ipv6"
			}
			for _, client := range clients {
				if client.Disabled || !remoteSubnetAllowedForClient(spec, client) {
					continue
				}
				clientCIDR := client.IP + "/32"
				if family == "ipv6" {
					if client.IPv6 == "" {
						continue
					}
					clientCIDR = client.IPv6 + "/128"
				}
				rules = append(rules,
					remoteFirewallRule{family: family, insert: true, args: []string{"FORWARD", "-i", r.cfg.WGInterface, "-o", process.interfaceName, "-s", clientCIDR, "-d", cidr, "-j", "ACCEPT"}},
					remoteFirewallRule{family: family, insert: true, args: []string{"FORWARD", "-i", process.interfaceName, "-o", r.cfg.WGInterface, "-d", clientCIDR, "-s", cidr, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}},
					remoteFirewallRule{family: family, table: "nat", args: []string{"POSTROUTING", "-s", clientCIDR, "-d", cidr, "-o", process.interfaceName, "-j", "MASQUERADE"}},
				)
			}
			rules = append(rules, remoteFirewallRule{family: family, args: []string{"FORWARD", "-i", r.cfg.WGInterface, "-o", process.interfaceName, "-d", cidr, "-j", "DROP"}})
		}
	}
	for _, rule := range rules {
		if err := addFirewallRule(ctx, rule); err != nil {
			return err
		}
	}
	r.rules = rules
	return nil
}

func (r *RemoteSubnetRuntime) clearFirewallLocked(ctx context.Context) error {
	for i := len(r.rules) - 1; i >= 0; i-- {
		if err := deleteFirewallRule(ctx, r.rules[i]); err != nil {
			return err
		}
	}
	r.rules = nil
	return nil
}

func (r *RemoteSubnetRuntime) clearFirewallBestEffortLocked(ctx context.Context) {
	for i := len(r.rules) - 1; i >= 0; i-- {
		_ = deleteFirewallRule(ctx, r.rules[i])
	}
	r.rules = nil
}

func remoteSubnetAllowedForClient(spec RemoteSubnetSpec, client Client) bool {
	if spec.FreeForAll || containsID(spec.GroupIDs, AllGroupID) {
		return true
	}
	if containsID(spec.ClientIDs, client.ID) {
		return true
	}
	for _, groupID := range client.GroupIDs {
		if containsID(spec.GroupIDs, groupID) {
			return true
		}
	}
	for _, id := range client.RemoteSubnetIDs {
		if id == spec.ID {
			return true
		}
	}
	return false
}

func runtimeOpenVPNConfig(spec RemoteSubnetSpec, interfaceName string) string {
	var builder strings.Builder
	hasPullFilter := false
	for _, line := range strings.Split(spec.OVPNConfig, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "pull-filter ignore \"redirect-gateway\"") {
			hasPullFilter = true
		}
		if strings.HasPrefix(trimmed, "dev ") || strings.HasPrefix(trimmed, "dev-type ") || strings.HasPrefix(trimmed, "route ") || strings.HasPrefix(trimmed, "route-ipv6 ") || strings.HasPrefix(trimmed, "daemon") || strings.HasPrefix(trimmed, "auth-user-pass ") || trimmed == "auth-user-pass" {
			continue
		}
		builder.WriteString(line)
		builder.WriteByte('\n')
	}
	fmt.Fprintf(&builder, "\ndev %s\ndev-type tun\n", interfaceName)
	if spec.OVPNCreds != "" {
		fmt.Fprintf(&builder, "auth-user-pass creds.txt\n")
	}
	if !hasPullFilter {
		fmt.Fprintf(&builder, "pull-filter ignore \"redirect-gateway\"\n")
	}
	for _, cidr := range spec.Subnets {
		prefix := netip.MustParsePrefix(cidr)
		if prefix.Addr().Is4() {
			fmt.Fprintf(&builder, "route %s %s\n", prefix.Masked().Addr(), ipv4Netmask(prefix.Bits()))
		} else {
			fmt.Fprintf(&builder, "route-ipv6 %s\n", prefix.Masked())
		}
	}
	return builder.String()
}

func remoteOpenVPNConfigHash(spec RemoteSubnetSpec) string {
	sum := sha256.Sum256([]byte(spec.OVPNConfig + "\n" + spec.OVPNCreds + "\n" + strings.Join(spec.Subnets, ",")))
	return hex.EncodeToString(sum[:])
}

func remoteInterfaceName(id string) string {
	if len(id) > 10 {
		id = id[:10]
	}
	return "brs" + id
}

func ipv4Netmask(bits int) string {
	mask := uint32(0xffffffff) << (32 - bits)
	return fmt.Sprintf("%d.%d.%d.%d", byte(mask>>24), byte(mask>>16), byte(mask>>8), byte(mask))
}

func addFirewallRule(ctx context.Context, rule remoteFirewallRule) error {
	checkArgs := firewallArgs(rule, "-C")
	if exec.CommandContext(ctx, firewallCommand(rule.family), checkArgs...).Run() == nil {
		return nil
	}
	action := "-A"
	if rule.insert {
		action = "-I"
	}
	return exec.CommandContext(ctx, firewallCommand(rule.family), firewallArgs(rule, action)...).Run()
}

func deleteFirewallRule(ctx context.Context, rule remoteFirewallRule) error {
	command := firewallCommand(rule.family)
	if exec.CommandContext(ctx, command, firewallArgs(rule, "-C")...).Run() != nil {
		return nil
	}
	return exec.CommandContext(ctx, command, firewallArgs(rule, "-D")...).Run()
}

func firewallCommand(family string) string {
	if family == "ipv6" {
		return "ip6tables"
	}
	return "iptables"
}

func firewallArgs(rule remoteFirewallRule, action string) []string {
	args := []string{}
	if rule.table != "" {
		args = append(args, "-t", rule.table)
	}
	args = append(args, action)
	if action == "-I" && len(rule.args) > 0 {
		args = append(args, rule.args[0], "1")
		args = append(args, rule.args[1:]...)
		return args
	}
	args = append(args, rule.args...)
	return args
}

func RemoteRuntimeSyncContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}
