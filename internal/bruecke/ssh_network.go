package bruecke

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"time"
)

// A dedicated dummy interface owns SSH source IPs. Unlike WireGuard peers these
// are local addresses: TCP replies must be delivered to our dialer's sockets.
// The marker prevents adopting or flushing an unrelated existing interface.
const sshInterface = "br-ssh"
const sshInterfaceMarker = "bruecke SSH jump host"

type sshAddressManager interface {
	Add(Client) error
	Remove(Client) error
}

type sshNetwork struct{}

func sshIP(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ip %v: %w: %s", args, err, out)
	}
	return out, nil
}

func prepareSSHNetwork() error {
	if _, err := net.InterfaceByName(sshInterface); err == nil {
		out, err := sshIP("-j", "-d", "link", "show", "dev", sshInterface)
		if err != nil {
			return err
		}
		var links []struct {
			Alias string `json:"ifalias"`
			Info  struct {
				Kind string `json:"info_kind"`
			} `json:"linkinfo"`
		}
		if err := json.Unmarshal(out, &links); err != nil {
			return err
		}
		if len(links) != 1 || links[0].Alias != sshInterfaceMarker || links[0].Info.Kind != "dummy" {
			return fmt.Errorf("interface %s already exists and is not owned by the SSH jump host", sshInterface)
		}
	} else {
		if _, err := sshIP("link", "add", sshInterface, "type", "dummy"); err != nil {
			return err
		}
		if _, err := sshIP("link", "set", "dev", sshInterface, "alias", sshInterfaceMarker); err != nil {
			return err
		}
	}
	// Remove only our own stale source addresses after an unclean shutdown.
	if _, err := sshIP("address", "flush", "dev", sshInterface); err != nil {
		return err
	}
	_, err := sshIP("link", "set", "dev", sshInterface, "up")
	return err
}

func (sshNetwork) Add(client Client) error {
	if _, err := sshIP("-4", "address", "replace", client.IP+"/32", "dev", sshInterface); err != nil {
		return err
	}
	if client.IPv6 != "" {
		if _, err := sshIP("-6", "address", "replace", client.IPv6+"/128", "dev", sshInterface, "nodad"); err != nil {
			_, _ = sshIP("-4", "address", "del", client.IP+"/32", "dev", sshInterface)
			return err
		}
	}
	return nil
}

func (sshNetwork) Remove(client Client) error {
	_, err := sshIP("-4", "address", "del", client.IP+"/32", "dev", sshInterface)
	if client.IPv6 != "" {
		_, v6err := sshIP("-6", "address", "del", client.IPv6+"/128", "dev", sshInterface)
		if err == nil {
			err = v6err
		}
	}
	return err
}

func dialSSHForward(ctx context.Context, source, target netip.Addr, port uint32) (net.Conn, error) {
	dialer := net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.IP(source.AsSlice())},
	}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.String(), strconv.Itoa(int(port))))
}
