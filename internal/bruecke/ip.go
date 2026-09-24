package bruecke

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
)

func firstUsableIP(prefix netip.Prefix) (netip.Addr, error) {
	base, err := ipv4ToUint(prefix.Masked().Addr())
	if err != nil {
		return netip.Addr{}, err
	}
	if prefix.Bits() > 30 {
		return netip.Addr{}, fmt.Errorf("%s has no usable host address", prefix)
	}
	return uintToIPv4(base + 1), nil
}

func isUsableHost(prefix netip.Prefix, addr netip.Addr) bool {
	if !addr.Is4() || !prefix.Contains(addr) || prefix.Bits() > 30 {
		return false
	}
	base, err := ipv4ToUint(prefix.Masked().Addr())
	if err != nil {
		return false
	}
	value, err := ipv4ToUint(addr)
	if err != nil {
		return false
	}
	total := uint64(1) << uint(32-prefix.Bits())
	return uint64(value) > uint64(base) && uint64(value) < uint64(base)+total-1
}

func firstUsableIPv6(prefix netip.Prefix) (netip.Addr, error) {
	if !prefix.Addr().Is6() || prefix.Addr().Is4() {
		return netip.Addr{}, fmt.Errorf("%s is not IPv6", prefix)
	}
	if prefix.Bits() >= 128 {
		return netip.Addr{}, fmt.Errorf("%s has no usable host address", prefix)
	}
	addr, ok := addIPv6(prefix.Masked().Addr(), 1)
	if !ok || !prefix.Contains(addr) {
		return netip.Addr{}, fmt.Errorf("%s has no usable host address", prefix)
	}
	return addr, nil
}

func isUsableIPv6Host(prefix netip.Prefix, addr netip.Addr) bool {
	if !addr.Is6() || addr.Is4() || !prefix.Contains(addr) || prefix.Bits() >= 128 {
		return false
	}
	return addr != prefix.Masked().Addr()
}

func ipv4ToUint(addr netip.Addr) (uint32, error) {
	if !addr.Is4() {
		return 0, fmt.Errorf("%s is not IPv4", addr)
	}
	bytes := addr.As4()
	return binary.BigEndian.Uint32(bytes[:]), nil
}

func uintToIPv4(value uint32) netip.Addr {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], value)
	return netip.AddrFrom4(bytes)
}

func allocateClientIP(prefix netip.Prefix, serverIP netip.Addr, clients map[string]Client) (netip.Addr, error) {
	base, err := ipv4ToUint(prefix.Masked().Addr())
	if err != nil {
		return netip.Addr{}, err
	}
	server, err := ipv4ToUint(serverIP)
	if err != nil {
		return netip.Addr{}, err
	}

	used := map[uint32]struct{}{server: {}}
	for _, client := range clients {
		addr, err := netip.ParseAddr(client.IP)
		if err != nil || !addr.Is4() {
			continue
		}
		value, err := ipv4ToUint(addr)
		if err == nil {
			used[value] = struct{}{}
		}
	}

	total := uint64(1) << uint(32-prefix.Bits())
	for offset := uint64(1); offset < total-1; offset++ {
		candidateValue := uint64(base) + offset
		if candidateValue > math.MaxUint32 {
			break
		}
		if _, ok := used[uint32(candidateValue)]; ok {
			continue
		}
		candidate := uintToIPv4(uint32(candidateValue))
		if prefix.Contains(candidate) {
			return candidate, nil
		}
	}

	return netip.Addr{}, fmt.Errorf("no free client IPs in %s", prefix)
}

func allocateClientIPv6(prefix netip.Prefix, serverIP netip.Addr, clients map[string]Client) (netip.Addr, error) {
	if !isUsableIPv6Host(prefix, serverIP) {
		return netip.Addr{}, fmt.Errorf("server IPv6 must be a usable host inside %s", prefix)
	}
	used := map[string]struct{}{serverIP.String(): {}}
	for _, client := range clients {
		addr, err := netip.ParseAddr(client.IPv6)
		if err == nil && addr.Is6() && !addr.Is4() {
			used[addr.String()] = struct{}{}
		}
	}

	maxOffset := maxIPv6Offset(prefix)
	base := prefix.Masked().Addr()
	for offset := uint64(1); ; offset++ {
		candidate, ok := addIPv6(base, offset)
		if !ok || !prefix.Contains(candidate) {
			break
		}
		if _, ok := used[candidate.String()]; !ok {
			return candidate, nil
		}
		if offset == maxOffset {
			break
		}
	}
	return netip.Addr{}, fmt.Errorf("no free client IPv6s in %s", prefix)
}

func addIPv6(addr netip.Addr, offset uint64) (netip.Addr, bool) {
	if !addr.Is6() || addr.Is4() {
		return netip.Addr{}, false
	}
	bytes := addr.As16()
	carry := offset
	for i := len(bytes) - 1; i >= 0 && carry > 0; i-- {
		sum := uint64(bytes[i]) + (carry & 0xff)
		bytes[i] = byte(sum)
		carry = (carry >> 8) + (sum >> 8)
	}
	if carry > 0 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom16(bytes), true
}

func maxIPv6Offset(prefix netip.Prefix) uint64 {
	hostBits := 128 - prefix.Bits()
	if hostBits >= 64 {
		return math.MaxUint64
	}
	return (uint64(1) << uint(hostBits)) - 1
}
