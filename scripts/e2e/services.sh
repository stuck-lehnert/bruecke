#!/bin/sh
# Infrastructure commands run inside the isolated e2e helper containers.
set -eu

serve_http() {
	address="$1"
	port="$2"
	body="$3"
	allowed_source="${4:-}"
	if [ -n "$allowed_source" ]; then
		iptables -A INPUT -p tcp --dport "$port" -s "$allowed_source" -j ACCEPT
		iptables -A INPUT -p tcp --dport "$port" -j DROP
	fi
	if [ -n "$address" ]; then
		set -- -s "$address"
	else
		set --
	fi
	while true; do
		printf 'HTTP/1.1 200 OK\r\nContent-Length: %s\r\n\r\n%s\n' \
			"$((${#body} + 1))" "$body" | nc -l "$@" -p "$port"
	done
}

serve_internet() {
	port="$1"
	ipv6_enabled="$2"
	serve_http "" "$port" bruecke-internet-e2e-ok &
	if [ "$ipv6_enabled" = 1 ]; then
		serve_http :: "$port" bruecke-internet-e2e-ok &
	fi
	wait
}

start_openvpn() {
	site="$1"
	vpn_cidr="$2"
	remote_cidr="$3"
	while [ ! -f "/work/$site-vpn-start" ]; do
		sleep 0.2
	done
	sysctl -w net.ipv4.ip_forward=1 >/dev/null || true
	iptables -A FORWARD -s "$vpn_cidr" -d "$remote_cidr" -j ACCEPT
	iptables -A FORWARD -s "$remote_cidr" -d "$vpn_cidr" \
		-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	iptables -t nat -A POSTROUTING -s "$vpn_cidr" -d "$remote_cidr" -j MASQUERADE
	exec openvpn --config "/work/$site-server.conf"
}

server_network_state() {
	# Diagnostics should continue even if an individual network query fails.
	set +e
	ip route
	ip addr
	iptables -S FORWARD
	iptables -t nat -S POSTROUTING
	for log in /data/remote-subnets-runtime/*/openvpn.log; do
		[ -f "$log" ] || continue
		printf '==== %s ====\n' "$log"
		tail -n 80 "$log"
	done
}

wait_healthy() {
	for _ in $(seq 1 60); do
		curl -fsS http://server:8080/healthz >/dev/null && return 0
		sleep 1
	done
	printf '%s\n' 'server did not become healthy' >&2
	return 1
}

command="$1"
shift
case "$command" in
	serve-http) serve_http "$@" ;;
	serve-internet) serve_internet "$@" ;;
	openvpn) start_openvpn "$@" ;;
	server-network-state) server_network_state ;;
	wait-healthy) wait_healthy ;;
	*) printf 'unknown e2e infrastructure command: %s\n' "$command" >&2; exit 2 ;;
esac
