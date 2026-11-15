#!/bin/sh
# Commands executed inside the isolated e2e client container.
set -eu

enroll_client() {
	WG_CIDR="$1"
	WG_IPV6_CIDR="$2"
	IPV6_EGRESS="$3"
	INTERNET_SERVICE_IPV6="$4"
	jq -Rs '{certificate:.}' /work/client.crt > /work/enroll-start.json
	curl -fsS -X POST http://server:8080/enroll/start \
		-H 'Content-Type: application/json' \
		--data-binary @/work/enroll-start.json > /work/enroll-start-response.json
	jq -r .challenge /work/enroll-start-response.json | base64 -d > /work/challenge.bin
	openssl dgst -sha256 -sign /work/client.key -out /work/challenge.sig /work/challenge.bin
	handshake_id=$(jq -r .handshake_id /work/enroll-start-response.json)
	signature=$(base64 /work/challenge.sig | tr -d '\n')
	jq -n --arg id "$handshake_id" --arg sig "$signature" --arg alg sha256-rsa \
		'{handshake_id:$id, algorithm:$alg, signature:$sig}' > /work/enroll-finish.json
	curl -fsS -X POST http://server:8080/enroll/finish \
		-H 'Content-Type: application/json' \
		--data-binary @/work/enroll-finish.json > /work/client.conf
	awk -F ' = ' '/PrivateKey/ {print $2; exit}' /work/client.conf > /work/client-wg.key
	addr_line=$(awk -F ' = ' '/Address/ {print $2; exit}' /work/client.conf)
	client_v4=$(printf '%s' "$addr_line" | cut -d, -f1 | tr -d ' ')
	client_v6=$(printf '%s' "$addr_line" | cut -s -d, -f2 | tr -d ' ')
	server_pub=$(awk -F ' = ' '/PublicKey/ {print $2; exit}' /work/client.conf)
	peer_allowed=$(awk -F ' = ' '/AllowedIPs/ {print $2; exit}' /work/client.conf | tr -d ' ')
	ip link add dev wg0 type wireguard
	wg set wg0 private-key /work/client-wg.key \
		peer "$server_pub" endpoint server:51820 \
		allowed-ips "$peer_allowed" persistent-keepalive 1
	ip address add "$client_v4" dev wg0
	if [ -n "$client_v6" ]; then
		ip -6 address add "$client_v6" dev wg0
	fi
	ip link set up dev wg0
	ip route replace "$WG_CIDR" dev wg0
	ip route replace default dev wg0
	if [ "$IPV6_EGRESS" = "1" ] && [ -n "$INTERNET_SERVICE_IPV6" ]; then
		ip -6 route replace "$WG_IPV6_CIDR" dev wg0
		ip -6 route replace default dev wg0
	fi
}

configure_remote_subnets() {
	ADMIN_PASSWORD="$1"
	HOSTNAME="$2"
	MANUAL_HOSTNAME="$3"
	MANUAL_SECOND_HOSTNAME="$4"
	REMOTE_FREE_CIDR="$5"
	REMOTE_RESTRICTED_CIDR="$6"
	jq -n --arg password "$ADMIN_PASSWORD" '{password:$password}' > /work/admin-login.json
	jq -Rs --arg name remote-free --arg cidr "$REMOTE_FREE_CIDR" '
		{name:$name, config_type:"ovpn", source_filename:"remote-free-client.ovpn",
		 config:., subnets:[$cidr], group_ids:["all"]}
	' /work/remote-free-client.ovpn > /work/remote-free.json
	jq -Rs --arg name remote-restricted --arg cidr "$REMOTE_RESTRICTED_CIDR" '
		{name:$name, config_type:"ovpn", source_filename:"remote-restricted-client.ovpn",
		 config:., subnets:[$cidr], group_ids:[]}
	' /work/remote-restricted-client.ovpn > /work/remote-restricted.json
	curl -fsS -c /work/admin-cookie.txt -X POST http://server:8080/api/admin/login \
		-H 'Content-Type: application/json' \
		--data-binary @/work/admin-login.json >/dev/null
	curl -fsS -b /work/admin-cookie.txt http://server:8080/api/admin/clients > /work/clients.json
	jq -e --arg hostname "$HOSTNAME" '
		.clients[] | select(
			.hostname == $hostname and (.id | length > 0) and (.domain_id | length > 0)
			and (.group_ids | index("all")) and any(.group_ids[]; startswith("domain:"))
		)
	' /work/clients.json >/dev/null
	jq -r --arg hostname "$HOSTNAME" '.clients[] | select(.hostname == $hostname) | .id' /work/clients.json > /work/client-id
	jq -r --arg hostname "$HOSTNAME" '.clients[] | select(.hostname == $hostname) | .domain_id' /work/clients.json > /work/domain-id
	domain_id=$(cat /work/domain-id)
	domain_path=$(jq -rn --arg id "$domain_id" '$id|@uri')
	curl -fsS -b /work/admin-cookie.txt http://server:8080/api/admin/groups > /work/groups.json
	jq -e --arg domain "$domain_id" '
		(.groups | any(.id == "all" and .built_in == true))
		and (.groups | any(.id == ("domain:" + $domain) and .type == "domain" and .built_in == true))
	' /work/groups.json >/dev/null
	printf '%s' '{"dns_servers":["1.1.1.1"]}' > /work/domain-dns-one.json
	curl -fsS -b /work/admin-cookie.txt -X PATCH "http://server:8080/api/admin/domains/$domain_path" \
		-H 'Content-Type: application/json' \
		--data-binary @/work/domain-dns-one.json > /work/domain-dns-one-response.json
	jq -e --arg domain "$domain_id" '.id == $domain and .dns_servers == ["1.1.1.1"]' /work/domain-dns-one-response.json >/dev/null
	curl -fsS -b /work/admin-cookie.txt -X POST http://server:8080/api/admin/remote-subnets \
		-H 'Content-Type: application/json' \
		--data-binary @/work/remote-free.json > /work/remote-free-response.json
	jq -e --arg cidr "$REMOTE_FREE_CIDR" '
		.name == "remote-free" and (.group_ids | index("all")) and (.subnets | index($cidr))
	' /work/remote-free-response.json >/dev/null
	jq -r .id /work/remote-free-response.json > /work/remote-free-id
	curl -fsS -b /work/admin-cookie.txt -X POST http://server:8080/api/admin/remote-subnets \
		-H 'Content-Type: application/json' \
		--data-binary @/work/remote-restricted.json > /work/remote-restricted-response.json
	jq -e --arg cidr "$REMOTE_RESTRICTED_CIDR" '
		.name == "remote-restricted" and ((.group_ids // []) | length == 0)
		and (.subnets | index($cidr))
	' /work/remote-restricted-response.json >/dev/null
	jq -r .id /work/remote-restricted-response.json > /work/remote-restricted-id
	jq -n --arg hostname "$MANUAL_HOSTNAME" --arg domain "$domain_id" '{hostname:$hostname, domain_id:$domain}' > /work/manual-enroll.json
	curl -fsS -b /work/admin-cookie.txt -X POST http://server:8080/api/admin/manual-enroll \
		-H 'Content-Type: application/json' \
		--data-binary @/work/manual-enroll.json > /work/manual-enroll-response.json
	jq -e --arg hostname "$MANUAL_HOSTNAME" \
		--arg free "$REMOTE_FREE_CIDR" --arg restricted "$REMOTE_RESTRICTED_CIDR" '
		.hostname == $hostname and (.config | contains("[Interface]"))
		and (.config | contains("PrivateKey = ")) and (.config | contains("DNS = 1.1.1.1"))
		and ((.config | contains($free)) | not) and ((.config | contains($restricted)) | not)
	' /work/manual-enroll-response.json >/dev/null
	printf '%s' '{"dns_servers":["8.8.8.8"]}' > /work/domain-dns-two.json
	curl -fsS -b /work/admin-cookie.txt -X PATCH "http://server:8080/api/admin/domains/$domain_path" \
		-H 'Content-Type: application/json' \
		--data-binary @/work/domain-dns-two.json > /work/domain-dns-two-response.json
	jq -e --arg domain "$domain_id" '.id == $domain and .dns_servers == ["8.8.8.8"]' /work/domain-dns-two-response.json >/dev/null
	jq -n --arg hostname "$MANUAL_SECOND_HOSTNAME" --arg domain "$domain_id" '{hostname:$hostname, domain_id:$domain}' > /work/manual-second-enroll.json
	curl -fsS -b /work/admin-cookie.txt -X POST http://server:8080/api/admin/manual-enroll \
		-H 'Content-Type: application/json' \
		--data-binary @/work/manual-second-enroll.json > /work/manual-second-enroll-response.json
	jq -e --arg hostname "$MANUAL_SECOND_HOSTNAME" '
		.hostname == $hostname and (.config | contains("DNS = 8.8.8.8"))
	' /work/manual-second-enroll-response.json >/dev/null
}

grant_nested_group() {
	restricted_id=$(cat /work/remote-restricted-id)
	client_id=$(cat /work/client-id)
	printf '%s' '{"name":"e2e-child"}' > /work/group-child-create.json
	curl -fsS -b /work/admin-cookie.txt -X POST http://server:8080/api/admin/groups \
		-H 'Content-Type: application/json' \
		--data-binary @/work/group-child-create.json > /work/group-child-response.json
	child_id=$(jq -r .id /work/group-child-response.json)
	jq -n --arg client "$client_id" '{client_ids:[$client]}' > /work/group-child-update.json
	curl -fsS -b /work/admin-cookie.txt -X PATCH "http://server:8080/api/admin/groups/$child_id" \
		-H 'Content-Type: application/json' \
		--data-binary @/work/group-child-update.json >/dev/null
	printf '%s' '{"name":"e2e-parent"}' > /work/group-parent-create.json
	curl -fsS -b /work/admin-cookie.txt -X POST http://server:8080/api/admin/groups \
		-H 'Content-Type: application/json' \
		--data-binary @/work/group-parent-create.json > /work/group-parent-response.json
	parent_id=$(jq -r .id /work/group-parent-response.json)
	jq -n --arg child "$child_id" '{group_ids:[$child]}' > /work/group-parent-update.json
	curl -fsS -b /work/admin-cookie.txt -X PATCH "http://server:8080/api/admin/groups/$parent_id" \
		-H 'Content-Type: application/json' \
		--data-binary @/work/group-parent-update.json >/dev/null
	jq -n --arg parent "$parent_id" '{group_ids:[$parent]}' > /work/group-child-recursive.json
	status=$(curl -sS -o /work/group-child-recursive-response.txt -w '%{http_code}' -b /work/admin-cookie.txt -X PATCH "http://server:8080/api/admin/groups/$child_id" \
		-H 'Content-Type: application/json' \
		--data-binary @/work/group-child-recursive.json)
	if [ "$status" != "400" ]; then
		echo "recursive group update returned $status" >&2
		exit 1
	fi
	jq -n --arg parent "$parent_id" '{group_ids:[$parent]}' > /work/remote-restricted-grant.json
	curl -fsS -b /work/admin-cookie.txt -X PATCH "http://server:8080/api/admin/remote-subnets/$restricted_id" \
		-H 'Content-Type: application/json' \
		--data-binary @/work/remote-restricted-grant.json > /work/remote-restricted-grant-response.json
	jq -e --arg parent "$parent_id" '(.group_ids | index($parent))' /work/remote-restricted-grant-response.json >/dev/null
}

revoke_remote_subnet() {
	restricted_id=$(cat /work/remote-restricted-id)
	printf '%s' '{"group_ids":[]}' > /work/remote-restricted-revoke.json
	curl -fsS -b /work/admin-cookie.txt -X PATCH "http://server:8080/api/admin/remote-subnets/$restricted_id" \
		-H 'Content-Type: application/json' \
		--data-binary @/work/remote-restricted-revoke.json >/dev/null
}

set_remote_enabled() {
	enabled="$1"
	free_id=$(cat /work/remote-free-id)
	jq -n --argjson enabled "$enabled" '{enabled:$enabled}' > /work/remote-free-enabled.json
	curl -fsS -b /work/admin-cookie.txt -X PATCH "http://server:8080/api/admin/remote-subnets/$free_id" \
		-H 'Content-Type: application/json' \
		--data-binary @/work/remote-free-enabled.json > /work/remote-free-enabled-response.json
	jq -e --argjson enabled "$enabled" '.enabled == $enabled' /work/remote-free-enabled-response.json >/dev/null
}

set_client_enabled() {
	enabled="$1"
	jq -n --argjson enabled "$enabled" '{enabled:$enabled}' > /work/client-enabled.json
	client_path=$(jq -rn --arg id "$(cat /work/client-id)" '$id|@uri')
	curl -fsS -b /work/admin-cookie.txt -X PATCH "http://server:8080/api/admin/clients/$client_path" \
		-H 'Content-Type: application/json' \
		--data-binary @/work/client-enabled.json >/dev/null
}

wait_reachable() {
	url="$1"
	expected="$2"
	attempts="$3"
	message="$4"
	case "$url" in
		*'['*) set -- -g -6 ;;
		*) set -- ;;
	esac
	attempt=1
	while [ "$attempt" -le "$attempts" ]; do
		if curl "$@" -fsS --max-time 2 "$url" 2>/dev/null | grep -q "$expected"; then
			return 0
		fi
		sleep 1
		attempt=$((attempt + 1))
	done
	printf '%s\n' "$message" >&2
	return 1
}

wait_denied() {
	url="$1"
	attempts="$2"
	message="$3"
	if [ "$#" -gt 3 ] && [ "$4" != 0 ]; then
		sleep "$4"
	fi
	attempt=1
	while [ "$attempt" -le "$attempts" ]; do
		if ! curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
		attempt=$((attempt + 1))
	done
	printf '%s\n' "$message" >&2
	return 1
}

command="$1"
shift
case "$command" in
	enroll) enroll_client "$@" ;;
	configure-remote-subnets) configure_remote_subnets "$@" ;;
	grant-nested-group) grant_nested_group ;;
	revoke-remote-subnet) revoke_remote_subnet ;;
	set-remote-enabled) set_remote_enabled "$@" ;;
	set-client-enabled) set_client_enabled "$@" ;;
	wait-reachable) wait_reachable "$@" ;;
	wait-denied) wait_denied "$@" ;;
	*) printf 'unknown e2e client command: %s\n' "$command" >&2; exit 2 ;;
esac
