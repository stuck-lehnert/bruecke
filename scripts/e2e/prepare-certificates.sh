#!/bin/sh
# Prepare certificates and OpenVPN fixtures in the e2e volumes.
set -eu
HOSTNAME="$1"
cat > /work/client.cnf <<CERTCONF
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = $HOSTNAME

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $HOSTNAME
CERTCONF
openssl genrsa -out /work/root.key 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -key /work/root.key -sha256 -days 2 \
	-subj '/CN=bruecke-e2e-root' \
	-addext 'basicConstraints=critical,CA:TRUE' \
	-addext 'keyUsage=critical,keyCertSign,cRLSign' \
	-out /work/root.crt >/dev/null 2>&1
openssl genrsa -out /work/client.key 2048 >/dev/null 2>&1
openssl req -new -key /work/client.key -out /work/client.csr -config /work/client.cnf >/dev/null 2>&1
openssl x509 -req -in /work/client.csr -CA /work/root.crt -CAkey /work/root.key -CAcreateserial \
	-out /work/client.crt -days 2 -sha256 -extensions v3_req -extfile /work/client.cnf >/dev/null 2>&1
cp /work/root.crt /data/domain-root-ca.pem
cat > /work/ovpn-server.cnf <<'CERTCONF'
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = remote-vpn

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = remote-vpn
CERTCONF
cat > /work/ovpn-client.cnf <<'CERTCONF'
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = bruecke-remote-client

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
CERTCONF
openssl genrsa -out /work/ovpn-ca.key 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -key /work/ovpn-ca.key -sha256 -days 2 \
	-subj '/CN=bruecke-e2e-ovpn-ca' \
	-addext 'basicConstraints=critical,CA:TRUE' \
	-addext 'keyUsage=critical,keyCertSign,cRLSign' \
	-out /work/ovpn-ca.crt >/dev/null 2>&1
openssl genrsa -out /work/ovpn-server.key 2048 >/dev/null 2>&1
openssl req -new -key /work/ovpn-server.key -out /work/ovpn-server.csr -config /work/ovpn-server.cnf >/dev/null 2>&1
openssl x509 -req -in /work/ovpn-server.csr -CA /work/ovpn-ca.crt -CAkey /work/ovpn-ca.key -CAcreateserial \
	-out /work/ovpn-server.crt -days 2 -sha256 -extensions v3_req -extfile /work/ovpn-server.cnf >/dev/null 2>&1
openssl genrsa -out /work/ovpn-client.key 2048 >/dev/null 2>&1
openssl req -new -key /work/ovpn-client.key -out /work/ovpn-client.csr -config /work/ovpn-client.cnf >/dev/null 2>&1
openssl x509 -req -in /work/ovpn-client.csr -CA /work/ovpn-ca.crt -CAkey /work/ovpn-ca.key -CAcreateserial \
	-out /work/ovpn-client.crt -days 2 -sha256 -extensions v3_req -extfile /work/ovpn-client.cnf >/dev/null 2>&1
cat > /work/remote-free-server.conf <<'OVPNCONF'
dev tun
proto tcp-server
port 1194
topology subnet
server 10.240.0.0 255.255.255.0
duplicate-cn
keepalive 1 5
persist-key
persist-tun
ca /work/ovpn-ca.crt
cert /work/ovpn-server.crt
key /work/ovpn-server.key
dh none
verb 3
OVPNCONF
cat > /work/remote-restricted-server.conf <<'OVPNCONF'
dev tun
proto tcp-server
port 1194
topology subnet
server 10.241.0.0 255.255.255.0
duplicate-cn
keepalive 1 5
persist-key
persist-tun
ca /work/ovpn-ca.crt
cert /work/ovpn-server.crt
key /work/ovpn-server.key
dh none
verb 3
OVPNCONF
{
	printf 'client\n'
	printf 'dev tun\n'
	printf 'proto tcp-client\n'
	printf 'remote remote-free-vpn 1194\n'
	printf 'nobind\n'
	printf 'persist-key\n'
	printf 'persist-tun\n'
	printf 'remote-cert-tls server\n'
	printf 'verify-x509-name remote-vpn name\n'
	printf 'verb 3\n'
	printf '<ca>\n'
	cat /work/ovpn-ca.crt
	printf '</ca>\n'
	printf '<cert>\n'
	cat /work/ovpn-client.crt
	printf '</cert>\n'
	printf '<key>\n'
	cat /work/ovpn-client.key
	printf '</key>\n'
} > /work/remote-free-client.ovpn
{
	printf 'client\n'
	printf 'dev tun\n'
	printf 'proto tcp-client\n'
	printf 'remote remote-restricted-vpn 1194\n'
	printf 'nobind\n'
	printf 'persist-key\n'
	printf 'persist-tun\n'
	printf 'remote-cert-tls server\n'
	printf 'verify-x509-name remote-vpn name\n'
	printf 'verb 3\n'
	printf '<ca>\n'
	cat /work/ovpn-ca.crt
	printf '</ca>\n'
	printf '<cert>\n'
	cat /work/ovpn-client.crt
	printf '</cert>\n'
	printf '<key>\n'
	cat /work/ovpn-client.key
	printf '</key>\n'
} > /work/remote-restricted-client.ovpn
