# bruecke

**The easiest VPN solution for domain-joined Windows computers.**

bruecke turns the machine certificates and Group Policy you already use into a managed WireGuard VPN. Deploy one startup script through GPO. Each computer proves its identity with its AD CS machine certificate, gets its own VPN configuration, and keeps it up to date. There are no new per-computer credentials or VPN configuration files to distribute.

Configure your office networks once and bruecke switches the VPN off on those networks and back on when the computer leaves. The admin UI handles domains, computers, access to remote networks, bootstrap logs, and VPN activity.

## What you need

- A Linux host with Docker or Podman, access to `/dev/net/tun`, and permission to manage network interfaces and firewall rules.
- A public hostname for HTTPS and the WireGuard UDP endpoint. The guided setup uses ports `80/tcp`, `443/tcp`, and `51820/udp` by default.
- Domain-joined Windows computers with an AD CS computer certificate that has Client Authentication and an accessible private key. Microsoft Entra `MS-Organization-*` device certificates do not satisfy this requirement.
- A way to deploy a computer startup script through Group Policy.

You can also create a domain without a CA certificate and issue configurations manually. Certificate-based enrollment requires the public certificate of the CA that issued the computers' certificates.

## Get started

From a checkout of this repository, run:

```sh
scripts/interactive-liftoff
```

The helper builds the image, creates the server's WireGuard key if needed, generates an admin password, starts a container with direct HTTPS via Let's Encrypt, and prints the admin URL. It stores persistent data in `data/` beside the repository. Keep the printed password and back up that directory.

Then:

1. Open the printed admin URL and sign in.
2. Create a domain. Upload the **public** AD CS CA certificate in PEM format and enable certificate auto enrollment. Set the DNS servers and search domain your clients need.
3. If the VPN should turn off at the office, add one or more Wi-Fi or Ethernet profiles to the domain. A profile can match SSID, gateway, subnet, or DNS suffix.
4. Download the Windows bootstrap script from the admin UI and deploy it as a **computer startup script** through GPO.
5. Check **Peers** as computers enroll. Use **Bootstrap Logs** if a computer does not appear.

The helper expects the public hostname to resolve to this host and ports `80/tcp`, `443/tcp`, and the selected WireGuard UDP port to be reachable. Port 80 is used for the HTTPS certificate challenge.

## What happens on a computer

The GPO script checks that bruecke is reachable, installs WireGuard if needed, authenticates with the computer certificate, and saves the issued configuration under `C:\ProgramData\bruecke`. It also installs a LocalSystem scheduled task for network changes and periodic checks.

That task compares the active network with the domain's configured local-network profiles. A match turns the VPN off; a nonmatch turns it on. The task uses cached configuration, so it can keep making these decisions while the server is unreachable. It runs after boot, after Windows network-profile changes, and every 2 minutes 30 seconds. An indeterminate result keeps the VPN on.

Each enrollment rotates the computer's WireGuard key while retaining its assigned tunnel addresses. The server returns the client private key once and does not store it. Disabling a peer removes its active server-side WireGuard peer; re-enrollment does not restore VPN access until the peer is enabled again.

## Manage access

The admin UI lets you:

- Create, rename, edit, and delete domains; set their CA certificate, DNS, search domain, and local-network profiles. Deleting a domain requires the admin password and removal of its enrolled computers and access grants.
- See enrolled computers, connection status, certificate details, and assigned addresses. Disable, remove, or manually enroll a computer.
- Grant access to remote subnets by computer or by group. Built-in all-computer and domain groups are available alongside custom groups.
- Inspect uploaded bootstrap logs and seven days of VPN decisions, including the network evidence behind each decision.

Remote subnets use uploaded `.ovpn` or `.apc` configurations. bruecke runs an OpenVPN client for each enabled remote subnet and manages forwarding and access rules on the server. With the default full-tunnel configuration, clients already route that traffic through bruecke. For split tunneling, include routes that cover the remote destinations.

## Deployment options

### Direct HTTPS

`scripts/interactive-liftoff` is the recommended first deployment. It chooses Docker or Podman, sets up the WireGuard interface and internet gateway, and uses Let's Encrypt for HTTPS.

To rebuild and replace a deployment created by that helper:

```sh
scripts/relaunch
```

`scripts/relaunch` pulls with `git pull --ff-only` by default, rebuilds the image, and preserves the container's settings and data mount. To stop the container and remove its image, run `scripts/cleanup`. The cleanup script asks separately before deleting persistent data.

### Existing reverse proxy

bruecke can serve HTTP on `:8080` behind a TLS-terminating reverse proxy. The proxy does not need to validate client certificates: enrollment verifies the machine certificate in the application protocol. Set `BRUECKE_PUBLIC_URL` to the public origin if your proxy does not reliably forward the original host and scheme. The downloaded Windows script uses that URL to contact bruecke.

For example:

```nginx
server {
    listen 443 ssl;
    server_name vpn.example.com;

    ssl_certificate /etc/nginx/tls/server.crt;
    ssl_certificate_key /etc/nginx/tls/server.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Build the container with `docker build -t bruecke .` and provide `/data`, `/dev/net/tun`, `NET_ADMIN`, a server WireGuard private key, and the required environment variables below. The WireGuard UDP port must also be reachable.

## Configuration

The guided setup supplies the required values. For a custom deployment, set these yourself:

| Variable | Purpose |
| --- | --- |
| `BRUECKE_WG_ENDPOINT` | Public WireGuard address, for example `vpn.example.com:51820`. |
| `BRUECKE_WG_SERVER_PUBLIC_KEY` | Server WireGuard public key included in client configurations. |
| `ADMIN_HASH` | Bcrypt hash of the admin password. Without it, admin login is unavailable. |
| `BRUECKE_WG_PRIVATE_KEY_FILE` | Server private key path; defaults to `/data/wg-server.key`. |

Generate an admin hash with `htpasswd -bnBC 12 "" "your-password" | tr -d ':\n'`. Keep the server private key and `/data` persistent across restarts.

Common settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `BRUECKE_TLS_TERMINATE` | `false` | Serve HTTPS directly using Let's Encrypt; changes the default listen address to `:443`. |
| `BRUECKE_ADDR` | `:8080` | HTTP listen address, or `:443` with direct HTTPS. |
| `BRUECKE_PUBLIC_URL` | Derived from the request | Public origin embedded in downloaded bootstrap scripts. |
| `BRUECKE_DATA_DIR` | `/data` | Persistent database, domain, log, and runtime files. |
| `BRUECKE_WG_CLIENT_ALLOWED_IPS` | `0.0.0.0/0, ::/0` | Client routes; change for split tunneling. |
| `BRUECKE_WG_CIDR` | `10.44.0.0/24` | IPv4 seed range for generated domain pools. |
| `BRUECKE_WG_IPV6_CIDR` | `fd44:44:44::/64` | IPv6 seed range for generated domain pools. |
| `BRUECKE_WG_DNS` | `9.9.9.9` | Initial DNS servers for new domains; editable per domain. |
| `BRUECKE_WG_OUTBOUND_INTERFACE` | `auto` | Outbound interface for forwarding and NAT; `-` disables gateway setup. |
| `BRUECKE_APPLY_WG` | `true` | Run the privileged WireGuard scripts; set `false` for local API development. |

Other paths, timeouts, script hooks, and TLS options are defined in [`internal/bruecke/config.go`](internal/bruecke/config.go). The container image includes WireGuard and OpenVPN tools. bruecke restores stored peers and remote-subnet connections on startup.

## Enrollment API

The GPO script uses a short-lived, two-step challenge:

1. `POST /enroll/start` receives a machine certificate and optional intermediate chain. bruecke verifies it against an enabled domain CA and returns a nonce and handshake ID.
2. The computer signs the nonce with its certificate private key. `POST /enroll/finish` verifies the signature and returns a fresh WireGuard configuration. Use `response_format: "json"` to receive the configuration and local-network rules together.

Machine identity comes from the first valid DNS SAN, or the certificate common name if there is no suitable DNS SAN. Supported signature algorithms are `sha256-rsa`, `sha256-rsa-pss`, and `sha256-ecdsa`. `GET /healthz` returns `ok` without authentication.

Admin endpoints live under `/api/admin/*` and require an admin session. These include domains, clients, groups, remote subnets, bootstrap logs, VPN activity, manual enrollment, and the Windows bootstrap download. `DELETE /api/admin/domains/{id}` also requires the admin password in the JSON request body and refuses to delete a domain that still has dependent clients or assignments.

## Troubleshooting

If a computer does not appear under **Peers**, start with **Bootstrap Logs**. A run without a client ID failed before enrollment completed. Check the public URL in the downloaded script, HTTPS reachability, the uploaded issuing CA, certificate auto enrollment, and whether the computer has a Client Authentication certificate with a private key. The logs also show signature, WireGuard installation, and scheduled-task errors.

For unexpected VPN switching, open **VPN activity**. Each entry records the local, nonlocal, or indeterminate decision and the adapter evidence used. A local profile matches only when its configured criteria hold on the same active non-tunnel adapter. A subnet match requires both the IPv4 address and the exact prefix length. If the evidence stays incomplete, bruecke keeps the VPN on.

## Development

Start a seeded local preview:

```sh
scripts/dev
```

The dev UI is printed by the script; the default admin password is `123456`. Press Ctrl-C to stop and remove its containers. Use `BRUECKE_DEV_RESET=1 scripts/dev` to reseed the sample data.

Build and test directly:

```sh
cd web && npm install && npm run build
cd ..
go test ./...
```

For an end-to-end test with Docker or Podman, run `scripts/test-e2e`. It exercises enrollment, VPN egress, remote-subnet access, and peer disabling.

## License

bruecke is licensed under the GNU Affero General Public License, version 3 or later. See [LICENSE](LICENSE).
