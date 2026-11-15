# bruecke

**The easiest VPN solution for domain-joined Windows computers.**

bruecke turns the machine certificates and Group Policy you already use into a managed WireGuard VPN. Deploy one startup script through GPO. Each computer proves its identity with its AD CS machine certificate, gets its own VPN configuration, and keeps it up to date. There are no new per-computer credentials or VPN configuration files to distribute.

Configure your office networks once and bruecke switches the VPN off on those networks and back on when the computer leaves. The admin UI handles domains, computers, access to remote networks, bootstrap logs, and VPN activity.

## What you need

- A Linux host with Docker or Podman, access to `/dev/net/tun`, and permission to manage network interfaces and firewall rules.
- A public hostname for HTTPS, the SSH jump host, and the WireGuard UDP endpoint. The guided setup uses ports `80/tcp`, `443/tcp`, `8888/tcp`, and `51820/udp` by default.
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

The helper expects the public hostname to resolve to this host and ports `80/tcp`, `443/tcp`, `8888/tcp`, and the selected WireGuard UDP port to be reachable. Port 80 is used for the HTTPS certificate challenge.

## SSH jump-host clients

For SSH access without installing WireGuard on the connecting computer, open **Manual enrollment** in the admin UI and register an **SSH client** with a hostname, a domain, and one public key in OpenSSH `.pub` format. No CA or auto enrollment is required. Keep the private key on the connecting computer; never upload it.

Supported keys are RSA **2048–8192 bits** (including 2048, 3072 and 4096), ECDSA **P-256, P-384, P-521**, and **Ed25519**. Public-key comments are accepted; multiple keys, `authorized_keys` options, SSH certificates, DSA, and weak RSA keys are rejected. RSA authentication uses SHA-2 signatures, not the obsolete SHA-1 `ssh-rsa` signature algorithm. Existing clients cannot be overwritten by provisioning; to replace a key, delete and recreate the SSH client.

The built-in Go SSH server listens on **TCP 8888**. Authentication uses the registered client hostname (or its full client ID) as the SSH username. For example, with an SSH client named `alice-laptop` and a VPN target at `10.44.0.3`:

```sshconfig
Host bruecke-jump
    HostName vpn.example.com
    Port 8888
    User alice-laptop
    IdentityFile ~/.ssh/bruecke_jump
    IdentitiesOnly yes

Host office-pc
    HostName 10.44.0.3
    User target-user
    ProxyJump bruecke-jump
```

Run `ssh office-pc`. The target still needs its own SSH service, account, and authentication; the jump key only authenticates to bruecke. Alternatively, keep a connection online with `ssh -N -p 8888 -i ~/.ssh/bruecke_jump alice-laptop@vpn.example.com`, or use local TCP forwarding with `-N -L 2222:10.44.0.3:22` and then connect to port 2222 locally.

There is **no shell, PTY, command execution, SFTP/SCP, agent/X11 forwarding, reverse forwarding, Unix-socket forwarding, or SSH VPN/TUN**. Only `direct-tcpip` channels (used by ProxyJump, `-W`, `-L` and `-D`) are implemented. This is not a general-purpose Internet proxy: destinations must be an enabled WireGuard client in the **same domain**, or an enabled remote subnet assigned to the SSH client through the existing client/group permissions. Known VPN clients in other domains and all bridge-local addresses remain blocked, even with a broad remote route. VPN client hostnames (and their domain search-suffix names) resolve internally; remote-subnet destinations currently require an IP address.

SSH clients share the regular client list, groups, remote-subnet assignments, enable/delete actions, and domain IPv4/IPv6 allocation. Each SSH client gets its **own source IPs**, not the bridge's IP: while connected these are installed on the dedicated `br-ssh` dummy interface, and outgoing TCP connections bind to the appropriate address. Normal WireGuard peers therefore see the SSH client's allocated IP; existing remote-subnet NAT rules can still translate traffic to remote networks. These are jump-host identities, not an inbound network interface on the user's computer: SSH clients do not accept inbound connections to their allocated IPs.

Online status reflects authenticated SSH connections, including idle `ssh -N` connections. The last-handshake field records the last successful SSH connection. Up to four connections per identity and 32 simultaneous forwarding channels per connection are allowed; the server admits at most 128 TCP connections including pending handshakes. Handshakes time out after 10 seconds, and keepalives detect dead connections in approximately 40 seconds. Disabling/deleting an SSH client disconnects it; access changes also terminate affected existing forwards within about one second. Source addresses are removed after its last connection closes, and stale addresses on bruecke's marked interface are cleared on restart.

The server generates a persistent Ed25519 host key at `/data/ssh_host_ed25519_key` with mode `0600`. Back it up with `/data` and verify its fingerprint on the first connection (for example `ssh-keygen -lf /data/ssh_host_ed25519_key` on the server). Do not disable host-key checking. SSH networking requires `iproute2` and `NET_ADMIN`, already supplied by the production container setup. Publish `-p 8888:8888/tcp` for custom **or existing** containers; an HTTP reverse proxy does not expose SSH. `scripts/relaunch` preserves old port mappings, so upgrading an older container requires adding this mapping when recreating it. The unprivileged `scripts/dev` UI/demo mode explicitly disables SSH networking.

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
| `BRUECKE_SSH_ENABLED` | `true` | Run the public-key-only SSH jump host; set `false` for unprivileged UI/demo-only deployments. |
| `BRUECKE_SSH_ADDR` | `:8888` | SSH TCP listen address. Publish the corresponding container port. |
| `BRUECKE_SSH_HOST_KEY_PATH` | `/data/ssh_host_ed25519_key` | Persistent SSH server private host key (mode `0600`). |
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

Go **1.26 or newer** is required for the current security-maintained SSH dependency.

```sh
cd web
npm ci
npm run check
cd ..
go test ./...
go test -race ./...
go vet ./...
scripts/check
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
```

`npm run check` checks formatting with Prettier, runs ESLint and the Node test suite,
and builds the production UI. Use `npm run format` from `web/` to format frontend
changes, and `gofmt -w` on changed Go files. `scripts/check` requires ShellCheck and
checks shell syntax without running any deployment commands. The Python tests
require Bash, jq, and ShellCheck and use
temporary command stubs; they do not start containers or modify network interfaces.

### Code organization and conventions

- Keep modules focused on one responsibility. Admin handlers are grouped by API
  resource; client persistence, group membership, and HTTP helpers are separate.
- The Windows bootstrap source lives in `internal/bruecke/windows/bootstrap.ps1`
  and is embedded in the Go binary with `go:embed`. Edit that file directly rather
  than adding PowerShell to Go string literals.
- The React entry point only mounts the app. Feature modules live under
  `web/src/features/`, reusable UI under `web/src/components/`, and pure data
  transformations alongside their tests.
- Prefer descriptive names, early returns, and small functions. Share repeated
  policy or I/O logic, but avoid wrappers that merely obscure a straightforward call.
- Preserve API fields, persisted formats, and existing behavior when refactoring;
  cover changes to validation, permissions, or rollback with regression tests.
- Use the checked-in EditorConfig and formatter configuration rather than manual
  formatting preferences. CI runs the same checks listed above.

The normal Go suite covers real SSH handshakes for RSA/ECDSA/Ed25519, forwarding and denial rules, online state, revocation, address-command rollback, and kernel TCP source binding on loopback. If `ssh` is installed it also checks standard OpenSSH `-W` forwarding and rejection of command execution.

`TestSSHNetworkIntegration` additionally exercises actual dummy-interface source addresses and cleanup with OpenSSH. It is **opt-in**: run it only in an isolated Linux network namespace/container with `NET_ADMIN`, IPv6, `iproute2`, and OpenSSH installed, using `BRUECKE_TEST_SSH_NETWORK=1 go test ./internal/bruecke -run '^TestSSHNetworkIntegration$' -v`. It creates/clears the bruecke-owned `br-ssh` interface; do not run it in a live bruecke network namespace.

For an end-to-end test with Docker or Podman, run `scripts/test-e2e`. It exercises enrollment, VPN egress, remote-subnet access, and peer disabling.

## License

bruecke is licensed under the GNU Affero General Public License, version 3 or later. See [LICENSE](LICENSE).
