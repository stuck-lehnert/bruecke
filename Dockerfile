FROM node:22-alpine AS web

WORKDIR /web
COPY web/package*.json web/index.html web/vite.config.js ./
COPY web/src ./src
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi \
	&& npm run build

FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/bruecked ./cmd/bruecked

FROM alpine:3.20

RUN apk add --no-cache ca-certificates iproute2 iptables openvpn wireguard-tools
COPY --from=build /out/bruecked /usr/local/bin/bruecked
COPY --from=web /web/dist /usr/local/share/bruecke/web
COPY scripts/bruecke-wg-apply-peer /usr/local/bin/bruecke-wg-apply-peer
COPY scripts/bruecke-wg-remove-peer /usr/local/bin/bruecke-wg-remove-peer
COPY scripts/bruecke-wg-peer-status /usr/local/bin/bruecke-wg-peer-status
COPY scripts/bruecke-wg-up /usr/local/bin/bruecke-wg-up
COPY scripts/bruecke-wg-down /usr/local/bin/bruecke-wg-down
RUN chmod +x /usr/local/bin/bruecked /usr/local/bin/bruecke-wg-apply-peer /usr/local/bin/bruecke-wg-remove-peer /usr/local/bin/bruecke-wg-peer-status /usr/local/bin/bruecke-wg-up /usr/local/bin/bruecke-wg-down \
	&& mkdir -p /data

VOLUME ["/data"]
EXPOSE 80/tcp 443/tcp 8080/tcp 51820/udp
ENTRYPOINT ["/usr/local/bin/bruecked"]
