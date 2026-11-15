export function mergeRemoteSubnets(current, subnet) {
  const exists = current.some((item) => item.id === subnet.id)
  const next = exists
    ? current.map((item) => (item.id === subnet.id ? subnet : item))
    : [...current, subnet]
  return next.sort((a, b) => a.name.localeCompare(b.name))
}

export function splitSubnetText(value) {
  return value
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

export function upsertClient(current, client) {
  const exists = current.some((item) => item.id === client.id)
  const next = exists
    ? current.map((item) => (item.id === client.id ? client : item))
    : [...current, client]
  return next.sort((a, b) => clientLabel(a).localeCompare(clientLabel(b)))
}

export function toggleID(ids, id) {
  const next = new Set(ids || [])
  if (next.has(id)) next.delete(id)
  else next.add(id)
  return [...next].sort()
}

export function clientLabel(client) {
  if (!client) return 'unknown'
  return client.domain_name ? `${client.hostname} (${client.domain_name})` : client.hostname
}

// Validate the OpenSSH envelope locally; the server remains authoritative for
// cryptographic validation and duplicate keys/hostnames.
export function isSupportedSshPublicKey(value) {
  const match = value
    .trim()
    .match(
      /^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521))[ \t]+([A-Za-z0-9+/]+={0,2})(?:[ \t]+[^\r\n]*)?$/,
    )
  if (!match || value.length > 16384) return false
  try {
    const bytes = Uint8Array.from(atob(match[2]), (character) => character.charCodeAt(0))
    let offset = 0
    const read = () => {
      if (offset + 4 > bytes.length) throw new Error('Invalid SSH field')
      const length = new DataView(bytes.buffer).getUint32(offset)
      offset += 4
      if (length > bytes.length - offset) throw new Error('Invalid SSH field')
      const field = bytes.slice(offset, offset + length)
      offset += length
      return field
    }
    const text = (field) => new TextDecoder().decode(field)
    if (text(read()) !== match[1]) return false
    let valid = false
    if (match[1] === 'ssh-ed25519') {
      valid = read().length === 32
    } else if (match[1] === 'ssh-rsa') {
      const exponent = read()
      const modulus = read()
      const first = modulus.findIndex((byte) => byte !== 0)
      const bits =
        first < 0 ? 0 : (modulus.length - first - 1) * 8 + Math.floor(Math.log2(modulus[first])) + 1
      valid = exponent.some((byte) => byte !== 0) && bits >= 2048 && bits <= 8192
    } else {
      const curve = match[1].slice('ecdsa-sha2-'.length)
      const curveMatches = text(read()) === curve
      const point = read()
      valid =
        curveMatches &&
        point[0] === 4 &&
        point.length === { nistp256: 65, nistp384: 97, nistp521: 133 }[curve]
    }
    return valid && offset === bytes.length
  } catch {
    return false
  }
}

export function groupLabel(groups, id) {
  const group = groups.find((item) => item.id === id)
  return group?.name || id
}

export function clientRemoteSubnets(client, subnets) {
  const groups = new Set(client.group_ids || [])
  return subnets.filter((subnet) => {
    if (!subnet.enabled) return false
    if ((subnet.client_ids || []).includes(client.id)) return true
    return (subnet.group_ids || []).some((id) => groups.has(id))
  })
}

export function remoteAccessSummary(subnet, groups, clients) {
  const groupNames = (subnet.group_ids || []).map((id) => groupLabel(groups, id))
  const clientNames = (subnet.client_ids || []).map((id) =>
    clientLabel(clients.find((client) => client.id === id)),
  )
  const parts = [...groupNames, ...clientNames]
  return parts.length ? parts.join(', ') : 'none'
}

export function filterClients(clients, query, status) {
  const normalizedPeerQuery = query.trim().toLowerCase()
  return clients.filter((client) => {
    if (status === 'connected' && (!client.enabled || !client.connected)) return false
    if (status === 'offline' && (!client.enabled || client.connected)) return false
    if (status === 'disabled' && client.enabled) return false
    if (!normalizedPeerQuery) return true
    return [
      client.hostname,
      client.domain_name,
      client.ip,
      client.ipv6,
      client.type || 'wireguard',
    ].some((value) =>
      String(value || '')
        .toLowerCase()
        .includes(normalizedPeerQuery),
    )
  })
}
