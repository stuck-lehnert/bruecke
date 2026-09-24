export function mergeRemoteSubnets(current, subnet) {
  const exists = current.some((item) => item.id === subnet.id)
  const next = exists
    ? current.map((item) => (item.id === subnet.id ? subnet : item))
    : [...current, subnet]
  return next.sort((a, b) => a.name.localeCompare(b.name))
}

export function splitSubnetText(value) {
  return value.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean)
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
  const clientNames = (subnet.client_ids || []).map((id) => clientLabel(clients.find((client) => client.id === id)))
  const parts = [...groupNames, ...clientNames]
  return parts.length ? parts.join(', ') : 'none'
}
