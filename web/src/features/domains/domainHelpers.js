export const newLocalNetwork = (type) => ({
  type,
  name: '',
  ssid: '',
  gateway: '',
  subnet: '',
  search_domain: '',
})

export const createEmptyDraft = () => ({
  name: '',
  dns_servers: '',
  search_domain: '',
  pem: '',
  auto_enroll_enabled: true,
  local_networks: [],
})

// Preserve domains saved before ordered local-network profiles were introduced.
const legacyLocalNetworks = (domain) => {
  const legacy = domain.local_network || {}
  const profiles = []
  if (
    [legacy.wifi_name, legacy.wifi_gateway, legacy.wifi_subnet, legacy.wifi_search_domain].some(
      Boolean,
    )
  ) {
    profiles.push({
      type: 'wifi',
      name: '',
      ssid: legacy.wifi_name || '',
      gateway: legacy.wifi_gateway || '',
      subnet: legacy.wifi_subnet || '',
      search_domain: legacy.wifi_search_domain || '',
    })
  }
  if ([legacy.eth_gateway, legacy.eth_subnet, legacy.eth_search_domain].some(Boolean)) {
    profiles.push({
      type: 'ethernet',
      name: '',
      ssid: '',
      gateway: legacy.eth_gateway || '',
      subnet: legacy.eth_subnet || '',
      search_domain: legacy.eth_search_domain || '',
    })
  }
  return profiles
}

export const domainLocalNetworks = (domain) => {
  if (Array.isArray(domain.local_networks)) {
    return domain.local_networks.map((network) => ({
      ...newLocalNetwork(network.type || 'ethernet'),
      ...network,
    }))
  }
  return legacyLocalNetworks(domain)
}

export const dnsList = (value) =>
  String(value || '')
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean)

export const domainDraft = (domain) => ({
  name: domain.name || '',
  dns_servers: (domain.dns_servers || []).join(', '),
  search_domain: domain.search_domain || '',
  pem: '',
  auto_enroll_enabled: Boolean(domain.auto_enroll_enabled),
  local_networks: domainLocalNetworks(domain),
})

export const localNetworkSummary = (network) => {
  const items = []
  if (network.type === 'wifi' && network.ssid) items.push(`SSID ${network.ssid}`)
  if (network.gateway) items.push(`gateway ${network.gateway}`)
  if (network.subnet) items.push(`subnet ${network.subnet}`)
  if (network.search_domain) items.push(`search ${network.search_domain}`)
  return items.join(', ')
}
