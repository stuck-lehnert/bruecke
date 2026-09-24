export const CLIENT_STATUS_INTERVAL_MS = 5000

export const TABS = [
  { id: 'peers', label: 'Peers', section: 'Overview' },
  { id: 'domains', label: 'Domains', section: 'Network' },
  { id: 'remote', label: 'Remote subnets', section: 'Network' },
  { id: 'groups', label: 'Groups', section: 'Access' },
  { id: 'logs', label: 'Bootstrap logs', section: 'Operations' },
  { id: 'vpn-activity', label: 'VPN activity', section: 'Operations' },
  { id: 'manual', label: 'Manual enrollment', section: 'Operations' },
  { id: 'wiki', label: 'Operator guide', section: 'Help' },
]

export const api = async (path, options = {}) => {
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  })

  const text = await response.text()
  let data = null
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = null
    }
  }
  if (!response.ok) {
    const error = new Error(data?.error || text || response.statusText)
    error.status = response.status
    throw error
  }
  return data
}
