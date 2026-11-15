import { useEffect, useState } from 'react'
import { api, CLIENT_STATUS_INTERVAL_MS } from '../api.js'

export function useAdminData() {
  const [clients, setClients] = useState([])
  const [remoteSubnets, setRemoteSubnets] = useState([])
  const [groups, setGroups] = useState([])
  const [domains, setDomains] = useState([])
  const [statusError, setStatusError] = useState('')
  const [error, setError] = useState('')

  const applyClientResponse = (data) => {
    setClients(data.clients || [])
    setStatusError(data.status_error || '')
  }

  const loadClients = async () => {
    const data = await api('/api/admin/clients')
    applyClientResponse(data)
  }

  const loadAdminConfig = async () => {
    const [remoteData, domainData, groupData] = await Promise.all([
      api('/api/admin/remote-subnets'),
      api('/api/admin/domains'),
      api('/api/admin/groups'),
    ])
    setRemoteSubnets(remoteData.subnets || [])
    setDomains(domainData.domains || [])
    setGroups(groupData.groups || [])
  }

  const load = async () => {
    setError('')
    try {
      await Promise.all([loadClients(), loadAdminConfig()])
    } catch (err) {
      setError(err.message)
    }
  }

  useEffect(() => {
    let cancelled = false
    let pollInterval = null
    let reconnectTimer = null
    let socket = null

    const refreshClients = async () => {
      try {
        const data = await api('/api/admin/clients')
        if (!cancelled) applyClientResponse(data)
      } catch (err) {
        if (!cancelled) setError(err.message)
      }
    }

    const refreshAdminConfig = async () => {
      try {
        const [remoteData, domainData, groupData] = await Promise.all([
          api('/api/admin/remote-subnets'),
          api('/api/admin/domains'),
          api('/api/admin/groups'),
        ])
        if (!cancelled) {
          setRemoteSubnets(remoteData.subnets || [])
          setDomains(domainData.domains || [])
          setGroups(groupData.groups || [])
        }
      } catch (err) {
        if (!cancelled) setError(err.message)
      }
    }

    const startPolling = () => {
      if (pollInterval) return
      refreshClients()
      pollInterval = window.setInterval(refreshClients, CLIENT_STATUS_INTERVAL_MS)
    }

    const stopPolling = () => {
      if (!pollInterval) return
      window.clearInterval(pollInterval)
      pollInterval = null
    }

    const connectStream = () => {
      if (cancelled) return
      if (!window.WebSocket) {
        startPolling()
        return
      }
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      socket = new WebSocket(`${protocol}//${window.location.host}/api/admin/clients/ws`)
      socket.onopen = stopPolling
      socket.onmessage = (event) => {
        try {
          applyClientResponse(JSON.parse(event.data))
        } catch {
          // Ignore malformed stream frames and wait for next 5s update.
        }
      }
      socket.onerror = () => socket.close()
      socket.onclose = () => {
        if (cancelled) return
        startPolling()
        reconnectTimer = window.setTimeout(connectStream, CLIENT_STATUS_INTERVAL_MS)
      }
    }

    refreshAdminConfig()
    connectStream()
    startPolling()
    return () => {
      cancelled = true
      stopPolling()
      if (reconnectTimer) window.clearTimeout(reconnectTimer)
      if (socket) socket.close()
    }
  }, [])

  return {
    clients,
    setClients,
    remoteSubnets,
    setRemoteSubnets,
    groups,
    setGroups,
    domains,
    setDomains,
    statusError,
    error,
    setError,
    load,
    loadClients,
    loadAdminConfig,
  }
}
