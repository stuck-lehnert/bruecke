import React, { useState } from 'react'
import { PeersPanel } from './features/peers/PeersPanel.jsx'
import { api } from './api.js'
import { useAdminData } from './hooks/useAdminData.js'
import { t } from './i18n.jsx'
import { clientLabel, filterClients, upsertClient } from './helpers.js'
import { Shell } from './layout.jsx'
import { Button } from './components/forms.jsx'
import { Notice } from './components/Notice.jsx'
import { AdminNavigation } from './components/AdminNavigation.jsx'
import { ConfirmModal } from './components/ConfirmModal.jsx'
import { WikiPanel } from './features/WikiPanel.jsx'
import { VPNActivityPanel } from './features/operations/VPNActivityPanel.jsx'
import { BootstrapLogsPanel } from './features/operations/BootstrapLogsPanel.jsx'
import { RemoteSubnetsPanel } from './features/remote-subnets/RemoteSubnetsPanel.jsx'
import { GroupsPanel } from './features/groups/GroupsPanel.jsx'
import { ManualEnrollment } from './features/enrollment/ManualEnrollment.jsx'
import { SSHClientEnrollment } from './features/enrollment/SSHClientEnrollment.jsx'
import { DomainsPanel } from './features/domains/DomainsPanel.jsx'

export function Dashboard({ onLogout }) {
  const {
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
  } = useAdminData()
  const [busyHost, setBusyHost] = useState('')
  const [busyDomain, setBusyDomain] = useState('')
  const [activeTab, setActiveTab] = useState('peers')
  const [expandedPeerID, setExpandedPeerID] = useState('')
  const [logFilterClientID, setLogFilterClientID] = useState('')
  const [vpnFilterClientID, setVPNFilterClientID] = useState('')
  const [peerQuery, setPeerQuery] = useState('')
  const [peerStatus, setPeerStatus] = useState('all')
  const [clientToRemove, setClientToRemove] = useState(null)

  const toggleClient = async (client) => {
    setBusyHost(client.id)
    setError('')
    try {
      const updated = await api(`/api/admin/clients/${encodeURIComponent(client.id)}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled: !client.enabled }),
      })
      setClients((current) => current.map((item) => (item.id === updated.id ? updated : item)))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusyHost('')
    }
  }

  const removeClient = async (client) => {
    setBusyHost(client.id)
    setError('')
    try {
      await api(`/api/admin/clients/${encodeURIComponent(client.id)}`, { method: 'DELETE' })
      setClients((current) => current.filter((item) => item.id !== client.id))
      await loadAdminConfig()
      setClientToRemove(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusyHost('')
    }
  }

  const logout = async () => {
    await api('/api/admin/logout', { method: 'POST', body: '{}' }).catch(() => {})
    onLogout()
  }

  const visibleClients = filterClients(clients, peerQuery, peerStatus)

  return (
    <Shell
      title={t('ui.bruecke_admin')}
      action={
        <Button className="ghost" onClick={logout}>
          {t('ui.logout')}
        </Button>
      }
    >
      <AdminNavigation activeTab={activeTab} onChange={setActiveTab} />
      {statusError && (
        <Notice status="warning">
          {t('ui.wireguard_status_unavailable_spaced')}
          {statusError}
        </Notice>
      )}
      {error && <Notice status="danger">{error}</Notice>}
      {activeTab === 'peers' && (
        <PeersPanel
          clients={clients}
          visibleClients={visibleClients}
          remoteSubnets={remoteSubnets}
          groups={groups}
          peerQuery={peerQuery}
          setPeerQuery={setPeerQuery}
          peerStatus={peerStatus}
          setPeerStatus={setPeerStatus}
          expandedPeerID={expandedPeerID}
          setExpandedPeerID={setExpandedPeerID}
          busyHost={busyHost}
          load={load}
          toggleClient={toggleClient}
          setClientToRemove={setClientToRemove}
          onShowLogs={(id) => {
            setLogFilterClientID(id)
            setActiveTab('logs')
          }}
          onShowVPNActivity={(id) => {
            setVPNFilterClientID(id)
            setActiveTab('vpn-activity')
          }}
        />
      )}
      {activeTab === 'logs' && (
        <section className="tab-panel">
          <BootstrapLogsPanel
            clients={clients}
            filterClientID={logFilterClientID}
            onClearFilter={() => setLogFilterClientID('')}
            onError={setError}
          />
        </section>
      )}
      {activeTab === 'vpn-activity' && (
        <section className="tab-panel">
          <VPNActivityPanel
            clients={clients}
            filterClientID={vpnFilterClientID}
            onClearFilter={() => setVPNFilterClientID('')}
            onError={setError}
          />
        </section>
      )}
      {activeTab === 'remote' && (
        <section className="tab-panel">
          <RemoteSubnetsPanel
            subnets={remoteSubnets}
            clients={clients}
            groups={groups}
            onChange={setRemoteSubnets}
            onError={setError}
          />
        </section>
      )}
      {activeTab === 'groups' && (
        <section className="tab-panel">
          <GroupsPanel
            groups={groups}
            clients={clients}
            onChange={setGroups}
            onClientsReload={loadClients}
            onError={setError}
          />
        </section>
      )}
      {activeTab === 'domains' && (
        <section className="tab-panel">
          <DomainsPanel
            domains={domains}
            clients={clients}
            busyDomain={busyDomain}
            setBusyDomain={setBusyDomain}
            onChange={setDomains}
            onRefresh={() => loadAdminConfig().catch((err) => setError(err.message))}
            onError={setError}
          />
        </section>
      )}
      {activeTab === 'wiki' && (
        <section className="tab-panel">
          <WikiPanel />
        </section>
      )}
      {activeTab === 'manual' && (
        <section className="tab-panel">
          <ManualEnrollment
            domains={domains}
            onEnroll={(client) => setClients((current) => upsertClient(current, client))}
            onError={setError}
          />
          <SSHClientEnrollment
            domains={domains}
            onEnroll={(client) => setClients((current) => upsertClient(current, client))}
          />
        </section>
      )}
      <ConfirmModal
        open={Boolean(clientToRemove)}
        title={t('ui.remove_peer')}
        message={
          clientToRemove
            ? clientToRemove.type === 'ssh'
              ? t('ssh.remove_confirmation', { name: clientLabel(clientToRemove) })
              : `Remove ${clientLabel(clientToRemove)} and its WireGuard key? This cannot be undone.`
            : ''
        }
        confirmLabel="Remove peer"
        busy={busyHost === clientToRemove?.id}
        onClose={() => setClientToRemove(null)}
        onConfirm={() => removeClient(clientToRemove)}
      />
    </Shell>
  )
}
