import React, { useEffect, useState } from 'react'
import { Alert, Button as HeroButton, Card, Checkbox, Chip, Disclosure, Dropdown, Input as HeroInput, Label, Surface, TextArea as HeroTextArea } from '@heroui/react'
import { LocaleProvider, useLocale, t, tr, formatDate, statusLabel } from './i18n'
import { createRoot } from 'react-dom/client'
import { CLIENT_STATUS_INTERVAL_MS, TABS, api } from './api'
import {
  clientLabel,
  clientRemoteSubnets,
  groupLabel,
  mergeRemoteSubnets,
  remoteAccessSummary,
  splitSubnetText,
  toggleID,
  upsertClient,
} from './helpers'
import { Modal, Shell } from './layout'
import { SelectField } from './select'
import './styles.css'

function App() {
  useLocale()
  const [authenticated, setAuthenticated] = useState(false)
  const [checkingSession, setCheckingSession] = useState(true)

  useEffect(() => {
    let cancelled = false
    api('/api/admin/session')
      .then((session) => {
        if (!cancelled) setAuthenticated(session.authenticated)
      })
      .catch(() => {
        if (!cancelled) setAuthenticated(false)
      })
      .finally(() => {
        if (!cancelled) setCheckingSession(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  if (checkingSession) return <Shell title={t("ui.bruecke")}><p>{t("ui.checking_session")}</p></Shell>
  if (!authenticated) return <Login onLogin={() => setAuthenticated(true)} />
  return <Dashboard onLogout={() => setAuthenticated(false)} />
}

function Button({ className = '', onClick, type, disabled, children, ...props }) {
  return <HeroButton
    {...props}
    className={className}
    variant={className.includes('danger') ? 'danger' : className.includes('nav-button') ? (className.includes('active') ? 'secondary' : 'ghost') : className.includes('ghost') ? 'ghost' : 'primary'}
    size={className.includes('compact-button') ? 'sm' : 'md'}
    type={type || (onClick ? 'button' : 'submit')}
    isDisabled={disabled}
    onPress={onClick ? (event) => onClick({ currentTarget: event.target, target: event.target }) : undefined}
  >{typeof children === 'string' ? tr(children) : children}</HeroButton>
}

function Input(props) {
  return <HeroInput fullWidth variant="secondary" {...props} />
}

function TextArea(props) {
  return <HeroTextArea fullWidth variant="secondary" {...props} />
}

function Notice({ status, children }) {
  return <Alert className="notice" status={status} role={status === 'danger' ? 'alert' : 'status'}><Alert.Indicator /><Alert.Content><Alert.Description>{children}</Alert.Description></Alert.Content></Alert>
}

function Login({ onLogin }) {
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await api('/api/admin/login', {
        method: 'POST',
        body: JSON.stringify({ password }),
      })
      onLogin()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Shell title={t("ui.bruecke_admin")}>
      <Card className="login"><form className="login-form" onSubmit={submit}>
        <label htmlFor="password">{t("ui.admin_password")}</label>
        <Input
          id="password"
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          autoFocus
          required
        />
        {error && <Notice status="danger">{error}</Notice>}
        <Button disabled={busy}>{busy ? 'Signing in...' : 'Sign in'}</Button>
      </form></Card>
    </Shell>
  )
}

function ExpandableRow({ title, meta, actions, expanded, onExpandedChange, children }) {
  return (
    <Disclosure className="expandable-row" isExpanded={expanded} onExpandedChange={onExpandedChange}>
      <div className="expandable-header">
        <Disclosure.Heading className="expandable-heading">
          <Disclosure.Trigger className="expandable-trigger">
            <span className="expandable-label"><strong>{title}</strong>{meta && <span className="expandable-meta">{meta}</span>}</span>
            <Disclosure.Indicator />
          </Disclosure.Trigger>
        </Disclosure.Heading>
        {actions && <div className="expandable-actions">{actions}</div>}
      </div>
      <Disclosure.Content className="expandable-content">{children}</Disclosure.Content>
    </Disclosure>
  )
}

function InfoDisclosure({ title, meta, children, defaultExpanded = false, className = '' }) {
  const [expanded, setExpanded] = useState(defaultExpanded)
  return (
    <Disclosure className={`info-disclosure ${className}`} isExpanded={expanded} onExpandedChange={setExpanded}>
      <Disclosure.Heading>
        <Disclosure.Trigger className="info-trigger">
          <span>{title}</span>{meta && <span className="info-meta">{meta}</span>}
          <Disclosure.Indicator />
        </Disclosure.Trigger>
      </Disclosure.Heading>
      <Disclosure.Content className="info-content">{children}</Disclosure.Content>
    </Disclosure>
  )
}

function CheckboxRow({ children, checked, disabled, onChange, compact = false }) {
  return (
      <Checkbox className={compact ? 'checkbox-row compact' : 'checkbox-row'} variant="secondary" isSelected={checked} isDisabled={disabled} onChange={onChange}>
      <Checkbox.Content>
        <Checkbox.Control><Checkbox.Indicator /></Checkbox.Control>
        <Label>{children}</Label>
      </Checkbox.Content>
    </Checkbox>
  )
}

function DetailGrid({ children, compact = false }) {
  return <dl className={compact ? 'detail-grid compact-grid' : 'detail-grid'}>{children}</dl>
}

function PillList({ children }) {
  return <span className="pill-list">{children}</span>
}

function Pill({ children, tone = '' }) {
  return <Chip color={tone === 'ok' ? 'success' : tone === 'danger' ? 'danger' : 'default'} variant="soft" size="sm">{typeof children === 'string' ? tr(children) : children}</Chip>
}

function AdminNavigation({ activeTab, onChange }) {
  return (
    <nav className="admin-navigation" aria-label={t("ui.admin_sections")}>
      <div className="desktop-navigation">
        {TABS.map((tab) => (
          <Button key={tab.id} className={activeTab === tab.id ? 'nav-button active' : 'nav-button'} aria-current={activeTab === tab.id ? 'page' : undefined} onClick={() => onChange(tab.id)}>{tr(tab.label)}</Button>
        ))}
      </div>
      <div className="mobile-navigation">
        <SelectField label={t('ui.section')} value={activeTab} onChange={onChange} options={TABS.map((tab) => ({ value: tab.id, label: `${tr(tab.section)} · ${tr(tab.label)}` }))} />
      </div>
    </nav>
  )
}

function ActionMenu({ label = 'Actions', items }) {
  return (
    <Dropdown>
      <HeroButton aria-label={label} variant="secondary" size="sm" isIconOnly>•••</HeroButton>
      <Dropdown.Popover placement="bottom end">
        <Dropdown.Menu aria-label={label} disabledKeys={items.flatMap((item, index) => item.disabled ? [String(index)] : [])} onAction={(key) => items[Number(key)]?.onAction()}>
          {items.map((item, index) => (
            <Dropdown.Item key={index} id={String(index)} textValue={item.label} variant={item.danger ? 'danger' : 'default'}>
              <Label>{item.label}</Label>
            </Dropdown.Item>
          ))}
        </Dropdown.Menu>
      </Dropdown.Popover>
    </Dropdown>
  )
}

function ConfirmModal({ open, title, message, confirmLabel, busy = false, onClose, onConfirm }) {
  return (
    <Modal title={tr(title)} open={open} onClose={onClose}>
      <div className="confirm-dialog">
        <p>{tr(message)}</p>
        <div className="modal-actions">
          <Button type="button" className="ghost" onClick={onClose}>{t("ui.cancel")}</Button>
          <Button type="button" className="danger" disabled={busy} onClick={onConfirm}>{tr(busy ? 'Working...' : confirmLabel)}</Button>
        </div>
      </div>
    </Modal>
  )
}

function SelectionPicker({ label, options, selectedIDs, onChange }) {
  const [query, setQuery] = useState('')
  const normalizedQuery = query.trim().toLowerCase()
  const visibleOptions = options.filter((option) => !normalizedQuery || option.label.toLowerCase().includes(normalizedQuery))
  return (
    <InfoDisclosure title={tr(label)} meta={`${selectedIDs.length}${t("ui.selected_spaced")}`}>
      <div className="selection-picker-body">
        {options.length > 6 && <Input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={tr(`Filter ${label.toLowerCase()}`)} />}
        <div className="selection-options">
          {visibleOptions.length === 0 && <p className="muted">{t("ui.no_matching_options")}</p>}
          {visibleOptions.map((option) => (
            <CheckboxRow compact key={option.id} checked={selectedIDs.includes(option.id)} onChange={() => onChange(toggleID(selectedIDs, option.id))}>
              {option.label}
            </CheckboxRow>
          ))}
        </div>
      </div>
    </InfoDisclosure>
  )
}

function Dashboard({ onLogout }) {
  const [clients, setClients] = useState([])
  const [remoteSubnets, setRemoteSubnets] = useState([])
  const [groups, setGroups] = useState([])
  const [domains, setDomains] = useState([])
  const [statusError, setStatusError] = useState('')
  const [error, setError] = useState('')
  const [busyHost, setBusyHost] = useState('')
  const [busyDomain, setBusyDomain] = useState('')
  const [activeTab, setActiveTab] = useState('peers')
  const [expandedPeerID, setExpandedPeerID] = useState('')
  const [logFilterClientID, setLogFilterClientID] = useState('')
  const [vpnFilterClientID, setVPNFilterClientID] = useState('')
  const [peerQuery, setPeerQuery] = useState('')
  const [peerStatus, setPeerStatus] = useState('all')
  const [clientToRemove, setClientToRemove] = useState(null)

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

  const normalizedPeerQuery = peerQuery.trim().toLowerCase()
  const visibleClients = clients.filter((client) => {
    if (peerStatus === 'connected' && (!client.enabled || !client.connected)) return false
    if (peerStatus === 'offline' && (!client.enabled || client.connected)) return false
    if (peerStatus === 'disabled' && client.enabled) return false
    if (!normalizedPeerQuery) return true
    return [client.hostname, client.domain_name, client.ip, client.ipv6]
      .some((value) => String(value || '').toLowerCase().includes(normalizedPeerQuery))
  })

  return (
    <Shell title={t("ui.bruecke_admin")} action={<Button className="ghost" onClick={logout}>{t("ui.logout")}</Button>}>
      <AdminNavigation activeTab={activeTab} onChange={setActiveTab} />
      {statusError && <Notice status="warning">{t("ui.wireguard_status_unavailable_spaced")}{statusError}</Notice>}
      {error && <Notice status="danger">{error}</Notice>}
      {activeTab === 'peers' && (
        <section className="tab-panel">
          <Card className="toolbar">
            <div className="toolbar-summary">
              <strong>{visibleClients.length}</strong>
              <span>{tr(visibleClients.length === clients.length ? 'computers enrolled' : `of ${clients.length} computers`)}</span>
            </div>
            <div className="toolbar-controls">
              <label className="search-field">
                <span className="sr-only">{t("ui.search_peers")}</span>
                <Input type="search" value={peerQuery} onChange={(event) => setPeerQuery(event.target.value)} placeholder={t("ui.search_peers")} />
              </label>
              <SelectField className="compact-field" label={t('ui.peer_status')} hideLabel value={peerStatus} onChange={setPeerStatus} options={[
                { value: 'all', label: t('ui.all_statuses') },
                { value: 'connected', label: t('ui.connected') },
                { value: 'offline', label: t('ui.offline') },
                { value: 'disabled', label: t('ui.disabled') },
              ]} />
              <Button className="ghost" onClick={load}>{t("ui.refresh")}</Button>
            </div>
          </Card>
          <Card className="list accordion-list">
            {clients.length === 0 && <p className="empty">{t("ui.no_computers_enrolled_yet")}</p>}
            {clients.length > 0 && visibleClients.length === 0 && <p className="empty">{t("ui.no_peers_match_these_filters")}</p>}
            {visibleClients.map((client) => {
              const allowedSubnets = clientRemoteSubnets(client, remoteSubnets)
              const expanded = expandedPeerID === client.id
              return (
                <ExpandableRow key={client.id || client.hostname} title={client.hostname} expanded={expanded} onExpandedChange={(open) => setExpandedPeerID(open ? client.id : '')} meta={
                  <PillList>
                    {client.domain_name && <Pill>{client.domain_name}</Pill>}
                    <Pill>{client.ip}</Pill>
                  </PillList>
                } actions={
                  <>
                      <Chip color={client.enabled && client.connected ? 'success' : 'default'} variant="soft" size="sm">{tr(client.enabled ? (client.connected ? 'connected' : 'offline') : 'disabled')}</Chip>
                      <ActionMenu label={tr(`Actions for ${client.hostname}`)} items={[
                        { label: tr(client.enabled ? 'Disable VPN' : 'Enable VPN'), disabled: busyHost === client.id, onAction: () => toggleClient(client) },
                        { label: t('ui.bootstrap_logs_596bd4'), onAction: () => { setLogFilterClientID(client.id); setActiveTab('logs') } },
                        { label: t('ui.vpn_activity'), onAction: () => { setVPNFilterClientID(client.id); setActiveTab('vpn-activity') } },
                        { label: t('ui.remove_peer'), danger: true, disabled: busyHost === client.id, onAction: () => setClientToRemove(client) },
                      ]} />
                  </>
                }>
                  {expanded && (
                    <div className="accordion-detail">
                      <DetailGrid compact>
                        <dt>{t("ui.ipv4_ipv6")}</dt>
                        <dd>{client.ip}{client.ipv6 ? ` / ${client.ipv6}` : ''}</dd>
                        <dt>{t("ui.certificate")}</dt>
                        <dd>{client.certificate_serial || t("ui.unknown")}</dd>
                        <dt>{t("ui.last_handshake")}</dt>
                        <dd>{client.latest_handshake ? formatDate(client.latest_handshake) : t("ui.never")}</dd>
                        <dt>{t("ui.updated")}</dt>
                        <dd>{formatDate(client.updated_at)}</dd>
                        <dt>{t("ui.groups")}</dt>
                        <dd>{client.group_ids?.length ? client.group_ids.map((id) => groupLabel(groups, id)).join(', ') : t("ui.none")}</dd>
                        <dt>{t("ui.remote_subnets_b72ae0")}</dt>
                        <dd>{allowedSubnets.length ? allowedSubnets.map((subnet) => subnet.name).join(', ') : t("ui.none")}</dd>
                        <dt>{t("ui.public_key")}</dt>
                        <dd>{client.public_key || t("ui.unknown")}</dd>
                      </DetailGrid>
                    </div>
                  )}
                </ExpandableRow>
              )
            })}
          </Card>
        </section>
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
        </section>
      )}
      <ConfirmModal
        open={Boolean(clientToRemove)}
        title={t("ui.remove_peer")}
        message={clientToRemove ? `Remove ${clientLabel(clientToRemove)} and its WireGuard key? This cannot be undone.` : ''}
        confirmLabel="Remove peer"
        busy={busyHost === clientToRemove?.id}
        onClose={() => setClientToRemove(null)}
        onConfirm={() => removeClient(clientToRemove)}
      />
    </Shell>
  )
}

function WikiPanel() {
  const [openArticle, setOpenArticle] = useState('')
  const expanded = openArticle === 'domain-ca-export'

  return (
    <Card className="wiki">
      <div className="section-title">
        <div>
          <h2>{t("ui.wiki")}</h2>
        </div>
      </div>
      <ExpandableRow title={t("ui.export_the_domain_ca_public_certificate")} expanded={expanded} onExpandedChange={(open) => setOpenArticle(open ? 'domain-ca-export' : '')}>
        {expanded && (
          <div className="accordion-detail wiki-body">
            <p>{t("ui.bruecke_needs_the_public_ad_cs_ca_certificate_that_issued_spaced")}<code>{t("ui.export_pfxcertificate")}</code>.
            </p>
            <p>{t("ui.windows_startup_runs_write_spaced")}<code>{t("ui.c_programdata_bruecke_bootstrap_log")}</code>{t("ui.and_upload_redacted_diagnostics_to_bootstrap_logs_check_pe_spaced")}</p>
            <ol className="wiki-steps">
              <li>{t("ui.run_these_commands_on_a_domain_joined_windows_computer_aft")}</li>
              <li>{t("ui.use_the_generated_pem_file_in_authentication_domain_cas")}</li>
              <li>{t("ui.ignore_microsoft_entra_azure_ad_spaced")}<code>{t("ui.ms_organization")}</code>{t("ui.device_certificates_for_this_use_case_spaced")}</li>
              <li>{t("ui.if_computers_use_multiple_issuing_cas_repeat_this_for_each")}</li>
            </ol>
            <h4>{t("ui.powershell_find_the_ad_cs_computer_cert_and_export_its_iss")}</h4>
            <pre className="command-block"><code>{`$clientAuthOid = '1.3.6.1.5.5.7.3.2'
$candidates = Get-ChildItem Cert:\\LocalMachine\\My |
  Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) } |
  Where-Object {
    $eku = @($_.EnhancedKeyUsageList)
    $eku.Count -eq 0 -or ($eku | Where-Object { $_.ObjectId -eq $clientAuthOid })
  } |
  Where-Object { $_.Issuer -notmatch 'MS-Organization' -and $_.Subject -notmatch 'MS-Organization' } |
  Sort-Object NotAfter -Descending |
  Select-Object Subject, Issuer, Thumbprint, NotAfter

$candidates | Format-List

$thumbprint = '<AD CS computer certificate thumbprint>'
$cert = Get-ChildItem Cert:\\LocalMachine\\My\\$thumbprint

$chain = New-Object Security.Cryptography.X509Certificates.X509Chain
$chain.ChainPolicy.RevocationMode = [Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
$chain.Build($cert) | Out-Null

$chain.ChainElements | ForEach-Object {
  [PSCustomObject]@{
    Subject    = $_.Certificate.Subject
    Issuer     = $_.Certificate.Issuer
    Thumbprint = $_.Certificate.Thumbprint
    NotAfter   = $_.Certificate.NotAfter
  }
} | Format-List

if ($chain.ChainElements.Count -lt 2) { throw 'selected certificate has no issuing CA in its chain' }
$issuingCa = $chain.ChainElements[1].Certificate

Export-Certificate -Cert $issuingCa -FilePath .\\domain-ca.cer
certutil -encode .\\domain-ca.cer .\\domain-ca.pem`}</code></pre>
            <p>{t("ui.if_spaced")}<code>{t("ui.export_certificate")}</code>{t("ui.says_spaced")}<code>{t("ui.parameterargumentvalidationerrornullnotallowed")}</code>{t("ui.the_selected_certificate_had_no_issuing_ca_in_its_chain_th_spaced")}<code>{t("ui.ms_organization")}</code>{t("ui.device_certificates_are_present_not_an_ad_cs_computer_cert_spaced")}</p>
            <h4>{t("ui.if_no_ad_cs_computer_certificate_appears")}</h4>
            <p>{t("ui.enable_computer_certificate_auto_enrollment_by_gpo_confirm_spaced")}</p>
            <pre className="command-block"><code>{`gpupdate /force
certutil -pulse`}</code></pre>
            <p>{t("ui.gpo_path_computer_configuration_policies_windows_settings_spaced")}</p>
            <p>{t("ui.template_path_spaced")}<code>{t("ui.certtmpl_msc")}</code>{t("ui.certificate_templates_computer_or_workstation_authenticati_spaced")}<code>{t("ui.certsrv_msc")}</code>{t("ui.if_needed_spaced")}</p>
            <h4>{t("ui.cmd_export_from_an_enterprise_ca")}</h4>
            <pre className="command-block"><code>{`certutil -config - -ping
certutil -config "CAHOST\\CA-NAME" -ca.cert domain-ca.cer
certutil -encode domain-ca.cer domain-ca.pem
type domain-ca.pem`}</code></pre>
            <p>{t("ui.replace_spaced")}<code>{t("ui.cahost_ca_name")}</code>{t("ui.with_the_ca_config_name_shown_by_the_first_command_the_pem_spaced")}<code>{t("ui.begin_certificate")}</code>.
            </p>
          </div>
        )}
      </ExpandableRow>
    </Card>
  )
}


function VPNActivityPanel({ clients, filterClientID, onClearFilter, onError }) {
  const [events, setEvents] = useState([])
  const [nextCursor, setNextCursor] = useState('')
  const [clientID, setClientID] = useState(filterClientID || '')
  const [decision, setDecision] = useState('all')
  const [outcome, setOutcome] = useState('all')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setClientID(filterClientID || '')
  }, [filterClientID])

  const queryPath = (cursor = '') => {
    const params = new URLSearchParams({ limit: '200' })
    if (clientID) params.set('client_id', clientID)
    if (decision !== 'all') params.set('decision', decision)
    if (outcome !== 'all') params.set('outcome', outcome)
    if (cursor) params.set('cursor', cursor)
    return '/api/admin/vpn-events?' + params.toString()
  }

  const refresh = async () => {
    setLoading(true)
    try {
      const data = await api(queryPath())
      setEvents(data.events || [])
      setNextCursor(data.next_cursor || '')
    } catch (err) {
      onError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let cancelled = false
    const poll = async () => {
      try {
        const data = await api(queryPath())
        if (!cancelled) {
          setEvents(data.events || [])
          setNextCursor(data.next_cursor || '')
        }
      } catch (err) {
        if (!cancelled) onError(err.message)
      }
    }
    poll()
    const interval = window.setInterval(poll, CLIENT_STATUS_INTERVAL_MS)
    return () => {
      cancelled = true
      window.clearInterval(interval)
    }
  }, [clientID, decision, outcome, onError])

  const loadOlder = async () => {
    if (!nextCursor) return
    setLoading(true)
    try {
      const data = await api(queryPath(nextCursor))
      setEvents((current) => [...current, ...(data.events || [])])
      setNextCursor(data.next_cursor || '')
    } catch (err) {
      onError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const displayValues = (values = {}) => {
    const parts = []
    if (values.kind) parts.push('type ' + values.kind)
    if (values.ssids?.length) parts.push('SSID ' + values.ssids.join(', '))
    if (values.gateways?.length) parts.push('gateway ' + values.gateways.join(', '))
    if (values.address_cidrs?.length) parts.push('address ' + values.address_cidrs.join(', '))
    if (values.dns_suffixes?.length) parts.push('DNS ' + values.dns_suffixes.join(', '))
    return parts.join(' · ') || 'none observed'
  }

  const scopedClient = clients.find((client) => client.id === clientID)
  return (
    <Card className="vpn-activity">
      <div className="section-title">
        <div>
          <h2>{t("ui.vpn_activity")}</h2>
        </div>
        <Button className="ghost" disabled={loading} onClick={refresh}>{loading ? 'Refreshing...' : 'Refresh'}</Button>
      </div>
      {scopedClient && (
        <Surface className="filter-banner" variant="secondary">
          <span>{t("ui.showing_spaced")}{clientLabel(scopedClient)}</span>
          <Button className="ghost compact-button" onClick={() => { setClientID(''); onClearFilter() }}>{t("ui.show_all")}</Button>
        </Surface>
      )}
      <div className="toolbar-controls vpn-activity-filters">
        <SelectField className="compact-field" label={t('ui.computer')} value={clientID} onChange={(next) => { setClientID(next); if (!next) onClearFilter() }} options={[
          { value: '', label: t('ui.all_computers') },
          ...clients.map((client) => ({ value: client.id, label: clientLabel(client) })),
        ]} />
        <SelectField className="compact-field" label={t('ui.decision')} value={decision} onChange={setDecision} options={[
          { value: 'all', label: t('ui.all_decisions') },
          { value: 'local', label: t('ui.local_vpn_off') },
          { value: 'non_local', label: t('ui.non_local_vpn_on') },
          { value: 'indeterminate', label: t('ui.indeterminate_vpn_on') },
        ]} />
        <SelectField className="compact-field" label={t('ui.outcome')} value={outcome} onChange={setOutcome} options={[
          { value: 'all', label: t('ui.all_outcomes') },
          { value: 'activated', label: t('ui.activated') },
          { value: 'deactivated', label: t('ui.deactivated') },
          { value: 'no_op', label: t('ui.no_change') },
          { value: 'failed', label: t('ui.failed') },
        ]} />
      </div>
      <div className="vpn-event-list">
        {!loading && events.length === 0 && <p className="empty">{t("ui.no_vpn_activity_matches_these_filters")}</p>}
        {events.map((event) => (
          <InfoDisclosure key={event.event_id} title={event.hostname || event.computer_name || event.client_id} meta={
            <><span className="vpn-event-time">{formatDate(event.occurred_at)}</span><Chip color={event.decision === 'local' ? 'success' : 'default'} variant="soft" size="sm">{statusLabel(event.decision)}</Chip><Chip color={event.outcome === 'failed' ? 'danger' : 'default'} variant="soft" size="sm">{statusLabel(event.outcome)}</Chip></>
          }>
            <div className="vpn-event-detail">
              <DetailGrid compact>
                <dt>{t("ui.policy")}</dt>
                <dd>{event.decision === 'local' ? t('ui.local_vpn_off') : `${statusLabel(event.decision)} → VPN on`}</dd>
                <dt>{t("ui.tunnel_state")}</dt>
                <dd>{statusLabel(event.state_before)} → {statusLabel(event.state_after)}</dd>
                <dt>{t("ui.trigger_actuator")}</dt>
                <dd>{event.trigger_source || 'unknown'} / {event.actuator_version || 'unknown'}</dd>
                <dt>{t("ui.reason")}</dt>
                <dd>{event.reason || 'none supplied'}</dd>
              </DetailGrid>
              <div className="vpn-evaluations">
                {(event.evaluations || []).length === 0 && <p className="muted">{t("ui.no_adapter_profile_evidence_was_available")}</p>}
                {(event.evaluations || []).map((evaluation, index) => (
                  <InfoDisclosure key={event.event_id + '-' + index} title={`${t('ui.profile_spaced')}${evaluation.profile_index} (${evaluation.profile_type}${t('ui.on_spaced')}${evaluation.adapter_alias || 'unknown adapter'})`} meta={statusLabel(evaluation.matched ? 'matched' : (evaluation.unavailable?.length ? 'indeterminate' : 'mismatch'))}>
                    <DetailGrid compact>
                      <dt>{t("ui.expected")}</dt>
                      <dd>{displayValues(evaluation.expected)}</dd>
                      <dt>{t("ui.actual")}</dt>
                      <dd>{displayValues(evaluation.actual)}</dd>
                      <dt>{t("ui.mismatches")}</dt>
                      <dd>{evaluation.mismatches?.length ? evaluation.mismatches.join('; ') : 'none'}</dd>
                      <dt>{t("ui.unavailable")}</dt>
                      <dd>{evaluation.unavailable?.length ? evaluation.unavailable.join('; ') : 'none'}</dd>
                    </DetailGrid>
                  </InfoDisclosure>
                ))}
              </div>
            </div>
          </InfoDisclosure>
        ))}
      </div>
      {nextCursor && <Button className="ghost load-older" disabled={loading} onClick={loadOlder}>{t("ui.load_older")}</Button>}
    </Card>
  )
}
function BootstrapLogsPanel({ clients, filterClientID, onClearFilter, onError }) {
  const [runs, setRuns] = useState([])
  const [selectedRunID, setSelectedRunID] = useState('')
  const [detail, setDetail] = useState(null)
  const [loadingRuns, setLoadingRuns] = useState(false)
  const [logStatus, setLogStatus] = useState('all')

  const filterClient = clients.find((client) => client.id === filterClientID)
  const loadRuns = async () => {
    setLoadingRuns(true)
    try {
      const data = await api('/api/admin/bootstrap-logs/runs?limit=100')
      setRuns(data.runs || [])
    } catch (err) {
      onError(err.message)
    } finally {
      setLoadingRuns(false)
    }
  }

  useEffect(() => {
    let cancelled = false
    const refresh = async () => {
      try {
        const data = await api('/api/admin/bootstrap-logs/runs?limit=100')
        if (!cancelled) setRuns(data.runs || [])
      } catch (err) {
        if (!cancelled) onError(err.message)
      }
    }
    refresh()
    const interval = window.setInterval(refresh, CLIENT_STATUS_INTERVAL_MS)
    return () => {
      cancelled = true
      window.clearInterval(interval)
    }
  }, [onError])

  const clientRuns = filterClientID
    ? runs.filter((run) => run.client_id === filterClientID || (filterClient?.hostname && run.hostname === filterClient.hostname))
    : runs
  const visibleRuns = logStatus === 'all' ? clientRuns : clientRuns.filter((run) => (run.status || 'running') === logStatus)

  useEffect(() => {
    if (visibleRuns.length === 0) {
      setSelectedRunID('')
      setDetail(null)
      return
    }
    if (!selectedRunID || !visibleRuns.some((run) => run.run_id === selectedRunID)) {
      setSelectedRunID(visibleRuns[0].run_id)
    }
  }, [runs, filterClientID, logStatus])

  useEffect(() => {
    if (!selectedRunID) return undefined
    let cancelled = false
    let lastSeq = 0
    const loadRun = async () => {
      try {
        const suffix = lastSeq > 0 ? `?since_seq=${lastSeq}` : ''
        const data = await api(`/api/admin/bootstrap-logs/runs/${encodeURIComponent(selectedRunID)}${suffix}`)
        if (cancelled) return
        setDetail((current) => {
          const previousEvents = lastSeq > 0 && current?.run?.run_id === selectedRunID ? current.events || [] : []
          const events = [...previousEvents, ...(data.events || [])]
          lastSeq = Math.max(lastSeq, data.run?.last_seq || 0)
          return { run: data.run, events }
        })
      } catch (err) {
        if (!cancelled) onError(err.message)
      }
    }
    setDetail(null)
    loadRun()
    const interval = window.setInterval(loadRun, CLIENT_STATUS_INTERVAL_MS)
    return () => {
      cancelled = true
      window.clearInterval(interval)
    }
  }, [selectedRunID, onError])

  return (
    <Card className="bootstrap-logs">
      <div className="section-title">
        <div>
          <h2>{t("ui.bootstrap_logs")}</h2>
        </div>
        <div className="row-actions">
          {filterClientID && <Button className="ghost" onClick={onClearFilter}>{t("ui.show_all_runs")}</Button>}
          <Button className="ghost" onClick={loadRuns}>{loadingRuns ? 'Refreshing...' : 'Refresh'}</Button>
          <SelectField className="compact-field" label={t('ui.bootstrap_status')} hideLabel value={logStatus} onChange={setLogStatus} options={[
            { value: 'all', label: t('ui.all_statuses') },
            { value: 'failed', label: t('ui.failed') },
            { value: 'running', label: t('ui.running') },
            { value: 'complete', label: t('ui.complete') },
          ]} />
        </div>
      </div>
      {filterClientID && <Notice status="default">{t("ui.filtered_to_spaced")}{filterClient ? clientLabel(filterClient) : filterClientID}.</Notice>}
      <div className="logs-layout">
        <div className="log-runs accordion-list">
          {visibleRuns.length === 0 && <p className="empty">{tr(runs.length === 0 ? 'No bootstrap logs received yet.' : 'No runs match these filters.')}</p>}
          {visibleRuns.map((run) => (
            <HeroButton variant={selectedRunID === run.run_id ? 'secondary' : 'ghost'} className="log-run" key={run.run_id} onPress={() => setSelectedRunID(run.run_id)}>
              <span className="item-summary">
                <span className="summary-main">
                  <strong className="log-run-title">{bootstrapRunTitle(run)}</strong>
                  <PillList>
                    <Pill tone={run.status === 'complete' ? 'ok' : run.status === 'failed' ? 'danger' : ''}>{statusLabel(run.status || 'running')}</Pill>
                    {run.client_id ? <Pill>{t("ui.registered")}</Pill> : <Pill>{t("ui.pending")}</Pill>}
                  </PillList>
                </span>
                <span className="summary-actions compact-time">{formatLogTime(run.last_seen)}</span>
              </span>
            </HeroButton>
          ))}
        </div>
        <div className="log-detail">
          {!detail && selectedRunID && <p className="empty">{t("ui.loading_log_run")}</p>}
          {!selectedRunID && <p className="empty">{t("ui.select_a_log_run")}</p>}
          {detail && (
            <>
              <InfoDisclosure title={t("ui.run_metadata")} className="log-metadata">
                <DetailGrid compact>
                  <dt>{t("ui.run")}</dt>
                  <dd>{detail.run.run_id}</dd>
                  <dt>{t("ui.computer_hostname")}</dt>
                  <dd>{detail.run.computer_name || 'unknown'} / {detail.run.hostname || 'unknown'}</dd>
                  <dt>{t("ui.client_id")}</dt>
                  <dd>{detail.run.client_id || 'not registered'}</dd>
                  <dt>{t("ui.certificate")}</dt>
                  <dd>{detail.run.certificate_thumbprint || 'unknown'}</dd>
                  <dt>{t("ui.last_error")}</dt>
                  <dd>{detail.run.last_level === 'error' ? detail.run.last_message : 'none'}</dd>
                </DetailGrid>
              </InfoDisclosure>
              <div className="log-lines" role="log" aria-live="polite">
                {(detail.events || []).length === 0 && <p className="empty">{t("ui.no_events_for_this_run")}</p>}
                {(detail.events || []).map((event) => (
                  <div className={`log-line ${event.level || 'info'}`} key={event.seq}>
                    <span>{formatLogTime(event.time)}</span>
                    <strong>{event.level || 'info'}</strong>
                    <em>{event.phase || 'bootstrap'}</em>
                    <code>{event.message}</code>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </Card>
  )
}

function bootstrapRunTitle(run) {
  return run.hostname || run.computer_name || run.run_id
}

function formatLogTime(value) {
  if (!value) return 'never'
  return formatDate(value)
}

function RemoteSubnetsPanel({ subnets, clients, groups, onChange, onError }) {
  const [name, setName] = useState('')
  const [subnetText, setSubnetText] = useState('')
  const [configType, setConfigType] = useState('ovpn')
  const [configText, setConfigText] = useState('')
  const [sourceFilename, setSourceFilename] = useState('')
  const [grantAll, setGrantAll] = useState(false)
  const [busyID, setBusyID] = useState('')
  const [uploading, setUploading] = useState(false)
  const [createOpen, setCreateOpen] = useState(false)
  const [editingSubnet, setEditingSubnet] = useState(null)
  const [expandedID, setExpandedID] = useState('')
  const [subnetToRemove, setSubnetToRemove] = useState(null)

  const readConfigFile = async (event) => {
    const file = event.target.files?.[0]
    if (!file) return
    setSourceFilename(file.name)
    const ext = file.name.toLowerCase().split('.').pop()
    if (ext === 'apc' || ext === 'ovpn') setConfigType(ext)
    setConfigText(await file.text())
  }

  const create = async (event) => {
    event.preventDefault()
    setUploading(true)
    onError('')
    try {
      const created = await api('/api/admin/remote-subnets', {
        method: 'POST',
        body: JSON.stringify({
          name,
          config_type: configType,
          source_filename: sourceFilename,
          config: configText,
          subnets: splitSubnetText(subnetText),
          group_ids: grantAll ? ['all'] : [],
        }),
      })
      onChange(mergeRemoteSubnets(subnets, created))
      setName('')
      setSubnetText('')
      setConfigText('')
      setSourceFilename('')
      setGrantAll(false)
      setCreateOpen(false)
    } catch (err) {
      onError(err.message)
    } finally {
      setUploading(false)
    }
  }

  const save = async (subnet, patch = {}) => {
    setBusyID(subnet.id)
    onError('')
    try {
      const updated = await api(`/api/admin/remote-subnets/${subnet.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          name: patch.name ?? subnet.name,
          subnets: patch.subnets ?? subnet.subnets,
          client_ids: patch.client_ids ?? subnet.client_ids ?? [],
          group_ids: patch.group_ids ?? subnet.group_ids ?? [],
          enabled: patch.enabled ?? subnet.enabled,
        }),
      })
      onChange(mergeRemoteSubnets(subnets, updated))
    } catch (err) {
      onError(err.message)
    } finally {
      setBusyID('')
    }
  }

  const remove = async (subnet) => {
    setBusyID(subnet.id)
    onError('')
    try {
      await api(`/api/admin/remote-subnets/${subnet.id}`, { method: 'DELETE' })
      onChange(subnets.filter((item) => item.id !== subnet.id))
      setSubnetToRemove(null)
    } catch (err) {
      onError(err.message)
    } finally {
      setBusyID('')
    }
  }

  return (
    <Card className="remote-subnets">
      <div className="section-title">
        <div>
          <h2>{t("ui.remote_subnets")}</h2>
        </div>
        <Button onClick={() => setCreateOpen(true)}>{t("ui.add_remote_subnet")}</Button>
      </div>
      <div className="remote-list accordion-list">
        {subnets.length === 0 && <p className="empty">{t("ui.no_remote_subnets_configured")}</p>}
        {subnets.map((subnet) => {
          const expanded = expandedID === subnet.id
          const accessCount = (subnet.group_ids || []).length + (subnet.client_ids || []).length
          return (
          <ExpandableRow key={subnet.id} title={subnet.name} expanded={expanded} onExpandedChange={(open) => setExpandedID(open ? subnet.id : '')} meta={
            <PillList>
              <Pill>{subnet.subnets[0] || 'no CIDR'}</Pill>
              {subnet.subnets.length > 1 && <Pill>{subnet.subnets.length}{t("ui.cidrs_spaced")}</Pill>}
              <Pill>{subnet.config_type.toUpperCase()}</Pill>
              <Pill>{accessCount === 0 ? 'no grants' : `${accessCount} grants`}</Pill>
            </PillList>
          } actions={
            <>
                <Chip color={subnet.enabled ? 'success' : 'default'} variant="soft" size="sm">{tr(subnet.enabled ? 'active' : 'inactive')}</Chip>
                <CheckboxRow compact checked={subnet.enabled} disabled={busyID === subnet.id} onChange={() => save(subnet, { enabled: !subnet.enabled })}>{t("ui.enabled")}</CheckboxRow>
            </>
          }>
            {expanded && (
              <div className="accordion-detail">
                <DetailGrid compact>
                  <dt>{t("ui.remote_cidrs")}</dt>
                  <dd>{subnet.subnets.join(', ')}</dd>
                  <dt>{t("ui.config")}</dt>
                  <dd>{subnet.config_type.toUpperCase()}{subnet.source_filename ? ` / ${subnet.source_filename}` : ''}</dd>
                  <dt>{t("ui.access")}</dt>
                  <dd>{remoteAccessSummary(subnet, groups, clients)}</dd>
                </DetailGrid>
                <div className="row-actions">
                  <Button className="ghost" disabled={busyID === subnet.id} onClick={() => setEditingSubnet(subnet)}>{t("ui.edit_access")}</Button>
                  <Button className="danger" disabled={busyID === subnet.id} onClick={() => setSubnetToRemove(subnet)}>{t("ui.delete")}</Button>
                </div>
              </div>
            )}
          </ExpandableRow>
          )
        })}
      </div>
      <Modal title={t("ui.add_remote_subnet")} open={createOpen} onClose={() => setCreateOpen(false)}>
        <form className="modal-form" onSubmit={create}>
          <Input value={name} onChange={(event) => setName(event.target.value)} placeholder={t("ui.name")} required />
          <TextArea value={subnetText} onChange={(event) => setSubnetText(event.target.value)} placeholder={t("ui.remote_cidrs_e_g_10_10_0_0_24")} rows={3} required />
          <div className="form-row two">
            <SelectField label={t('ui.config_type_spaced')} value={configType} onChange={setConfigType} options={[
              { value: 'ovpn', label: t('ui.ovpn') },
              { value: 'apc', label: t('ui.apc') },
            ]} />
            <label>{t("ui.config_file_spaced")}<input type="file" accept=".ovpn,.apc" onChange={readConfigFile} />
            </label>
          </div>
          <TextArea value={configText} onChange={(event) => setConfigText(event.target.value)} placeholder={t("ui.paste_apc_or_ovpn_config")} rows={8} required />
          <CheckboxRow compact checked={grantAll} onChange={setGrantAll}>{t("ui.grant_all_clients")}</CheckboxRow>
          <div className="modal-actions">
            <Button type="button" className="ghost" onClick={() => setCreateOpen(false)}>{t("ui.cancel")}</Button>
            <Button disabled={uploading}>{uploading ? 'Uploading...' : 'Create'}</Button>
          </div>
        </form>
      </Modal>
      <RemoteSubnetAccessModal
        subnet={editingSubnet}
        clients={clients}
        groups={groups}
        busy={busyID === editingSubnet?.id}
        onClose={() => setEditingSubnet(null)}
        onSave={async (subnet, patch) => {
          await save(subnet, patch)
          setEditingSubnet(null)
        }}
      />
      <ConfirmModal
        open={Boolean(subnetToRemove)}
        title={t("ui.delete_remote_subnet")}
        message={subnetToRemove ? `Delete ${subnetToRemove.name} and stop its site-to-site connection?` : ''}
        confirmLabel="Delete remote subnet"
        busy={busyID === subnetToRemove?.id}
        onClose={() => setSubnetToRemove(null)}
        onConfirm={() => remove(subnetToRemove)}
      />
    </Card>
  )
}

function RemoteSubnetAccessModal({ subnet, clients, groups, busy, onClose, onSave }) {
  const [name, setName] = useState('')
  const [subnetText, setSubnetText] = useState('')
  const [clientIDs, setClientIDs] = useState([])
  const [groupIDs, setGroupIDs] = useState([])

  useEffect(() => {
    setName(subnet?.name || '')
    setSubnetText((subnet?.subnets || []).join(', '))
    setClientIDs(subnet?.client_ids || [])
    setGroupIDs(subnet?.group_ids || [])
  }, [subnet])

  if (!subnet) return null

  const submit = (event) => {
    event.preventDefault()
    onSave(subnet, {
      name,
      subnets: splitSubnetText(subnetText),
      client_ids: clientIDs,
      group_ids: groupIDs,
    })
  }

  return (
    <Modal title={tr(`Edit ${subnet.name}`)} open={Boolean(subnet)} onClose={onClose}>
      <form className="modal-form" onSubmit={submit}>
        <Input value={name} onChange={(event) => setName(event.target.value)} placeholder={t("ui.name")} required />
        <TextArea value={subnetText} onChange={(event) => setSubnetText(event.target.value)} placeholder={t("ui.remote_cidrs")} rows={3} required />
        <SelectionPicker
          label="Groups"
          options={groups.map((group) => ({ id: group.id, label: group.name }))}
          selectedIDs={groupIDs}
          onChange={setGroupIDs}
        />
        <SelectionPicker
          label="Individual clients"
          options={clients.map((client) => ({ id: client.id, label: clientLabel(client) }))}
          selectedIDs={clientIDs}
          onChange={setClientIDs}
        />
        <div className="modal-actions">
          <Button type="button" className="ghost" onClick={onClose}>{t("ui.cancel")}</Button>
          <Button disabled={busy}>{busy ? 'Saving...' : 'Save access'}</Button>
        </div>
      </form>
    </Modal>
  )
}

function GroupsPanel({ groups, clients, onChange, onClientsReload, onError }) {
  const [name, setName] = useState('')
  const [busyID, setBusyID] = useState('')
  const [createOpen, setCreateOpen] = useState(false)
  const [expandedID, setExpandedID] = useState('')
  const [groupToRemove, setGroupToRemove] = useState(null)

  const reloadGroups = async () => {
    const data = await api('/api/admin/groups')
    onChange(data.groups || [])
  }

  const create = async (event) => {
    event.preventDefault()
    setBusyID('new')
    onError('')
    try {
      await api('/api/admin/groups', {
        method: 'POST',
        body: JSON.stringify({ name }),
      })
      setName('')
      setCreateOpen(false)
      await reloadGroups()
    } catch (err) {
      onError(err.message)
    } finally {
      setBusyID('')
    }
  }

  const save = async (group, patch = {}) => {
    setBusyID(group.id)
    onError('')
    try {
      await api(`/api/admin/groups/${encodeURIComponent(group.id)}`, {
        method: 'PATCH',
        body: JSON.stringify({
          name: patch.name ?? group.name,
          client_ids: patch.client_ids ?? group.client_ids ?? [],
          group_ids: patch.group_ids ?? group.group_ids ?? [],
        }),
      })
      await reloadGroups()
      await onClientsReload?.()
    } catch (err) {
      onError(err.message)
    } finally {
      setBusyID('')
    }
  }

  const remove = async (group) => {
    setBusyID(group.id)
    onError('')
    try {
      await api(`/api/admin/groups/${encodeURIComponent(group.id)}`, { method: 'DELETE' })
      await reloadGroups()
      await onClientsReload?.()
      setGroupToRemove(null)
    } catch (err) {
      onError(err.message)
    } finally {
      setBusyID('')
    }
  }

  return (
    <Card className="groups">
      <div className="section-title">
        <div>
          <h2>{t("ui.groups")}</h2>
        </div>
        <Button onClick={() => setCreateOpen(true)}>{t("ui.create_group")}</Button>
      </div>
      <div className="group-list">
        {groups.map((group) => (
          <GroupEditor
            key={group.id}
            group={group}
            groups={groups}
            clients={clients}
            busy={busyID === group.id}
            expanded={expandedID === group.id}
            onToggle={() => setExpandedID(expandedID === group.id ? '' : group.id)}
            onSave={save}
            onRemove={setGroupToRemove}
          />
        ))}
      </div>
      <Modal title={t("ui.create_group")} open={createOpen} onClose={() => setCreateOpen(false)}>
        <form className="modal-form" onSubmit={create}>
          <Input value={name} onChange={(event) => setName(event.target.value)} placeholder={t("ui.new_custom_group")} required autoFocus />
          <div className="modal-actions">
            <Button type="button" className="ghost" onClick={() => setCreateOpen(false)}>{t("ui.cancel")}</Button>
            <Button disabled={busyID === 'new'}>{busyID === 'new' ? 'Creating...' : 'Create'}</Button>
          </div>
        </form>
      </Modal>
      <ConfirmModal
        open={Boolean(groupToRemove)}
        title={t("ui.delete_group")}
        message={groupToRemove ? `Delete ${groupToRemove.name}? Its clients remain enrolled.` : ''}
        confirmLabel="Delete group"
        busy={busyID === groupToRemove?.id}
        onClose={() => setGroupToRemove(null)}
        onConfirm={() => remove(groupToRemove)}
      />
    </Card>
  )
}

function GroupEditor({ group, groups, clients, busy, expanded, onToggle, onSave, onRemove }) {
  const groupIDs = group.group_ids || []
  const clientIDs = group.client_ids || []
  const [name, setName] = useState(group.name || '')
  const [draftClientIDs, setDraftClientIDs] = useState(clientIDs)
  const [draftGroupIDs, setDraftGroupIDs] = useState(groupIDs)

  useEffect(() => {
    setName(group.name || '')
    setDraftClientIDs(group.client_ids || [])
    setDraftGroupIDs(group.group_ids || [])
  }, [group])

  const childChoices = groups.filter((item) => item.id !== 'all' && item.id !== group.id)
  const memberClients = clients.filter((client) => clientIDs.includes(client.id))
  const childGroups = groupIDs.map((id) => groups.find((item) => item.id === id)).filter(Boolean)

  const submit = (event) => {
    event.preventDefault()
    onSave(group, { name, client_ids: draftClientIDs, group_ids: draftGroupIDs })
  }

  return (
    <ExpandableRow title={group.name} expanded={expanded} onExpandedChange={onToggle} meta={
      <PillList>
        <Pill>{group.type}{group.built_in ? ' / built-in' : ''}</Pill>
        <Pill>{clientIDs.length}{t("ui.clients_spaced")}</Pill>
        <Pill>{groupIDs.length}{t("ui.child_groups_spaced")}</Pill>
      </PillList>
    }>
      {expanded && group.built_in && (
        <div className="accordion-detail">
          <p className="muted">{t("ui.members_are_managed_automatically")}</p>
          <div className="form-row two align-start">
            <div className="assignment-grid">
              <strong>{t("ui.clients")}</strong>
              {memberClients.length === 0 && <p className="muted">{t("ui.no_clients")}</p>}
              {memberClients.map((client) => <p key={client.id}>{clientLabel(client)}</p>)}
            </div>
            <div className="assignment-grid">
              <strong>{t("ui.child_groups")}</strong>
              {childGroups.length === 0 && <p className="muted">{t("ui.no_child_groups")}</p>}
              {childGroups.map((child) => <p key={child.id}>{child.name}</p>)}
            </div>
          </div>
        </div>
      )}
      {expanded && !group.built_in && (
        <form className="accordion-detail" onSubmit={submit}>
          <label>{t("ui.name_spaced")}<Input value={name} onChange={(event) => setName(event.target.value)} required />
          </label>
          <SelectionPicker
            label="Clients"
            options={clients.map((client) => ({ id: client.id, label: clientLabel(client) }))}
            selectedIDs={draftClientIDs}
            onChange={setDraftClientIDs}
          />
          <SelectionPicker
            label="Child groups"
            options={childChoices.map((child) => ({ id: child.id, label: child.name }))}
            selectedIDs={draftGroupIDs}
            onChange={setDraftGroupIDs}
          />
          <div className="modal-actions">
            <Button type="button" className="danger" disabled={busy} onClick={() => onRemove(group)}>{t("ui.delete")}</Button>
            <Button disabled={busy}>{busy ? 'Saving...' : 'Save group'}</Button>
          </div>
        </form>
      )}
    </ExpandableRow>
  )
}

function ManualEnrollment({ domains, onEnroll, onError }) {
  const [hostname, setHostname] = useState('')
  const [domainID, setDomainID] = useState('')
  const [result, setResult] = useState(null)
  const [copyState, setCopyState] = useState('')
  const [busy, setBusy] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)
  const [configOpen, setConfigOpen] = useState(false)

  useEffect(() => {
    if (!domainID && domains.length > 0) setDomainID(domains[0].id)
  }, [domainID, domains])

  const enroll = async (event) => {
    event.preventDefault()
    setBusy(true)
    setCopyState('')
    onError('')
    try {
      const data = await api('/api/admin/manual-enroll', {
        method: 'POST',
        body: JSON.stringify({ hostname, domain_id: domainID }),
      })
      setResult(data)
      setConfigOpen(false)
      setHostname('')
      setModalOpen(false)
      if (data.client) onEnroll(data.client)
    } catch (err) {
      onError(err.message)
    } finally {
      setBusy(false)
    }
  }

  const copyConfig = async () => {
    if (!result?.config) return
    try {
      await navigator.clipboard.writeText(result.config)
      setCopyState('Copied')
    } catch {
      setCopyState('Clipboard unavailable')
    }
  }

  const downloadConfig = () => {
    if (!result?.config) return
    const blob = new Blob([result.config], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${result.hostname || 'bruecke'}.conf`
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <Card className="manual">
      <div className="section-title">
        <div>
          <h2>{t("ui.manual_enrollment")}</h2>
        </div>
        <Button onClick={() => setModalOpen(true)}>{t("ui.issue_config")}</Button>
      </div>
      {result && (
        <ExpandableRow title={result.hostname} expanded={configOpen} onExpandedChange={setConfigOpen} meta={<PillList><Pill>{result.address}</Pill></PillList>} actions={
          <>
              <Button className="ghost" onClick={copyConfig}>{t("ui.copy")}</Button>
              <Button className="ghost" onClick={downloadConfig}>{t("ui.download")}</Button>
          </>
        }>
          {copyState && <p className="copy-state">{tr(copyState)}</p>}
          {configOpen && (
            <div className="accordion-detail">
              <TextArea className="config-output" value={result.config || ''} readOnly rows={12} />
            </div>
          )}
        </ExpandableRow>
      )}
      {!result && <p className="empty">{t("ui.no_manual_config_issued_in_this_session")}</p>}
      <Modal title={t("ui.issue_manual_config")} open={modalOpen} onClose={() => setModalOpen(false)}>
        <form className="modal-form" onSubmit={enroll}>
          <Input
            value={hostname}
            onChange={(event) => setHostname(event.target.value)}
            placeholder={t("ui.pc1_example_com")}
            required
            autoFocus
          />
          <SelectField label={t('ui.domain_spaced')} value={domainID} onChange={setDomainID} required options={domains.map((domain) => ({ value: domain.id, label: domain.name }))} />
          <div className="modal-actions">
            <Button type="button" className="ghost" onClick={() => setModalOpen(false)}>{t("ui.cancel")}</Button>
            <Button disabled={busy || domains.length === 0}>{busy ? 'Issuing...' : 'Issue config'}</Button>
          </div>
        </form>
      </Modal>
    </Card>
  )
}

function DomainsPanel({ domains, clients, busyDomain, setBusyDomain, onChange, onRefresh, onError }) {

  const newLocalNetwork = (type) => ({ type, name: '', ssid: '', gateway: '', subnet: '', search_domain: '' })
  const createEmptyDraft = () => ({ name: '', dns_servers: '', search_domain: '', pem: '', auto_enroll_enabled: true, local_networks: [] })
  const legacyLocalNetworks = (domain) => {
    const legacy = domain.local_network || {}
    const profiles = []
    if ([legacy.wifi_name, legacy.wifi_gateway, legacy.wifi_subnet, legacy.wifi_search_domain].some(Boolean)) {
      profiles.push({ type: 'wifi', name: '', ssid: legacy.wifi_name || '', gateway: legacy.wifi_gateway || '', subnet: legacy.wifi_subnet || '', search_domain: legacy.wifi_search_domain || '' })
    }
    if ([legacy.eth_gateway, legacy.eth_subnet, legacy.eth_search_domain].some(Boolean)) {
      profiles.push({ type: 'ethernet', name: '', ssid: '', gateway: legacy.eth_gateway || '', subnet: legacy.eth_subnet || '', search_domain: legacy.eth_search_domain || '' })
    }
    return profiles
  }
  const domainLocalNetworks = (domain) => {
    if (Array.isArray(domain.local_networks)) {
      return domain.local_networks.map((network) => ({ ...newLocalNetwork(network.type || 'ethernet'), ...network }))
    }
    return legacyLocalNetworks(domain)
  }
  const [createOpen, setCreateOpen] = useState(false)
  const [editingDomain, setEditingDomain] = useState(null)
  const [renamingDomain, setRenamingDomain] = useState(null)
  const [renameValue, setRenameValue] = useState('')
  const [deletingDomain, setDeletingDomain] = useState(null)
  const [deletePassword, setDeletePassword] = useState('')
  const [deleteError, setDeleteError] = useState('')
  const [expandedID, setExpandedID] = useState('')
  const [draft, setDraft] = useState(createEmptyDraft)

  const updateDraft = (field, value) => setDraft((current) => ({ ...current, [field]: value }))
  const dnsList = (value) => String(value || '').split(/[\s,]+/).map((item) => item.trim()).filter(Boolean)
  const domainDraft = (domain) => ({
    name: domain.name || '',
    dns_servers: (domain.dns_servers || []).join(', '),
    search_domain: domain.search_domain || '',
    pem: '',
    auto_enroll_enabled: Boolean(domain.auto_enroll_enabled),
    local_networks: domainLocalNetworks(domain),
  })
  const localNetworkSummary = (network) => {
    const items = []
    if (network.type === 'wifi' && network.ssid) items.push(`SSID ${network.ssid}`)
    if (network.gateway) items.push(`gateway ${network.gateway}`)
    if (network.subnet) items.push(`subnet ${network.subnet}`)
    if (network.search_domain) items.push(`search ${network.search_domain}`)
    return items.join(', ')
  }
  const create = async (event) => {
    event.preventDefault()
    setBusyDomain('new')
    onError('')
    try {
      const created = await api('/api/admin/domains', {
        method: 'POST',
        body: JSON.stringify({
          name: draft.name,
          dns_servers: dnsList(draft.dns_servers),
          search_domain: draft.search_domain,
          pem: draft.pem,
          auto_enroll_enabled: draft.auto_enroll_enabled,
          local_networks: draft.local_networks,
        }),
      })
      onChange([...domains, created].sort((a, b) => a.name.localeCompare(b.name)))
      setDraft(createEmptyDraft())
      setCreateOpen(false)
      await onRefresh?.()
    } catch (err) {
      onError(err.message)
    } finally {
      setBusyDomain('')
    }
  }

  const save = async (domain, nextDraft) => {
    setBusyDomain(domain.id)
    onError('')
    try {
      const updated = await api(`/api/admin/domains/${encodeURIComponent(domain.id)}`, {
        method: 'PATCH',
        body: JSON.stringify({
          name: nextDraft.name,
          dns_servers: dnsList(nextDraft.dns_servers),
          search_domain: nextDraft.search_domain,
          pem: nextDraft.pem,
          auto_enroll_enabled: nextDraft.auto_enroll_enabled,
          local_networks: nextDraft.local_networks,
        }),
      })
      onChange(domains.map((item) => (item.id === updated.id ? updated : item)).sort((a, b) => a.name.localeCompare(b.name)))
      setEditingDomain(null)
      await onRefresh?.()
    } catch (err) {
      onError(err.message)
    } finally {
      setBusyDomain('')
    }
  }

  const toggleAutoEnroll = async (domain) => {
    await save(domain, { ...domainDraft(domain), auto_enroll_enabled: !domain.auto_enroll_enabled })
  }

  const rename = async (event) => {
    event.preventDefault()
    if (!renamingDomain || !renameValue.trim()) return
    setBusyDomain(renamingDomain.id)
    onError('')
    try {
      const updated = await api(`/api/admin/domains/${encodeURIComponent(renamingDomain.id)}`, {
        method: 'PATCH',
        body: JSON.stringify({ name: renameValue.trim() }),
      })
      onChange(domains.map((item) => item.id === updated.id ? updated : item).sort((a, b) => a.name.localeCompare(b.name)))
      setRenamingDomain(null)
      await onRefresh?.()
    } catch (err) {
      onError(err.message)
    } finally {
      setBusyDomain('')
    }
  }

  const closeDelete = () => {
    if (busyDomain === deletingDomain?.id) return
    setDeletingDomain(null)
    setDeletePassword('')
    setDeleteError('')
  }

  const remove = async (event) => {
    event.preventDefault()
    if (!deletingDomain || !deletePassword) return
    const id = deletingDomain.id
    setBusyDomain(id)
    setDeleteError('')
    try {
      await api(`/api/admin/domains/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        body: JSON.stringify({ password: deletePassword }),
      })
      onChange(domains.filter((domain) => domain.id !== id))
      setExpandedID((current) => current === id ? '' : current)
      setDeletingDomain(null)
      setDeletePassword('')
      onRefresh?.().catch((err) => onError(err.message))
    } catch (err) {
      if (err.status === 401 && err.message.trim() === 'invalid password') {
        setDeleteError(t('domain.invalid_password'))
      } else if (err.status === 409) {
        setDeleteError(t({
          'domain has enrolled clients; remove them first': 'domain.blocked_clients',
          'domain is used by a group; remove the assignment first': 'domain.blocked_group',
          'domain is used by a remote subnet; remove the assignment first': 'domain.blocked_remote',
        }[err.message.trim()] || 'domain.delete_failed'))
      } else {
        setDeleteError(err.message)
      }
    } finally {
      setBusyDomain('')
    }
  }

  const downloadStartupScript = () => {
    window.location.href = '/api/admin/windows-bootstrap.ps1'
  }

  return (
    <Card className="domains">
      <div className="section-title">
        <div>
          <h2>{t("ui.domains")}</h2>
        </div>
        <div className="row-actions">
          <Button className="ghost" type="button" onClick={downloadStartupScript}>{t("ui.download_gpo_startup_script")}</Button>
          <Button onClick={() => setCreateOpen(true)}>{t("ui.create_domain")}</Button>
        </div>
      </div>
      <div className="domain-list accordion-list">
        {domains.length === 0 && <p className="empty">{t("ui.no_domains_configured_create_one_before_manual_enrollment")}</p>}
        {domains.map((domain) => {
          const expanded = expandedID === domain.id
          const localNetworks = domainLocalNetworks(domain)
          return (
          <ExpandableRow key={domain.id} title={domain.name} expanded={expanded} onExpandedChange={(open) => setExpandedID(open ? domain.id : '')} meta={
            <PillList>
              <Pill>{tr(domain.certificate ? 'CA present' : 'manual only')}</Pill>
              {domain.search_domain && <Pill>{t("ui.search_spaced")}{domain.search_domain}</Pill>}
              {localNetworks.length > 0 && <Pill>{localNetworks.length}{t("ui.lan_spaced")}{tr(localNetworks.length === 1 ? 'profile' : 'profiles')}</Pill>}
            </PillList>
          } actions={
            <>
                <Chip color={domain.auto_enroll_enabled ? 'success' : 'default'} variant="soft" size="sm">{tr(domain.auto_enroll_enabled ? 'auto enroll' : 'manual only')}</Chip>
                <ActionMenu label={tr(`Actions for ${domain.name}`)} items={[
                  { label: t('ui.rename_domain'), disabled: busyDomain === domain.id, onAction: () => { setRenamingDomain(domain); setRenameValue(domain.name) } },
                  { label: t('ui.edit_domain'), disabled: busyDomain === domain.id, onAction: () => setEditingDomain(domain) },
                  { label: tr(domain.auto_enroll_enabled ? 'Disable auto enrollment' : 'Enable auto enrollment'), disabled: !domain.certificate || busyDomain === domain.id, onAction: () => toggleAutoEnroll(domain) },
                  { label: t('ui.delete_domain'), danger: true, disabled: busyDomain === domain.id, onAction: () => { setDeletingDomain(domain); setDeletePassword(''); setDeleteError('') } },
                ]} />
            </>
          }>
            {expanded && (
              <div className="accordion-detail">
                <DetailGrid compact>
                  <dt>{t("ui.dns")}</dt>
                  <dd>{domain.dns_servers?.length ? domain.dns_servers.join(', ') : t('ui.none')}</dd>
                  <dt>{t("ui.search_domain")}</dt>
                  <dd>{domain.search_domain || t('ui.none')}</dd>
                  <dt>{t("ui.local_networks")}</dt>
                  <dd>
                    {localNetworks.length === 0 ? t('ui.none') : (
                      <ol className="local-network-summary-list">
                        {localNetworks.map((network, index) => (
                          <li key={`${network.type}-${index}`}><strong>{network.name || `${tr(network.type === 'wifi' ? 'Wi-Fi' : 'Ethernet')} ${index + 1}`}</strong><span>{localNetworkSummary(network) || t('ui.no_criteria')}</span></li>
                        ))}
                      </ol>
                    )}
                  </dd>
                </DetailGrid>
                <InfoDisclosure title={t("ui.generated_addresses_and_ca_metadata")}>
                  <DetailGrid compact>
                    <dt>{t("ui.ca_subject_issuer")}</dt>
                    <dd>{domain.certificate ? `${domain.certificate.subject} / ${domain.certificate.issuer}` : t('ui.none')}</dd>
                    <dt>{t("ui.ipv4_pool_gateway")}</dt>
                    <dd>{domain.wg_cidr} / {domain.wg_server_ip}</dd>
                    <dt>{t("ui.ipv6_pool_gateway")}</dt>
                    <dd>{domain.wg_ipv6_cidr} / {domain.wg_ipv6_server_ip}</dd>
                  </DetailGrid>
                </InfoDisclosure>
              </div>
            )}
          </ExpandableRow>
          )
        })}
      </div>
      <Modal title={t("ui.create_domain")} open={createOpen} onClose={() => setCreateOpen(false)}>
        <DomainForm draft={draft} busy={busyDomain === 'new'} submitLabel="Create domain" busyLabel="Creating..." onChange={updateDraft} onCancel={() => setCreateOpen(false)} onSubmit={create} />
      </Modal>
      <Modal title={t("ui.rename_domain")} open={Boolean(renamingDomain)} onClose={() => setRenamingDomain(null)}>
        <form className="modal-form" onSubmit={rename}>
          <label>{t("ui.name")}<Input value={renameValue} onChange={(event) => setRenameValue(event.target.value)} required autoFocus /></label>
          <div className="modal-actions">
            <Button className="ghost" type="button" onClick={() => setRenamingDomain(null)}>{t("ui.cancel")}</Button>
            <Button disabled={busyDomain === renamingDomain?.id || !renameValue.trim()}>{busyDomain === renamingDomain?.id ? t("ui.saving") : t("ui.rename_domain")}</Button>
          </div>
        </form>
      </Modal>
      <Modal title={t('ui.delete_domain')} open={Boolean(deletingDomain)} onClose={closeDelete}>
        <form className="modal-form" onSubmit={remove}>
          <p>{t('domain.delete_description', { name: deletingDomain?.name || '' })}</p>
          {deletingDomain && clients.some((client) => client.domain_id === deletingDomain.id) && (
            <Notice status="warning">{t('domain.linked_clients', { count: clients.filter((client) => client.domain_id === deletingDomain.id).length })}</Notice>
          )}
          <label>{t('ui.admin_password')}
            <Input type="password" value={deletePassword} onChange={(event) => setDeletePassword(event.target.value)} autoComplete="current-password" required autoFocus />
          </label>
          {deleteError && <Notice status="danger">{deleteError}</Notice>}
          <div className="modal-actions">
            <Button className="ghost" type="button" onClick={closeDelete}>{t('ui.cancel')}</Button>
            <Button className="danger" disabled={!deletePassword || busyDomain === deletingDomain?.id || clients.some((client) => client.domain_id === deletingDomain?.id)}>{busyDomain === deletingDomain?.id ? t('domain.deleting') : t('ui.delete_domain')}</Button>
          </div>
        </form>
      </Modal>
      <DomainEditModal
        domain={editingDomain}
        busy={busyDomain === editingDomain?.id}
        draftFor={domainDraft}
        onClose={() => setEditingDomain(null)}
        onSave={save}
      />
    </Card>
  )
}

function DomainEditModal({ domain, busy, draftFor, onClose, onSave }) {
  const [draft, setDraft] = useState(draftFor(domain || {}))

  useEffect(() => {
    setDraft(draftFor(domain || {}))
  }, [domain])

  if (!domain) return null

  const update = (field, value) => setDraft((current) => ({ ...current, [field]: value }))
  const submit = (event) => {
    event.preventDefault()
    onSave(domain, draft)
  }

  return (
    <Modal title={tr(`Edit ${domain.name}`)} open={Boolean(domain)} onClose={onClose}>
      <DomainForm draft={draft} busy={busy} submitLabel="Save domain" busyLabel="Saving..." onChange={update} onCancel={onClose} onSubmit={submit} />
    </Modal>
  )
}

function DomainForm({ draft, busy, submitLabel, busyLabel, onChange, onCancel, onSubmit }) {
  const networks = Array.isArray(draft.local_networks) ? draft.local_networks : []
  const setNetworks = (next) => onChange('local_networks', next)
  const updateNetwork = (index, field, value) => {
    const next = networks.map((network) => ({ ...network }))
    const updated = { ...next[index], [field]: value }
    if (field === 'type' && value === 'ethernet') {
      updated.ssid = ''
    }
    next[index] = updated
    setNetworks(next)
  }
  const addNetwork = (type) => setNetworks([...networks, { type, name: '', ssid: '', gateway: '', subnet: '', search_domain: '' }])
  const removeNetwork = (index) => setNetworks(networks.filter((_, current) => current !== index))
  const moveNetwork = (index, direction) => {
    const target = index + direction
    if (target < 0 || target >= networks.length) return
    const next = networks.map((network) => ({ ...network }))
    ;[next[index], next[target]] = [next[target], next[index]]
    setNetworks(next)
  }

  return (
    <form className="modal-form" onSubmit={onSubmit}>
      <fieldset className="form-section">
        <legend>{t("ui.general")}</legend>
        <label>{t("ui.name_spaced")}<Input value={draft.name} onChange={(event) => onChange('name', event.target.value)} required autoFocus />
        </label>
        <div className="form-row two">
          <label>{t("ui.dns_servers_spaced")}<Input value={draft.dns_servers} onChange={(event) => onChange('dns_servers', event.target.value)} placeholder="9.9.9.9, 1.1.1.1" />
          </label>
          <label>{t("ui.search_domain_spaced")}<Input value={draft.search_domain} onChange={(event) => onChange('search_domain', event.target.value)} placeholder={t("ui.corp_example_com")} />
          </label>
        </div>
      </fieldset>
      <InfoDisclosure title={t("ui.local_network_auto_disable")} meta={tr(networks.length === 0 ? 'Not configured' : `${networks.length} ${networks.length === 1 ? 'profile' : 'profiles'}`)} defaultExpanded>
        <div className="disclosure-body">
          <p className="muted">{t("ui.add_any_number_of_wi_fi_and_ethernet_profiles_a_match_on_a")}</p>
          {networks.length === 0 && (
            <p className="empty compact-empty">{t("ui.no_local_networks_configured_the_wireguard_tunnel_remains_spaced")}</p>
          )}
          <div className="local-network-editor-list">
            {networks.map((network, index) => (
              <fieldset className="local-network-editor" key={`${network.type}-${index}`}>
                <legend>{network.name || `${network.type === 'wifi' ? 'Wi-Fi' : 'Ethernet'} profile ${index + 1}`}</legend>
                <div className="local-network-editor-header">
                  <div>
                    <strong>{t("ui.profile_spaced")}{index + 1}</strong>
                    <span>{[network.ssid, network.gateway, network.subnet, network.search_domain].filter(Boolean).length}{t("ui.matching_fields_spaced")}</span>
                  </div>
                  <div className="row-actions">
                    <Button type="button" className="ghost compact-button" disabled={index === 0} aria-label={`Move profile ${index + 1} up`} onClick={() => moveNetwork(index, -1)}>↑</Button>
                    <Button type="button" className="ghost compact-button" disabled={index === networks.length - 1} aria-label={`Move profile ${index + 1} down`} onClick={() => moveNetwork(index, 1)}>↓</Button>
                    <Button type="button" className="danger compact-button" onClick={() => removeNetwork(index)}>{t("ui.remove")}</Button>
                  </div>
                </div>
                <div className="form-row two">
                  <SelectField label={t('ui.type_spaced')} value={network.type || 'ethernet'} onChange={(next) => updateNetwork(index, 'type', next)} options={[
                    { value: 'wifi', label: t('ui.wi_fi') },
                    { value: 'ethernet', label: t('ui.ethernet') },
                  ]} />
                  <label>{t("ui.profile_label_spaced")}<Input value={network.name || ''} onChange={(event) => updateNetwork(index, 'name', event.target.value)} placeholder={t("ui.headquarters")} />
                  </label>
                  {network.type === 'wifi' && (
                    <label>{t("ui.ssid_spaced")}<Input value={network.ssid || ''} onChange={(event) => updateNetwork(index, 'ssid', event.target.value)} placeholder={t("ui.corp_wi_fi")} required={!network.gateway && !network.subnet && !network.search_domain} />
                    </label>
                  )}
                  <label>{t("ui.gateway_spaced")}<Input value={network.gateway || ''} onChange={(event) => updateNetwork(index, 'gateway', event.target.value)} placeholder="192.168.10.1" required={network.type === 'ethernet' && !network.subnet && !network.search_domain} />
                  </label>
                  <label>{t("ui.ipv4_subnet_spaced")}<Input value={network.subnet || ''} onChange={(event) => updateNetwork(index, 'subnet', event.target.value)} placeholder="192.168.10.0/24" />
                  </label>
                  <label>{t("ui.dns_suffix_spaced")}<Input value={network.search_domain || ''} onChange={(event) => updateNetwork(index, 'search_domain', event.target.value)} placeholder={t("ui.corp_example_com")} />
                  </label>
                </div>
                <p className="muted profile-rule-note">{t("ui.configure_at_least_one_matching_field_multiple_fields_are")}</p>
              </fieldset>
            ))}
          </div>
          <div className="row-actions local-network-add-actions">
            <Button type="button" className="ghost" onClick={() => addNetwork('wifi')}>{t("ui.add_wi_fi_profile")}</Button>
            <Button type="button" className="ghost" onClick={() => addNetwork('ethernet')}>{t("ui.add_ethernet_profile")}</Button>
          </div>
        </div>
      </InfoDisclosure>
      <InfoDisclosure title={t("ui.certificate_enrollment")} meta={tr(draft.auto_enroll_enabled ? 'Enabled when CA is present' : 'Disabled')} defaultExpanded={submitLabel === 'Create domain'}>
        <div className="disclosure-body">
          <p className="muted">{t("ui.upload_only_the_public_ad_cs_ca_certificate_leave_this_bla")}</p>
          <label>{t("ui.ca_public_certificate_spaced")}<TextArea value={draft.pem} onChange={(event) => onChange('pem', event.target.value)} placeholder={t("ui.begin_certificate")} rows={6} />
          </label>
          <CheckboxRow compact checked={draft.auto_enroll_enabled} onChange={(selected) => onChange('auto_enroll_enabled', selected)}>{t("ui.enable_certificate_auto_enrollment_when_a_ca_is_present")}</CheckboxRow>
        </div>
      </InfoDisclosure>
      <div className="modal-actions">
        <Button type="button" className="ghost" onClick={onCancel}>{t("ui.cancel")}</Button>
        <Button disabled={busy}>{busy ? busyLabel : submitLabel}</Button>
      </div>
    </form>
  )
}

createRoot(document.getElementById('root')).render(<LocaleProvider><App /></LocaleProvider>)
