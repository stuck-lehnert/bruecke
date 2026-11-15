import React from 'react'
import { Card, Chip } from '@heroui/react'
import { t, tr, formatDate } from '../../i18n.jsx'
import { clientRemoteSubnets, groupLabel } from '../../helpers.js'
import { SelectField } from '../../select.jsx'
import { Button, Input } from '../../components/forms.jsx'
import { DetailGrid, ExpandableRow, Pill, PillList } from '../../components/details.jsx'
import { ActionMenu } from '../../components/ActionMenu.jsx'

export function PeersPanel({
  clients,
  visibleClients,
  remoteSubnets,
  groups,
  peerQuery,
  setPeerQuery,
  peerStatus,
  setPeerStatus,
  expandedPeerID,
  setExpandedPeerID,
  busyHost,
  load,
  toggleClient,
  setClientToRemove,
  onShowLogs,
  onShowVPNActivity,
}) {
  return (
    <section className="tab-panel">
      <Card className="toolbar">
        <div className="toolbar-summary">
          <strong>{visibleClients.length}</strong>
          <span>
            {tr(
              visibleClients.length === clients.length
                ? 'computers enrolled'
                : `of ${clients.length} computers`,
            )}
          </span>
        </div>
        <div className="toolbar-controls">
          <label className="search-field">
            <span className="sr-only">{t('ui.search_peers')}</span>
            <Input
              type="search"
              value={peerQuery}
              onChange={(event) => setPeerQuery(event.target.value)}
              placeholder={t('ui.search_peers')}
            />
          </label>
          <SelectField
            className="compact-field"
            label={t('ui.peer_status')}
            hideLabel
            value={peerStatus}
            onChange={setPeerStatus}
            options={[
              { value: 'all', label: t('ui.all_statuses') },
              { value: 'connected', label: t('ui.connected') },
              { value: 'offline', label: t('ui.offline') },
              { value: 'disabled', label: t('ui.disabled') },
            ]}
          />
          <Button className="ghost" onClick={load}>
            {t('ui.refresh')}
          </Button>
        </div>
      </Card>
      <Card className="list accordion-list">
        {clients.length === 0 && <p className="empty">{t('ui.no_computers_enrolled_yet')}</p>}
        {clients.length > 0 && visibleClients.length === 0 && (
          <p className="empty">{t('ui.no_peers_match_these_filters')}</p>
        )}
        {visibleClients.map((client) => {
          const allowedSubnets = clientRemoteSubnets(client, remoteSubnets)
          const expanded = expandedPeerID === client.id
          const isSSH = client.type === 'ssh'
          return (
            <ExpandableRow
              key={client.id || client.hostname}
              title={client.hostname}
              expanded={expanded}
              onExpandedChange={(open) => setExpandedPeerID(open ? client.id : '')}
              meta={
                <PillList>
                  <Pill>{isSSH ? 'SSH' : 'WireGuard'}</Pill>
                  {client.domain_name && <Pill>{client.domain_name}</Pill>}
                  {client.ip && <Pill>{client.ip}</Pill>}
                </PillList>
              }
              actions={
                <>
                  <Chip
                    color={client.enabled && client.connected ? 'success' : 'default'}
                    variant="soft"
                    size="sm"
                  >
                    {tr(client.enabled ? (client.connected ? 'connected' : 'offline') : 'disabled')}
                  </Chip>
                  <ActionMenu
                    label={tr(`Actions for ${client.hostname}`)}
                    items={[
                      {
                        label: isSSH
                          ? t(client.enabled ? 'ssh.disable_access' : 'ssh.enable_access')
                          : tr(client.enabled ? 'Disable VPN' : 'Enable VPN'),
                        disabled: busyHost === client.id,
                        onAction: () => toggleClient(client),
                      },
                      {
                        label: t('ui.bootstrap_logs_596bd4'),
                        onAction: () => onShowLogs(client.id),
                      },
                      { label: t('ui.vpn_activity'), onAction: () => onShowVPNActivity(client.id) },
                      {
                        label: t('ui.remove_peer'),
                        danger: true,
                        disabled: busyHost === client.id,
                        onAction: () => setClientToRemove(client),
                      },
                    ]}
                  />
                </>
              }
            >
              {expanded && (
                <div className="accordion-detail">
                  <DetailGrid compact>
                    <dt>{t('ssh.client_type')}</dt>
                    <dd>{isSSH ? 'SSH' : 'WireGuard'}</dd>
                    <dt>{t('ui.ipv4_ipv6')}</dt>
                    <dd>
                      {client.ip || '—'}
                      {client.ipv6 ? ` / ${client.ipv6}` : ''}
                    </dd>
                    {!isSSH && (
                      <>
                        <dt>{t('ui.certificate')}</dt>
                        <dd>{client.certificate_serial || t('ui.unknown')}</dd>
                      </>
                    )}
                    <dt>{t('ui.last_handshake')}</dt>
                    <dd>
                      {client.latest_handshake
                        ? formatDate(client.latest_handshake)
                        : t('ui.never')}
                    </dd>
                    <dt>{t('ui.updated')}</dt>
                    <dd>{formatDate(client.updated_at)}</dd>
                    <dt>{t('ui.groups')}</dt>
                    <dd>
                      {client.group_ids?.length
                        ? client.group_ids.map((id) => groupLabel(groups, id)).join(', ')
                        : t('ui.none')}
                    </dd>
                    <dt>{t('ui.remote_subnets_b72ae0')}</dt>
                    <dd>
                      {allowedSubnets.length
                        ? allowedSubnets.map((subnet) => subnet.name).join(', ')
                        : t('ui.none')}
                    </dd>
                    <dt>{t('ui.public_key')}</dt>
                    <dd>{client.public_key || t('ui.unknown')}</dd>
                    {isSSH && (
                      <>
                        <dt>{t('ssh.fingerprint')}</dt>
                        <dd>{client.ssh_fingerprint || t('ui.unknown')}</dd>
                      </>
                    )}
                  </DetailGrid>
                </div>
              )}
            </ExpandableRow>
          )
        })}
      </Card>
    </section>
  )
}
