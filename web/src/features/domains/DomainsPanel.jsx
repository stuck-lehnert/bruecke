import React, { useState } from 'react'
import { Card, Chip } from '@heroui/react'
import { api } from '../../api.js'
import { t, tr } from '../../i18n.jsx'
import { Modal } from '../../layout.jsx'
import { Button, Input } from '../../components/forms.jsx'
import {
  DetailGrid,
  ExpandableRow,
  InfoDisclosure,
  Pill,
  PillList,
} from '../../components/details.jsx'
import { Notice } from '../../components/Notice.jsx'
import { ActionMenu } from '../../components/ActionMenu.jsx'
import { DomainForm } from './DomainForm.jsx'
import { DomainEditModal } from './DomainEditModal.jsx'
import {
  createEmptyDraft,
  domainLocalNetworks,
  dnsList,
  domainDraft,
  localNetworkSummary,
} from './domainHelpers.js'

export function DomainsPanel({
  domains,
  clients,
  busyDomain,
  setBusyDomain,
  onChange,
  onRefresh,
  onError,
}) {
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
      onChange(
        domains
          .map((item) => (item.id === updated.id ? updated : item))
          .sort((a, b) => a.name.localeCompare(b.name)),
      )
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
      onChange(
        domains
          .map((item) => (item.id === updated.id ? updated : item))
          .sort((a, b) => a.name.localeCompare(b.name)),
      )
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
      setExpandedID((current) => (current === id ? '' : current))
      setDeletingDomain(null)
      setDeletePassword('')
      onRefresh?.().catch((err) => onError(err.message))
    } catch (err) {
      if (err.status === 401 && err.message.trim() === 'invalid password') {
        setDeleteError(t('domain.invalid_password'))
      } else if (err.status === 409) {
        setDeleteError(
          t(
            {
              'domain has enrolled clients; remove them first': 'domain.blocked_clients',
              'domain is used by a group; remove the assignment first': 'domain.blocked_group',
              'domain is used by a remote subnet; remove the assignment first':
                'domain.blocked_remote',
            }[err.message.trim()] || 'domain.delete_failed',
          ),
        )
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
          <h2>{t('ui.domains')}</h2>
        </div>
        <div className="row-actions">
          <Button className="ghost" type="button" onClick={downloadStartupScript}>
            {t('ui.download_gpo_startup_script')}
          </Button>
          <Button onClick={() => setCreateOpen(true)}>{t('ui.create_domain')}</Button>
        </div>
      </div>
      <div className="domain-list accordion-list">
        {domains.length === 0 && (
          <p className="empty">
            {t('ui.no_domains_configured_create_one_before_manual_enrollment')}
          </p>
        )}
        {domains.map((domain) => {
          const expanded = expandedID === domain.id
          const localNetworks = domainLocalNetworks(domain)
          return (
            <ExpandableRow
              key={domain.id}
              title={domain.name}
              expanded={expanded}
              onExpandedChange={(open) => setExpandedID(open ? domain.id : '')}
              meta={
                <PillList>
                  <Pill>{tr(domain.certificate ? 'CA present' : 'manual only')}</Pill>
                  {domain.search_domain && (
                    <Pill>
                      {t('ui.search_spaced')}
                      {domain.search_domain}
                    </Pill>
                  )}
                  {localNetworks.length > 0 && (
                    <Pill>
                      {localNetworks.length}
                      {t('ui.lan_spaced')}
                      {tr(localNetworks.length === 1 ? 'profile' : 'profiles')}
                    </Pill>
                  )}
                </PillList>
              }
              actions={
                <>
                  <Chip
                    color={domain.auto_enroll_enabled ? 'success' : 'default'}
                    variant="soft"
                    size="sm"
                  >
                    {tr(domain.auto_enroll_enabled ? 'auto enroll' : 'manual only')}
                  </Chip>
                  <ActionMenu
                    label={tr(`Actions for ${domain.name}`)}
                    items={[
                      {
                        label: t('ui.rename_domain'),
                        disabled: busyDomain === domain.id,
                        onAction: () => {
                          setRenamingDomain(domain)
                          setRenameValue(domain.name)
                        },
                      },
                      {
                        label: t('ui.edit_domain'),
                        disabled: busyDomain === domain.id,
                        onAction: () => setEditingDomain(domain),
                      },
                      {
                        label: tr(
                          domain.auto_enroll_enabled
                            ? 'Disable auto enrollment'
                            : 'Enable auto enrollment',
                        ),
                        disabled: !domain.certificate || busyDomain === domain.id,
                        onAction: () => toggleAutoEnroll(domain),
                      },
                      {
                        label: t('ui.delete_domain'),
                        danger: true,
                        disabled: busyDomain === domain.id,
                        onAction: () => {
                          setDeletingDomain(domain)
                          setDeletePassword('')
                          setDeleteError('')
                        },
                      },
                    ]}
                  />
                </>
              }
            >
              {expanded && (
                <div className="accordion-detail">
                  <DetailGrid compact>
                    <dt>{t('ui.dns')}</dt>
                    <dd>
                      {domain.dns_servers?.length ? domain.dns_servers.join(', ') : t('ui.none')}
                    </dd>
                    <dt>{t('ui.search_domain')}</dt>
                    <dd>{domain.search_domain || t('ui.none')}</dd>
                    <dt>{t('ui.local_networks')}</dt>
                    <dd>
                      {localNetworks.length === 0 ? (
                        t('ui.none')
                      ) : (
                        <ol className="local-network-summary-list">
                          {localNetworks.map((network, index) => (
                            <li key={`${network.type}-${index}`}>
                              <strong>
                                {network.name ||
                                  `${tr(network.type === 'wifi' ? 'Wi-Fi' : 'Ethernet')} ${index + 1}`}
                              </strong>
                              <span>{localNetworkSummary(network) || t('ui.no_criteria')}</span>
                            </li>
                          ))}
                        </ol>
                      )}
                    </dd>
                  </DetailGrid>
                  <InfoDisclosure title={t('ui.generated_addresses_and_ca_metadata')}>
                    <DetailGrid compact>
                      <dt>{t('ui.ca_subject_issuer')}</dt>
                      <dd>
                        {domain.certificate
                          ? `${domain.certificate.subject} / ${domain.certificate.issuer}`
                          : t('ui.none')}
                      </dd>
                      <dt>{t('ui.ipv4_pool_gateway')}</dt>
                      <dd>
                        {domain.wg_cidr} / {domain.wg_server_ip}
                      </dd>
                      <dt>{t('ui.ipv6_pool_gateway')}</dt>
                      <dd>
                        {domain.wg_ipv6_cidr} / {domain.wg_ipv6_server_ip}
                      </dd>
                    </DetailGrid>
                  </InfoDisclosure>
                </div>
              )}
            </ExpandableRow>
          )
        })}
      </div>
      <Modal title={t('ui.create_domain')} open={createOpen} onClose={() => setCreateOpen(false)}>
        <DomainForm
          draft={draft}
          busy={busyDomain === 'new'}
          submitLabel="Create domain"
          busyLabel="Creating..."
          onChange={updateDraft}
          onCancel={() => setCreateOpen(false)}
          onSubmit={create}
        />
      </Modal>
      <Modal
        title={t('ui.rename_domain')}
        open={Boolean(renamingDomain)}
        onClose={() => setRenamingDomain(null)}
      >
        <form className="modal-form" onSubmit={rename}>
          <label>
            {t('ui.name')}
            <Input
              value={renameValue}
              onChange={(event) => setRenameValue(event.target.value)}
              required
              autoFocus
            />
          </label>
          <div className="modal-actions">
            <Button className="ghost" type="button" onClick={() => setRenamingDomain(null)}>
              {t('ui.cancel')}
            </Button>
            <Button disabled={busyDomain === renamingDomain?.id || !renameValue.trim()}>
              {busyDomain === renamingDomain?.id ? t('ui.saving') : t('ui.rename_domain')}
            </Button>
          </div>
        </form>
      </Modal>
      <Modal title={t('ui.delete_domain')} open={Boolean(deletingDomain)} onClose={closeDelete}>
        <form className="modal-form" onSubmit={remove}>
          <p>{t('domain.delete_description', { name: deletingDomain?.name || '' })}</p>
          {deletingDomain && clients.some((client) => client.domain_id === deletingDomain.id) && (
            <Notice status="warning">
              {t('domain.linked_clients', {
                count: clients.filter((client) => client.domain_id === deletingDomain.id).length,
              })}
            </Notice>
          )}
          <label>
            {t('ui.admin_password')}
            <Input
              type="password"
              value={deletePassword}
              onChange={(event) => setDeletePassword(event.target.value)}
              autoComplete="current-password"
              required
              autoFocus
            />
          </label>
          {deleteError && <Notice status="danger">{deleteError}</Notice>}
          <div className="modal-actions">
            <Button className="ghost" type="button" onClick={closeDelete}>
              {t('ui.cancel')}
            </Button>
            <Button
              className="danger"
              disabled={
                !deletePassword ||
                busyDomain === deletingDomain?.id ||
                clients.some((client) => client.domain_id === deletingDomain?.id)
              }
            >
              {busyDomain === deletingDomain?.id ? t('domain.deleting') : t('ui.delete_domain')}
            </Button>
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
