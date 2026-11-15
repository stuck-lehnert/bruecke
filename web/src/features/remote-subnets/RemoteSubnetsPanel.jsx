import React, { useState } from 'react'
import { Card, Chip } from '@heroui/react'
import { api } from '../../api.js'
import { t, tr } from '../../i18n.jsx'
import { mergeRemoteSubnets, remoteAccessSummary, splitSubnetText } from '../../helpers.js'
import { Modal } from '../../layout.jsx'
import { SelectField } from '../../select.jsx'
import { Button, CheckboxRow, Input, TextArea } from '../../components/forms.jsx'
import { DetailGrid, ExpandableRow, Pill, PillList } from '../../components/details.jsx'
import { ConfirmModal } from '../../components/ConfirmModal.jsx'
import { RemoteSubnetAccessModal } from './RemoteSubnetAccessModal.jsx'

export function RemoteSubnetsPanel({ subnets, clients, groups, onChange, onError }) {
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
          <h2>{t('ui.remote_subnets')}</h2>
        </div>
        <Button onClick={() => setCreateOpen(true)}>{t('ui.add_remote_subnet')}</Button>
      </div>
      <div className="remote-list accordion-list">
        {subnets.length === 0 && <p className="empty">{t('ui.no_remote_subnets_configured')}</p>}
        {subnets.map((subnet) => {
          const expanded = expandedID === subnet.id
          const accessCount = (subnet.group_ids || []).length + (subnet.client_ids || []).length
          return (
            <ExpandableRow
              key={subnet.id}
              title={subnet.name}
              expanded={expanded}
              onExpandedChange={(open) => setExpandedID(open ? subnet.id : '')}
              meta={
                <PillList>
                  <Pill>{subnet.subnets[0] || 'no CIDR'}</Pill>
                  {subnet.subnets.length > 1 && (
                    <Pill>
                      {subnet.subnets.length}
                      {t('ui.cidrs_spaced')}
                    </Pill>
                  )}
                  <Pill>{subnet.config_type.toUpperCase()}</Pill>
                  <Pill>{accessCount === 0 ? 'no grants' : `${accessCount} grants`}</Pill>
                </PillList>
              }
              actions={
                <>
                  <Chip color={subnet.enabled ? 'success' : 'default'} variant="soft" size="sm">
                    {tr(subnet.enabled ? 'active' : 'inactive')}
                  </Chip>
                  <CheckboxRow
                    compact
                    checked={subnet.enabled}
                    disabled={busyID === subnet.id}
                    onChange={() => save(subnet, { enabled: !subnet.enabled })}
                  >
                    {t('ui.enabled')}
                  </CheckboxRow>
                </>
              }
            >
              {expanded && (
                <div className="accordion-detail">
                  <DetailGrid compact>
                    <dt>{t('ui.remote_cidrs')}</dt>
                    <dd>{subnet.subnets.join(', ')}</dd>
                    <dt>{t('ui.config')}</dt>
                    <dd>
                      {subnet.config_type.toUpperCase()}
                      {subnet.source_filename ? ` / ${subnet.source_filename}` : ''}
                    </dd>
                    <dt>{t('ui.access')}</dt>
                    <dd>{remoteAccessSummary(subnet, groups, clients)}</dd>
                  </DetailGrid>
                  <div className="row-actions">
                    <Button
                      className="ghost"
                      disabled={busyID === subnet.id}
                      onClick={() => setEditingSubnet(subnet)}
                    >
                      {t('ui.edit_access')}
                    </Button>
                    <Button
                      className="danger"
                      disabled={busyID === subnet.id}
                      onClick={() => setSubnetToRemove(subnet)}
                    >
                      {t('ui.delete')}
                    </Button>
                  </div>
                </div>
              )}
            </ExpandableRow>
          )
        })}
      </div>
      <Modal
        title={t('ui.add_remote_subnet')}
        open={createOpen}
        onClose={() => setCreateOpen(false)}
      >
        <form className="modal-form" onSubmit={create}>
          <Input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder={t('ui.name')}
            required
          />
          <TextArea
            value={subnetText}
            onChange={(event) => setSubnetText(event.target.value)}
            placeholder={t('ui.remote_cidrs_e_g_10_10_0_0_24')}
            rows={3}
            required
          />
          <div className="form-row two">
            <SelectField
              label={t('ui.config_type_spaced')}
              value={configType}
              onChange={setConfigType}
              options={[
                { value: 'ovpn', label: t('ui.ovpn') },
                { value: 'apc', label: t('ui.apc') },
              ]}
            />
            <label>
              {t('ui.config_file_spaced')}
              <input type="file" accept=".ovpn,.apc" onChange={readConfigFile} />
            </label>
          </div>
          <TextArea
            value={configText}
            onChange={(event) => setConfigText(event.target.value)}
            placeholder={t('ui.paste_apc_or_ovpn_config')}
            rows={8}
            required
          />
          <CheckboxRow compact checked={grantAll} onChange={setGrantAll}>
            {t('ui.grant_all_clients')}
          </CheckboxRow>
          <div className="modal-actions">
            <Button type="button" className="ghost" onClick={() => setCreateOpen(false)}>
              {t('ui.cancel')}
            </Button>
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
        title={t('ui.delete_remote_subnet')}
        message={
          subnetToRemove
            ? `Delete ${subnetToRemove.name} and stop its site-to-site connection?`
            : ''
        }
        confirmLabel="Delete remote subnet"
        busy={busyID === subnetToRemove?.id}
        onClose={() => setSubnetToRemove(null)}
        onConfirm={() => remove(subnetToRemove)}
      />
    </Card>
  )
}
