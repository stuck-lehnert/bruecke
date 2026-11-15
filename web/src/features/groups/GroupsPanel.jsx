import React, { useState } from 'react'
import { Card } from '@heroui/react'
import { api } from '../../api.js'
import { t } from '../../i18n.jsx'
import { Modal } from '../../layout.jsx'
import { Button, Input } from '../../components/forms.jsx'
import { ConfirmModal } from '../../components/ConfirmModal.jsx'
import { GroupEditor } from './GroupEditor.jsx'

export function GroupsPanel({ groups, clients, onChange, onClientsReload, onError }) {
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
          <h2>{t('ui.groups')}</h2>
        </div>
        <Button onClick={() => setCreateOpen(true)}>{t('ui.create_group')}</Button>
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
      <Modal title={t('ui.create_group')} open={createOpen} onClose={() => setCreateOpen(false)}>
        <form className="modal-form" onSubmit={create}>
          <Input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder={t('ui.new_custom_group')}
            required
            autoFocus
          />
          <div className="modal-actions">
            <Button type="button" className="ghost" onClick={() => setCreateOpen(false)}>
              {t('ui.cancel')}
            </Button>
            <Button disabled={busyID === 'new'}>
              {busyID === 'new' ? 'Creating...' : 'Create'}
            </Button>
          </div>
        </form>
      </Modal>
      <ConfirmModal
        open={Boolean(groupToRemove)}
        title={t('ui.delete_group')}
        message={groupToRemove ? `Delete ${groupToRemove.name}? Its clients remain enrolled.` : ''}
        confirmLabel="Delete group"
        busy={busyID === groupToRemove?.id}
        onClose={() => setGroupToRemove(null)}
        onConfirm={() => remove(groupToRemove)}
      />
    </Card>
  )
}
