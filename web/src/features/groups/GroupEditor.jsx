import React, { useEffect, useState } from 'react'
import { t } from '../../i18n.jsx'
import { clientLabel } from '../../helpers.js'
import { Button, Input } from '../../components/forms.jsx'
import { ExpandableRow, Pill, PillList } from '../../components/details.jsx'
import { SelectionPicker } from '../../components/SelectionPicker.jsx'

export function GroupEditor({
  group,
  groups,
  clients,
  busy,
  expanded,
  onToggle,
  onSave,
  onRemove,
}) {
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
    <ExpandableRow
      title={group.name}
      expanded={expanded}
      onExpandedChange={onToggle}
      meta={
        <PillList>
          <Pill>
            {group.type}
            {group.built_in ? ' / built-in' : ''}
          </Pill>
          <Pill>
            {clientIDs.length}
            {t('ui.clients_spaced')}
          </Pill>
          <Pill>
            {groupIDs.length}
            {t('ui.child_groups_spaced')}
          </Pill>
        </PillList>
      }
    >
      {expanded && group.built_in && (
        <div className="accordion-detail">
          <p className="muted">{t('ui.members_are_managed_automatically')}</p>
          <div className="form-row two align-start">
            <div className="assignment-grid">
              <strong>{t('ui.clients')}</strong>
              {memberClients.length === 0 && <p className="muted">{t('ui.no_clients')}</p>}
              {memberClients.map((client) => (
                <p key={client.id}>{clientLabel(client)}</p>
              ))}
            </div>
            <div className="assignment-grid">
              <strong>{t('ui.child_groups')}</strong>
              {childGroups.length === 0 && <p className="muted">{t('ui.no_child_groups')}</p>}
              {childGroups.map((child) => (
                <p key={child.id}>{child.name}</p>
              ))}
            </div>
          </div>
        </div>
      )}
      {expanded && !group.built_in && (
        <form className="accordion-detail" onSubmit={submit}>
          <label>
            {t('ui.name_spaced')}
            <Input value={name} onChange={(event) => setName(event.target.value)} required />
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
            <Button
              type="button"
              className="danger"
              disabled={busy}
              onClick={() => onRemove(group)}
            >
              {t('ui.delete')}
            </Button>
            <Button disabled={busy}>{busy ? 'Saving...' : 'Save group'}</Button>
          </div>
        </form>
      )}
    </ExpandableRow>
  )
}
