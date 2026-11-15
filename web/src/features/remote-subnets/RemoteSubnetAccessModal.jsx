import React, { useEffect, useState } from 'react'
import { t, tr } from '../../i18n.jsx'
import { clientLabel, splitSubnetText } from '../../helpers.js'
import { Modal } from '../../layout.jsx'
import { Button, Input, TextArea } from '../../components/forms.jsx'
import { SelectionPicker } from '../../components/SelectionPicker.jsx'

export function RemoteSubnetAccessModal({ subnet, clients, groups, busy, onClose, onSave }) {
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
        <Input
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder={t('ui.name')}
          required
        />
        <TextArea
          value={subnetText}
          onChange={(event) => setSubnetText(event.target.value)}
          placeholder={t('ui.remote_cidrs')}
          rows={3}
          required
        />
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
          <Button type="button" className="ghost" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button disabled={busy}>{busy ? 'Saving...' : 'Save access'}</Button>
        </div>
      </form>
    </Modal>
  )
}
