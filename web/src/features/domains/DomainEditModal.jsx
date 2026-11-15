import React, { useEffect, useState } from 'react'
import { tr } from '../../i18n.jsx'
import { Modal } from '../../layout.jsx'
import { DomainForm } from './DomainForm.jsx'

export function DomainEditModal({ domain, busy, draftFor, onClose, onSave }) {
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
      <DomainForm
        draft={draft}
        busy={busy}
        submitLabel="Save domain"
        busyLabel="Saving..."
        onChange={update}
        onCancel={onClose}
        onSubmit={submit}
      />
    </Modal>
  )
}
