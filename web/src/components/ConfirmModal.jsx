import React from 'react'
import { t, tr } from '../i18n.jsx'
import { Modal } from '../layout.jsx'
import { Button } from './forms.jsx'

export function ConfirmModal({
  open,
  title,
  message,
  confirmLabel,
  busy = false,
  onClose,
  onConfirm,
}) {
  return (
    <Modal title={tr(title)} open={open} onClose={onClose}>
      <div className="confirm-dialog">
        <p>{tr(message)}</p>
        <div className="modal-actions">
          <Button type="button" className="ghost" onClick={onClose}>
            {t('ui.cancel')}
          </Button>
          <Button type="button" className="danger" disabled={busy} onClick={onConfirm}>
            {tr(busy ? 'Working...' : confirmLabel)}
          </Button>
        </div>
      </div>
    </Modal>
  )
}
