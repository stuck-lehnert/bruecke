import React, { useEffect, useState } from 'react'
import { Card } from '@heroui/react'
import { api } from '../../api.js'
import { t, tr } from '../../i18n.jsx'
import { Modal } from '../../layout.jsx'
import { SelectField } from '../../select.jsx'
import { Button, Input, TextArea } from '../../components/forms.jsx'
import { ExpandableRow, Pill, PillList } from '../../components/details.jsx'

export function ManualEnrollment({ domains, onEnroll, onError }) {
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
          <h2>{t('ui.manual_enrollment')}</h2>
        </div>
        <Button onClick={() => setModalOpen(true)}>{t('ui.issue_config')}</Button>
      </div>
      {result && (
        <ExpandableRow
          title={result.hostname}
          expanded={configOpen}
          onExpandedChange={setConfigOpen}
          meta={
            <PillList>
              <Pill>{result.address}</Pill>
            </PillList>
          }
          actions={
            <>
              <Button className="ghost" onClick={copyConfig}>
                {t('ui.copy')}
              </Button>
              <Button className="ghost" onClick={downloadConfig}>
                {t('ui.download')}
              </Button>
            </>
          }
        >
          {copyState && <p className="copy-state">{tr(copyState)}</p>}
          {configOpen && (
            <div className="accordion-detail">
              <TextArea className="config-output" value={result.config || ''} readOnly rows={12} />
            </div>
          )}
        </ExpandableRow>
      )}
      {!result && <p className="empty">{t('ui.no_manual_config_issued_in_this_session')}</p>}
      <Modal
        title={t('ui.issue_manual_config')}
        open={modalOpen}
        onClose={() => setModalOpen(false)}
      >
        <form className="modal-form" onSubmit={enroll}>
          <Input
            value={hostname}
            onChange={(event) => setHostname(event.target.value)}
            placeholder={t('ui.pc1_example_com')}
            required
            autoFocus
          />
          <SelectField
            label={t('ui.domain_spaced')}
            value={domainID}
            onChange={setDomainID}
            required
            options={domains.map((domain) => ({ value: domain.id, label: domain.name }))}
          />
          <div className="modal-actions">
            <Button type="button" className="ghost" onClick={() => setModalOpen(false)}>
              {t('ui.cancel')}
            </Button>
            <Button disabled={busy || domains.length === 0}>
              {busy ? 'Issuing...' : 'Issue config'}
            </Button>
          </div>
        </form>
      </Modal>
    </Card>
  )
}
