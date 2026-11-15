import React, { useEffect, useState } from 'react'
import { Card } from '@heroui/react'
import { api } from '../../api.js'
import { t } from '../../i18n.jsx'
import { isSupportedSshPublicKey } from '../../helpers.js'
import { Modal } from '../../layout.jsx'
import { SelectField } from '../../select.jsx'
import { Button, Input, TextArea } from '../../components/forms.jsx'
import { InfoDisclosure } from '../../components/details.jsx'
import { Notice } from '../../components/Notice.jsx'

export function SSHClientEnrollment({ domains, onEnroll }) {
  const [hostname, setHostname] = useState('')
  const [domainID, setDomainID] = useState('')
  const [publicKey, setPublicKey] = useState('')
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)

  useEffect(() => {
    if (!domains.some((domain) => domain.id === domainID)) setDomainID(domains[0]?.id || '')
  }, [domainID, domains])

  const enroll = async (event) => {
    event.preventDefault()
    if (busy) return
    setError('')
    if (!hostname.trim() || !domains.some((domain) => domain.id === domainID)) {
      setError(t('ssh.required_fields'))
      return
    }
    if (!isSupportedSshPublicKey(publicKey)) {
      setError(t('ssh.invalid_public_key'))
      return
    }
    setBusy(true)
    try {
      const client = await api('/api/admin/ssh-clients', {
        method: 'POST',
        body: JSON.stringify({
          hostname: hostname.trim(),
          domain_id: domainID,
          public_key: publicKey.trim(),
        }),
      })
      setResult(client)
      onEnroll(client)
      setHostname('')
      setPublicKey('')
      setModalOpen(false)
    } catch (err) {
      setError(err.status === 409 ? t('ssh.duplicate_client') : err.message)
    } finally {
      setBusy(false)
    }
  }

  const sshUsername = result?.hostname || '<client-hostname>'

  return (
    <Card className="ssh-enrollment">
      <div className="section-title">
        <div>
          <h2>{t('ssh.enrollment_title')}</h2>
          <p>{t('ssh.enrollment_description')}</p>
        </div>
        <Button
          disabled={domains.length === 0}
          onClick={() => {
            setError('')
            setModalOpen(true)
          }}
        >
          {t('ssh.add_client')}
        </Button>
      </div>
      {domains.length === 0 && (
        <Notice status="warning">
          {t('ui.no_domains_configured_create_one_before_manual_enrollment')}
        </Notice>
      )}
      {result && (
        <Notice status="success">
          {t('ssh.client_created', { name: result.hostname })}
          {result.ssh_fingerprint && (
            <div className="ssh-fingerprint">
              {t('ssh.fingerprint')}: <code>{result.ssh_fingerprint}</code>
            </div>
          )}
        </Notice>
      )}
      <p className="muted">{t('ssh.access_scope')}</p>
      <InfoDisclosure title={t('ssh.usage_title')} defaultExpanded>
        <div className="disclosure-body">
          <p className="muted">{t('ssh.usage_description')}</p>
          <pre className="command-block">
            <code>{`ssh -N -p 8888 -i <private-key> ${sshUsername}@<bridge-host>`}</code>
          </pre>
          <p className="muted">{t('ssh.forwarding_description')}</p>
          <pre className="command-block">
            <code>{`ssh -N -p 8888 -i <private-key> -L 127.0.0.1:8080:<vpn-client-ip>:80 ${sshUsername}@<bridge-host>`}</code>
          </pre>
          <p className="muted">{t('ssh.proxyjump_description')}</p>
          <pre className="command-block">
            <code>{`Host bruecke-jump
    HostName <bridge-host>
    Port 8888
    User ${sshUsername}
    IdentityFile <private-key>
    IdentitiesOnly yes`}</code>
          </pre>
          <pre className="command-block">
            <code>{'ssh -J bruecke-jump <target-user>@<vpn-client-ip>'}</code>
          </pre>
        </div>
      </InfoDisclosure>
      <Modal
        title={t('ssh.add_client')}
        open={modalOpen}
        onClose={() => {
          if (!busy) setModalOpen(false)
        }}
      >
        <form className="modal-form" onSubmit={enroll} aria-busy={busy}>
          {error && <Notice status="danger">{error}</Notice>}
          <label htmlFor="ssh-client-hostname">
            {t('ssh.hostname')}
            <Input
              id="ssh-client-hostname"
              value={hostname}
              onChange={(event) => setHostname(event.target.value)}
              placeholder={t('ui.pc1_example_com')}
              maxLength={253}
              pattern="[A-Za-z0-9.\-]+"
              required
              autoFocus
              disabled={busy}
            />
          </label>
          <SelectField
            label={t('ui.domain_spaced')}
            value={domainID}
            onChange={(value) => {
              if (!busy) setDomainID(value)
            }}
            required
            options={domains.map((domain) => ({ value: domain.id, label: domain.name }))}
          />
          <label htmlFor="ssh-client-public-key">
            {t('ssh.public_key')}
            <TextArea
              id="ssh-client-public-key"
              className="config-output"
              value={publicKey}
              onChange={(event) => setPublicKey(event.target.value)}
              placeholder="ssh-ed25519 AAAA…"
              rows={5}
              maxLength={16384}
              required
              disabled={busy}
              spellCheck={false}
              autoCapitalize="none"
              autoCorrect="off"
              aria-describedby="ssh-key-help"
            />
          </label>
          <p id="ssh-key-help" className="muted">
            {t('ssh.public_key_help')}
          </p>
          <p className="muted">{t('ssh.duplicate_notice')}</p>
          <div className="modal-actions">
            <Button
              type="button"
              className="ghost"
              disabled={busy}
              onClick={() => setModalOpen(false)}
            >
              {t('ui.cancel')}
            </Button>
            <Button disabled={busy || !hostname.trim() || !domainID || !publicKey.trim()}>
              {t(busy ? 'ssh.creating' : 'ssh.add_client')}
            </Button>
          </div>
        </form>
      </Modal>
    </Card>
  )
}
