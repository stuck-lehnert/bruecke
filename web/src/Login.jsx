import React, { useState } from 'react'
import { Card } from '@heroui/react'
import { api } from './api.js'
import { t } from './i18n.jsx'
import { Shell } from './layout.jsx'
import { Button, Input } from './components/forms.jsx'
import { Notice } from './components/Notice.jsx'

export function Login({ onLogin }) {
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      await api('/api/admin/login', {
        method: 'POST',
        body: JSON.stringify({ password }),
      })
      onLogin()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Shell title={t('ui.bruecke_admin')}>
      <Card className="login">
        <form className="login-form" onSubmit={submit}>
          <label htmlFor="password">{t('ui.admin_password')}</label>
          <Input
            id="password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoFocus
            required
          />
          {error && <Notice status="danger">{error}</Notice>}
          <Button disabled={busy}>{busy ? 'Signing in...' : 'Sign in'}</Button>
        </form>
      </Card>
    </Shell>
  )
}
