import React, { useEffect, useState } from 'react'
import { api } from './api.js'
import { t, useLocale } from './i18n.jsx'
import { Shell } from './layout.jsx'
import { Login } from './Login.jsx'
import { Dashboard } from './Dashboard.jsx'

export function App() {
  useLocale()
  const [authenticated, setAuthenticated] = useState(false)
  const [checkingSession, setCheckingSession] = useState(true)

  useEffect(() => {
    let cancelled = false
    api('/api/admin/session')
      .then((session) => {
        if (!cancelled) setAuthenticated(session.authenticated)
      })
      .catch(() => {
        if (!cancelled) setAuthenticated(false)
      })
      .finally(() => {
        if (!cancelled) setCheckingSession(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  if (checkingSession)
    return (
      <Shell title={t('ui.bruecke')}>
        <p>{t('ui.checking_session')}</p>
      </Shell>
    )
  if (!authenticated) return <Login onLogin={() => setAuthenticated(true)} />
  return <Dashboard onLogout={() => setAuthenticated(false)} />
}
