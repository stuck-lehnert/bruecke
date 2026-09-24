import React, { createContext, useContext, useState } from 'react'
import en from './locales/en'
import de from './locales/de'
import { SelectField } from './select'

// Add a catalog and one entry here to support another language.
export const languages = [
  { code: 'en', label: 'English', messages: en },
  { code: 'de', label: 'Deutsch', messages: de },
]

const catalogs = Object.fromEntries(languages.map(({ code, messages }) => [code, messages]))
const englishKeys = new Map(Object.entries(en).map(([key, value]) => [value, key]))
const supportedLocale = (code) => languages.some((language) => language.code === code)
const browserLocale = () => {
  try {
    const saved = localStorage.getItem('bruecke-locale')
    if (supportedLocale(saved)) return saved
    const browser = navigator.language.split('-')[0].toLowerCase()
    return supportedLocale(browser) ? browser : 'en'
  } catch { return 'en' }
}

let activeLocale = browserLocale()

export function t(key, parameters = {}) {
  const template = catalogs[activeLocale]?.[key] ?? en[key] ?? key
  return template.replace(/\{\{(\w+)\}\}/g, (_, name) => String(parameters[name] ?? ''))
}

export function formatDate(value) {
  return new Date(value).toLocaleString(activeLocale === 'de' ? 'de-DE' : 'en-GB')
}

const statusKeys = {
  local: 'ui.status_local', non_local: 'ui.status_non_local', indeterminate: 'ui.status_indeterminate',
  activated: 'ui.status_activated', deactivated: 'ui.status_deactivated', no_op: 'ui.status_no_op',
  failed: 'ui.status_failed', complete: 'ui.status_complete', running: 'ui.status_running',
  matched: 'ui.status_matched', mismatch: 'ui.status_mismatch', up: 'ui.status_up', down: 'ui.status_down',
}

export function statusLabel(value) { return statusKeys[value] ? t(statusKeys[value]) : value }

// Handles values produced by existing UI code; new UI text should use t(key).
export function tr(value) {
  if (activeLocale === 'en' || typeof value !== 'string') return value
  const key = englishKeys.get(value)
  if (key) return t(key)
  const match = value.match(/^(\s*)(.*?)(\s*)$/s)
  const trimmedKey = englishKeys.get(match[2])
  if (trimmedKey) return match[1] + t(trimmedKey) + match[3]
  const count = match[2].match(/^of (\d+) computers$/)
  if (count) return t('ui.of_n_computers', { count: count[1] })
  const actions = match[2].match(/^Actions for (.+)$/)
  if (actions) return t('ui.actions_for', { name: actions[1] })
  const filter = match[2].match(/^Filter (.+)$/)
  if (filter) return t('ui.filter_name', { name: tr(filter[1]) })
  const grants = match[2].match(/^(\d+) grants?$/)
  if (grants) return t('ui.grants', { count: grants[1] })
  const edit = match[2].match(/^Edit (.+)$/)
  if (edit) return t('ui.edit_named', { name: edit[1] })
  const peerRemoval = match[2].match(/^Remove (.+) and its WireGuard key\? This cannot be undone\.$/)
  if (peerRemoval) return t('ui.remove_peer_confirmation', { name: peerRemoval[1] })
  const remoteRemoval = match[2].match(/^Delete (.+) and stop its site-to-site connection\?$/)
  if (remoteRemoval) return t('ui.remove_remote_confirmation', { name: remoteRemoval[1] })
  const groupRemoval = match[2].match(/^Delete (.+)\? Its clients remain enrolled\.$/)
  if (groupRemoval) return t('ui.remove_group_confirmation', { name: groupRemoval[1] })
  return value
}

const LocaleContext = createContext(null)

export function LocaleProvider({ children }) {
  const [locale, changeLocale] = useState(activeLocale)
  activeLocale = locale
  const setLocale = (next) => {
    if (!supportedLocale(next)) return
    activeLocale = next
    document.documentElement.lang = next
    try { localStorage.setItem('bruecke-locale', next) } catch { /* Storage may be unavailable. */ }
    changeLocale(next)
  }
  document.documentElement.lang = locale
  return <LocaleContext.Provider value={{ locale, setLocale }}>{children}</LocaleContext.Provider>
}

export function useLocale() { return useContext(LocaleContext) }

export function LanguageSwitcher() {
  const { locale, setLocale } = useLocale()
  return <SelectField className="language-switcher" label={t('ui.language')} hideLabel value={locale} onChange={setLocale} options={languages.map(({ code, label }) => ({ value: code, label }))} />
}
