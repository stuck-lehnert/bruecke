import React from 'react'
import { TABS } from '../api.js'
import { t, tr } from '../i18n.jsx'
import { SelectField } from '../select.jsx'
import { Button } from './forms.jsx'

export function AdminNavigation({ activeTab, onChange }) {
  return (
    <nav className="admin-navigation" aria-label={t('ui.admin_sections')}>
      <div className="desktop-navigation">
        {TABS.map((tab) => (
          <Button
            key={tab.id}
            className={activeTab === tab.id ? 'nav-button active' : 'nav-button'}
            aria-current={activeTab === tab.id ? 'page' : undefined}
            onClick={() => onChange(tab.id)}
          >
            {tr(tab.label)}
          </Button>
        ))}
      </div>
      <div className="mobile-navigation">
        <SelectField
          label={t('ui.section')}
          value={activeTab}
          onChange={onChange}
          options={TABS.map((tab) => ({
            value: tab.id,
            label: `${tr(tab.section)} · ${tr(tab.label)}`,
          }))}
        />
      </div>
    </nav>
  )
}
