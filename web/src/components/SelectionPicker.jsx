import React, { useState } from 'react'
import { t, tr } from '../i18n.jsx'
import { toggleID } from '../helpers.js'
import { CheckboxRow, Input } from './forms.jsx'
import { InfoDisclosure } from './details.jsx'

export function SelectionPicker({ label, options, selectedIDs, onChange }) {
  const [query, setQuery] = useState('')
  const normalizedQuery = query.trim().toLowerCase()
  const visibleOptions = options.filter(
    (option) => !normalizedQuery || option.label.toLowerCase().includes(normalizedQuery),
  )
  return (
    <InfoDisclosure title={tr(label)} meta={`${selectedIDs.length}${t('ui.selected_spaced')}`}>
      <div className="selection-picker-body">
        {options.length > 6 && (
          <Input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={tr(`Filter ${label.toLowerCase()}`)}
          />
        )}
        <div className="selection-options">
          {visibleOptions.length === 0 && <p className="muted">{t('ui.no_matching_options')}</p>}
          {visibleOptions.map((option) => (
            <CheckboxRow
              compact
              key={option.id}
              checked={selectedIDs.includes(option.id)}
              onChange={() => onChange(toggleID(selectedIDs, option.id))}
            >
              {option.label}
            </CheckboxRow>
          ))}
        </div>
      </div>
    </InfoDisclosure>
  )
}
