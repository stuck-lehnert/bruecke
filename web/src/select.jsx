import React from 'react'
import { Label, ListBox, Select } from '@heroui/react'

const EMPTY = '__empty__'

export function SelectField({ label, value, onChange, options, required = false, hideLabel = false, className = '' }) {
  return (
    <Select className={className} fullWidth variant="secondary" isRequired={required} value={value === '' ? EMPTY : value ?? null} onChange={(next) => onChange(next === EMPTY || next == null ? '' : String(next))}>
      <Label className={hideLabel ? 'sr-only' : undefined}>{label}</Label>
      <Select.Trigger><Select.Value /><Select.Indicator /></Select.Trigger>
      <Select.Popover>
        <ListBox>
          {options.map((option) => (
            <ListBox.Item key={option.value} id={option.value === '' ? EMPTY : option.value} textValue={option.label}>
              <Label>{option.label}</Label>
            </ListBox.Item>
          ))}
        </ListBox>
      </Select.Popover>
    </Select>
  )
}
