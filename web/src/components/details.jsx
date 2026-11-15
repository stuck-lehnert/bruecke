import React, { useState } from 'react'
import { Chip, Disclosure } from '@heroui/react'
import { tr } from '../i18n.jsx'

export function ExpandableRow({ title, meta, actions, expanded, onExpandedChange, children }) {
  return (
    <Disclosure
      className="expandable-row"
      isExpanded={expanded}
      onExpandedChange={onExpandedChange}
    >
      <div className="expandable-header">
        <Disclosure.Heading className="expandable-heading">
          <Disclosure.Trigger className="expandable-trigger">
            <span className="expandable-label">
              <strong>{title}</strong>
              {meta && <span className="expandable-meta">{meta}</span>}
            </span>
            <Disclosure.Indicator />
          </Disclosure.Trigger>
        </Disclosure.Heading>
        {actions && <div className="expandable-actions">{actions}</div>}
      </div>
      <Disclosure.Content className="expandable-content">{children}</Disclosure.Content>
    </Disclosure>
  )
}

export function InfoDisclosure({ title, meta, children, defaultExpanded = false, className = '' }) {
  const [expanded, setExpanded] = useState(defaultExpanded)
  return (
    <Disclosure
      className={`info-disclosure ${className}`}
      isExpanded={expanded}
      onExpandedChange={setExpanded}
    >
      <Disclosure.Heading>
        <Disclosure.Trigger className="info-trigger">
          <span>{title}</span>
          {meta && <span className="info-meta">{meta}</span>}
          <Disclosure.Indicator />
        </Disclosure.Trigger>
      </Disclosure.Heading>
      <Disclosure.Content className="info-content">{children}</Disclosure.Content>
    </Disclosure>
  )
}

export function DetailGrid({ children, compact = false }) {
  return <dl className={compact ? 'detail-grid compact-grid' : 'detail-grid'}>{children}</dl>
}

export function PillList({ children }) {
  return <span className="pill-list">{children}</span>
}

export function Pill({ children, tone = '' }) {
  return (
    <Chip
      color={tone === 'ok' ? 'success' : tone === 'danger' ? 'danger' : 'default'}
      variant="soft"
      size="sm"
    >
      {typeof children === 'string' ? tr(children) : children}
    </Chip>
  )
}
