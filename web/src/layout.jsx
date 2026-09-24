import React from 'react'
import { Modal as HeroModal } from '@heroui/react'
import { LanguageSwitcher, t } from './i18n'

export function Modal({ title, open, onClose, children }) {
  return (
    <HeroModal.Backdrop isOpen={open} onOpenChange={(isOpen) => { if (!isOpen) onClose() }}>
      <HeroModal.Container size="lg" scroll="inside" placement="center">
        <HeroModal.Dialog aria-label={title}>
          <HeroModal.CloseTrigger aria-label={t("ui.close")} />
          <HeroModal.Header><HeroModal.Heading>{title}</HeroModal.Heading></HeroModal.Header>
          <HeroModal.Body>{children}</HeroModal.Body>
        </HeroModal.Dialog>
      </HeroModal.Container>
    </HeroModal.Backdrop>
  )
}

export function Shell({ action, children }) {
  return (
    <div className="app-frame">
      <header className="app-header">
        <strong className="brand-name">bruecke</strong>
        <div className="header-action"><LanguageSwitcher />{action}</div>
      </header>
      <main className="shell">{children}</main>
    </div>
  )
}
