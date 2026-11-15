import React from 'react'
import { Button as HeroButton, Dropdown, Label } from '@heroui/react'

export function ActionMenu({ label = 'Actions', items }) {
  return (
    <Dropdown>
      <HeroButton aria-label={label} variant="secondary" size="sm" isIconOnly>
        •••
      </HeroButton>
      <Dropdown.Popover placement="bottom end">
        <Dropdown.Menu
          aria-label={label}
          disabledKeys={items.flatMap((item, index) => (item.disabled ? [String(index)] : []))}
          onAction={(key) => items[Number(key)]?.onAction()}
        >
          {items.map((item, index) => (
            <Dropdown.Item
              key={index}
              id={String(index)}
              textValue={item.label}
              variant={item.danger ? 'danger' : 'default'}
            >
              <Label>{item.label}</Label>
            </Dropdown.Item>
          ))}
        </Dropdown.Menu>
      </Dropdown.Popover>
    </Dropdown>
  )
}
