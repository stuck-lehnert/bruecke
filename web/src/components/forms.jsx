import React from 'react'
import {
  Button as HeroButton,
  Input as HeroInput,
  TextArea as HeroTextArea,
  Checkbox,
  Label,
} from '@heroui/react'
import { tr } from '../i18n.jsx'

function buttonVariant(className) {
  if (className.includes('danger')) return 'danger'
  if (className.includes('nav-button')) {
    return className.includes('active') ? 'secondary' : 'ghost'
  }
  return className.includes('ghost') ? 'ghost' : 'primary'
}

export function Button({ className = '', onClick, type, disabled, children, ...props }) {
  return (
    <HeroButton
      {...props}
      className={className}
      variant={buttonVariant(className)}
      size={className.includes('compact-button') ? 'sm' : 'md'}
      type={type || (onClick ? 'button' : 'submit')}
      isDisabled={disabled}
      onPress={
        onClick
          ? (event) => onClick({ currentTarget: event.target, target: event.target })
          : undefined
      }
    >
      {typeof children === 'string' ? tr(children) : children}
    </HeroButton>
  )
}

export function Input(props) {
  return <HeroInput fullWidth variant="secondary" {...props} />
}

export function TextArea(props) {
  return <HeroTextArea fullWidth variant="secondary" {...props} />
}

export function CheckboxRow({ children, checked, disabled, onChange, compact = false }) {
  return (
    <Checkbox
      className={compact ? 'checkbox-row compact' : 'checkbox-row'}
      variant="secondary"
      isSelected={checked}
      isDisabled={disabled}
      onChange={onChange}
    >
      <Checkbox.Content>
        <Checkbox.Control>
          <Checkbox.Indicator />
        </Checkbox.Control>
        <Label>{children}</Label>
      </Checkbox.Content>
    </Checkbox>
  )
}
