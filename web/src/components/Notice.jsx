import React from 'react'
import { Alert } from '@heroui/react'

export function Notice({ status, children }) {
  return (
    <Alert className="notice" status={status} role={status === 'danger' ? 'alert' : 'status'}>
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Description>{children}</Alert.Description>
      </Alert.Content>
    </Alert>
  )
}
