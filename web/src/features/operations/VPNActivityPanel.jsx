import React, { useEffect, useState } from 'react'
import { Card, Chip, Surface } from '@heroui/react'
import { CLIENT_STATUS_INTERVAL_MS, api } from '../../api.js'
import { t, formatDate, statusLabel } from '../../i18n.jsx'
import { clientLabel } from '../../helpers.js'
import { SelectField } from '../../select.jsx'
import { Button } from '../../components/forms.jsx'
import { DetailGrid, InfoDisclosure } from '../../components/details.jsx'

export function VPNActivityPanel({ clients, filterClientID, onClearFilter, onError }) {
  const [events, setEvents] = useState([])
  const [nextCursor, setNextCursor] = useState('')
  const [clientID, setClientID] = useState(filterClientID || '')
  const [decision, setDecision] = useState('all')
  const [outcome, setOutcome] = useState('all')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setClientID(filterClientID || '')
  }, [filterClientID])

  const queryPath = (cursor = '') => {
    const params = new URLSearchParams({ limit: '200' })
    if (clientID) params.set('client_id', clientID)
    if (decision !== 'all') params.set('decision', decision)
    if (outcome !== 'all') params.set('outcome', outcome)
    if (cursor) params.set('cursor', cursor)
    return '/api/admin/vpn-events?' + params.toString()
  }

  const refresh = async () => {
    setLoading(true)
    try {
      const data = await api(queryPath())
      setEvents(data.events || [])
      setNextCursor(data.next_cursor || '')
    } catch (err) {
      onError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let cancelled = false
    const poll = async () => {
      try {
        const data = await api(queryPath())
        if (!cancelled) {
          setEvents(data.events || [])
          setNextCursor(data.next_cursor || '')
        }
      } catch (err) {
        if (!cancelled) onError(err.message)
      }
    }
    poll()
    const interval = window.setInterval(poll, CLIENT_STATUS_INTERVAL_MS)
    return () => {
      cancelled = true
      window.clearInterval(interval)
    }
  }, [clientID, decision, outcome, onError])

  const loadOlder = async () => {
    if (!nextCursor) return
    setLoading(true)
    try {
      const data = await api(queryPath(nextCursor))
      setEvents((current) => [...current, ...(data.events || [])])
      setNextCursor(data.next_cursor || '')
    } catch (err) {
      onError(err.message)
    } finally {
      setLoading(false)
    }
  }

  const displayValues = (values = {}) => {
    const parts = []
    if (values.kind) parts.push('type ' + values.kind)
    if (values.ssids?.length) parts.push('SSID ' + values.ssids.join(', '))
    if (values.gateways?.length) parts.push('gateway ' + values.gateways.join(', '))
    if (values.address_cidrs?.length) parts.push('address ' + values.address_cidrs.join(', '))
    if (values.dns_suffixes?.length) parts.push('DNS ' + values.dns_suffixes.join(', '))
    return parts.join(' · ') || 'none observed'
  }

  const scopedClient = clients.find((client) => client.id === clientID)
  return (
    <Card className="vpn-activity">
      <div className="section-title">
        <div>
          <h2>{t('ui.vpn_activity')}</h2>
        </div>
        <Button className="ghost" disabled={loading} onClick={refresh}>
          {loading ? 'Refreshing...' : 'Refresh'}
        </Button>
      </div>
      {scopedClient && (
        <Surface className="filter-banner" variant="secondary">
          <span>
            {t('ui.showing_spaced')}
            {clientLabel(scopedClient)}
          </span>
          <Button
            className="ghost compact-button"
            onClick={() => {
              setClientID('')
              onClearFilter()
            }}
          >
            {t('ui.show_all')}
          </Button>
        </Surface>
      )}
      <div className="toolbar-controls vpn-activity-filters">
        <SelectField
          className="compact-field"
          label={t('ui.computer')}
          value={clientID}
          onChange={(next) => {
            setClientID(next)
            if (!next) onClearFilter()
          }}
          options={[
            { value: '', label: t('ui.all_computers') },
            ...clients.map((client) => ({ value: client.id, label: clientLabel(client) })),
          ]}
        />
        <SelectField
          className="compact-field"
          label={t('ui.decision')}
          value={decision}
          onChange={setDecision}
          options={[
            { value: 'all', label: t('ui.all_decisions') },
            { value: 'local', label: t('ui.local_vpn_off') },
            { value: 'non_local', label: t('ui.non_local_vpn_on') },
            { value: 'indeterminate', label: t('ui.indeterminate_vpn_on') },
          ]}
        />
        <SelectField
          className="compact-field"
          label={t('ui.outcome')}
          value={outcome}
          onChange={setOutcome}
          options={[
            { value: 'all', label: t('ui.all_outcomes') },
            { value: 'activated', label: t('ui.activated') },
            { value: 'deactivated', label: t('ui.deactivated') },
            { value: 'no_op', label: t('ui.no_change') },
            { value: 'failed', label: t('ui.failed') },
          ]}
        />
      </div>
      <div className="vpn-event-list">
        {!loading && events.length === 0 && (
          <p className="empty">{t('ui.no_vpn_activity_matches_these_filters')}</p>
        )}
        {events.map((event) => (
          <InfoDisclosure
            key={event.event_id}
            title={event.hostname || event.computer_name || event.client_id}
            meta={
              <>
                <span className="vpn-event-time">{formatDate(event.occurred_at)}</span>
                <Chip
                  color={event.decision === 'local' ? 'success' : 'default'}
                  variant="soft"
                  size="sm"
                >
                  {statusLabel(event.decision)}
                </Chip>
                <Chip
                  color={event.outcome === 'failed' ? 'danger' : 'default'}
                  variant="soft"
                  size="sm"
                >
                  {statusLabel(event.outcome)}
                </Chip>
              </>
            }
          >
            <div className="vpn-event-detail">
              <DetailGrid compact>
                <dt>{t('ui.policy')}</dt>
                <dd>
                  {event.decision === 'local'
                    ? t('ui.local_vpn_off')
                    : `${statusLabel(event.decision)} → VPN on`}
                </dd>
                <dt>{t('ui.tunnel_state')}</dt>
                <dd>
                  {statusLabel(event.state_before)} → {statusLabel(event.state_after)}
                </dd>
                <dt>{t('ui.trigger_actuator')}</dt>
                <dd>
                  {event.trigger_source || 'unknown'} / {event.actuator_version || 'unknown'}
                </dd>
                <dt>{t('ui.reason')}</dt>
                <dd>{event.reason || 'none supplied'}</dd>
              </DetailGrid>
              <div className="vpn-evaluations">
                {(event.evaluations || []).length === 0 && (
                  <p className="muted">{t('ui.no_adapter_profile_evidence_was_available')}</p>
                )}
                {(event.evaluations || []).map((evaluation, index) => (
                  <InfoDisclosure
                    key={event.event_id + '-' + index}
                    title={`${t('ui.profile_spaced')}${evaluation.profile_index} (${evaluation.profile_type}${t('ui.on_spaced')}${evaluation.adapter_alias || 'unknown adapter'})`}
                    meta={statusLabel(
                      evaluation.matched
                        ? 'matched'
                        : evaluation.unavailable?.length
                          ? 'indeterminate'
                          : 'mismatch',
                    )}
                  >
                    <DetailGrid compact>
                      <dt>{t('ui.expected')}</dt>
                      <dd>{displayValues(evaluation.expected)}</dd>
                      <dt>{t('ui.actual')}</dt>
                      <dd>{displayValues(evaluation.actual)}</dd>
                      <dt>{t('ui.mismatches')}</dt>
                      <dd>
                        {evaluation.mismatches?.length ? evaluation.mismatches.join('; ') : 'none'}
                      </dd>
                      <dt>{t('ui.unavailable')}</dt>
                      <dd>
                        {evaluation.unavailable?.length
                          ? evaluation.unavailable.join('; ')
                          : 'none'}
                      </dd>
                    </DetailGrid>
                  </InfoDisclosure>
                ))}
              </div>
            </div>
          </InfoDisclosure>
        ))}
      </div>
      {nextCursor && (
        <Button className="ghost load-older" disabled={loading} onClick={loadOlder}>
          {t('ui.load_older')}
        </Button>
      )}
    </Card>
  )
}
