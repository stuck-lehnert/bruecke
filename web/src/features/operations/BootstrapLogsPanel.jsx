import React, { useEffect, useState } from 'react'
import { Button as HeroButton, Card } from '@heroui/react'
import { CLIENT_STATUS_INTERVAL_MS, api } from '../../api.js'
import { t, tr, formatDate, statusLabel } from '../../i18n.jsx'
import { clientLabel } from '../../helpers.js'
import { SelectField } from '../../select.jsx'
import { Button } from '../../components/forms.jsx'
import { DetailGrid, InfoDisclosure, Pill, PillList } from '../../components/details.jsx'
import { Notice } from '../../components/Notice.jsx'

export function BootstrapLogsPanel({ clients, filterClientID, onClearFilter, onError }) {
  const [runs, setRuns] = useState([])
  const [selectedRunID, setSelectedRunID] = useState('')
  const [detail, setDetail] = useState(null)
  const [loadingRuns, setLoadingRuns] = useState(false)
  const [logStatus, setLogStatus] = useState('all')

  const filterClient = clients.find((client) => client.id === filterClientID)
  const loadRuns = async () => {
    setLoadingRuns(true)
    try {
      const data = await api('/api/admin/bootstrap-logs/runs?limit=100')
      setRuns(data.runs || [])
    } catch (err) {
      onError(err.message)
    } finally {
      setLoadingRuns(false)
    }
  }

  useEffect(() => {
    let cancelled = false
    const refresh = async () => {
      try {
        const data = await api('/api/admin/bootstrap-logs/runs?limit=100')
        if (!cancelled) setRuns(data.runs || [])
      } catch (err) {
        if (!cancelled) onError(err.message)
      }
    }
    refresh()
    const interval = window.setInterval(refresh, CLIENT_STATUS_INTERVAL_MS)
    return () => {
      cancelled = true
      window.clearInterval(interval)
    }
  }, [onError])

  const clientRuns = filterClientID
    ? runs.filter(
        (run) =>
          run.client_id === filterClientID ||
          (filterClient?.hostname && run.hostname === filterClient.hostname),
      )
    : runs
  const visibleRuns =
    logStatus === 'all'
      ? clientRuns
      : clientRuns.filter((run) => (run.status || 'running') === logStatus)

  useEffect(() => {
    if (visibleRuns.length === 0) {
      setSelectedRunID('')
      setDetail(null)
      return
    }
    if (!selectedRunID || !visibleRuns.some((run) => run.run_id === selectedRunID)) {
      setSelectedRunID(visibleRuns[0].run_id)
    }
  }, [runs, filterClientID, logStatus])

  useEffect(() => {
    if (!selectedRunID) return undefined
    let cancelled = false
    let lastSeq = 0
    const loadRun = async () => {
      try {
        const suffix = lastSeq > 0 ? `?since_seq=${lastSeq}` : ''
        const data = await api(
          `/api/admin/bootstrap-logs/runs/${encodeURIComponent(selectedRunID)}${suffix}`,
        )
        if (cancelled) return
        setDetail((current) => {
          const previousEvents =
            lastSeq > 0 && current?.run?.run_id === selectedRunID ? current.events || [] : []
          const events = [...previousEvents, ...(data.events || [])]
          lastSeq = Math.max(lastSeq, data.run?.last_seq || 0)
          return { run: data.run, events }
        })
      } catch (err) {
        if (!cancelled) onError(err.message)
      }
    }
    setDetail(null)
    loadRun()
    const interval = window.setInterval(loadRun, CLIENT_STATUS_INTERVAL_MS)
    return () => {
      cancelled = true
      window.clearInterval(interval)
    }
  }, [selectedRunID, onError])

  return (
    <Card className="bootstrap-logs">
      <div className="section-title">
        <div>
          <h2>{t('ui.bootstrap_logs')}</h2>
        </div>
        <div className="row-actions">
          {filterClientID && (
            <Button className="ghost" onClick={onClearFilter}>
              {t('ui.show_all_runs')}
            </Button>
          )}
          <Button className="ghost" onClick={loadRuns}>
            {loadingRuns ? 'Refreshing...' : 'Refresh'}
          </Button>
          <SelectField
            className="compact-field"
            label={t('ui.bootstrap_status')}
            hideLabel
            value={logStatus}
            onChange={setLogStatus}
            options={[
              { value: 'all', label: t('ui.all_statuses') },
              { value: 'failed', label: t('ui.failed') },
              { value: 'running', label: t('ui.running') },
              { value: 'complete', label: t('ui.complete') },
            ]}
          />
        </div>
      </div>
      {filterClientID && (
        <Notice status="default">
          {t('ui.filtered_to_spaced')}
          {filterClient ? clientLabel(filterClient) : filterClientID}.
        </Notice>
      )}
      <div className="logs-layout">
        <div className="log-runs accordion-list">
          {visibleRuns.length === 0 && (
            <p className="empty">
              {tr(
                runs.length === 0
                  ? 'No bootstrap logs received yet.'
                  : 'No runs match these filters.',
              )}
            </p>
          )}
          {visibleRuns.map((run) => (
            <HeroButton
              variant={selectedRunID === run.run_id ? 'secondary' : 'ghost'}
              className="log-run"
              key={run.run_id}
              onPress={() => setSelectedRunID(run.run_id)}
            >
              <span className="item-summary">
                <span className="summary-main">
                  <strong className="log-run-title">{bootstrapRunTitle(run)}</strong>
                  <PillList>
                    <Pill
                      tone={
                        run.status === 'complete' ? 'ok' : run.status === 'failed' ? 'danger' : ''
                      }
                    >
                      {statusLabel(run.status || 'running')}
                    </Pill>
                    {run.client_id ? (
                      <Pill>{t('ui.registered')}</Pill>
                    ) : (
                      <Pill>{t('ui.pending')}</Pill>
                    )}
                  </PillList>
                </span>
                <span className="summary-actions compact-time">{formatLogTime(run.last_seen)}</span>
              </span>
            </HeroButton>
          ))}
        </div>
        <div className="log-detail">
          {!detail && selectedRunID && <p className="empty">{t('ui.loading_log_run')}</p>}
          {!selectedRunID && <p className="empty">{t('ui.select_a_log_run')}</p>}
          {detail && (
            <>
              <InfoDisclosure title={t('ui.run_metadata')} className="log-metadata">
                <DetailGrid compact>
                  <dt>{t('ui.run')}</dt>
                  <dd>{detail.run.run_id}</dd>
                  <dt>{t('ui.computer_hostname')}</dt>
                  <dd>
                    {detail.run.computer_name || 'unknown'} / {detail.run.hostname || 'unknown'}
                  </dd>
                  <dt>{t('ui.client_id')}</dt>
                  <dd>{detail.run.client_id || 'not registered'}</dd>
                  <dt>{t('ui.certificate')}</dt>
                  <dd>{detail.run.certificate_thumbprint || 'unknown'}</dd>
                  <dt>{t('ui.last_error')}</dt>
                  <dd>{detail.run.last_level === 'error' ? detail.run.last_message : 'none'}</dd>
                </DetailGrid>
              </InfoDisclosure>
              <div className="log-lines" role="log" aria-live="polite">
                {(detail.events || []).length === 0 && (
                  <p className="empty">{t('ui.no_events_for_this_run')}</p>
                )}
                {(detail.events || []).map((event) => (
                  <div className={`log-line ${event.level || 'info'}`} key={event.seq}>
                    <span>{formatLogTime(event.time)}</span>
                    <strong>{event.level || 'info'}</strong>
                    <em>{event.phase || 'bootstrap'}</em>
                    <code>{event.message}</code>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </Card>
  )
}

export function bootstrapRunTitle(run) {
  return run.hostname || run.computer_name || run.run_id
}

export function formatLogTime(value) {
  if (!value) return 'never'
  return formatDate(value)
}
