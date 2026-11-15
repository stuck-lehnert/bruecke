import React from 'react'
import { t, tr } from '../../i18n.jsx'
import { SelectField } from '../../select.jsx'
import { Button, CheckboxRow, Input, TextArea } from '../../components/forms.jsx'
import { InfoDisclosure } from '../../components/details.jsx'
import { newLocalNetwork } from './domainHelpers.js'

export function DomainForm({ draft, busy, submitLabel, busyLabel, onChange, onCancel, onSubmit }) {
  const networks = Array.isArray(draft.local_networks) ? draft.local_networks : []
  const setNetworks = (next) => onChange('local_networks', next)
  const updateNetwork = (index, field, value) => {
    const next = networks.map((network) => ({ ...network }))
    const updated = { ...next[index], [field]: value }
    if (field === 'type' && value === 'ethernet') {
      updated.ssid = ''
    }
    next[index] = updated
    setNetworks(next)
  }
  const addNetwork = (type) => setNetworks([...networks, newLocalNetwork(type)])
  const removeNetwork = (index) => setNetworks(networks.filter((_, current) => current !== index))
  const moveNetwork = (index, direction) => {
    const target = index + direction
    if (target < 0 || target >= networks.length) return
    const next = networks.map((network) => ({ ...network }))
    ;[next[index], next[target]] = [next[target], next[index]]
    setNetworks(next)
  }

  return (
    <form className="modal-form" onSubmit={onSubmit}>
      <fieldset className="form-section">
        <legend>{t('ui.general')}</legend>
        <label>
          {t('ui.name_spaced')}
          <Input
            value={draft.name}
            onChange={(event) => onChange('name', event.target.value)}
            required
            autoFocus
          />
        </label>
        <div className="form-row two">
          <label>
            {t('ui.dns_servers_spaced')}
            <Input
              value={draft.dns_servers}
              onChange={(event) => onChange('dns_servers', event.target.value)}
              placeholder="9.9.9.9, 1.1.1.1"
            />
          </label>
          <label>
            {t('ui.search_domain_spaced')}
            <Input
              value={draft.search_domain}
              onChange={(event) => onChange('search_domain', event.target.value)}
              placeholder={t('ui.corp_example_com')}
            />
          </label>
        </div>
      </fieldset>
      <InfoDisclosure
        title={t('ui.local_network_auto_disable')}
        meta={tr(
          networks.length === 0
            ? 'Not configured'
            : `${networks.length} ${networks.length === 1 ? 'profile' : 'profiles'}`,
        )}
        defaultExpanded
      >
        <div className="disclosure-body">
          <p className="muted">
            {t('ui.add_any_number_of_wi_fi_and_ethernet_profiles_a_match_on_a')}
          </p>
          {networks.length === 0 && (
            <p className="empty compact-empty">
              {t('ui.no_local_networks_configured_the_wireguard_tunnel_remains_spaced')}
            </p>
          )}
          <div className="local-network-editor-list">
            {networks.map((network, index) => (
              <fieldset className="local-network-editor" key={`${network.type}-${index}`}>
                <legend>
                  {network.name ||
                    `${network.type === 'wifi' ? 'Wi-Fi' : 'Ethernet'} profile ${index + 1}`}
                </legend>
                <div className="local-network-editor-header">
                  <div>
                    <strong>
                      {t('ui.profile_spaced')}
                      {index + 1}
                    </strong>
                    <span>
                      {
                        [
                          network.ssid,
                          network.gateway,
                          network.subnet,
                          network.search_domain,
                        ].filter(Boolean).length
                      }
                      {t('ui.matching_fields_spaced')}
                    </span>
                  </div>
                  <div className="row-actions">
                    <Button
                      type="button"
                      className="ghost compact-button"
                      disabled={index === 0}
                      aria-label={`Move profile ${index + 1} up`}
                      onClick={() => moveNetwork(index, -1)}
                    >
                      ↑
                    </Button>
                    <Button
                      type="button"
                      className="ghost compact-button"
                      disabled={index === networks.length - 1}
                      aria-label={`Move profile ${index + 1} down`}
                      onClick={() => moveNetwork(index, 1)}
                    >
                      ↓
                    </Button>
                    <Button
                      type="button"
                      className="danger compact-button"
                      onClick={() => removeNetwork(index)}
                    >
                      {t('ui.remove')}
                    </Button>
                  </div>
                </div>
                <div className="form-row two">
                  <SelectField
                    label={t('ui.type_spaced')}
                    value={network.type || 'ethernet'}
                    onChange={(next) => updateNetwork(index, 'type', next)}
                    options={[
                      { value: 'wifi', label: t('ui.wi_fi') },
                      { value: 'ethernet', label: t('ui.ethernet') },
                    ]}
                  />
                  <label>
                    {t('ui.profile_label_spaced')}
                    <Input
                      value={network.name || ''}
                      onChange={(event) => updateNetwork(index, 'name', event.target.value)}
                      placeholder={t('ui.headquarters')}
                    />
                  </label>
                  {network.type === 'wifi' && (
                    <label>
                      {t('ui.ssid_spaced')}
                      <Input
                        value={network.ssid || ''}
                        onChange={(event) => updateNetwork(index, 'ssid', event.target.value)}
                        placeholder={t('ui.corp_wi_fi')}
                        required={!network.gateway && !network.subnet && !network.search_domain}
                      />
                    </label>
                  )}
                  <label>
                    {t('ui.gateway_spaced')}
                    <Input
                      value={network.gateway || ''}
                      onChange={(event) => updateNetwork(index, 'gateway', event.target.value)}
                      placeholder="192.168.10.1"
                      required={
                        network.type === 'ethernet' && !network.subnet && !network.search_domain
                      }
                    />
                  </label>
                  <label>
                    {t('ui.ipv4_subnet_spaced')}
                    <Input
                      value={network.subnet || ''}
                      onChange={(event) => updateNetwork(index, 'subnet', event.target.value)}
                      placeholder="192.168.10.0/24"
                    />
                  </label>
                  <label>
                    {t('ui.dns_suffix_spaced')}
                    <Input
                      value={network.search_domain || ''}
                      onChange={(event) =>
                        updateNetwork(index, 'search_domain', event.target.value)
                      }
                      placeholder={t('ui.corp_example_com')}
                    />
                  </label>
                </div>
                <p className="muted profile-rule-note">
                  {t('ui.configure_at_least_one_matching_field_multiple_fields_are')}
                </p>
              </fieldset>
            ))}
          </div>
          <div className="row-actions local-network-add-actions">
            <Button type="button" className="ghost" onClick={() => addNetwork('wifi')}>
              {t('ui.add_wi_fi_profile')}
            </Button>
            <Button type="button" className="ghost" onClick={() => addNetwork('ethernet')}>
              {t('ui.add_ethernet_profile')}
            </Button>
          </div>
        </div>
      </InfoDisclosure>
      <InfoDisclosure
        title={t('ui.certificate_enrollment')}
        meta={tr(draft.auto_enroll_enabled ? 'Enabled when CA is present' : 'Disabled')}
        defaultExpanded={submitLabel === 'Create domain'}
      >
        <div className="disclosure-body">
          <p className="muted">
            {t('ui.upload_only_the_public_ad_cs_ca_certificate_leave_this_bla')}
          </p>
          <label>
            {t('ui.ca_public_certificate_spaced')}
            <TextArea
              value={draft.pem}
              onChange={(event) => onChange('pem', event.target.value)}
              placeholder={t('ui.begin_certificate')}
              rows={6}
            />
          </label>
          <CheckboxRow
            compact
            checked={draft.auto_enroll_enabled}
            onChange={(selected) => onChange('auto_enroll_enabled', selected)}
          >
            {t('ui.enable_certificate_auto_enrollment_when_a_ca_is_present')}
          </CheckboxRow>
        </div>
      </InfoDisclosure>
      <div className="modal-actions">
        <Button type="button" className="ghost" onClick={onCancel}>
          {t('ui.cancel')}
        </Button>
        <Button disabled={busy}>{busy ? busyLabel : submitLabel}</Button>
      </div>
    </form>
  )
}
