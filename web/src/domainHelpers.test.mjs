import assert from 'node:assert/strict'
import test from 'node:test'
import {
  createEmptyDraft,
  dnsList,
  domainDraft,
  domainLocalNetworks,
  localNetworkSummary,
  newLocalNetwork,
} from './features/domains/domainHelpers.js'

test('new domain drafts have independent editable network lists', () => {
  const first = createEmptyDraft()
  const second = createEmptyDraft()
  first.local_networks.push(newLocalNetwork('wifi'))

  assert.deepEqual(second.local_networks, [])
  assert.equal(second.auto_enroll_enabled, true)
  assert.equal(second.pem, '')
})

test('modern network profiles preserve order and default missing fields without mutation', () => {
  const profiles = [{ type: 'wifi', ssid: 'Office' }, { gateway: '192.168.1.1' }]
  const result = domainLocalNetworks({ local_networks: profiles })

  assert.deepEqual(result, [
    { ...newLocalNetwork('wifi'), ssid: 'Office' },
    { ...newLocalNetwork('ethernet'), gateway: '192.168.1.1' },
  ])
  result[0].ssid = 'Changed'
  assert.equal(profiles[0].ssid, 'Office')
})

test('legacy Wi-Fi and Ethernet criteria become separate network profiles', () => {
  assert.deepEqual(
    domainLocalNetworks({
      local_network: {
        wifi_name: 'Office',
        wifi_gateway: '10.0.0.1',
        wifi_search_domain: 'corp.example',
        eth_subnet: '10.1.0.0/24',
      },
    }),
    [
      {
        ...newLocalNetwork('wifi'),
        ssid: 'Office',
        gateway: '10.0.0.1',
        search_domain: 'corp.example',
      },
      { ...newLocalNetwork('ethernet'), subnet: '10.1.0.0/24' },
    ],
  )
  assert.deepEqual(domainLocalNetworks({ local_network: {} }), [])
})

test('an explicitly empty modern network list takes precedence over legacy settings', () => {
  assert.deepEqual(
    domainLocalNetworks({ local_networks: [], local_network: { wifi_name: 'Old' } }),
    [],
  )
})

test('editing a domain never prepopulates or replaces its existing CA certificate', () => {
  const domain = {
    name: 'Example',
    dns_servers: ['9.9.9.9', '1.1.1.1'],
    search_domain: 'corp.example',
    certificate: { subject: 'Existing CA' },
    auto_enroll_enabled: false,
  }
  assert.deepEqual(domainDraft(domain), {
    name: 'Example',
    dns_servers: '9.9.9.9, 1.1.1.1',
    search_domain: 'corp.example',
    pem: '',
    auto_enroll_enabled: false,
    local_networks: [],
  })
})

test('DNS input accepts commas and whitespace and preserves address order', () => {
  assert.deepEqual(dnsList(' 9.9.9.9,\n 2001:db8::1\t1.1.1.1, '), [
    '9.9.9.9',
    '2001:db8::1',
    '1.1.1.1',
  ])
  assert.deepEqual(dnsList(undefined), [])
})

test('network summaries include only configured matching criteria', () => {
  assert.equal(
    localNetworkSummary({
      type: 'wifi',
      ssid: 'Office',
      gateway: '10.0.0.1',
      subnet: '10.0.0.0/24',
      search_domain: 'corp.example',
    }),
    'SSID Office, gateway 10.0.0.1, subnet 10.0.0.0/24, search corp.example',
  )
  assert.equal(localNetworkSummary({ type: 'ethernet', ssid: 'Ignored' }), '')
})
