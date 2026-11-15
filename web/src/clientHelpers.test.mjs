import assert from 'node:assert/strict'
import test from 'node:test'
import {
  clientLabel,
  clientRemoteSubnets,
  filterClients,
  groupLabel,
  mergeRemoteSubnets,
  remoteAccessSummary,
  splitSubnetText,
  toggleID,
  upsertClient,
} from './helpers.js'
import en from './locales/en.js'
import de from './locales/de.js'

const clients = [
  {
    id: 'online',
    hostname: 'Alpha',
    domain_name: 'Example',
    ip: '10.0.0.2',
    ipv6: 'fd00::2',
    enabled: true,
    connected: true,
  },
  { id: 'offline', hostname: 'Beta', enabled: true, connected: false, type: 'ssh' },
  { id: 'disabled', hostname: 'Gamma', enabled: false, connected: true },
]

test('peer status filters distinguish enabled peers from disabled peers', () => {
  for (const [status, expected] of [
    ['all', clients],
    ['connected', [clients[0]]],
    ['offline', [clients[1]]],
    ['disabled', [clients[2]]],
  ]) {
    assert.deepEqual(filterClients(clients, '', status), expected)
  }
})

test('peer search trims input and matches host, domain, addresses and client type', () => {
  for (const query of [' ALPHA ', 'EXAMPLE', '10.0.0.2', 'FD00::2']) {
    assert.deepEqual(filterClients(clients, query, 'all'), [clients[0]])
  }
  assert.deepEqual(filterClients(clients, 'ssh', 'all'), [clients[1]])
  assert.deepEqual(filterClients(clients, 'wireguard', 'connected'), [clients[0]])
  assert.deepEqual(filterClients(clients, 'Alpha', 'offline'), [])
})

test('client labels and group labels preserve fallback values', () => {
  assert.equal(clientLabel(clients[0]), 'Alpha (Example)')
  assert.equal(clientLabel(clients[1]), 'Beta')
  assert.equal(clientLabel(undefined), 'unknown')
  assert.equal(groupLabel([{ id: 'team', name: 'Team' }], 'team'), 'Team')
  assert.equal(groupLabel([], 'missing'), 'missing')
})

test('remote subnet upserts replace by ID, sort by name and leave the original list untouched', () => {
  const current = [
    { id: 'z', name: 'Zulu' },
    { id: 'a', name: 'Alpha' },
  ]
  assert.deepEqual(mergeRemoteSubnets(current, { id: 'z', name: 'Beta' }), [
    { id: 'a', name: 'Alpha' },
    { id: 'z', name: 'Beta' },
  ])
  assert.equal(mergeRemoteSubnets(current, { id: 'b', name: 'Bravo' }).length, 3)
  assert.equal(current[0].name, 'Zulu')
})

test('client upserts replace or insert by ID and sort by display label', () => {
  const current = [clients[1]]
  assert.deepEqual(upsertClient(current, clients[0]), [clients[0], clients[1]])
  assert.deepEqual(upsertClient(current, { ...clients[1], hostname: 'Changed' }), [
    { ...clients[1], hostname: 'Changed' },
  ])
  assert.equal(current[0].hostname, 'Beta')
})

test('selection toggles are unique, sorted and do not mutate the supplied IDs', () => {
  const ids = ['b', 'a', 'a']
  assert.deepEqual(toggleID(ids, 'c'), ['a', 'b', 'c'])
  assert.deepEqual(toggleID(ids, 'a'), ['b'])
  assert.deepEqual(toggleID(undefined, 'a'), ['a'])
  assert.deepEqual(ids, ['b', 'a', 'a'])
})

test('remote access includes direct or group grants but never disabled subnets', () => {
  const subnets = [
    { id: 'direct', enabled: true, client_ids: ['online'] },
    { id: 'group', enabled: true, group_ids: ['team'] },
    { id: 'off', enabled: false, client_ids: ['online'], group_ids: ['team'] },
    { id: 'unassigned', enabled: true },
  ]
  assert.deepEqual(
    clientRemoteSubnets({ ...clients[0], group_ids: ['team'] }, subnets),
    subnets.slice(0, 2),
  )
  assert.deepEqual(clientRemoteSubnets(clients[1], subnets), [])
})

test('access summaries and CIDR parsing preserve established fallback text and ordering', () => {
  assert.equal(
    remoteAccessSummary(
      { group_ids: ['team'], client_ids: ['online', 'missing'] },
      [{ id: 'team', name: 'Team' }],
      clients,
    ),
    'Team, Alpha (Example), unknown',
  )
  assert.equal(remoteAccessSummary({}, [], []), 'none')
  assert.deepEqual(splitSubnetText(' 10.0.0.0/24,\n 2001:db8::/64\t'), [
    '10.0.0.0/24',
    '2001:db8::/64',
  ])
})

test('all shared catalog entries are nonempty and use the same interpolation parameters', () => {
  for (const [key, value] of Object.entries(de)) {
    assert.ok(Object.hasOwn(en, key), key)
    assert.ok(value.trim(), key)
    assert.deepEqual(
      (value.match(/\{\{\w+\}\}/g) || []).sort(),
      (en[key].match(/\{\{\w+\}\}/g) || []).sort(),
      key,
    )
  }
})
