import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import test from 'node:test'

import { isSupportedSshPublicKey } from './helpers.js'
import en from './locales/en.js'
import de from './locales/de.js'

function field(value) {
  const data = Buffer.from(value)
  const size = Buffer.alloc(4)
  size.writeUInt32BE(data.length)
  return Buffer.concat([size, data])
}

function keyLine(algorithm, ...fields) {
  return `${algorithm} ${Buffer.concat([field(algorithm), ...fields.map(field)]).toString('base64')}`
}

function positiveInteger(value) {
  const bytes = Buffer.from(value, 'base64url')
  return bytes[0] & 0x80 ? Buffer.concat([Buffer.from([0]), bytes]) : bytes
}

function generatedKey(type, options = {}) {
  const { publicKey } = generateKeyPairSync(type, options)
  const jwk = publicKey.export({ format: 'jwk' })
  if (type === 'ed25519') return keyLine('ssh-ed25519', Buffer.from(jwk.x, 'base64url'))
  if (type === 'rsa') return keyLine('ssh-rsa', positiveInteger(jwk.e), positiveInteger(jwk.n))
  const curve = { 'P-256': 'nistp256', 'P-384': 'nistp384', 'P-521': 'nistp521' }[jwk.crv]
  return keyLine(
    `ecdsa-sha2-${curve}`,
    curve,
    Buffer.concat([
      Buffer.from([4]),
      Buffer.from(jwk.x, 'base64url'),
      Buffer.from(jwk.y, 'base64url'),
    ]),
  )
}

const ed25519 = generatedKey('ed25519')

test('accepts generated Ed25519 public keys with optional comments and surrounding whitespace', () => {
  assert.equal(isSupportedSshPublicKey(ed25519), true)
  assert.equal(isSupportedSshPublicKey(`  ${ed25519} admin@example.com\n`), true)
  assert.equal(isSupportedSshPublicKey(ed25519.replace(' ', '\t')), true)
})

for (const namedCurve of ['P-256', 'P-384', 'P-521']) {
  test(`accepts a generated ECDSA ${namedCurve} public key`, () => {
    assert.equal(isSupportedSshPublicKey(generatedKey('ec', { namedCurve })), true)
  })
}

test('accepts a real generated RSA 2048 public key', () => {
  assert.equal(isSupportedSshPublicKey(generatedKey('rsa', { modulusLength: 2048 })), true)
})

// Wire-envelope fixtures avoid expensive generation of large RSA keys. The
// browser validates format/size; full cryptographic validation is server-side.
for (const bits of [2048, 3072, 4096, 8192, 1024, 2047, 8193, 9216]) {
  test(`validates the RSA ${bits}-bit modulus boundary`, () => {
    const modulus = Buffer.alloc(Math.ceil(bits / 8))
    modulus[0] = 1 << (bits - 1) % 8
    const positiveModulus = modulus[0] & 0x80 ? Buffer.concat([Buffer.from([0]), modulus]) : modulus
    const key = keyLine('ssh-rsa', Buffer.from([1, 0, 1]), positiveModulus)
    assert.equal(isSupportedSshPublicKey(key), bits >= 2048 && bits <= 8192)
  })
}

test('rejects private keys, key options, certificates, unsupported types and multiple keys', () => {
  for (const value of [
    '',
    '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----',
    `no-pty ${ed25519}`,
    `command="echo hello" ${ed25519}`,
    ed25519.replace('ssh-ed25519 ', 'ssh-ed25519-cert-v01@openssh.com '),
    keyLine('ssh-dss', Buffer.alloc(32)),
    `${ed25519}\n${ed25519}`,
  ])
    assert.equal(isSupportedSshPublicKey(value), false, value)
})

test('rejects malformed base64, binary envelopes, key lengths and mismatched algorithms', () => {
  for (const value of [
    'ssh-ed25519 !!!!',
    'ssh-ed25519 A',
    'ssh-ed25519 AAAA',
    'ssh-ed25519 /////w==',
    keyLine('ssh-ed25519', Buffer.alloc(31)),
    keyLine('ssh-ed25519', Buffer.alloc(33)),
    keyLine('ssh-ed25519', Buffer.alloc(32), Buffer.from('extra')),
    ed25519.replace('ssh-ed25519 ', 'ssh-rsa '),
    keyLine('ecdsa-sha2-nistp256', 'nistp384', Buffer.concat([Buffer.from([4]), Buffer.alloc(64)])),
    keyLine('ecdsa-sha2-nistp256', 'nistp256', Buffer.alloc(65)),
    keyLine('ecdsa-sha2-nistp256', 'nistp256', Buffer.concat([Buffer.from([4]), Buffer.alloc(63)])),
    keyLine('ssh-rsa', Buffer.alloc(0), Buffer.alloc(256, 255)),
    `${ed25519} ${'x'.repeat(16384)}`,
  ])
    assert.equal(isSupportedSshPublicKey(value), false, value.slice(0, 120))
})

test('SSH translation keys exist in both languages with matching parameters', () => {
  const catalogs = [en, de]
  const keys = Object.keys(catalogs[0]).filter((key) => key.startsWith('ssh.'))
  assert.deepEqual(
    Object.keys(catalogs[1])
      .filter((key) => key.startsWith('ssh.'))
      .sort(),
    keys.sort(),
  )
  for (const key of keys) {
    assert.ok(catalogs[0][key].trim())
    assert.ok(catalogs[1][key].trim())
    assert.deepEqual(
      catalogs[0][key].match(/\{\{\w+\}\}/g),
      catalogs[1][key].match(/\{\{\w+\}\}/g),
      key,
    )
  }
})
