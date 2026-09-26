import test from 'node:test'
import assert from 'node:assert/strict'
import { analyzeUrl } from '../services/urlAnalyzer.js'

const descriptions = (result) => result.signals.map(({ description }) => description).join(' ')

test('parses and normalizes a normal URL without treating HTTPS as proof of safety', async () => {
  const result = await analyzeUrl('https://www.google.com')
  assert.equal(result.success, true)
  assert.equal(result.url.registrableDomain, 'google.com')
  assert.equal(result.url.hostname, 'www.google.com')
  assert.equal(result.verdict.label, 'likely legitimate')
  assert.match(result.limitations.join(' '), /not necessarily safe/i)
})

test('detects brand typosquatting and brand names placed in subdomains', async () => {
  const typo = await analyzeUrl('https://paypa1-example.com')
  assert.match(descriptions(typo), /resembles PayPal/i)
  assert.equal(typo.verdict.label, 'suspicious')

  const nested = await analyzeUrl('https://paypal.com.security-example.com')
  assert.equal(nested.url.registrableDomain, 'security-example.com')
  assert.match(descriptions(nested), /PayPal in a subdomain/i)

  const transposed = await analyzeUrl('https://microsfot-example.com')
  assert.match(descriptions(transposed), /resembles Microsoft/i)
  const digitSwap = await analyzeUrl('https://micros0ft-example.com')
  assert.match(descriptions(digitSwap), /resembles Microsoft/i)
})

test('does not flag business domains that only contain a brand as part of a longer word', async () => {
  for (const host of ['appleseedbooks.com', 'mygoogleadsagency.com', 'amazonwarehouse-careers.com']) {
    const result = await analyzeUrl(`https://${host}`)
    assert.deepEqual(result.brandAnalysis.impersonationSignals, [], host)
  }
})

test('detects userinfo, IP hosts, HTTP and suspicious keywords as signals', async () => {
  const userinfo = await analyzeUrl('https://paypal.com@evil-example.com')
  assert.equal(userinfo.url.hostname, 'evil-example.com')
  assert.match(descriptions(userinfo), /actual destination is evil-example.com/i)

  const ip = await analyzeUrl('http://192.0.2.1/login')
  assert.equal(ip.technical.usesIpAddress, true)
  assert.match(descriptions(ip), /IP address/i)
  assert.match(descriptions(ip), /HTTP/i)

  const terms = await analyzeUrl('https://example.com/account/verify-login')
  assert.match(descriptions(terms), /verification and login|account access and verification/i)
})

test('detects punycode and URL shorteners without automatically calling them malicious', async () => {
  const idn = await analyzeUrl('https://xn--pple-43d.com')
  assert.equal(idn.technical.usesPunycode, true)
  assert.match(descriptions(idn), /encoded international characters/i)

  const shortener = await analyzeUrl('https://bit.ly/example')
  assert.match(descriptions(shortener), /URL shortener/i)
  assert.equal(shortener.verdict.label, 'suspicious')
})

test('extracts URL parts and recognizes supported legitimate brand hosts', async () => {
  const result = await analyzeUrl('https://secure.paypal.com.account-verification.example.co.uk:4444/login?next=%2Faccount&next=%2Fverify#form')
  assert.equal(result.url.registrableDomain, 'example.co.uk')
  assert.deepEqual(result.url.subdomains, ['secure', 'paypal', 'com', 'account-verification'])
  assert.equal(result.url.protocol, 'https')
  assert.equal(result.url.port, '4444')
  assert.equal(result.url.path, '/login')
  assert.deepEqual(result.url.query, [['next', '/account'], ['next', '/verify']])
  assert.equal(result.url.fragment, 'form')
  assert.match(descriptions(result), /unusual port/i)

  for (const url of ['https://www.microsoft.com', 'https://www.ubc.ca', 'https://www.apple.com']) {
    const ordinary = await analyzeUrl(url)
    assert.equal(ordinary.verdict.label, 'likely legitimate')
    assert.equal(ordinary.brandAnalysis.impersonationSignals.length, 0)
  }
})

test('rejects malformed, unsupported, and oversized URL input', async () => {
  for (const value of ['', 'not a url', 'javascript:alert(1)', `https://example.com/${'a'.repeat(2100)}`]) {
    await assert.rejects(() => analyzeUrl(value), Error)
  }
})
