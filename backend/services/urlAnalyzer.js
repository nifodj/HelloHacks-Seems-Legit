import { domainToASCII, domainToUnicode } from 'node:url'
import { isIP } from 'node:net'
import { resolve4, resolve6, resolveCname, resolveMx, resolveNs } from 'node:dns/promises'
import { getDomain } from 'tldts'
import { MAX_URL_LENGTH, BRANDS, RISK_WEIGHTS, URL_SHORTENERS } from '../config/urlAnalysis.js'
import { checkThreatIntelligence } from './threatIntel/index.js'
import { editDistance } from '../utils/domainSimilarity.js'

const keywords = ['login', 'signin', 'verify', 'verification', 'secure', 'account', 'password', 'update', 'confirm', 'payment', 'invoice', 'refund', 'wallet', 'gift', 'claim', 'authentication', 'unlock', 'suspended']
const scamPatterns = [
  { category: 'account_verification', pattern: /(?:secure|account|login|signin).{0,24}(?:verify|verification|confirm|password)|(?:verify|verification|confirm).{0,24}(?:account|login|signin)/i, description: 'The URL combines account access and verification terms commonly used on fake sign-in pages.' },
  { category: 'delivery_fee', pattern: /(?:delivery|package|parcel|shipping).{0,24}(?:fee|payment|confirm|claim)/i, description: 'The URL resembles a delivery-fee or package confirmation pattern.' },
  { category: 'payment_request', pattern: /(?:invoice|payment|refund).{0,24}(?:confirm|claim|update|secure)/i, description: 'The URL combines payment-related terms in a pattern often used to prompt account or payment details.' },
  { category: 'crypto_wallet', pattern: /(?:crypto|wallet|seed.?phrase).{0,24}(?:verify|secure|unlock|claim)/i, description: 'The URL resembles a cryptocurrency wallet verification or unlock pattern.' },
]

function registrableDomain(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, '')
  if (isIP(host) || host === 'localhost' || !host.includes('.')) return host
  return getDomain(host, { allowPrivateDomains: false }) || host
}

function confusableSkeleton(value) {
  const substitutions = new Map(Object.entries({
    'а': 'a', 'α': 'a', 'е': 'e', 'ε': 'e', 'о': 'o', 'ο': 'o', 'р': 'p', 'ρ': 'p',
    'с': 'c', 'ϲ': 'c', 'х': 'x', 'χ': 'x', 'і': 'i', 'ι': 'i', 'ј': 'j', 'ӏ': 'l',
    'у': 'y', 'ѕ': 's', 'м': 'm', 'т': 't', 'к': 'k', 'в': 'b', 'н': 'h',
  }))
  return [...value.toLowerCase()].map((char) => substitutions.get(char) || char).join('').replace(/[^a-z0-9]/g, '')
}

function ipv4Private(ip) {
  const octets = ip.split('.').map(Number)
  return octets[0] === 10 || octets[0] === 127 || octets[0] === 0 || (octets[0] === 169 && octets[1] === 254)
    || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) || (octets[0] === 192 && octets[1] === 168)
    || (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127)
}

function isPrivateAddress(ip) {
  if (isIP(ip) === 4) return ipv4Private(ip)
  if (isIP(ip) === 6) {
    const lower = ip.toLowerCase()
    if (lower.startsWith('::ffff:')) {
      const parts = lower.slice(7).split(':')
      if (parts.length === 2) {
        const first = Number.parseInt(parts[0], 16)
        const second = Number.parseInt(parts[1], 16)
        if (Number.isFinite(first) && Number.isFinite(second)) return ipv4Private([first >> 8, first & 255, second >> 8, second & 255].join('.'))
      }
    }
    return ip === '::1' || ip === '::' || lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80:')
  }
  return false
}

function signal(type, severity, description, weightKey) {
  return { type, severity, description, weight: RISK_WEIGHTS[weightKey] || 0 }
}

function normalizeInput(input) {
  let value = input.trim()
  if (!value || value.length > MAX_URL_LENGTH) throw new Error(`URL must be between 1 and ${MAX_URL_LENGTH} characters.`)
  if (/[\s<>"'\\]/.test(value)) throw new Error('Enter a single URL without spaces or quote characters.')
  if (!/^[a-z][a-z\d+.-]*:\/\//i.test(value)) value = `https://${value}`
  let parsed
  try { parsed = new URL(value) } catch { throw new Error('Enter a valid URL.') }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Only http and https URLs are supported.')
  if (!parsed.hostname) throw new Error('The URL must include a hostname.')
  const asciiHost = domainToASCII(parsed.hostname)
  if (!asciiHost) throw new Error('The URL hostname is invalid.')
  parsed.hostname = asciiHost
  return parsed
}

async function getDns(host) {
  if (!process.env.URL_DNS_LOOKUP || process.env.URL_DNS_LOOKUP !== 'true' || isIP(host) || host === 'localhost' || !host.includes('.')) return { available: false, reason: 'disabled' }
  try {
    const timeout = (promise) => new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('DNS_TIMEOUT')), 1200)
      promise.then(resolve, reject).finally(() => clearTimeout(timer))
    })
    const queries = await Promise.all([resolve4(host), resolve6(host), resolveCname(host), resolveMx(host), resolveNs(host)].map(async (promise) => {
      try { return await timeout(promise) } catch { return [] }
    }))
    const [a, aaaa, cname, mx, nameservers] = queries
    return { available: a.length + aaaa.length + cname.length + mx.length + nameservers.length > 0, a, aaaa, cname, mx, nameservers }
  } catch (error) {
    return { available: false, reason: error.code || 'lookup_failed' }
  }
}

async function getDomainRegistration(domain) {
  if (process.env.URL_RDAP_LOOKUP !== 'true') return { available: false, reason: 'disabled' }
  if (isIP(domain) || domain === 'localhost' || !domain.includes('.')) return { available: false }
  try {
    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { signal: AbortSignal.timeout(3000), headers: { accept: 'application/rdap+json' } })
    if (!response.ok) return { available: false }
    const data = await response.json()
    const event = (data.events || []).find((item) => item.eventAction === 'registration')
    const createdAt = event?.eventDate || null
    const ageDays = createdAt ? Math.max(0, Math.floor((Date.now() - Date.parse(createdAt)) / 86400000)) : null
    return { available: true, createdAt, expiresAt: (data.events || []).find((item) => item.eventAction === 'expiration')?.eventDate || null, registrar: data.entities?.find((entity) => entity.roles?.includes('registrar'))?.vcardArray?.[1]?.find((item) => item[0] === 'fn')?.[3] || null, status: data.status || [], ageDays }
  } catch { return { available: false } }
}

function analyzeLocal(url, host, root, technical) {
  const signals = []
  const hostLabels = host.split('.')
  const subdomains = hostLabels.slice(0, Math.max(0, hostLabels.length - root.split('.').length))
  const lowerAll = `${host}${url.pathname}${url.search}`.toLowerCase()
  if (url.protocol === 'http:') signals.push(signal('protocol', 'low', 'This URL uses HTTP, so the connection is not encrypted in transit.', 'http'))
  if (technical.usesIpAddress) signals.push(signal('ip_address', 'medium', 'The URL uses an IP address instead of a recognizable domain. This is unusual for public sign-in pages.', 'ipAddress'))
  if (url.port && !['80', '443'].includes(url.port)) signals.push(signal('unusual_port', 'low', `The URL uses the unusual port ${url.port}.`, 'unusualPort'))
  if (subdomains.length >= 4) signals.push(signal('subdomains', 'low', 'The hostname has an unusually large number of subdomain levels.', 'excessiveSubdomains'))
  if (url.username || url.password) signals.push(signal('userinfo', 'high', `Text appears before @ in the URL; the actual destination is ${host}.`, 'strongBrandImpersonation'))
  if (url.href.length > 500 || host.length > 100 || url.pathname.length > 200 || url.search.length > 300) signals.push(signal('length', 'low', 'One part of the URL is unusually long.', 'suspiciousKeywords'))
  const domainLabel = root.split('.')[0]
  const digitCount = (domainLabel.match(/\d/g) || []).length
  if (digitCount >= 2 || (digitCount && /[a-z]/i.test(domainLabel) && digitCount / domainLabel.length >= 0.15)) signals.push(signal('numbers', 'low', 'The registered domain mixes several numbers with letters, which can make it harder to recognize.', 'suspiciousKeywords'))
  const specialCount = (url.href.match(/[@\-_%?=&.]/g) || []).length
  const hyphens = (domainLabel.match(/-/g) || []).length
  const encodedChars = (url.href.match(/%[\da-f]{2}/gi) || []).length
  if (specialCount > 35 || hyphens > 3 || encodedChars > 8) signals.push(signal('special_characters', 'low', 'The URL contains an unusually high number of separators or encoded characters.', 'suspiciousKeywords'))
  if (technical.usesPunycode) signals.push(signal('punycode', 'medium', `The hostname uses encoded international characters (${domainToUnicode(host)}). This is not harmful by itself but can disguise a lookalike.`, 'homograph'))
  if (URL_SHORTENERS.has(root)) signals.push(signal('shortener', 'low', 'This is a URL shortener, so the final destination is hidden until opened.', 'shortenedUrl'))

  const brandEntries = Object.entries(BRANDS).flatMap(([brand, domains]) => domains.map((domain) => ({ brand, domain })))
  for (const { brand, domain } of brandEntries) {
    const brandDomain = domain.split('.')[0]
    const exactOfficial = host === domain || host.endsWith(`.${domain}`)
    const brandInSubdomain = !exactOfficial && subdomains.some((part) => part.includes(brandDomain) || part.includes(domain))
    const compactRoot = root.split('.')[0].toLowerCase().replace(/0/g, 'o').replace(/1/g, 'l').replace(/[^a-z]/g, '')
    const candidates = [compactRoot.slice(0, brandDomain.length - 1), compactRoot.slice(0, brandDomain.length), compactRoot.slice(0, brandDomain.length + 1)]
    const resembles = !exactOfficial && (root.includes(brandDomain) || candidates.some((candidate) => editDistance(candidate, brandDomain) <= 1))
    if (brandInSubdomain) signals.push(signal('brand_in_subdomain', 'high', `The hostname contains ${brand} in a subdomain, but the registered domain is ${root}.`, 'brandInSubdomain'))
    else if (resembles) signals.push(signal('brand_impersonation', 'high', `The registered domain ${root} resembles ${brand}, but is not one of its configured official domains.`, 'strongBrandImpersonation'))
  }

  const foundKeywords = [...new Set(keywords.filter((word) => lowerAll.includes(word)))].slice(0, 5)
  if (foundKeywords.length) signals.push(signal('suspicious_keywords', 'low', `The URL contains terms often used in account or payment requests: ${foundKeywords.join(', ')}. These terms are also common on legitimate sites.`, 'suspiciousKeywords'))
  const pattern = scamPatterns.find((item) => item.pattern.test(lowerAll))
  const scamPattern = pattern ? { type: 'scam_pattern', category: pattern.category, description: pattern.description } : null
  if (scamPattern) signals.push(signal('scam_pattern', 'medium', scamPattern.description, 'suspiciousPattern'))
  if (/[\u0080-\uFFFF]/.test(url.hostname)) signals.push(signal('homograph', 'medium', 'The hostname contains Unicode characters that may visually resemble other characters.', 'homograph'))
  if (technical.usesPunycode) {
    const unicodeRoot = domainToUnicode(root).split('.')[0]
    const skeleton = confusableSkeleton(unicodeRoot)
    const lookalike = Object.entries(BRANDS).find(([, domains]) => domains.some((domain) => skeleton === domain.split('.')[0]))
    if (lookalike) signals.push(signal('homograph', 'high', `The encoded hostname visually resembles a configured ${lookalike[0]} domain.`, 'homograph'))
  }
  return { signals, scamPattern }
}

function calculateRisk(signals, matches) {
  const grouped = new Map()
  for (const item of signals) {
    const group = item.type.includes('brand') ? 'brand' : ['suspicious_keywords', 'scam_pattern', 'message_context'].includes(item.type) ? 'url_language' : item.type === 'threat_intelligence' ? 'threat' : item.type
    grouped.set(group, Math.max(grouped.get(group) || 0, item.weight))
  }
  if (matches.length) grouped.set('threat', RISK_WEIGHTS.knownThreat)
  // Correlated detections share a category ceiling; multiple providers count once.
  const score = Math.min(100, Math.max(0, [...grouped.values()].reduce((sum, value) => sum + value, 0)))
  const hasShortenerSignal = signals.some((item) => item.type === 'shortener')
  const verdict = matches.length || score >= 60 ? 'likely scam' : score >= 15 || hasShortenerSignal ? 'suspicious' : 'likely legitimate'
  const confidence = matches.length || score >= 60 ? 'high' : score >= 25 ? 'medium' : 'low'
  return { label: verdict, riskScore: score, confidence }
}

export async function analyzeUrl(input, messageContext = '') {
  if (messageContext && typeof messageContext !== 'string') throw new Error('messageContext must be text.')
  if (messageContext.length > 4000) throw new Error('messageContext must be 4,000 characters or fewer.')
  const parsed = normalizeInput(input)
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  const root = registrableDomain(host)
  const ipAddress = isIP(host) > 0
  const subdomainCount = ipAddress || host === root ? 0 : host.slice(0, -(root.length + 1)).split('.').length
  const usesPunycode = host.split('.').some((label) => label.startsWith('xn--'))
  const technical = { usesHttps: parsed.protocol === 'https:', usesIpAddress: ipAddress, usesPunycode, subdomainCount, urlLength: parsed.href.length, hostnameLength: host.length, pathLength: parsed.pathname.length, queryLength: parsed.search.length, specialCharacterCount: (parsed.href.match(/[@\-_%?=&.]/g) || []).length }
  const local = analyzeLocal(parsed, host, root, technical)
  const privateTarget = ipAddress && isPrivateAddress(host) || host === 'localhost' || host.endsWith('.localhost') || !host.includes('.')
  const [threatIntelligence, dns, domain] = await Promise.all([
    privateTarget ? Promise.resolve({ sourcesChecked: [], providers: [], matches: [] }) : checkThreatIntelligence(parsed.href),
    privateTarget ? Promise.resolve({ available: false, reason: 'private_or_local_target' }) : getDns(host),
    privateTarget ? Promise.resolve({ available: false }) : getDomainRegistration(root),
  ])
  if (domain.available && domain.ageDays !== null && domain.ageDays < 30) local.signals.push(signal('new_domain', 'medium', `The domain was registered ${domain.ageDays} days ago. New domains are not necessarily malicious.`, 'newDomain'))
  if (dns.available && [...dns.a, ...dns.aaaa].some((address) => isPrivateAddress(address))) local.signals.push(signal('private_dns', 'high', 'DNS points to a private or local network address; lookups were not followed.', 'strongBrandImpersonation'))
  if (threatIntelligence.matches.length) local.signals.push(signal('threat_intelligence', 'critical', `This URL matched ${[...new Set(threatIntelligence.matches.map((match) => match.source))].join(', ')} threat-intelligence data.`, 'knownThreat'))
  if (messageContext.trim()) {
    const contextTerms = /urgent|suspend|verify|password|payment|gift card|crypto|act now/i.test(messageContext)
    if (contextTerms) local.signals.push(signal('message_context', 'medium', 'The message context contains urgency, account, or payment language.', 'suspiciousPattern'))
  }
  const verdict = calculateRisk(local.signals, threatIntelligence.matches)
  const maliciousMatches = threatIntelligence.matches
  if (maliciousMatches.length) verdict.label = 'Urgent: Malicious URL Detected'
  const threatCategories = new Set(maliciousMatches.map((match) => match.category))
  const threatExplanation = [...threatCategories].some((category) => /phish|social_engineering/i.test(category))
    ? 'This URL is listed as a phishing site. It may impersonate a trusted service to steal sign-in details, payment information, or other personal data.'
    : 'This URL is listed in a threat database as a malware distribution link. Visiting it may expose your device to malicious downloads or harmful software.'
  const registrableLabels = root.split('.')
  return {
    success: true,
    url: { original: input, normalized: parsed.href, protocol: parsed.protocol.slice(0, -1), hostname: host, port: parsed.port || null, path: parsed.pathname, query: [...parsed.searchParams.entries()], fragment: parsed.hash.slice(1), registrableDomain: root, subdomains: host === root ? [] : host.slice(0, -(root.length + 1)).split('.') },
    verdict,
    signals: local.signals.map(({ weight, ...item }) => item),
    domain: { available: domain.available, ageDays: domain.ageDays ?? null, createdAt: domain.createdAt ?? null, expiresAt: domain.expiresAt ?? null, registrar: domain.registrar ?? null, registrationStatus: domain.status ?? [], tld: ipAddress || !host.includes('.') ? null : `.${registrableLabels.at(-1)}` },
    technical,
    brandAnalysis: { configuredBrands: Object.keys(BRANDS), impersonationSignals: local.signals.filter((item) => item.type.includes('brand') || item.type === 'homograph').map(({ weight, ...item }) => item) },
    threatIntelligence,
    dns,
    scamPattern: local.scamPattern,
    recommendation: maliciousMatches.length ? threatExplanation : verdict.label === 'likely scam' ? 'Do not open this URL or enter personal information or payment details. Verify through an independently found official channel.' : 'Do not enter sensitive information unless you independently verify the destination through an official channel.',
    recoverySteps: maliciousMatches.length ? [
      'Do not open the URL again. Close the page if it is still open, and do not download or run files from it.',
      'If you entered a password, change it using the service’s official website or app and sign out of other sessions. Change it anywhere else you reused it.',
      'If you shared a sign-in code or payment details, contact the service or your bank through an official channel immediately and review recent account activity.',
      'Run your device’s security scan if you downloaded or opened a file, and report the URL using your browser or security software’s reporting tools.',
    ] : [],
    limitations: ['A URL not found in the databases checked is not necessarily safe.', 'URL checks can produce false positives and false negatives.', 'HTTPS encrypts a connection but does not establish that a site is trustworthy.'],
  }
}
