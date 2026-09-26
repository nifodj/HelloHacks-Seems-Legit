import { createServer } from 'node:http'

const PORT = Number(process.env.PORT) || 3001
const MAX_BODY_BYTES = 10_000

const disclaimer = 'This automated assessment can be wrong. A “likely legitimate” result does not prove a message is safe. Verify important requests through an official channel.'
const privacyReminder = 'Do not submit passwords, one-time codes, payment details, or other sensitive information.'

const recoverySteps = {
  clicked_link: [
    'Close the page. Do not enter information or download anything from it.',
    'If you entered a password, change it from the organization’s official website and sign out of other sessions.',
    'If you downloaded a file, do not open it; run your device’s security scan.',
  ],
  shared_password: [
    'Change that password now using the organization’s official website or app, not the message link.',
    'Change the same password anywhere else you reused it, then turn on multi-factor authentication if available.',
    'Sign out of other sessions and contact the organization through an official channel.',
  ],
  shared_code: [
    'Contact the organization using its official website or phone number and say you shared a sign-in code.',
    'Secure the account: change its password, sign out of other sessions, and review recent activity.',
  ],
  shared_payment: [
    'Contact your bank, card issuer, or payment service immediately using the number on its official website or card.',
    'Ask whether the payment can be stopped or reversed, and monitor the account for unfamiliar activity.',
  ],
  shared_personal_info: [
    'Contact the relevant organization through its official channel and ask what steps to take for the information you shared.',
    'Watch for unfamiliar account activity and consider contacting your bank if financial details were included.',
  ],
}

function sendJson(response, statusCode, data) {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': 'http://localhost:5173',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  })
  response.end(JSON.stringify(data))
}

async function readRequestBody(request) {
  const chunks = []
  let size = 0

  for await (const chunk of request) {
    size += chunk.length
    if (size > MAX_BODY_BYTES) {
      throw new Error('Message is too long. Please use fewer than 10,000 characters.')
    }
    chunks.push(chunk)
  }

  return JSON.parse(Buffer.concat(chunks).toString('utf8'))
}

// Find likely misspellings in common words used in account and payment requests.
function findTypos(text) {
  const commonTypos = new Map([
    [' recieve ', 'receive'], [' recive ', 'receive'], [' adress ', 'address'],
    [' verfy ', 'verify'], [' varify ', 'verify'], [' acccount ', 'account'],
    [' pasword ', 'password'], [' securty ', 'security'], [' succesful ', 'successful'],
    [' succesfully ', 'successfully'], [' tranfer ', 'transfer'], [' beneift ', 'benefit'],
    [' cliam ', 'claim'], [' expir ', 'expire'],
  ])
  const padded = ` ${text.toLowerCase().replace(/[^a-z0-9]+/g, ' ')} `
  return [...commonTypos].filter(([typo]) => padded.includes(typo))
    .map(([typo, correction]) => `The word '${typo.trim()}' appears misspelled (usually '${correction}').`)
}

function inspectLinks(message) {
  const links = message.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) || []
  const findings = []
  for (const raw of links) {
    let url
    try { url = new URL(raw.startsWith('www.') ? `http://${raw}` : raw) } catch { continue }
    const host = url.hostname.toLowerCase().replace(/^www\./, '')
    if (url.username || url.password) findings.push('A link hides credentials before its domain.')
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) findings.push('A link uses a numeric IP address instead of a recognizable domain.')
    if (host.split('.').some(label => label.startsWith('xn--'))) findings.push('A link uses an encoded domain name that can disguise its appearance.')
    if (/\.(zip|mov|click|top|work)$/i.test(host)) findings.push('A link uses a domain ending often abused in deceptive messages.')
  }
  if (links.length && /\b(sign in|log ?in|verify your account|confirm your password|confirm your account)\b/i.test(message)) {
    findings.push('The message links to a sign-in or account verification request.')
  }
  return findings
}

function isOneEditAway(label, brand) {
  if (Math.abs(label.length - brand.length) > 1) return false
  let edits = 0
  let left = 0
  let right = 0
  while (left < label.length && right < brand.length) {
    if (label[left] === brand[right]) { left++; right++; continue }
    if (++edits > 1) return false
    if (label.length > brand.length) left++
    else if (label.length < brand.length) right++
    else { left++; right++ }
  }
  if (left < label.length || right < brand.length) edits++
  return edits <= 1
}

function inspectSender(message) {
  const findings = []
  const match = message.match(/\b(?:from|reply-to|sender)\s*:?\s*[^\n<]*<([^>]+)>/i)
    || message.match(/\b(?:from|reply-to|sender)\s*:?\s*([\w.+-]+@[\w.-]+\.[a-z]{2,})/i)
  if (!match) return findings
  const email = match[1].trim().match(/^([^@\s]+)@([^@\s]+)$/)
  if (!email || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(email[2]) || email[2].includes('..')) {
    return ['The sender address appears malformed.']
  }
  const domain = email[2].toLowerCase()
  const brands = ['paypal', 'microsoft', 'apple', 'amazon', 'google', 'netflix', 'bankofamerica', 'chase']
  const mentionedBrand = brands.find(brand => new RegExp(`\\b${brand}\\b`, 'i').test(message))
  if (mentionedBrand) {
    const officialDomain = domain === `${mentionedBrand}.com` || domain.endsWith(`.${mentionedBrand}.com`)
    const similarLabel = domain.split('.').some(label => isOneEditAway(label, mentionedBrand))
    if (!officialDomain && similarLabel) findings.push(`The sender domain resembles ${mentionedBrand} but is not an official ${mentionedBrand} domain.`)
  }
  return findings
}

// Message wording is summarized for context; only concrete typo, sender, and
// link indicators affect the verdict. The interaction affects recovery advice only.
function analyzeMessage(message, interaction = 'none') {
  const text = message.toLowerCase()
  const signals = []
  const typoSignals = findTypos(text)
  const linkSignals = inspectLinks(message)
  const senderSignals = inspectSender(message)
  signals.push(...typoSignals, ...linkSignals, ...senderSignals)

  if (/urgent|immediately|act now|expires today|within 24 hours|final warning|account.{0,20}(suspend|lock)/.test(text)) {
    signals.push('The message creates pressure to act quickly.')
  }
  if (/password|one[- ]time code|verification code|security code|sign[- ]in code|social security|credit card|bank details|date of birth|personal information/.test(text)) {
    signals.push('The message mentions a password, sign-in code, or sensitive personal or financial information.')
  }
  if (/gift card|wire transfer|cryptocurrency|crypto payment|bitcoin|payment in crypto/.test(text)) {
    signals.push('The message mentions an unusual or hard-to-reverse payment method.')
  }
  if (/prize|you have won|claim your reward|unclaimed package|delivery fee/.test(text)) {
    signals.push('The message promises a prize or unexpected delivery that may be used to prompt a response.')
  }
  if (/keep this (secret|confidential)|do not tell|don't tell|gift cards? for (my|the) (boss|ceo|manager)/.test(text)) {
    signals.push('The message asks for secrecy, which can be a sign of impersonation or fraud.')
  }
  if (/click here|sign in|log ?in|verify your account|confirm your account/.test(text) && /https?:\/\//.test(text) &&
      !signals.some(signal => signal.includes('links to a sign-in or account verification request'))) {
    signals.push('The message combines a link with a request to sign in or verify an account.')
  }

  const concreteSignals = typoSignals.length + linkSignals.length + senderSignals.length
  let verdict = 'likely legitimate'
  let confidence = 'low'
  let nextSteps = ['No common warning signs were found. If the message was unexpected, verify it through a phone number or website you already trust.']
  if (concreteSignals >= 2) {
    verdict = 'likely scam'
    confidence = 'medium'
    nextSteps = [
      'Do not click links, reply, or provide information or payment.',
      'Contact the claimed organization using its official website or phone number.',
      'Report or block the message using your email or messaging app’s built-in tools.',
    ]
  } else if (concreteSignals === 1) {
    verdict = 'suspicious'
    confidence = 'low'
    nextSteps = [
      'Pause before responding, clicking a link, or opening an attachment.',
      'Check the request through an official website or phone number you find yourself.',
    ]
  } else {
    signals.push('This basic checker did not find common warning signs; that does not prove the message is safe.')
  }

  return {
    verdict,
    confidence,
    signals,
    nextSteps,
    recoverySteps: recoverySteps[interaction] ?? [],
    privacyReminder,
    disclaimer,
  }
}

async function handleRequest(request, response) {
  if (request.method === 'OPTIONS') {
    response.writeHead(204, {
      'Access-Control-Allow-Origin': 'http://localhost:5173',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    })
    response.end()
    return
  }

  if (request.method !== 'POST' || request.url !== '/api/analyze') {
    sendJson(response, 404, { error: 'Not found. Use POST /api/analyze.' })
    return
  }

  try {
    const data = await readRequestBody(request)
    if (!data || typeof data !== 'object' || typeof data.message !== 'string' || data.message.trim().length === 0) {
      sendJson(response, 400, { error: 'Please provide a message to analyze.' })
      return
    }
    if (data.interaction !== undefined && !['none', ...Object.keys(recoverySteps)].includes(data.interaction)) {
      sendJson(response, 400, { error: 'interaction must be none, clicked_link, shared_password, shared_code, shared_payment, or shared_personal_info.' })
      return
    }

    sendJson(response, 200, analyzeMessage(data.message.trim(), data.interaction ?? 'none'))
  } catch (error) {
    const tooLarge = error.message.startsWith('Message is too long')
    sendJson(response, tooLarge ? 413 : 400, {
      error: tooLarge ? error.message : 'The request must contain valid JSON with a message field.',
    })
  }
}

createServer(handleRequest).listen(PORT, () => {
  console.log(`Seems Legit backend listening at http://localhost:${PORT}`)
})
