import { createServer } from 'node:http'

const PORT = Number(process.env.PORT) || 3001
const MAX_BODY_BYTES = 10_000

const disclaimer = 'This automated assessment can be wrong. Verify important requests through an official channel.'

// Send one JSON response and finish handling this web request.
function sendJson(response, statusCode, data) {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': 'http://localhost:5173',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  })
  response.end(JSON.stringify(data))
}

// Read the text sent by the webpage, while refusing unusually large requests.
async function readRequestBody(request) {
  let body = ''

  for await (const chunk of request) {
    body += chunk
    if (Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES) {
      throw new Error('Message is too long. Please use fewer than 10,000 characters.')
    }
  }

  return JSON.parse(body)
}

// Find likely misspellings in common words used in account and payment requests.
// This is intentionally a small heuristic list, not a general spell checker.
function findTypos(text) {
  const commonTypos = new Map([
    [' recieve ', 'receive'], [' recive ', 'receive'], [' adress ', 'address'],
    [' verfy ', 'verify'], [' varify ', 'verify'], [' acccount ', 'account'],
    [' pasword ', 'password'], [' securty ', 'security'], [' succesful ', 'successful'],
    [' succesfully ', 'successfully'], [' tranfer ', 'transfer'], [' beneift ', 'benefit'],
    [' custo mer ', 'customer'], [' cliam ', 'claim'], [' expir ', 'expire'],
  ])
  const padded = ` ${text.toLowerCase().replace(/[^a-z0-9]+/g, ' ')} `
  const found = []
  for (const [typo, correction] of commonTypos) {
    if (padded.includes(typo)) found.push(`The word '${typo.trim()}' appears misspelled (usually '${correction}').`)
  }
  return found
}

function inspectLinks(message) {
  const links = message.match(/(?:https?:\/\/|www\.)[^\s<>"']+/gi) || []
  const findings = []
  for (const raw of links) {
    let url
    try { url = new URL(raw.startsWith('www.') ? `http://${raw}` : raw) } catch { continue }
    const host = url.hostname.toLowerCase().replace(/^www\./, '')
    if (url.username || url.password) findings.push('A link hides extra credentials before its domain.')
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) findings.push('A link uses a numeric IP address instead of a recognizable domain.')
    if (host.startsWith('xn--') || host.split('.').some(part => part.startsWith('xn--'))) {
      findings.push('A link uses an encoded domain name that can disguise its appearance.')
    }
    if (/\.(zip|mov|click|top|work)$/i.test(host)) findings.push('A link uses a domain ending often abused in deceptive messages.')
  }
  if (links.length > 0 && /\b(sign in|log ?in|verify your account|confirm your password)\b/i.test(message)) {
    findings.push('The message links to a sign-in or account verification request.')
  }
  return findings
}

function inspectSender(message) {
  const findings = []
  const match = message.match(/\b(?:from|reply-to|sender)\s*:?\s*[^\n<]*<([^>]+)>/i)
    || message.match(/\b(?:from|reply-to|sender)\s*:?\s*([\w.+-]+@[\w.-]+\.[a-z]{2,})/i)
  if (!match) return findings
  const address = match[1].trim()
  const email = address.match(/^([^@\s]+)@([^@\s]+)$/)
  if (!email || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(email[2]) || email[2].includes('..')) {
    findings.push('The sender address appears malformed.')
    return findings
  }
  const domain = email[2].toLowerCase()
  const brands = ['paypal', 'microsoft', 'apple', 'amazon', 'google', 'netflix', 'bankofamerica', 'chase']
  const mentionedBrand = brands.find(brand => new RegExp(`\\b${brand}\\b`, 'i').test(message))
  if (mentionedBrand) {
    const labels = domain.split('.')
    const exactOfficialDomain = domain === `${mentionedBrand}.com` || domain.endsWith(`.${mentionedBrand}.com`)
    const brandLikeLabel = labels.some(label => {
      if (label === mentionedBrand) return true
      if (Math.abs(label.length - mentionedBrand.length) > 1) return false
      // Detect a single-character typo, such as “paypai” in place of “paypal”.
      let edits = 0
      let left = 0
      let right = 0
      while (left < label.length && right < mentionedBrand.length) {
        if (label[left] === mentionedBrand[right]) { left++; right++; continue }
        if (++edits > 1) return false
        if (label.length > mentionedBrand.length) left++
        else if (label.length < mentionedBrand.length) right++
        else { left++; right++ }
      }
      if (left < label.length || right < mentionedBrand.length) edits++
      return edits <= 1
    })
    if (!exactOfficialDomain && brandLikeLabel) {
      findings.push(`The sender domain resembles ${mentionedBrand} but is not an official ${mentionedBrand} domain.`)
    }
  }
  return findings
}

// Look for multiple independent warning signs and return a cautious result.
function analyzeMessage(message) {
  const signals = []
  const text = message.toLowerCase()
  
  let verdict = 'likely legitimate'
  let confidence = 'low'
  let nextSteps = ['If the message is unexpected, contact the sender through a phone number or website you already trust.']

  if (Buffer.byteLength(text, 'utf8') === 0) {
    signals.push('The message is empty.')
    verdict = 'N/A'
    confidence = 'N/A'
    nextSteps = [
      'The message is empty. Please provide a message to analyze.',
    ]
  }

  if (Buffer.byteLength(text, 'utf8') < 50) {
    signals.push('The message is too short to analyze effectively.')
    verdict = 'N/A'
    confidence = 'N/A'
    nextSteps = [
      'The message is too short to analyze effectively. Please provide more details.',
    ]
  }

  if (verdict === 'N/A') return { verdict, confidence, signals, nextSteps, disclaimer }

  const typoSignals = findTypos(text)
  const linkSignals = inspectLinks(message)
  const senderSignals = inspectSender(message)
  signals.push(...typoSignals, ...linkSignals, ...senderSignals)

  // Keep wording observations in the summary, but never use them to decide
  // whether the message is suspicious or scam-like.
  if (/urgent|immediately|act now|expires today|within 24 hours/.test(text)) {
    signals.push('The message pressures you to act quickly.')
  }
  if (/password|one[- ]time code|verification code|social security|credit card/.test(text)) {
    signals.push('The message asks for sensitive information.')
  }
  if (/gift card|wire transfer|cryptocurrency|crypto payment/.test(text)) {
    signals.push('The message mentions an unusual or hard-to-reverse payment method.')
  }
  if (/click here|sign in|login|verify your account/.test(text) && /https?:\/\//.test(text)) {
    if (!signals.some(signal => signal.includes('sign-in or account verification'))) {
      signals.push('The message combines a link with a request to sign in or verify an account.')
    }
  }

  const concreteSignals = typoSignals.length + linkSignals.length + senderSignals.length
  if (concreteSignals >= 2) {
    verdict = 'likely scam'
    confidence = 'medium'
    nextSteps = [
      'Do not click links or reply with personal information.',
      'Contact the organization using its official website or phone number.',
    ]
  } else if (concreteSignals >= 1) {
    verdict = 'suspicious'
    confidence = 'low'
    nextSteps = [
      'Pause before responding or clicking anything.',
      'Check the request through an official website or phone number you find yourself.',
    ]
  }

  if (signals.length === 0) signals.push('No common warning signs were found by this basic checker.')

  return { verdict, confidence, signals, nextSteps, disclaimer }
}

// Route webpage requests to the right action and handle errors safely.
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
    if (typeof data.message !== 'string' || data.message.trim().length === 0) {
      sendJson(response, 400, { error: 'Please provide a message to analyze.' })
      return
    }

    sendJson(response, 200, analyzeMessage(data.message.trim()))
  } catch (error) {
    const tooLarge = error.message.startsWith('Message is too long')
    sendJson(response, tooLarge ? 413 : 400, {
      error: tooLarge ? error.message : 'The request must contain valid JSON with a message field.',
    })
  }
}

// Start listening so the webpage can contact this backend on port 3001.
createServer(handleRequest).listen(PORT, () => {
  console.log(`Seems Legit backend listening at http://localhost:${PORT}`)
})
