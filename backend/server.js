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

// Look for common warning signs and return a cautious, easy-to-display result.
function analyzeMessage(message) {
  const signals = []
  const text = message.toLowerCase()

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
    signals.push('The message combines a link with a request to sign in or verify an account.')
  }

  let verdict = 'likely legitimate'
  let confidence = 'low'
  let nextSteps = ['If the message is unexpected, contact the sender through a phone number or website you already trust.']

  if (signals.length >= 2) {
    verdict = 'likely scam'
    confidence = 'medium'
    nextSteps = [
      'Do not click links or reply with personal information.',
      'Contact the organization using its official website or phone number.',
    ]
  } else if (signals.length === 1) {
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
