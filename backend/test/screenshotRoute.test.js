import assert from 'node:assert/strict'
import { createServer as createHttpServer } from 'node:http'
import { once } from 'node:events'
import test from 'node:test'
import sharp from 'sharp'
import { OcrProcessingError } from '../services/ocrService.js'
import { createScreenshotRoute } from '../routes/screenshotRoute.js'

const phishingText = 'Urgent: your bank account is locked. Verify your account now.'
const legitimateText = 'The scheduled maintenance for your Northstar Cloud account is complete. Open the usual app to review service details.'
const paymentText = 'Act now: send payment by gift card within 24 hours to prevent your account from being locked.'

async function createPng() {
  const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="640" height="240"><rect width="100%" height="100%" fill="white"/><text x="20" y="100" font-family="Arial" font-size="36" fill="black">Seems Legit screenshot test</text></svg>')
  return sharp(svg).png().toBuffer()
}

const validPng = await createPng()

function sendJson(response, statusCode, data) {
  response.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' })
  response.end(JSON.stringify(data))
}

async function startTestServer({ extractedText = phishingText, ocrError } = {}) {
  const analyzerCalls = []
  const route = createScreenshotRoute({
    sendJson,
    extractText: async () => {
      if (ocrError) throw ocrError
      return extractedText
    },
    analyzeMessage: (message, interaction) => {
      analyzerCalls.push({ message, interaction })
      return { testAnalyzer: true, interaction }
    },
  })
  const server = createHttpServer((request, response) => {
    if (request.method === 'POST' && request.url === '/api/analyze-screenshot') {
      void route(request, response)
      return
    }
    response.writeHead(404).end()
  })

  server.listen(0, '127.0.0.1')
  await once(server, 'listening')

  return {
    analyzerCalls,
    url: `http://127.0.0.1:${server.address().port}/api/analyze-screenshot`,
    close: () => new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve())
    }),
  }
}

async function withTestServer(options, run) {
  const app = await startTestServer(options)
  try {
    await run(app)
  } finally {
    await app.close()
  }
}

async function uploadImage(url, imageBuffer, filename = 'screenshot.png', mimeType = 'image/png', interaction) {
  const form = new FormData()
  form.append('image', new Blob([imageBuffer], { type: mimeType }), filename)
  if (interaction) form.append('interaction', interaction)
  return fetch(url, { method: 'POST', body: form })
}

test('phishing screenshot text and interaction reach the analyzer', async () => {
  await withTestServer({ extractedText: phishingText }, async ({ url, analyzerCalls }) => {
    const response = await uploadImage(url, validPng, 'message.png', 'image/png', 'shared_code')
    const body = await response.json()

    assert.equal(response.status, 200, JSON.stringify(body))
    assert.equal(body.success, true)
    assert.equal(body.extractedText, phishingText)
    assert.deepEqual(body.analysis, { testAnalyzer: true, interaction: 'shared_code' })
    assert.deepEqual(analyzerCalls, [{ message: phishingText, interaction: 'shared_code' }])
    assert.equal(body.ocr.provider, 'tesseract')
    assert.equal(body.ocr.limitedText, false)
  })
})

test('legitimate message screenshot is passed through for assessment', async () => {
  await withTestServer({ extractedText: legitimateText }, async ({ url, analyzerCalls }) => {
    const response = await uploadImage(url, validPng)
    const body = await response.json()

    assert.equal(response.status, 200)
    assert.equal(body.extractedText, legitimateText)
    assert.deepEqual(analyzerCalls, [{ message: legitimateText, interaction: 'none' }])
  })
})

test('suspicious payment screenshot is passed through for assessment', async () => {
  await withTestServer({ extractedText: paymentText }, async ({ url, analyzerCalls }) => {
    const response = await uploadImage(url, validPng)
    const body = await response.json()

    assert.equal(response.status, 200)
    assert.equal(body.extractedText, paymentText)
    assert.deepEqual(analyzerCalls, [{ message: paymentText, interaction: 'none' }])
  })
})

test('screenshot with no readable text returns 422 without analysis', async () => {
  await withTestServer({ extractedText: ' \n\f  ' }, async ({ url, analyzerCalls }) => {
    const response = await uploadImage(url, validPng)
    const body = await response.json()

    assert.equal(response.status, 422)
    assert.match(body.error, /no readable text/i)
    assert.deepEqual(analyzerCalls, [])
  })
})

test('invalid bytes named as PNG are rejected by signature', async () => {
  await withTestServer({}, async ({ url, analyzerCalls }) => {
    const response = await uploadImage(url, Buffer.from('not an image'), 'renamed.png')
    const body = await response.json()

    assert.equal(response.status, 415)
    assert.match(body.error, /unsupported image type/i)
    assert.deepEqual(analyzerCalls, [])
  })
})

test('image larger than 5 MB returns 413', async () => {
  await withTestServer({}, async ({ url, analyzerCalls }) => {
    const response = await uploadImage(url, Buffer.alloc(5 * 1024 * 1024 + 1))
    const body = await response.json()

    assert.equal(response.status, 413)
    assert.match(body.error, /5 MB limit/i)
    assert.deepEqual(analyzerCalls, [])
  })
})

test('corrupt PNG data returns 422', async () => {
  await withTestServer({}, async ({ url, analyzerCalls }) => {
    const truncatedPng = validPng.subarray(0, 32)
    const response = await uploadImage(url, truncatedPng)
    const body = await response.json()

    assert.equal(response.status, 422)
    assert.match(body.error, /not a valid, readable image/i)
    assert.deepEqual(analyzerCalls, [])
  })
})

test('short OCR text is still analyzed with an uncertainty warning', async () => {
  await withTestServer({ extractedText: 'Help me' }, async ({ url, analyzerCalls }) => {
    const response = await uploadImage(url, validPng)
    const body = await response.json()

    assert.equal(response.status, 200)
    assert.equal(body.extractedText, 'Help me')
    assert.equal(body.ocr.limitedText, true)
    assert.match(body.ocr.warning, /may be unreliable/i)
    assert.deepEqual(analyzerCalls, [{ message: 'Help me', interaction: 'none' }])
  })
})

test('OCR processing failure returns a generic 500 response', async () => {
  await withTestServer({ ocrError: new OcrProcessingError() }, async ({ url, analyzerCalls }) => {
    const response = await uploadImage(url, validPng)
    const body = await response.json()

    assert.equal(response.status, 500)
    assert.equal(body.error, 'Could not process the screenshot with OCR.')
    assert.deepEqual(analyzerCalls, [])
  })
})
