import { createWorker } from 'tesseract.js'

const OCR_LANGUAGE = 'eng'

let workerPromise
let recognitionQueue = Promise.resolve()

export class OcrProcessingError extends Error {
  constructor() {
    super('OCR processing failed.')
    this.name = 'OcrProcessingError'
  }
}

async function getWorker() {
  if (!workerPromise) {
    workerPromise = createWorker(OCR_LANGUAGE, 1, { logger: () => {} }).catch((error) => {
      workerPromise = undefined
      throw error
    })
  }

  return workerPromise
}

function normalizeExtractedText(text) {
  return text
    .replace(/\r\n?/g, '\n')
    .replace(/\f/g, '\n')
    .replace(/[\t ]+/g, ' ')
    .replace(/\n[\t ]+/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

export async function extractTextFromImage(imageBuffer) {
  if (!Buffer.isBuffer(imageBuffer) || imageBuffer.length === 0) {
    throw new OcrProcessingError()
  }

  const recognition = recognitionQueue.then(async () => {
    const worker = await getWorker()
    const { data } = await worker.recognize(imageBuffer)
    return normalizeExtractedText(data.text)
  })

  recognitionQueue = recognition.catch(() => {})

  try {
    return await recognition
  } catch {
    throw new OcrProcessingError()
  }
}

export async function terminateOcrWorker() {
  const currentWorker = workerPromise
  workerPromise = undefined

  if (currentWorker) {
    try {
      const worker = await currentWorker
      await worker.terminate()
    } catch {
      // A worker that failed during startup has nothing left to terminate.
    }
  }
}
