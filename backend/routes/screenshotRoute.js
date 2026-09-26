import Busboy from 'busboy'
import { OcrProcessingError, extractTextFromImage } from '../services/ocrService.js'
import { ImageValidationError, validateAndNormalizeImage } from '../utils/imageValidation.js'

const MAX_IMAGE_BYTES = 5 * 1024 * 1024
const MAX_REQUEST_BYTES = MAX_IMAGE_BYTES + 16 * 1024
const ALLOWED_INTERACTIONS = new Set([
  'none',
  'clicked_link',
  'shared_password',
  'shared_code',
  'shared_payment',
  'shared_personal_info',
])
const MEANINGFUL_TEXT = /[\p{L}\p{N}]/u

class ScreenshotRequestError extends Error {
  constructor(statusCode, message) {
    super(message)
    this.name = 'ScreenshotRequestError'
    this.statusCode = statusCode
  }
}

function readMultipartUpload(request) {
  return new Promise((resolve, reject) => {
    const contentType = request.headers['content-type'] ?? ''
    if (!/^multipart\/form-data(?:;|$)/i.test(contentType)) {
      request.resume()
      reject(new ScreenshotRequestError(415, 'Content-Type must be multipart/form-data.'))
      return
    }

    const contentLength = Number(request.headers['content-length'])
    if (Number.isFinite(contentLength) && contentLength > MAX_REQUEST_BYTES) {
      request.resume()
      reject(new ScreenshotRequestError(413, 'Screenshot upload exceeds the 5 MB limit.'))
      return
    }

    let parser
    try {
      parser = Busboy({
        headers: request.headers,
        limits: {
          fileSize: MAX_IMAGE_BYTES,
          files: 1,
          fields: 2,
          parts: 3,
          fieldNameSize: 32,
          fieldSize: 64,
          headerPairs: 32,
        },
      })
    } catch {
      request.resume()
      reject(new ScreenshotRequestError(400, 'Malformed multipart upload.'))
      return
    }

    let failure
    let imageBuffer
    let fileSeen = false
    let interaction = 'none'
    let interactionSeen = false
    let requestBytes = 0
    let finished = false

    const fail = (statusCode, message) => {
      if (!failure) failure = new ScreenshotRequestError(statusCode, message)
    }

    const finish = () => {
      if (finished) return
      finished = true

      if (failure) {
        reject(failure)
      } else if (!fileSeen || !imageBuffer) {
        reject(new ScreenshotRequestError(400, 'Missing image upload. Send the file in the "image" field.'))
      } else {
        resolve({ imageBuffer, interaction })
      }
    }

    parser.on('file', (fieldName, file) => {
      if (fieldName !== 'image') {
        fail(400, 'Unexpected file field. Send the screenshot in the "image" field.')
        file.resume()
        return
      }

      fileSeen = true
      const chunks = []
      file.on('data', (chunk) => chunks.push(chunk))
      file.on('limit', () => fail(413, 'Screenshot upload exceeds the 5 MB limit.'))
      file.on('end', () => {
        if (!file.truncated) imageBuffer = Buffer.concat(chunks)
      })
    })

    parser.on('field', (fieldName, value, info) => {
      if (fieldName !== 'interaction') {
        fail(400, 'Unexpected form field. Only "image" and optional "interaction" are accepted.')
      } else if (interactionSeen) {
        fail(400, 'The interaction field may only be sent once.')
      } else if (info.valueTruncated) {
        fail(400, 'The interaction field is too long.')
      } else if (!ALLOWED_INTERACTIONS.has(value)) {
        fail(400, 'Invalid interaction value.')
      } else {
        interaction = value
        interactionSeen = true
      }
    })

    parser.on('filesLimit', () => fail(400, 'Only one screenshot may be uploaded.'))
    parser.on('fieldsLimit', () => fail(400, 'Too many form fields.'))
    parser.on('partsLimit', () => fail(400, 'Too many multipart fields.'))
    parser.on('error', () => fail(400, 'Malformed multipart upload.'))
    parser.on('close', finish)

    request.on('data', (chunk) => {
      requestBytes += chunk.length
      if (requestBytes > MAX_REQUEST_BYTES && !failure) {
        fail(413, 'Screenshot upload exceeds the 5 MB limit.')
        request.unpipe(parser)
        parser.destroy()
        request.resume()
      }
    })
    request.once('aborted', () => {
      fail(400, 'Upload was interrupted before it completed.')
      parser.destroy()
    })
    request.once('error', () => {
      fail(400, 'Could not read the upload.')
      parser.destroy()
    })

    request.pipe(parser)
  })
}

function getImageErrorStatus(error) {
  if (error.code === 'unsupported_image_type') return 415
  if (error.code === 'image_dimensions_too_large') return 413
  if (error.code === 'invalid_image') return 422
  return 400
}

export function createScreenshotRoute({ sendJson, analyzeMessage, extractText = extractTextFromImage }) {
  return async function handleScreenshotRequest(request, response) {
    try {
      const { imageBuffer, interaction } = await readMultipartUpload(request)
      const image = await validateAndNormalizeImage(imageBuffer)
      const extractedText = await extractText(image.buffer)

      if (!MEANINGFUL_TEXT.test(extractedText)) {
        sendJson(response, 422, {
          success: false,
          error: 'No readable text was found in the screenshot. Try a clearer image with larger text.',
        })
        return
      }

      let analysis
      try {
        analysis = analyzeMessage(extractedText, interaction)
      } catch {
        sendJson(response, 500, { success: false, error: 'Could not analyze the extracted text.' })
        return
      }

      const limitedText = extractedText.length < 30
      sendJson(response, 200, {
        success: true,
        extractedText,
        analysis,
        ocr: {
          provider: 'tesseract',
          language: 'eng',
          limitedText,
          warning: limitedText ? 'Only a small amount of text was recognized; this assessment may be unreliable.' : null,
        },
      })
    } catch (error) {
      if (error instanceof ScreenshotRequestError) {
        sendJson(response, error.statusCode, { success: false, error: error.message })
      } else if (error instanceof ImageValidationError) {
        sendJson(response, getImageErrorStatus(error), { success: false, error: error.message })
      } else if (error instanceof OcrProcessingError) {
        sendJson(response, 500, { success: false, error: 'Could not process the screenshot with OCR.' })
      } else {
        sendJson(response, 500, { success: false, error: 'Could not process the screenshot.' })
      }
    }
  }
}
