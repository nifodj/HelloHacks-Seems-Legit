import { fileTypeFromBuffer } from 'file-type'
import sharp from 'sharp'

const MAX_IMAGE_PIXELS = 16_000_000
const SUPPORTED_IMAGE_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp'])

export class ImageValidationError extends Error {
  constructor(message, code) {
    super(message)
    this.name = 'ImageValidationError'
    this.code = code
  }
}

export async function validateAndNormalizeImage(imageBuffer) {
  if (!Buffer.isBuffer(imageBuffer) || imageBuffer.length === 0) {
    throw new ImageValidationError('The uploaded image is empty.', 'empty_image')
  }

  const detectedType = await fileTypeFromBuffer(imageBuffer)
  if (!detectedType || !SUPPORTED_IMAGE_TYPES.has(detectedType.mime)) {
    throw new ImageValidationError(
      'Unsupported image type. Upload a JPEG, PNG, or WebP image.',
      'unsupported_image_type',
    )
  }

  try {
    const { data, info } = await sharp(imageBuffer, {
      failOn: 'error',
      limitInputPixels: MAX_IMAGE_PIXELS,
    })
      .rotate()
      .png()
      .toBuffer({ resolveWithObject: true })

    return {
      buffer: data,
      mimeType: detectedType.mime,
      width: info.width,
      height: info.height,
    }
  } catch (error) {
    if (/pixel limit|exceeds.*limit|image is too large/i.test(error.message)) {
      throw new ImageValidationError(
        'Image dimensions are too large to process safely.',
        'image_dimensions_too_large',
      )
    }

    throw new ImageValidationError(
      'The uploaded file is not a valid, readable image.',
      'invalid_image',
    )
  }
}
