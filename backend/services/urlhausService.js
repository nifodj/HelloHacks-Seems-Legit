const URLHAUS_LOOKUP_ENDPOINT = 'https://urlhaus-api.abuse.ch/v1/url/'
const URLHAUS_REFERENCE_HOST = 'urlhaus.abuse.ch'

export class UrlhausLookupError extends Error {
  constructor(message, code = 'lookup_failed') {
    super(message)
    this.name = 'UrlhausLookupError'
    this.code = code
  }
}

export async function lookupUrlhaus(url, {
  authKey = process.env.URLHAUS_AUTH_KEY,
  fetchImpl = fetch,
} = {}) {
  if (!authKey) {
    throw new UrlhausLookupError('URLhaus lookup is not configured.', 'missing_auth_key')
  }

  let response
  try {
    response = await fetchImpl(URLHAUS_LOOKUP_ENDPOINT, {
      method: 'POST',
      headers: {
        'Auth-Key': authKey,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ url }),
      signal: AbortSignal.timeout(8000),
    })
  } catch {
    throw new UrlhausLookupError('Could not reach the URLhaus service.', 'network_error')
  }

  if (!response.ok) {
    throw new UrlhausLookupError('URLhaus could not complete the lookup.', 'upstream_error')
  }

  let data
  try {
    data = await response.json()
  } catch {
    throw new UrlhausLookupError('URLhaus returned an unreadable response.', 'invalid_response')
  }

  if (data.query_status === 'no_results') {
    return { listed: false }
  }

  if (data.query_status !== 'ok') {
    throw new UrlhausLookupError('URLhaus could not complete the lookup.', 'upstream_error')
  }

  let referenceUrl
  try {
    const reference = new URL(data.urlhaus_reference)
    if (reference.protocol === 'https:' && reference.hostname === URLHAUS_REFERENCE_HOST) {
      referenceUrl = reference.toString()
    }
  } catch {
    // A reference link is optional; an invalid link is not returned to the client.
  }

  return {
    listed: true,
    threat: typeof data.threat === 'string' ? data.threat : 'malware_download',
    urlStatus: typeof data.url_status === 'string' ? data.url_status : 'unknown',
    dateAdded: typeof data.date_added === 'string' ? data.date_added : null,
    referenceUrl,
    tags: Array.isArray(data.tags) ? data.tags.filter((tag) => typeof tag === 'string') : [],
  }
}
