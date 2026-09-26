const timeoutMs = 3500
const sources = []
let openPhishCache = { expiresAt: 0, urls: new Set() }

async function timedFetch(url, options = {}) {
  return fetch(url, { ...options, signal: AbortSignal.timeout(timeoutMs) })
}

function addSource(name, enabled, check) {
  if (enabled) sources.push({ name, check })
}

addSource('Google Safe Browsing', Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY), async (url) => {
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(process.env.GOOGLE_SAFE_BROWSING_API_KEY)}`
  const response = await timedFetch(endpoint, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client: { clientId: 'seems-legit', clientVersion: '1.0' }, threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: [{ url }],
    } }),
  })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  const data = await response.json()
  return (data.matches || []).map((match) => ({ source: 'Google Safe Browsing', category: match.threatType, url: match.threat?.url || url }))
})

addSource('VirusTotal', Boolean(process.env.VIRUSTOTAL_API_KEY), async (url) => {
  const response = await timedFetch('https://www.virustotal.com/api/v3/urls', {
    method: 'POST', headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ url }),
  })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  const { data } = await response.json()
  const analysis = await timedFetch(`https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(data.id)}`, { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY } })
  if (!analysis.ok) throw new Error(`HTTP ${analysis.status}`)
  const analysisData = (await analysis.json()).data?.attributes
  if (analysisData?.status !== 'completed') throw new Error('Analysis is not complete')
  const stats = analysisData.stats || {}
  return stats.malicious > 0 ? [{ source: 'VirusTotal', category: 'malicious', positives: stats.malicious, url }] : []
})

addSource('URLhaus', process.env.URLHAUS_ENABLED === 'true', async (url) => {
  const response = await timedFetch('https://urlhaus-api.abuse.ch/v1/url/', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ url }),
  })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  const data = await response.json()
  return data.query_status === 'ok' ? [{ source: 'URLhaus', category: 'malware', url }] : []
})

addSource('OpenPhish Community Feed', process.env.OPENPHISH_ENABLED === 'true', async (url) => {
  if (Date.now() >= openPhishCache.expiresAt) {
    const response = await timedFetch('https://openphish.com/feed.txt')
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    const text = await response.text()
    openPhishCache = { expiresAt: Date.now() + 15 * 60 * 1000, urls: new Set(text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)) }
  }
  return openPhishCache.urls.has(url) ? [{ source: 'OpenPhish Community Feed', category: 'phishing', url }] : []
})

addSource('PhishTank', Boolean(process.env.PHISHTANK_API_KEY), async (url) => {
  const response = await timedFetch('https://checkurl.phishtank.com/checkurl/', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'SeemsLegit/1.0' },
    body: new URLSearchParams({ url, format: 'json', app_key: process.env.PHISHTANK_API_KEY }),
  })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  const data = await response.json()
  return data.results?.in_database ? [{ source: 'PhishTank', category: 'phishing', url }] : []
})

export async function checkThreatIntelligence(url) {
  const results = await Promise.all(sources.map(async ({ name, check }) => {
    try { return { name, status: 'checked', matches: await check(url) } }
    catch { return { name, status: 'unavailable', matches: [] } }
  }))
  return {
    sourcesChecked: results.filter((result) => result.status === 'checked').map((result) => result.name),
    providers: results.map(({ name, status }) => ({ name, status })),
    matches: results.flatMap((result) => result.matches),
  }
}
