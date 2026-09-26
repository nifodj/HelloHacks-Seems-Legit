const timeoutMs = 3500
const sources = []

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

addSource('URLhaus', Boolean(process.env.URLHAUS_AUTH_KEY), async (url) => {
  const response = await timedFetch('https://urlhaus-api.abuse.ch/v1/url/', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'Auth-Key': process.env.URLHAUS_AUTH_KEY }, body: new URLSearchParams({ url }),
  })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  const data = await response.json()
  return data.query_status === 'ok' ? [{ source: 'URLhaus', category: data.threat || 'malware', url, referenceUrl: 'https://urlhaus.abuse.ch/browse/' }] : []
})

addSource('PhishTank', process.env.PHISHTANK_ENABLED === 'true' || Boolean(process.env.PHISHTANK_API_KEY), async (url) => {
  const response = await timedFetch('https://checkurl.phishtank.com/checkurl/', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'user-agent': 'SeemsLegit/1.0' },
    body: new URLSearchParams({ url, format: 'json', ...(process.env.PHISHTANK_API_KEY ? { app_key: process.env.PHISHTANK_API_KEY } : {}) }),
  })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
  const data = await response.json()
  const result = data.results
  const verified = result?.verified === 'y' || result?.verified === true
  const valid = result?.valid === 'y' || result?.valid === true
  return result?.in_database && verified && valid
    ? [{ source: 'PhishTank', category: 'phishing', url, referenceUrl: result.phish_detail_page || 'https://phishtank.org/' }]
    : []
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
