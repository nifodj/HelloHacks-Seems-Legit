export const MAX_URL_LENGTH = 2048
export const RISK_WEIGHTS = {
  knownThreat: 100,
  strongBrandImpersonation: 40,
  brandInSubdomain: 40,
  homograph: 40,
  newDomain: 25,
  ipAddress: 20,
  suspiciousPattern: 20,
  suspiciousKeywords: 10,
  unusualPort: 8,
  shortenedUrl: 10,
  http: 8,
  excessiveSubdomains: 10,
}

export const BRANDS = {
  PayPal: ['paypal.com'],
  Microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'office365.com', 'login.live.com', 'onedrive.com', 'sharepoint.com', 'microsoftonline.com'],
  Google: ['google.com', 'gmail.com', 'googlemail.com'],
  Apple: ['apple.com', 'icloud.com'],
  Amazon: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'amazon.co.jp'],
  Netflix: ['netflix.com'],
  GitHub: ['github.com'],
}

export const URL_SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'shorturl.at'])
