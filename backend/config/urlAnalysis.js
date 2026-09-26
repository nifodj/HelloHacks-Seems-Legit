export const MAX_URL_LENGTH = 2048
export const RISK_WEIGHTS = {
  knownThreat: 100,
  strongBrandImpersonation: 40,
  brandInSubdomain: 35,
  homograph: 35,
  newDomain: 20,
  ipAddress: 15,
  suspiciousPattern: 15,
  suspiciousKeywords: 5,
  unusualPort: 5,
  shortenedUrl: 5,
  http: 5,
  excessiveSubdomains: 5,
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
