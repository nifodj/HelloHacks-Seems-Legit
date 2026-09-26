// Format summaries based on public FTC and FBI IC3 scam advisories. These are
// explainable cue groups, not a corpus of verbatim emails or a sender lookup.
const scamFormats = [
  {
    name: 'Account or payment problem alert',
    source: 'FTC: How to Recognize and Avoid Phishing Scams',
    sourceUrl: 'https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams',
    cues: [
      { label: 'Claims an account, login, or payment problem', pattern: /\b(account|login|payment|billing|charge)\b.{0,45}\b(problem|issue|hold|locked|suspend(?:ed)?|failed|declined|unusual|confirm)\b|\b(?:problem|issue|hold|locked|suspend(?:ed)?|failed|declined|unusual)\b.{0,45}\b(account|login|payment|billing|charge)\b/i },
      { label: 'Pushes the recipient to verify or update information', pattern: /\b(verify|confirm|update|restore|secure|sign[ -]?in|log[ -]?in)\b.{0,45}\b(account|payment|billing|password|details|information|identity)\b|\b(account|payment|billing|password|details|information|identity)\b.{0,45}\b(verify|confirm|update|restore|secure)\b/i },
      { label: 'Includes a link or a deadline to act', pattern: /https?:\/\/|www\.|\b(within 24 hours|immediately|urgent|expires today|act now|final warning)\b/i },
    ],
  },
  {
    name: 'Unexpected invoice or renewal notice',
    source: 'FTC: How to Recognize and Avoid Phishing Scams',
    sourceUrl: 'https://consumer.ftc.gov/articles/how-recognize-and-avoid-phishing-scams',
    cues: [
      { label: 'Mentions an invoice, receipt, order, or renewal', pattern: /\b(invoice|receipt|order|subscription|renewal|purchase)\b/i },
      { label: 'Asks for payment or claims money is due', pattern: /\b(pay(?:ment)?|amount due|past due|charged|charge|billing|refund|cancel|dispute)\b/i },
      { label: 'Prompts a quick response through a link, phone number, or attachment', pattern: /https?:\/\/|www\.|\b(call|contact|click|open|download|attachment|within 24 hours|immediately|urgent)\b/i },
    ],
  },
  {
    name: 'Package delivery fee or address notice',
    source: 'FTC: Fake USPS and delivery messages',
    sourceUrl: 'https://consumer.ftc.gov/consumer-alerts/2025/04/think-text-message-usps-it-could-be-scam',
    cues: [
      { label: 'Mentions a package, shipment, or delivery', pattern: /\b(package|parcel|shipment|delivery|tracking|postage)\b/i },
      { label: 'Claims delivery failed or requests a fee or address update', pattern: /\b(missed|failed|unable|held|delayed|fee|postage|address|reschedule|redeliver|update)\b/i },
      { label: 'Links to a page or asks for personal or payment details', pattern: /https?:\/\/|www\.|\b(card|payment|personal information|details|confirm|verify)\b/i },
    ],
  },
  {
    name: 'Vendor invoice or payment-detail change (business email compromise)',
    source: 'FBI IC3: Business Email Compromise Tactics Used to Defraud Vendors',
    sourceUrl: 'https://www.ic3.gov/PSA/2023/psa230324',
    cues: [
      { label: 'Discusses a vendor, supplier, invoice, or purchase order', pattern: /\b(vendor|supplier|invoice|purchase order|accounts payable)\b/i },
      { label: 'Requests payment or a change to bank or payment details', pattern: /\b(payment|pay|wire|transfer|bank|account|routing|ACH|remittance)\b/i },
      { label: 'Mentions new or changed instructions, urgency, or confidentiality', pattern: /\b(new|change|changed|update|different|alternate|revised|urgent|immediately|confidential|secret)\b.{0,50}\b(account|bank|payment|wire|instructions|details|invoice)\b|\b(account|bank|payment|wire|instructions|details|invoice)\b.{0,50}\b(new|change|changed|update|different|alternate|revised|urgent|immediately|confidential|secret)\b/i },
    ],
  },
  {
    name: 'Executive impersonation or payroll-data request',
    source: 'FBI IC3: Business Email Compromise — The 3.1 Billion Dollar Scam',
    sourceUrl: 'https://www.ic3.gov/PSA/2016/PSA160614',
    cues: [
      { label: 'Mentions an executive, HR, payroll, tax form, or employee records', pattern: /\b(CEO|CFO|executive|boss|HR|human resources|payroll|W[ -]?2|tax form|employee records|personnel records)\b/i },
      { label: 'Requests money, a wire, gift cards, or sensitive staff information', pattern: /\b(wire|transfer|payment|gift cards?|W[ -]?2|tax form|employee information|personal information|records|direct deposit)\b/i },
      { label: 'Creates urgency or asks the recipient to keep the request secret', pattern: /\b(urgent|immediately|asap|today|confidential|secret|do not tell|don't tell|keep this between us)\b/i },
    ],
  },
]

export function findScamFormatMatches(message) {
  return scamFormats.flatMap((format) => {
    const matchedCues = format.cues
      .filter((cue) => cue.pattern.test(message))
      .map((cue) => cue.label)

    if (matchedCues.length < 2) return []

    return [{
      name: format.name,
      strength: matchedCues.length === format.cues.length ? 'strong' : 'partial',
      matchedCues,
      referenceCueCount: format.cues.length,
      source: format.source,
      sourceUrl: format.sourceUrl,
    }]
  })
}
