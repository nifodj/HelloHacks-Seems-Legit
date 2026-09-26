import { useState } from 'react'

const inputTypes = [
  { value: 'email', label: 'Email', description: 'Paste or upload an email' },
  { value: 'screenshot', label: 'Screenshot', description: 'Upload an image' },
  { value: 'transcript', label: 'Phone transcript', description: 'Paste a call transcript' },
  { value: 'url', label: 'URL', description: 'Paste a suspicious website address' },
]

const recoveryActions = [
  { value: 'clicked_link', label: 'I clicked a link' },
  { value: 'shared_password', label: 'I shared a password' },
  { value: 'shared_code', label: 'I shared a sign-in or verification code' },
  { value: 'shared_payment', label: 'I sent money or shared payment details' },
  { value: 'shared_personal_info', label: 'I shared other personal information' },
]

const API_BASE_URL = (import.meta.env.VITE_API_URL || '').replace(/\/+$/, '')

function ShieldIcon({ className = 'h-5 w-5' }) {
  return (
    <svg aria-hidden="true" className={className} viewBox="0 0 24 24" fill="none">
      <path d="M12 3 20 6v5.4c0 4.7-3.2 8.1-8 9.6-4.8-1.5-8-4.9-8-9.6V6l8-3Z" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" />
      <path d="m8.8 12.1 2.1 2.1 4.5-4.6" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function UploadIcon({ className = 'h-5 w-5' }) {
  return (
    <svg aria-hidden="true" className={className} viewBox="0 0 24 24" fill="none">
      <path d="M12 15V4m0 0L8 8m4-4 4 4M5 15v4a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-4" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function ArrowIcon() {
  return (
    <svg aria-hidden="true" className="h-4 w-4" viewBox="0 0 24 24" fill="none">
      <path d="M5 12h14m-6-6 6 6-6 6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function formatAnalysis(analysis, extra = {}) {
  const analysisLevel = analysis.verdict === 'likely scam'
    ? 'high'
    : analysis.verdict === 'suspicious'
      ? 'caution'
      : 'clear'
  const level = extra.ocrWarning && analysisLevel === 'clear' ? 'caution' : analysisLevel
  const summary = extra.ocrWarning
    ? 'The screenshot contained little readable text, so this assessment may be unreliable. Review the recognized text before relying on it.'
    : level === 'high'
    ? 'Several warning signs were found. Do not click links, reply, or provide information or payment.'
    : level === 'caution'
      ? 'A warning sign was found. Verify the request through a trusted, independent channel before acting.'
      : 'No common warning signs were found. This does not prove the message is safe.'

  return {
    ...analysis,
    verdict: extra.ocrWarning && analysisLevel === 'clear' ? 'Limited text recognized' : analysis.verdict,
    level,
    summary,
    signals: Array.isArray(analysis.signals) ? analysis.signals : [],
    formatMatches: Array.isArray(analysis.formatMatches) ? analysis.formatMatches : [],
    nextSteps: Array.isArray(analysis.nextSteps) ? analysis.nextSteps : [],
    ...extra,
  }
}

function App() {
  const [inputType, setInputType] = useState('email')
  const [message, setMessage] = useState('')
  const [attachment, setAttachment] = useState(null)
  const [result, setResult] = useState(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [showRecoveryOptions, setShowRecoveryOptions] = useState(false)
  const [recoveryAction, setRecoveryAction] = useState('')
  const [isRecoveryPopupOpen, setIsRecoveryPopupOpen] = useState(false)

  function changeInputType(event) {
    setInputType(event.target.value)
    setMessage('')
    setAttachment(null)
    setResult(null)
    setShowRecoveryOptions(false)
    setRecoveryAction('')
    setIsRecoveryPopupOpen(false)
  }

  async function handleFile(event) {
    const file = event.target.files?.[0]
    if (!file) return

    setResult(null)
    setIsRecoveryPopupOpen(false)
    setAttachment(file)
    if (inputType === 'email') {
      setMessage(await file.text())
    }
  }

  async function analyzeInput(interaction = 'none') {
    if (isAnalyzing) return

    setIsAnalyzing(true)
    setResult(null)
    setIsRecoveryPopupOpen(false)

    try {
      let response
      if (inputType === 'screenshot') {
        if (!attachment) throw new Error('Choose a screenshot before submitting.')
        const formData = new FormData()
        formData.append('image', attachment)
        formData.append('interaction', interaction)

        response = await fetch(`${API_BASE_URL}/api/analyze-screenshot`, {
          method: 'POST',
          body: formData,
        })
      } else {
        response = await fetch(`${API_BASE_URL}/api/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: message.trim(), interaction }),
        })
      }

      const data = await response.json().catch(() => null)
      if (!data) throw new Error('The backend returned an unreadable response.')
      if (!response.ok) throw new Error(data.error || 'The message could not be analyzed.')
      let formattedResult
      if (inputType === 'screenshot') {
        if (!data.success || !data.analysis) throw new Error(data.error || 'The screenshot could not be analyzed.')
        formattedResult = formatAnalysis(data.analysis, {
          extractedText: data.extractedText,
          ocrWarning: data.ocr?.warning,
        })
      } else {
        formattedResult = formatAnalysis(data)
      }
      setResult(formattedResult)
      setIsRecoveryPopupOpen(Boolean(formattedResult.recoverySteps?.length))
      setShowRecoveryOptions(false)
    } catch (error) {
      setResult({
        verdict: 'Analysis unavailable',
        level: 'error',
        summary: error instanceof TypeError
          ? `Could not reach the backend${API_BASE_URL ? ` at ${API_BASE_URL}` : ''}. Make sure it is running.`
          : error.message,
        signals: [],
        nextSteps: ['Check the backend server and try again.'],
      })
      setIsRecoveryPopupOpen(false)
    } finally {
      setIsAnalyzing(false)
    }
  }

  async function handleSubmit(event) {
    event.preventDefault()
    if (event.nativeEvent.submitter?.dataset.recoverySubmit === 'true') {
      await requestRecoverySteps()
      return
    }
    setRecoveryAction('')
    await analyzeInput()
  }

  async function requestRecoverySteps() {
    if (!recoveryAction || isAnalyzing) return
    await analyzeInput(recoveryAction)
  }

  const selectedType = inputTypes.find((type) => type.value === inputType)
  const canSubmit = inputType === 'screenshot' ? Boolean(attachment) : Boolean(message.trim())

  return (
    <div className="min-h-screen bg-[#07131d] text-[#e8f3f1]">
      <div className="pointer-events-none fixed inset-0 -z-0 bg-[linear-gradient(rgba(54,224,205,0.055)_1px,transparent_1px),linear-gradient(90deg,rgba(54,224,205,0.055)_1px,transparent_1px)] bg-[size:36px_36px]" />

      <header className="relative z-10 border-b border-[#173340] bg-[#091923]/90">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4 sm:px-8">
          <a href="#home" className="flex items-center gap-3" aria-label="Seems Legit home">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-[#10313b] text-[#4ce8d3] shadow-[0_0_24px_-8px_rgba(54,224,205,0.55)]">
              <ShieldIcon className="h-6 w-6" />
            </span>
            <span className="text-[15px] font-bold tracking-[-0.02em] text-[#e8f3f1]">seems<span className="text-[#4ce8d3]">legit</span></span>
          </a>
          <div className="flex items-center gap-2 rounded-full border border-[#1d414b] bg-[#102630] px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.12em] text-[#9ec6bf]">
            <span className="h-1.5 w-1.5 rounded-full bg-[#a6f16d] shadow-[0_0_8px_rgba(166,241,109,0.75)]" />
            Private by design
          </div>
        </div>
      </header>

      <main id="home" className="relative z-10 mx-auto max-w-7xl px-5 pb-12 pt-10 sm:px-8 sm:pt-14">
        <section className="mb-8 flex flex-col justify-between gap-6 md:mb-10 md:flex-row md:items-end">
          <div className="max-w-2xl">
            <p className="mb-3 flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.17em] text-[#54dcca]">
              <span className="h-px w-6 bg-[#54dcca]" />
              A calmer way to check
            </p>
            <h1 className="max-w-xl text-[36px] font-semibold leading-[1.08] tracking-[-0.045em] text-[#eff8f6] sm:text-[48px]">
              Something feel off? <span className="text-[#55e4d1]">Let’s look closer.</span>
            </h1>
              <p className="mt-4 max-w-xl text-[15px] leading-7 text-[#9ab0aa]">
              Check a suspicious email, screenshot, phone call transcript, or website URL for common scam signals.
            </p>
          </div>
          <div className="flex max-w-xs items-center gap-3 rounded-xl border border-[#1d3c46] bg-[#0c202a] px-4 py-3 text-[12px] leading-5 text-[#9ab0aa]">
            <ShieldIcon className="h-5 w-5 shrink-0 text-[#52dfcd]" />
            <span><strong className="font-semibold text-[#d8e9e3]">Your content stays private.</strong> Text and screenshots are sent to your backend for analysis and are not stored.</span>
          </div>
        </section>

        <form onSubmit={handleSubmit} className="overflow-hidden rounded-2xl border border-[#1b3945] bg-[#0d1e28] shadow-[0_24px_90px_-35px_rgba(0,0,0,0.8),0_0_48px_-32px_rgba(54,224,205,0.38)]">
          <div className="grid lg:grid-cols-[1.04fr_0.96fr]">
            <section className="border-b border-[#1b3945] p-5 sm:p-8 lg:border-b-0 lg:border-r" aria-labelledby="input-heading">
              <div className="mb-6 flex items-start justify-between gap-4">
                <div>
                  <p className="mb-1 text-[10px] font-bold uppercase tracking-[0.16em] text-[#51cdbc]">Step 01 / Input</p>
                  <h2 id="input-heading" className="text-lg font-semibold tracking-[-0.02em] text-[#e7f2ef]">What would you like to check?</h2>
                </div>
                <span className="rounded-md border border-[#24505a] bg-[#102a34] px-2 py-1 font-mono text-[10px] text-[#83cfc1]">SECURE SESSION</span>
              </div>

              <label htmlFor="input-type" className="mb-2 block text-xs font-semibold text-[#b1c7be]">Information type</label>
              <div className="relative mb-5">
                <select
                  id="input-type"
                  value={inputType}
                  onChange={changeInputType}
                  className="w-full appearance-none rounded-lg border border-[#284550] bg-[#091923] px-3.5 py-3 pr-10 text-sm font-medium text-[#e0eeea] outline-none transition focus:border-[#43d9c6] focus:ring-4 focus:ring-[#43d9c6]/15"
                >
                  {inputTypes.map((type) => <option key={type.value} value={type.value}>{type.label}</option>)}
                </select>
                <svg aria-hidden="true" className="pointer-events-none absolute right-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-[#80aaa0]" viewBox="0 0 20 20" fill="none">
                  <path d="m5 7.5 5 5 5-5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>

              {inputType === 'screenshot' ? (
                <div className="flex min-h-[285px] flex-col">
                  <label htmlFor="screenshot-file" className="group flex flex-1 cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-[#32616a] bg-[#0a1c26] px-5 py-8 text-center transition hover:border-[#4ce8d3] hover:bg-[#102932]">
                    {attachment ? (
                      <>
                        <span className="mb-3 flex h-11 w-11 items-center justify-center rounded-xl bg-[#153943] text-[#4ce8d3]">
                          <UploadIcon className="h-5 w-5" />
                        </span>
                        <span className="max-w-full truncate text-sm font-semibold text-[#d8e9e3]">{attachment?.name}</span>
                        <span className="mt-1 text-xs text-[#91aaa0]">Screenshot added · Choose a different file</span>
                      </>
                    ) : (
                      <>
                        <span className="mb-3 flex h-11 w-11 items-center justify-center rounded-xl bg-[#153943] text-[#4ce8d3] transition group-hover:bg-[#1c4b53]">
                          <UploadIcon className="h-5 w-5" />
                        </span>
                        <span className="text-sm font-semibold text-[#d8e9e3]">Choose a screenshot to upload</span>
                        <span className="mt-1.5 text-xs text-[#91aaa0]">PNG, JPG, or WEBP · 5 MB max</span>
                      </>
                    )}
                    <input id="screenshot-file" type="file" accept="image/png,image/jpeg,image/webp" className="sr-only" onChange={handleFile} />
                  </label>
                  <p className="mt-3 text-[11px] leading-5 text-[#8ba49a]">Screenshots are sent to your backend for local OCR and scam analysis. Images are not sent to an OCR provider.</p>
                </div>
              ) : (
                <>
                  <div className="mb-2 flex items-center justify-between gap-3">
                    <label htmlFor="message" className="text-xs font-semibold text-[#b1c7be]">
                      {inputType === 'email' ? 'Email content' : inputType === 'url' ? 'Website URL' : 'Call transcript'}
                    </label>
                    {inputType === 'email' && (
                      <label htmlFor="email-file" className="inline-flex cursor-pointer items-center gap-1.5 text-[11px] font-semibold text-[#57d6c5] transition hover:text-[#a4f58c]">
                        <UploadIcon className="h-3.5 w-3.5" />
                        Upload .eml or .txt
                        <input id="email-file" type="file" accept=".eml,.txt,message/rfc822,text/plain" className="sr-only" onChange={handleFile} />
                      </label>
                    )}
                  </div>
                  {inputType === 'url' ? (
                    <>
                      <input
                        id="message"
                        type="url"
                        value={message}
                        onChange={(event) => { setMessage(event.target.value); setResult(null); setIsRecoveryPopupOpen(false) }}
                        maxLength={2048}
                        required
                        pattern="https?://.+"
                        title="Enter a URL starting with http:// or https://"
                        inputMode="url"
                        autoCapitalize="none"
                        autoCorrect="off"
                        spellCheck={false}
                        placeholder="https://example.com/login"
                        className="h-14 w-full rounded-xl border border-[#284550] bg-[#091923] px-4 text-sm text-[#e0eeea] outline-none transition placeholder:text-[#6f8981] focus:border-[#43d9c6] focus:ring-4 focus:ring-[#43d9c6]/15"
                      />
                      <p className="mt-3 text-[11px] leading-5 text-[#8ba49a]">We check the address text only. This demo does not open the link or inspect the website.</p>
                    </>
                  ) : (
                    <textarea
                      id="message"
                      value={message}
                      onChange={(event) => { setMessage(event.target.value); setResult(null); setIsRecoveryPopupOpen(false) }}
                      maxLength={10000}
                      placeholder={inputType === 'email' ? 'Paste the email text here. You can include the sender, subject, and message body...' : 'Add the words you remember from the call. Include what they asked you to do...'}
                      className="min-h-[238px] w-full resize-y rounded-xl border border-[#284550] bg-[#091923] p-4 text-sm leading-6 text-[#e0eeea] outline-none transition placeholder:text-[#6f8981] focus:border-[#43d9c6] focus:ring-4 focus:ring-[#43d9c6]/15"
                    />
                  )}
                  <div className="mt-2 flex items-center justify-between text-[11px] text-[#829c92]">
                    <span>{selectedType?.description}</span>
                    <span>{message.length.toLocaleString()} / {inputType === 'url' ? '2,048' : '10,000'}</span>
                  </div>
                  {attachment && inputType === 'email' && (
                    <div className="mt-3 flex items-center justify-between gap-3 rounded-lg bg-[#122a32] px-3 py-2 text-xs text-[#b3c9c0]">
                      <span className="truncate">Loaded {attachment.name}</span>
                      <button type="button" onClick={() => { setAttachment(null); setMessage(''); setIsRecoveryPopupOpen(false) }} className="shrink-0 font-semibold hover:text-[#4ce8d3]">Remove</button>
                    </div>
                  )}
                </>
              )}

              {isRecoveryPopupOpen && result?.recoverySteps?.length > 0 && (
                <section role="region" aria-live="polite" aria-labelledby="recovery-popup-heading" className="mt-5 rounded-xl border border-[#805144] bg-[#2b2222] p-4 shadow-[0_12px_32px_-18px_rgba(255,152,119,0.65)]">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#ff9877]">Recovery guidance</p>
                      <h3 id="recovery-popup-heading" className="mt-1 text-sm font-semibold text-[#fff0e7]">What to do now</h3>
                    </div>
                    <button
                      type="button"
                      aria-label="Close recovery steps"
                      onClick={() => setIsRecoveryPopupOpen(false)}
                      className="rounded-md px-2 py-1 text-xs font-semibold text-[#d9b8aa] hover:bg-[#493331] hover:text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#ffd05c]"
                    >
                      Close
                    </button>
                  </div>
                  <ol className="mt-3 list-inside list-decimal space-y-2 text-[13px] leading-5 text-[#eedbd3]">
                    {result.recoverySteps.map((step) => <li key={step}>{step}</li>)}
                  </ol>
                </section>
              )}
            </section>

            <section className="flex min-h-[390px] flex-col bg-[#0a1a24] p-5 sm:p-8" aria-labelledby="results-heading" aria-live="polite">
              <div className="mb-6 flex items-start justify-between gap-4">
                <div>
                  <p className="mb-1 text-[10px] font-bold uppercase tracking-[0.16em] text-[#51cdbc]">Step 02 / Destination</p>
                  <h2 id="results-heading" className="text-lg font-semibold tracking-[-0.02em] text-[#e7f2ef]">Your scan results</h2>
                </div>
                <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#24505a] bg-[#102a34] text-[#4ce8d3]">
                  <ShieldIcon className="h-[18px] w-[18px]" />
                </span>
              </div>

              {isAnalyzing ? (
                <div className="flex flex-1 flex-col items-center justify-center py-12 text-center">
                  <span className="mb-4 h-9 w-9 animate-spin rounded-full border-2 border-[#dbe8dd] border-t-[#4e8764]" />
                  <p className="text-sm font-semibold text-[#dbeae3]">Checking for common warning signs</p>
                  <p className="mt-1 text-xs text-[#8da59a]">{inputType === 'screenshot' ? 'Uploading screenshot and extracting text with OCR.' : 'Sending your message to the backend analyzer.'}</p>
                </div>
              ) : result ? (
                <div className="flex flex-1 flex-col animate-[fade-in_300ms_ease-out]">
                  <div className={`rounded-xl border p-4 ${result.level === 'high' || result.level === 'error' ? 'border-[#793d43] bg-[#321f2a]' : result.level === 'caution' ? 'border-[#806739] bg-[#302b20]' : result.level === 'pending' ? 'border-[#31505a] bg-[#102630]' : 'border-[#35634e] bg-[#142d2b]'}`}>
                    <div className="flex items-center gap-2">
                      <span className={`h-2 w-2 rounded-full shadow-[0_0_9px_currentColor] ${result.level === 'high' || result.level === 'error' ? 'bg-[#ff7568] text-[#ff7568]' : result.level === 'caution' ? 'bg-[#ffd05c] text-[#ffd05c]' : result.level === 'pending' ? 'bg-[#74a2aa] text-[#74a2aa]' : 'bg-[#9be879] text-[#9be879]'}`} />
                      <p className="text-[10px] font-bold uppercase tracking-[0.13em] text-[#9ab5aa]">{result.level === 'error' ? 'Backend error' : result.level === 'pending' ? 'Action needed' : result.level === 'clear' ? 'Preliminary check' : 'Warning signs'}</p>
                    </div>
                    <h3 className="mt-2 text-base font-semibold text-[#eef7f3]">{result.verdict}</h3>
                    <p className="mt-1.5 text-[13px] leading-5 text-[#b5c9c0]">{result.summary}</p>
                  </div>

                  {result.extractedText && (
                    <div className="mt-5">
                      <h3 className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#6ed4c7]">Text recognized</h3>
                      <pre className="mt-2 max-h-36 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-[#24404a] bg-[#071720] p-3 font-sans text-xs leading-5 text-[#c7d9d1]">{result.extractedText}</pre>
                      {result.ocrWarning && <p className="mt-2 text-xs leading-5 text-[#ffd05c]">{result.ocrWarning}</p>}
                    </div>
                  )}

                  <div className="mt-5">
                    <h3 className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#6ed4c7]">Signals detected</h3>
                    {result.signals.length ? (
                      <ul className="mt-2 space-y-2">
                        {result.signals.map((signal) => (
                          <li key={signal} className="flex items-center gap-2.5 text-[13px] text-[#d5e4dd]">
                            <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-[#ff9877] shadow-[0_0_8px_rgba(255,152,119,0.55)]" />{signal}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="mt-2 text-[13px] text-[#8ca59a]">{result.level === 'pending' ? 'No text signals checked yet.' : 'No matching patterns in this quick check.'}</p>
                    )}
                  </div>

                  <div className="mt-5 border-t border-[#24404a] pt-4">
                    <h3 className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#6ed4c7]">Reference format matches</h3>
                    <p className="mt-2 text-[11px] leading-5 text-[#8da59a]">These results compare message cues with scam formats described by the FTC and FBI. They do not identify an exact archived email.</p>
                    {result.formatMatches.length ? (
                      <ul className="mt-3 space-y-3">
                        {result.formatMatches.map((match) => (
                          <li key={match.name} className="rounded-lg border border-[#284550] bg-[#0b202a] p-3">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <p className="text-[13px] font-semibold text-[#d5e4dd]">{match.name}</p>
                              <span className="rounded-full border border-[#806739] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-[#ffd05c]">
                                {match.strength === 'strong' ? 'Strong resemblance' : 'Partial resemblance'}
                              </span>
                            </div>
                            <p className="mt-1 text-[11px] text-[#9ab5aa]">{match.matchedCues.length} of {match.referenceCueCount} reference cues found</p>
                            <ul className="mt-2 list-inside list-disc space-y-1 text-[11px] leading-5 text-[#b5c9c0]">
                              {match.matchedCues.map((cue) => <li key={cue}>{cue}</li>)}
                            </ul>
                            <a href={match.sourceUrl} target="_blank" rel="noreferrer" className="mt-2 inline-block text-[11px] font-semibold text-[#57d6c5] underline decoration-[#32616a] underline-offset-2 hover:text-[#a4f58c]">
                              Source: {match.source}
                            </a>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="mt-2 text-[12px] leading-5 text-[#9ab5aa]">No close format match was found in these references. Scams vary, so this does not establish that a message is legitimate.</p>
                    )}
                  </div>

                  <div className="mt-5 border-t border-[#24404a] pt-4">
                    <h3 className="text-[10px] font-bold uppercase tracking-[0.14em] text-[#6ed4c7]">What to do next</h3>
                    <ul className="mt-2 space-y-2">
                      {result.nextSteps.map((step) => <li key={step} className="text-[13px] leading-5 text-[#b5c9c0]">{step}</li>)}
                    </ul>
                  </div>

                  {(result.level === 'high' || result.level === 'caution' || result.formatMatches?.length > 0) && !result.recoverySteps?.length && (
                    <div className="mt-5 rounded-xl border border-[#5a4140] bg-[#211f23] p-4">
                      <button
                        type="button"
                        aria-expanded={showRecoveryOptions}
                        aria-controls="recovery-options"
                        onClick={() => setShowRecoveryOptions((isOpen) => !isOpen)}
                        className="text-left text-sm font-semibold text-[#ffd0a6] underline decoration-[#8d6254] underline-offset-4 hover:text-[#fff0df] focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-[#ffd05c]"
                      >
                        Already interacted with it? Get recovery steps
                      </button>
                      {showRecoveryOptions && (
                        <div id="recovery-options" className="mt-4">
                          <label htmlFor="recovery-action" className="block text-xs font-semibold text-[#d5c5b5]">
                            What did you do?
                          </label>
                          <select
                            id="recovery-action"
                            value={recoveryAction}
                            onChange={(event) => setRecoveryAction(event.target.value)}
                            className="mt-2 w-full rounded-lg border border-[#5a4140] bg-[#111b22] px-3 py-2.5 text-sm text-[#e8f3f1] outline-none focus:border-[#ffd05c] focus:ring-4 focus:ring-[#ffd05c]/15"
                          >
                            <option value="">Choose what happened</option>
                            {recoveryActions.map((action) => <option key={action.value} value={action.value}>{action.label}</option>)}
                          </select>
                          <button
                            type="submit"
                            data-recovery-submit="true"
                            formNoValidate
                            disabled={!recoveryAction || isAnalyzing}
                            className="mt-3 rounded-lg bg-[#ffd05c] px-4 py-2.5 text-xs font-bold text-[#201a0a] transition hover:bg-[#ffe39b] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#ffd05c] disabled:cursor-not-allowed disabled:bg-[#5a5543] disabled:text-[#b9b19a]"
                          >
                            Show my recovery steps
                          </button>
                        </div>
                      )}
                    </div>
                  )}

                  {result.disclaimer && <p className="mt-4 text-[11px] leading-5 text-[#8da59a]">{result.disclaimer}</p>}

                  {result.recoverySteps?.length > 0 && !isRecoveryPopupOpen && (
                    <button
                      type="button"
                      onClick={() => setIsRecoveryPopupOpen(true)}
                      className="mt-5 self-start rounded-lg border border-[#805144] px-3 py-2 text-xs font-semibold text-[#ffd0a6] hover:bg-[#211f23] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#ffd05c]"
                    >
                      View recovery steps
                    </button>
                  )}
                </div>
              ) : (
                <div className="flex flex-1 flex-col items-center justify-center py-12 text-center">
                  <div className="relative mb-5 flex h-16 w-16 items-center justify-center rounded-2xl border border-[#28505c] bg-[#102a34] text-[#4ce8d3] shadow-[0_0_32px_-14px_rgba(54,224,205,0.55)]">
                    <ShieldIcon className="h-8 w-8" />
                    <span className="absolute -right-1 -top-1 h-3 w-3 rounded-full border-2 border-[#0a1a24] bg-[#a6f16d] shadow-[0_0_10px_rgba(166,241,109,0.7)]" />
                  </div>
                  <p className="text-sm font-semibold text-[#dbeae3]">Your results will appear here</p>
                  <p className="mt-1.5 max-w-xs text-xs leading-5 text-[#8da59a]">Add a message or screenshot, then run a check to see signals and recommended next steps.</p>
                </div>
              )}

              <div className="mt-4 flex items-start gap-2 border-t border-[#24404a] pt-4 text-[11px] leading-5 text-[#8da59a]">
                <span className="mt-0.5 font-mono text-[10px] text-[#57d6c5]">i</span>
                <p>This quick demo is not a security service. A clean result does not guarantee a message is safe.</p>
              </div>
            </section>
          </div>

          <div className="flex flex-col gap-4 border-t border-[#1b3945] bg-[#0d1e28] px-5 py-5 sm:flex-row sm:items-center sm:justify-between sm:px-8">
            <p className="max-w-md text-[11px] leading-5 text-[#8da59a]">Avoid entering passwords, one-time codes, or payment information. Content is sent to your backend for analysis and is not stored.</p>
            <button
              type="submit"
              disabled={!canSubmit || isAnalyzing}
              className="group inline-flex min-h-12 w-full items-center justify-center gap-2.5 rounded-lg bg-[#40dfcb] px-6 text-sm font-bold text-[#082019] shadow-[0_0_25px_-9px_rgba(64,223,203,0.8)] transition hover:bg-[#a6f16d] hover:shadow-[0_0_28px_-7px_rgba(166,241,109,0.65)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#a6f16d] disabled:cursor-not-allowed disabled:bg-[#36534f] disabled:text-[#8ca59a] disabled:shadow-none sm:w-auto"
            >
              {isAnalyzing ? 'Checking message...' : 'Is this a scam?'}
              {!isAnalyzing && <span className="transition-transform group-hover:translate-x-0.5"><ArrowIcon /></span>}
            </button>
          </div>
        </form>

        <footer className="mt-6 flex flex-col gap-2 text-[10px] font-medium uppercase tracking-[0.12em] text-[#78948a] sm:flex-row sm:items-center sm:justify-between">
          <span>Seems Legit <span className="px-1.5 text-[#3d625a]">/</span> Message safety, made clearer</span>
          <span>Prototype analysis · Always verify independently</span>
        </footer>
      </main>
    </div>
  )
}

export default App
