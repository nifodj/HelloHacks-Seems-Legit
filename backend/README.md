# Seems Legit backend

This Node.js server checks message text, screenshots, and URLs for common scam warning signs. Message and URL analysis use explainable rules; screenshot analysis uses local OCR. The server does not save submissions. Optional URL intelligence integrations can send the submitted URL to external providers when enabled, as described below.

## Run it

You need Node.js 22 or later. From this folder, install dependencies and start the server:

```sh
npm install
npm start
```

The server listens at `http://localhost:3001`. Use `npm run dev` while changing code; Node restarts the server when a file changes.

## API

### URL analysis

Send a URL to the dedicated URL analyzer. A scheme is required in the UI; the API also accepts a bare hostname and normalizes it to HTTPS.

```sh
curl -X POST http://localhost:3001/api/analyze/url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://secure.paypal.com.account-verification.example.com/login"}'
```

You may include `messageContext` for lightweight context signals. The response includes the normalized URL and registered domain, technical details, explainable signals, a cautious verdict and score, domain registration and DNS availability, provider status and matches, and limitations. Unknown reputation is never treated as proof that a URL is safe.

Local checks do not visit the submitted site or follow redirects. DNS and RDAP checks are disabled by default and can be enabled on the backend with `URL_DNS_LOOKUP=true` and `URL_RDAP_LOOKUP=true`. These checks send the domain (not the full URL) to DNS resolvers or the RDAP service. Results are time limited and are skipped for local/private IP destinations.

Threat-intelligence lookups are also disabled unless configured. Set backend environment variables to enable them:

- `GOOGLE_SAFE_BROWSING_API_KEY` enables Google Safe Browsing.
- `VIRUSTOTAL_API_KEY` enables VirusTotal.
- `PHISHTANK_API_KEY` enables PhishTank.
- `URLHAUS_ENABLED=true` enables URLhaus.
- `OPENPHISH_ENABLED=true` enables the OpenPhish community feed, cached in memory for 15 minutes.

Enabled providers receive the submitted URL, including its path and query parameters. Keep keys on the backend; do not add them to frontend environment variables. Provider failures are reported as unavailable and do not block local analysis. Threat-feed matches are grouped into one risk class so multiple feeds do not inflate the score repeatedly.

`backend/config/urlAnalysis.js` contains the initial brand list, URL shorteners, maximum URL length, and risk weights for adjustment. Domain age and reputation are only shown when successfully retrieved. A URL that is absent from checked databases is not necessarily safe.

URL checks intentionally never fetch the user submitted destination, execute page code, follow redirects, or download content. That avoids the SSRF and unsafe redirect risks described in the project brief.

### Message analysis

Send a `POST` request to `http://localhost:3001/api/analyze` with JSON:

```json
{
  "message": "Urgent: verify your account at https://example.invalid"
}
```

Optional `interaction` tells the backend what the user did. Choose one value:

- `none` (the default)
- `clicked_link`
- `shared_password`
- `shared_code`
- `shared_payment`
- `shared_personal_info`

For example, if the person entered a password after clicking, send `"interaction": "shared_password"`. The response will include `recoverySteps`. If no action happened, omit the field or use `none`.

The response includes:

- `verdict`: `likely legitimate`, `suspicious`, or `likely scam`
- `confidence`: a cautious `low` or `medium` estimate, not a guarantee
- `signals`: the reasons the rules matched
- `formatMatches`: scam-format references that share at least two cues with the message. Each match includes its name, strength (`partial` or `strong`), matched cues, and a link to the public source.
- `nextSteps`: what to do about the message
- `recoverySteps`: action-specific help, or an empty list
- `privacyReminder` and `disclaimer`: safety reminders to show in the app

An empty message gets HTTP `400`, a message over the request limit gets `413`, and other paths get `404`. The server accepts browser requests from the local frontend at `http://localhost:5173`.

`formatMatches` compares cue groups from FTC and FBI Internet Crime Complaint Center advisories covering account/payment alerts, unexpected invoices, delivery-fee notices, vendor payment changes, and executive or payroll impersonation. It reports a resemblance to a scam format, not a match to an exact archived email or proof that a message is fraudulent. Reference pages are linked in each match; the analyzer does not fetch them at request time.

## Try it

With the server running, send a sample request from another terminal:

```sh
curl -X POST http://localhost:3001/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"message":"Urgent! Verify your account with your password at https://example.invalid","interaction":"shared_password"}'
```

Use fabricated examples only. Do not submit passwords, one-time codes, payment details, or other secrets. The server does not store messages, but the frontend should also remind users before they paste one.

## Screenshot analysis

The screenshot endpoint accepts one `image` file and an optional `interaction` field as `multipart/form-data`. Supported image types are JPEG, PNG, and WebP. The actual image signature is checked; the supplied filename and MIME type are not trusted. Uploads are limited to 5 MB and processed in memory.

OCR uses Tesseract.js locally in the backend. The screenshot is not sent to an OCR provider. The first OCR run downloads the English language model if it is not cached; the model is cached locally and ignored by Git. OCR can misread text, and the rule-based analyzer can miss scams or flag legitimate messages.

Example with `curl`:

```sh
curl -X POST http://localhost:3001/api/analyze-screenshot \
  -F 'image=@/path/to/screenshot.png' \
  -F 'interaction=clicked_link'
```

Omit `interaction` if no recovery guidance is needed. Do not set the multipart `Content-Type` header manually when using browser `FormData`; the browser must add its boundary:

```js
const formData = new FormData()
formData.append('image', file)
formData.append('interaction', 'none')

const response = await fetch('http://localhost:3001/api/analyze-screenshot', {
  method: 'POST',
  body: formData,
})
const result = await response.json()
```

Successful responses contain `extractedText`, `analysis` (the existing analyzer result, including recovery steps and disclaimers), and OCR metadata. If little text is recognized, `ocr.limitedText` is `true` and `ocr.warning` explains the uncertainty. No readable text returns `422` rather than a legitimate verdict.

| Test case | Expected response |
| --- | --- |
| Phishing screenshot with an urgent request to verify an account using a password and a link | `200`; extracted text and the analyzer's `likely scam` assessment |
| Legitimate service notice with no common warning phrases | `200`; extracted text and typically `likely legitimate` from the basic rules |
| Urgent gift-card or wire-payment request | `200`; extracted text and typically `likely scam` from the payment and urgency signals |
| Screenshot with no readable text | `422`; readable-text error, with no scam assessment |
| Non-image bytes named `something.png` | `415`; unsupported image type, based on the bytes rather than the filename |
| Image larger than 5 MB | `413`; upload-size error |
| Truncated/corrupt image with a recognizable image signature | `422`; invalid/readable-image error |
| Very short readable text, such as `Help` | `200`; analysis is still returned, marked `suspicious` with low confidence and an OCR warning |
| OCR worker failure | `500`; generic OCR error without internal details |

Run the deterministic route tests with:

```sh
npm test
```

The route tests use generated images and a controlled OCR result so they run quickly and reproducibly. The OCR-failure case injects a simulated worker failure. To exercise real OCR, start the server and use `curl` with a real screenshot fixture as shown above.

Other expected error statuses: malformed multipart or missing `image` returns `400`; an unsupported request content type returns `415`; and internal analysis failures return a generic `500` response.

## Connecting a machine-learning service later

The current analyzer is `analyzeMessage` in `server.js`. A future version can call a text-classification service from that function (or from a new helper it calls). Keep the service call on the backend so its API key stays private:

1. Choose a provider and a model that supports text classification or structured JSON output.
2. Store the key in an environment variable, such as `SCAM_MODEL_API_KEY`; never put it in React/browser code or commit it to Git.
3. Send only the pasted message and ask for a small structured result: warning signs and a suggested risk category. Do not send it unless your privacy notice tells users about the external service.
4. Validate the service response and combine its suggestions with the existing rule checks. Treat the model as another fallible signal, not proof.
5. If the key is missing, the service is unavailable, or its response is invalid, return a useful error or fall back to the local rules.

Before adding a provider, decide what its privacy and data-retention terms mean for messages users submit. The current version makes no external requests.
