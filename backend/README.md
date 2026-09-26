# Seems Legit backend

This small Node.js server accepts a message, checks it for common scam warning signs, and returns a cautious result. It does not save messages or call an AI service. Its checks are simple rules, so they can miss scams or flag ordinary messages.

## Run it

You need Node.js installed. From this folder, run:

```sh
npm start
```

The server listens at `http://localhost:3001`. Use `npm run dev` while changing code; Node restarts the server when a file changes.

## API

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
- `nextSteps`: what to do about the message
- `recoverySteps`: action-specific help, or an empty list
- `privacyReminder` and `disclaimer`: safety reminders to show in the app

An empty message gets HTTP `400`, a message over the request limit gets `413`, and other paths get `404`. The server accepts browser requests from the local frontend at `http://localhost:5173`.

## Try it

With the server running, send a sample request from another terminal:

```sh
curl -X POST http://localhost:3001/api/analyze \
  -H 'Content-Type: application/json' \
  -d '{"message":"Urgent! Verify your account with your password at https://example.invalid","interaction":"shared_password"}'
```

Use fabricated examples only. Do not submit passwords, one-time codes, payment details, or other secrets. The server does not store messages, but the frontend should also remind users before they paste one.

## Connecting a machine-learning service later

The current analyzer is `analyzeMessage` in `server.js`. A future version can call a text-classification service from that function (or from a new helper it calls). Keep the service call on the backend so its API key stays private:

1. Choose a provider and a model that supports text classification or structured JSON output.
2. Store the key in an environment variable, such as `SCAM_MODEL_API_KEY`; never put it in React/browser code or commit it to Git.
3. Send only the pasted message and ask for a small structured result: warning signs and a suggested risk category. Do not send it unless your privacy notice tells users about the external service.
4. Validate the service response and combine its suggestions with the existing rule checks. Treat the model as another fallible signal, not proof.
5. If the key is missing, the service is unavailable, or its response is invalid, return a useful error or fall back to the local rules.

Before adding a provider, decide what its privacy and data-retention terms mean for messages users submit. The current version makes no external requests.
