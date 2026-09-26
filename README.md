# HelloHacks-Seems-Legit

HelloHacks 2026 project: check suspicious emails and forms of communication of indicators of a scam and provides information.

## Project Brief

- **Problem:** People may have trouble deciding whether a message is legitimate and what to do after interacting with a scam.
- **Audience:** Anyone who receives a suspicious email or text message.
- **Proposed solution:** Analyze a message for known scam patterns, explain the warning signs, and provide safe next steps. If someone clicked a link or shared information, include account recovery guidance.
- **Primary user action:** Paste a suspicious message and request an assessment.

## MVP

- [ ] Accept pasted email or text content.
- [ ] Show a clear result: likely legitimate, suspicious, or likely scam.
- [ ] Explain the specific signals behind the result.
- [ ] Give practical next steps appropriate to the result.
- [ ] Handle empty input and analysis failures with a useful message.
- [ ] Include a visible reminder not to submit passwords, payment details, or other sensitive information.

Keep the demo focused on this flow. Defer accounts, inbox integrations, and other features until the core flow works.

## User Flow

1. The user pastes a message into the app.
2. The app analyzes the content for common scam indicators.
3. The app displays a result, reasons, and relevant next steps.
4. The user can edit the message and run another check.

## Architecture

Fill in the choices as the team makes them; keep the first version as small as possible.

| Part | Responsibility | Choice |
| --- | --- | --- |
| Frontend | Message input, loading/error states, and result display | TBD |
| Backend | Validate input, run analysis, and return a structured result | TBD |
| Detection data | Store or query known scam indicators | TBD |
| Language model | Explain findings and suggest next steps, if used | TBD |
| Hosting | Run the demo for judges and teammates | TBD |

Suggested analysis flow: validate and limit the input, check for known indicators, combine those findings with any model-generated explanation, and return a cautious assessment. Do not treat a model response as proof that a message is safe.

## API Contract (Draft)

### `POST /api/analyze`

Request:

```json
{
	"message": "Paste the message to check"
}
```

Response:

```json
{
	"verdict": "suspicious",
	"confidence": "medium",
	"signals": ["Urgent request for personal information"],
	"nextSteps": ["Contact the organization using its official website or phone number."],
	"disclaimer": "This assessment can be wrong. Verify important requests through an official channel."
}
```

Keep verdicts and confidence calibrated; when the evidence is unclear, say so instead of presenting certainty.

## Build Plan

1. **Agree on the demo:** Confirm the user, problem, and one successful end-to-end example.
2. **Sketch the interface:** Decide what the user enters and what the result needs to show.
3. **Build the happy path:** Return a temporary example result so the frontend and backend can be connected early.
4. **Implement analysis:** Add scam indicators and, if time allows, a language-model explanation.
5. **Cover edge cases:** Check empty, long, benign, suspicious, and ambiguous messages, plus service failures.
6. **Deploy and rehearse:** Test the deployed flow and prepare a short demo using sample messages only.

## Local Setup

Run the frontend and backend in separate terminals from the repository root.

```powershell
# Terminal 1: frontend
Set-Location .\@seems-legit
npm install
npm run dev
```

```powershell
# Terminal 2: backend
Set-Location .\backend
npm run dev
```

## Configuration

- Keep API keys and credentials in environment variables, never in source control.
- Add required variable names and safe example values here; do not commit real secrets.
- Provide a clear error when a required integration is not configured.

## Safety and Privacy

- Tell users not to paste passwords, one-time codes, payment details, or other secrets.
- Avoid storing submitted messages unless storage is necessary and clearly disclosed.
- Do not claim a message is definitely safe based only on automated analysis.
- Make recovery advice conditional and direct users to official organization channels.
- Use fabricated messages for demos; do not expose real personal information.

## Demo Checklist

- [ ] The deployed app loads on the presentation device.
- [ ] A benign sample and a scam sample both produce understandable results.
- [ ] The result explains its reasoning and offers relevant next steps.
- [ ] Loading, invalid input, and analysis failure states are presentable.
- [ ] The team can explain what is rule-based, what uses an external service, and known limitations.

## Team Notes

- **Team:** TBD
- **Demo URL:** TBD
- **Repository owner:** TBD
- **Known limitations:** TBD
- **Next steps after the hackathon:** TBD
