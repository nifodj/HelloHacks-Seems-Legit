# Seems Legit backend template

This folder contains a tiny Node.js web server for the scam-message checker. It has no extra packages to install. It accepts a message at `POST /api/analyze` and returns a verdict, warning signs, and next steps as JSON.

## Start it

1. Install Node.js if it is not already installed.
2. Open a terminal in this `backend` folder.
3. Run `npm run dev` (or `npm start`).
4. The server will print `http://localhost:3001` when it is ready.

The React/Vite website usually runs at `http://localhost:5173`. The backend allows requests from that local address.

## Try a request

Send a POST request to `http://localhost:3001/api/analyze` with this JSON body:

```json
{
  "message": "Urgent! Click here to verify your account with your password."
}
```

The response has this shape:

```json
{
  "verdict": "likely scam",
  "confidence": "medium",
  "signals": ["..."],
  "nextSteps": ["..."],
  "disclaimer": "..."
}
```

## What each function does

- **`sendJson(response, statusCode, data)`**: Sends information back to the webpage in JSON format. The status number tells the webpage whether the request worked (200), had a problem (400/413), or used an unknown address (404).
- **`readRequestBody(request)`**: Collects the information the webpage sent. It limits the request size and turns the JSON text into data the server can use.
- **`analyzeMessage(message)`**: Checks the message for a few known warning phrases, chooses a cautious verdict, and creates practical next steps. This is a simple demonstration rule set, not an AI or proof that a message is safe.
- **`handleRequest(request, response)`**: The traffic director. It accepts the webpage's connection check, verifies the address and request format, calls the analyzer, and returns helpful errors when needed.
- **`createServer(...).listen(...)`**: Turns the server on and keeps it ready for requests. `PORT` can change the port; it defaults to 3001.

## Important limits

This starter does not save messages or call an AI service. Its phrase checks can miss scams and can flag harmless messages. A result of “likely legitimate” does not mean a message is safe. Do not paste passwords, one-time codes, payment details, or other secrets into the demo.
