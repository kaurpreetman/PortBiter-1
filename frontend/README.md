# PortBiter frontend

This frontend renders the PortBiter dashboard and talks to the FastAPI backend over HTTP and WebSocket.

## Required setup

1. Start the backend first, typically on port 8000.
2. Set the API base URL for the browser if the backend is not on the default local address:
   - `NEXT_PUBLIC_API_URL=http://127.0.0.1:8000`
3. Install dependencies and run the dev server:

```bash
npm install
npm run dev -- --hostname 127.0.0.1 --port 3000
```

## Expected runtime

- The dashboard expects the backend scan API and WebSocket endpoint to be available.
- The backend must be running before starting a scan from the UI.
- The report download button calls the backend PDF endpoint directly.
