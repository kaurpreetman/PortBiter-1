# PortBiter frontend

This frontend renders the PortBiter dashboard and talks to the FastAPI backend over HTTP and WebSocket.

## Required setup

1. Start the backend first, typically on port 8000.
2. Set `NEXT_PUBLIC_API_URL` to the backend's origin (scheme included, no path), not the frontend's URL. For local development, use `http://localhost:8000`; for deployment, use the public URL of the FastAPI service. This value is embedded in the frontend at build time, so set it in the frontend deployment's environment settings and redeploy after changing it.
3. Install dependencies and run the dev server:

```bash
npm install
npm run dev -- --hostname 127.0.0.1 --port 3000
```

## Expected runtime

- The backend must expose the scan HTTP routes and `/ws/{scan_id}` over WebSocket (`wss://` in production). A static/serverless host that does not support persistent WebSocket connections is not sufficient for live scans.
- The backend must be running before starting a scan from the UI.
- Configure `GROQ_API_KEY` in the backend environment to enable scan creation.
- The report download button calls the backend PDF endpoint directly.
