# WatchGuard EPDR Isolated Device Alert

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Python](https://img.shields.io/badge/Python-3.12-blue)
![Docker](https://img.shields.io/badge/Docker-ready-0db7ed)
![Requests](https://img.shields.io/badge/requests-HTTP%20client-orange)

A lightweight watcher that polls WatchGuard EPDR tenants for isolated endpoints and automatically opens ConnectWise service tickets. State is persisted locally so the watcher can resume after restarts without duplicating tickets.

## Features
- Polls managed WatchGuard tenants on a configurable cadence to detect isolated devices.
- Creates ConnectWise tickets with detailed device metadata when isolation begins, and posts a note when isolation clears.
- Caches WatchGuard audience and tenant tokens to minimize API calls.
- Maintains on-disk state for devices, tenants, and cached ConnectWise mappings under `./data/state.json`.
- Ships with Docker and Docker Compose for repeatable deployment.

## Technology stack
- Python 3.12 (async-free polling loop)
- `requests` for HTTP calls
- `python-dotenv` for environment configuration
- Docker/Docker Compose for containerized execution

## Prerequisites
- Docker and Docker Compose installed (for containerized runs), or Python 3.12+ with `pip` (for local runs).
- Credentials for both WatchGuard Cloud and ConnectWise configured as environment variables (see below).

## Configuration
Create a `.env` file in the project root (used by `docker-compose.yml`) or export the variables locally. Required variables:

### WatchGuard
- `WG_ACCESS_ID`, `WG_ACCESS_PASSWORD`, `WG_API_KEY`, `WG_PARTNER_ACCOUNT_ID` – Partner authentication and tenant discovery.
- `WG_AUTH_URL` – OAuth token endpoint (defaults to `https://api.usa.cloud.watchguard.com/oauth/token`).
- `WG_REGION` – Regional prefix for WatchGuard API hosts (defaults to `usa`).
- `WG_BASE_EPDR_URL`, `WG_BASE_ACCOUNTS_URL` – Override endpoints if needed.
- `TENANT_REFRESH_MINUTES` – Minutes between tenant syncs (default `1440`).
- `DEVICE_POLL_MINUTES` – Minutes between device polls on weekdays (default `60`).

### ConnectWise
- `CW_BASE_URL`, `CW_COMPANY_ID`, `CW_PUBLIC_KEY`, `CW_PRIVATE_KEY`, `CW_CLIENT_ID` – ConnectWise API access.
- `CW_DEFAULT_BOARD_ID`, `CW_HOLLISTER_BOARD_ID` – Board selection.
- `CW_DEFAULT_STATUS_ID`, `CW_DEFAULT_PRIORITY_ID`, `CW_DEFAULT_SOURCE_ID` – Ticket metadata defaults.
- `CW_FALLBACK_COMPANY_NAME` – Company to use when tenant name mapping fails.

## Running with Docker Compose
1. Populate `.env` with the values above.
2. Start the watcher:
   ```bash
   docker compose up --build
   ```
3. State data will be written to `./data/state.json` on the host via the `./data:/data` volume.

## Running with Docker only
```bash
docker build -t wg-epdr-cw-watcher .
docker run --rm \
  --env-file .env \
  -v $(pwd)/data:/data \
  wg-epdr-cw-watcher
```

## Running locally (without Docker)
1. Install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. Export environment variables (or load them from `.env` with `python-dotenv`).
3. Run the watcher:
   ```bash
   python main.py
   ```

## Operational notes
- The main loop sleeps for five minutes between cycles and skips device polling on weekends; cadence is controlled by `TENANT_REFRESH_MINUTES` and `DEVICE_POLL_MINUTES`.
- WatchGuard tenant tokens and ConnectWise company mappings are cached in `state.json` to reduce API calls.
- Isolation events transition from non-isolated→isolated create tickets; isolated→non-isolated add a closing note to the existing ticket.
- Logs are printed to stdout; when running in Docker, use `docker logs` to inspect activity.

## Project structure
- `main.py` – Core polling loop and integration logic for WatchGuard and ConnectWise.
- `requirements.txt` – Python dependencies.
- `Dockerfile` – Container image definition targeting Python 3.12-slim.
- `docker-compose.yml` – Compose service wiring with environment loading and persistent state volume.

## License
This project is licensed under the terms of The Unlicense License. See [LICENSE](LICENSE) for details.
