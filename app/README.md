# Demo App

This directory contains a demonstration FastAPI app that is intentionally kept separate from the installable `openetr` component.

## Why It Is Separate

The root Poetry package defines `openetr` as the installable component. Files and dependencies under `app/` do not become part of that component unless the root packaging configuration is explicitly changed.

This keeps:

- the reusable `openetr` package clean
- FastAPI and app-only dependencies out of the core component
- the demo web app free to evolve independently

## Install

Install the component from the repo root if you want the app to import package code later:

```sh
poetry install
```

Install app-only dependencies separately:

```sh
pip install -r app/requirements.txt
```

This installs the web-only dependencies used by the demo app, including FastAPI, Jinja templates, multipart upload support, Gunicorn, and session-cookie support.

## Run

From the repo root:

```sh
gunicorn app.main:app -k uvicorn.workers.UvicornWorker --reload
```

Then open:

- `http://127.0.0.1:8000/`
- `http://127.0.0.1:8000/docs`

## Current Demo

The current demo app renders an OpenETR `query-etr` style result page from an uploaded file digest.

The result page includes the same categories of information shown by the CLI:

- the initial ETR origin event
- issuer social profile details
- matching origin records
- matching control events
- the summary control chain
- the current controller

## Docker

The app can also be built and run as a single container.

Build from the repo root so Docker can see both the `openetr` package and the `app/` directory:

```sh
docker build -f app/Dockerfile -t openetr-web .
```

Run it:

```sh
docker run --rm -p 8000:8000 \
  -e OPENETR_APP_SESSION_SECRET=change-me \
  -e OPENETR_ROOT_NSEC=your-root-nsec \
  -e OPENETR_HOME_RELAYS=wss://your-home-relay \
  openetr-web
```

Then open:

- `http://127.0.0.1:8000/`
- `http://127.0.0.1:8000/docs`

## Docker Compose

A simple Compose file is also available at the repo root:

```sh
docker compose up --build
```

It uses the same build context and `gunicorn` entrypoint as the standalone Docker run.

If you want to override the session secret:

```sh
OPENETR_APP_SESSION_SECRET=change-me docker compose up --build
```

For stateless relay-backed operation, also provide the root bootstrap and home relays as environment variables:

```sh
OPENETR_APP_SESSION_SECRET=change-me \
OPENETR_ROOT_NSEC=your-root-nsec \
OPENETR_HOME_RELAYS=wss://your-home-relay \
docker compose up --build
```

If you change the runtime bootstrap values, restart the service:

```sh
docker compose down
docker compose up --build
```

## Do We Need Docker Compose?

Not strictly.

Right now the web app is still a single service, so the `Dockerfile` is enough for straightforward build and deployment.

Compose is now included mainly for convenience and for future growth. It becomes more useful if you later want to add:

- a reverse proxy
- a separate API container
- local development volumes and overrides
- observability or background workers

## Stateless Runtime Model

The intended container deployment model is stateless:

- no mounted `~/.openetr` directory
- no local `config.yaml` required in the container
- relay-backed profiles, profile config, and signer secrets
- runtime bootstrap supplied by environment variables

For the web app to discover relay-backed profiles and encrypted profile signer records, supply:

- `OPENETR_ROOT_NSEC`
- `OPENETR_HOME_RELAYS`

The browser session may still hold the logged-in `nsec` in a signed cookie for this demo app, but the container itself does not rely on local profile or session files.
