# Setup

A first-run walkthrough. You need Docker with Compose, and nothing else.

## 1. Get the code

```bash
git clone https://github.com/skraft9/quarry-vrc.git quarry && cd quarry
```

## 2. Configure

```bash
cp .env.example .env
$EDITOR .env
```

The only value you must set is `QUARRY_ADMIN_PASSWORD` - the first admin login is created from it,
and the server refuses to start without one. Everything else has a sensible default:

- `QUARRY_ALLOWLIST` is empty (open), which is fine for a host only you can reach. Set it to your
  IP/CIDR list to lock it down.
- `QUARRY_PORT` defaults to `8443`.
- `QUARRY_APP_NAME` is the name shown in the UI - rename it to whatever you like.

Your HackerOne credentials are **not** set here. You paste them once in the app (step 5), so they
are stored server-side and never rendered back.

## 3. Run

```bash
docker compose up -d
docker compose logs -f quarry     # watch the first-boot banner and the URL it prints
```

On first boot the container:

1. generates `config.json` on the data volume from your env,
2. generates a self-signed local CA + TLS certificate (unless you set `QUARRY_TLS_MODE=mounted`),
3. creates the database schema,
4. indexes whatever markdown is already in the workspace volume,
5. prints the URL and starts serving.

## 4. Sign in

Open the printed `https://<host>:<port>/`. Your browser will warn about the self-signed certificate;
the **Certificates** page (the seal icon by the version, bottom-left) serves the local CA and walks
through trusting it so the warning goes away for good. Sign in with `QUARRY_ADMIN_USER` /
`QUARRY_ADMIN_PASSWORD`.

## 5. Connect HackerOne

Open **Integrations**, paste your HackerOne API username and token. They are verified against the
live API before they are stored. Then the Tracker fills with your reports, Programs with your scope,
and you can submit a finished report straight from the app.

## 6. (optional) Load the payload library

The **Payloads** tab is populated from a public payload reference cloned onto the payloads volume.
Trigger the clone/sync from the app, or run `scripts/sync-payloads.sh` inside the container.

## Upgrading

```bash
docker compose pull
docker compose up -d
```

The image is replaced; your data volumes carry everything across untouched.

## Bringing your own files

Prefer to keep leads or payloads on your host? Bind-mount them in `docker-compose.yml`:

```yaml
    volumes:
      - /path/to/my/workspace:/workspace
      - /path/to/my/payloads:/payloads
```

They are indexed on the next boot (or a re-index from the app).
