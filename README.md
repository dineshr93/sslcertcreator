# sslcreator

![Demo of the app](image_ssl.gif)

Web tool for generating and managing SSL certificates. Gradio UI wrapped around `openssl` commands, packaged as a Docker container.

## Features

Five tabs in the web UI:

- **CSR Request** — generate a private key and CSR. Builds an OpenSSL config file (`.cnf`) with subject fields and SAN (DNS alternative names) table, runs `openssl req`, and offers the `.cnf`, `.key`, and `.csr` files for download. Also has a button to delete generated files from the server.
- **Nginx Converter** — turn nginx-issued material into a deployable bundle. Extracts the certificate chain from a `.p7b` (PEM or DER) into `nginx-bundle.crt`, converts a DER `nginx.crt` to `nginx.pem`, concatenates the two into `nginx-fullchain.crt`, and rewrites a passphrase-protected private key as an unencrypted `nginx-nopass.key`. Run the four steps individually or with **Convert All**, watching live status chips.
- **Convert Certificate** — auto-detects the uploaded file format (PEM, DER, or a CSR) and converts between PEM and DER with `openssl x509`. CSRs are rejected (they are not certificates); converting to the file's own format is a no-op.
- **Create New Keystore** — build a keystore from a certificate + key with `openssl pkcs12 -export`. The Platform dropdown picks the output: Linux → `keystore.jks`, Windows → `keystore.pfx` (with `-legacy` for broad Windows/Java import). Optional "Key Password" field for a passphrase-protected key file.
- **Root CA Integrator** — a local root CA store in `./root_cas`: upload and save root CA certificates, "load all ROOT CAs" rehashes the store (`openssl rehash`) and lists what is trusted, and uploaded certificates can be verified against the whole store (`openssl verify -CApath`).

All tabs share a **New Session / Clear** button in the top toolbar: after a confirmation prompt it deletes every file the tool generated on the server (`.cnf`, `.key`, `.csr`, keystores, nginx outputs) and resets each field, ready for the next certificate. Uploaded files are never touched. The interface runs on a refreshed, light/dark-adaptive theme with card-based sections and comfortable, scroll-free download areas.

## Quick start

### Docker

```bash
docker build -t sslcreator .

# one-off run
docker run --rm -d --name sslcreator -p 7860:7860 sslcreator

# or, to restart automatically after reboots
docker run -d --restart unless-stopped --name sslcreator -p 7860:7860 sslcreator
```

Then open http://localhost:7860

### Makefile

The `Makefile` builds the image as `dineshr93/ssltool:1.0` (instead of the local `sslcreator` tag) and records the container id in `container_id.txt`:

```bash
make r    # remove any old container + image, then build and run (detached)
make run  # run an already-built image
make rm   # stop the container and remove both container and image
```

### Local (no Docker)

```bash
pip install gradio pandas
python app.py
```

## Usage notes

- Files are written to `/usr/src/app` inside the container (the default save location `./`). Add a volume mount, e.g. `-v certs:/usr/src/app`, if you want to keep the generated keys and CSRs after the container exits. The Root CA store lives in `./root_cas` — mount that too if you want CAs to persist.
- The default password for the key is the server name itself. The "Key Password" field in the Keystore tab is only for a passphrase-protected key file.
- Gradio listens on `0.0.0.0:7860` (set in the Dockerfile via `GRADIO_SERVER_NAME`).
- Server names / keyfile names must be a single word (`A-Z a-z 0-9 . _ -` only) — they end up as filenames.

## Security notes

- Commands run as argv lists (no shell), so shell metacharacters cannot be injected through filenames.
- OpenSSL passphrases are passed via environment variables (`SSLCERT_PASS` / `SSLCERT_KEYPASS`, using `env:...` in the openssl argv) instead of `pass:...` on the command line, so they don't show in the process list.
- Config-file fields are stripped of newlines to prevent injection into the generated `.cnf`.

## Requirements

- Python 3.14 (Docker image base; any Python with `gradio` + `pandas` available works)
- Python packages: `gradio`, `pandas`
- `openssl` must be on the PATH (it is present in the `python:3.14-slim` base image)

## Project layout

```
app.py        # the entire app: openssl helpers + Gradio UI
Dockerfile    # python:3.14-slim, installs gradio + pandas, exposes 7860
.dockerignore # keeps .venv/.git/cert material out of the build context
Makefile      # convenience build/run/clean targets
```
