# Import an existing Python or TypeScript app

Airlock apps use the Go Agent SDK for authentication, lifecycle, tools, and the
runtime manifest. Existing HTTP applications do not need a business-logic
rewrite: this importer creates a small native host around their unchanged
Python or TypeScript source.

## 1. Inspect first

```sh
python3 tools/import-app/import_app.py /path/to/app --plan
```

The JSON plan is deliberately AI-friendly. It detects Python or TypeScript,
reports whether a launch command is known, and lists the exact private
environment names, model-callable routes, and platform capabilities that the
wrapper attaches automatically: authentication, caller identity, the web
proxy, readiness, and process lifecycle. A coding assistant may propose an
`airlock.app.json`, but a human must review the command and every capability.
No endpoint is exported as a model tool merely because it exists.

An optional source-owned manifest removes repeated CLI flags:

```json
{
  "runtime": "python",
  "command": ["python3", "app.py", "--port", "{port}"],
  "description": "Existing invoicing application",
  "healthPath": "/health",
  "environment": ["DATABASE_URL"],
  "toolRoutes": ["POST:/quote"]
}
```

Only environment variable names belong here. Values remain encrypted Airlock
configuration. TypeScript projects with a `start` package script can usually
infer `npm run start`; Python commands stay explicit unless the manifest
supplies one.

## 2. Package

Python:

```sh
python3 tools/import-app/import_app.py /path/to/python-app /tmp/python-airlock \
  --runtime python \
  --command 'python3 app.py --port {port}' \
  --tool-route 'POST:/quote'
```

TypeScript:

```sh
python3 tools/import-app/import_app.py /path/to/typescript-app /tmp/typescript-airlock \
  --runtime typescript \
  --command 'npm run start'
```

The result is a normal Agent SDK source directory and a sibling `.tar.gz`
source archive. Deploy it with the standard `air` CLI:

```sh
air login https://your-airlock.example
air deploy /tmp/python-airlock --create --name "Imported app" \
  --url https://your-airlock.example -m "Import existing application"
```

Airlock still owns authentication. The host strips Airlock credentials and
caller-shaped headers before proxying, then injects the authenticated
`X-Airlock-User-ID` and access level. User cookies that do not belong to
Airlock are retained for the application's own session model.

`toolRoutes` is an operator allowlist, not discovery. The model can call only
those exact method/path pairs through `app_request`; uncertain results are not
automatically retried. Side-effecting operations must retain their own approval
flow or remain in the web UI.

## Runtime and storage behavior

- `setup.sh` installs the selected runtime and dependencies while the image is
  built. Python uses a private venv; TypeScript uses the lockfile when present
  and runs the package's `build` script when defined.
- The application process binds to the private loopback port (default `8181`).
  `{port}` is replaced in argv, and `PORT`/`HOST=127.0.0.1` are also supplied.
- `.env*`, common private-key files, local databases, virtualenvs, and
  `node_modules` are excluded. Original source bytes and executable modes are
  recorded in `source-manifest.json` and are never edited.
- Object storage is optional for the imported application. Airlock's turnkey
  installer already provisions its own bundled object store and bucket by
  default; those credentials are not leaked into app code. If the application
  needs a database or S3-compatible store, declare only its existing variable
  names with `--env` and configure their values privately in Airlock.

This is an HTTP-app bridge, not automatic migration of desktop programs,
SQLite files, background schedulers, or arbitrary local state. The application
keeps responsibility for its own data authorization and persistence.

## Verify

```sh
python3 -m unittest discover -s tools/import-app -p 'test_*.py'

python3 tools/import-app/import_app.py \
  tools/import-app/fixtures/python_flask /tmp/python-import-proof \
  --command 'python3 app.py --port {port}' --tool-route 'POST:/sum'
(cd /tmp/python-import-proof && go mod tidy && go test -count=1 ./...)

python3 tools/import-app/import_app.py \
  tools/import-app/fixtures/typescript_http /tmp/typescript-import-proof
(cd /tmp/typescript-import-proof && go mod tidy && go test -count=1 ./...)
```
