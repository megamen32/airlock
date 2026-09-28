#!/usr/bin/env python3
"""Package an existing Python or TypeScript HTTP app for Airlock."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import tarfile
from typing import Any, Iterable
import zipfile


PLAN_SCHEMA = "airlock.import-plan.v1"
MANIFEST_NAME = "airlock.app.json"
SUPPORTED_RUNTIMES = {"python", "typescript"}
EXCLUDED = {
    ".git", ".venv", "venv", "__pycache__", "node_modules", ".airlock",
    ".pytest_cache", ".mypy_cache", ".idea", ".vscode", ".ssh", ".aws",
    ".gnupg",
}
PRIVATE_SUFFIXES = {".pem", ".key", ".p12", ".sqlite", ".sqlite3", ".db"}
MAX_SOURCE_FILES = 10_000
MAX_SOURCE_BYTES = 128 * 1024 * 1024
ROUTE = re.compile(r"(GET|POST|PUT|PATCH|DELETE|OPTIONS):/[^?#\s]*")
ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]*")


def _source_files(source: Path) -> list[Path]:
    files: list[Path] = []
    for directory, directories, names in os.walk(source):
        directories[:] = sorted(
            name for name in directories
            if name not in EXCLUDED and not name.startswith(".env")
        )
        if any((Path(directory) / name).is_symlink() for name in directories):
            raise ValueError("source directory symlinks must be resolved explicitly")
        files.extend(Path(directory) / name for name in sorted(names))
    return files


def _read_manifest(source: Path) -> dict[str, Any]:
    path = source / MANIFEST_NAME
    if not path.exists():
        return {}
    if path.stat().st_size > 64 * 1024:
        raise ValueError(f"{MANIFEST_NAME} exceeds 64 KiB")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {MANIFEST_NAME}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{MANIFEST_NAME} must contain one JSON object")
    allowed = {
        "runtime", "command", "description", "port", "healthPath",
        "environment", "toolRoutes",
    }
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ValueError(f"unknown {MANIFEST_NAME} fields: {', '.join(unknown)}")
    return data


def detect_runtime(source: Path, files: Iterable[Path] | None = None) -> str:
    files = list(files if files is not None else _source_files(source))
    relative = [path.relative_to(source) for path in files if path.is_file()]
    python = any(path.name in {"requirements.txt", "pyproject.toml", "setup.py"} or path.suffix == ".py" for path in relative)
    typescript = (source / "package.json").is_file() and (
        (source / "tsconfig.json").is_file()
        or any(path.suffix in {".ts", ".tsx", ".mts", ".cts"} for path in relative)
    )
    if python == typescript:
        if python:
            raise ValueError("both Python and TypeScript markers found; select --runtime explicitly")
        raise ValueError("no supported Python or TypeScript application markers found")
    return "python" if python else "typescript"


def _command(value: Any, source: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        result = shlex.split(value)
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        result = list(value)
    else:
        raise ValueError(f"{source} command must be a string or string array")
    if not result or len(result) > 200 or any(not item or len(item) > 4096 for item in result):
        raise ValueError(f"{source} command is empty or exceeds the argument limits")
    return result


def _inferred_command(runtime: str, source: Path) -> list[str]:
    if runtime != "typescript":
        return []
    package = source / "package.json"
    try:
        data = json.loads(package.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid package.json: {exc}") from exc
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if isinstance(scripts, dict) and isinstance(scripts.get("start"), str) and scripts["start"].strip():
        return ["npm", "run", "start"]
    main = data.get("main") if isinstance(data, dict) else None
    if isinstance(main, str) and main.strip() and not Path(main).is_absolute() and ".." not in Path(main).parts:
        return ["node", main]
    return []


def _string_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a string array")
    return list(value)


def _unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result


def plan(
    source: str | Path,
    *,
    runtime: str | None = None,
    command: str | list[str] | None = None,
    description: str | None = None,
    port: int | None = None,
    health_path: str | None = None,
    env: Iterable[str] = (),
    tool_routes: Iterable[str] = (),
) -> dict[str, Any]:
    source = Path(source).resolve()
    if not source.is_dir():
        raise ValueError("source directory is required")
    manifest = _read_manifest(source)
    selected_runtime = runtime or manifest.get("runtime") or detect_runtime(source)
    if selected_runtime not in SUPPORTED_RUNTIMES:
        raise ValueError("runtime must be python or typescript")
    selected_command = _command(command, "CLI") if command is not None else _command(manifest.get("command"), MANIFEST_NAME)
    inferred = False
    if not selected_command:
        selected_command = _inferred_command(selected_runtime, source)
        inferred = bool(selected_command)
    runtime_label = "TypeScript" if selected_runtime == "typescript" else "Python"
    selected_description = description if description is not None else manifest.get("description", f"Existing {runtime_label} application hosted by Airlock")
    selected_port = port if port is not None else manifest.get("port", 8181)
    selected_health = health_path if health_path is not None else manifest.get("healthPath", "/")
    selected_env = _unique([*_string_list(manifest.get("environment"), "environment"), *env])
    selected_routes = _unique([*_string_list(manifest.get("toolRoutes"), "toolRoutes"), *tool_routes])
    if not isinstance(selected_description, str) or not selected_description.strip() or len(selected_description) > 1000:
        raise ValueError("description must be between 1 and 1000 characters")
    if not isinstance(selected_port, int) or isinstance(selected_port, bool) or not 1024 <= selected_port <= 65535:
        raise ValueError("port must be between 1024 and 65535")
    if not isinstance(selected_health, str) or not selected_health.startswith("/") or selected_health.startswith("//") or "?" in selected_health or "#" in selected_health:
        raise ValueError("healthPath must be one local absolute path")
    if len(set(selected_env)) != len(selected_env) or any(
        not ENV_NAME.fullmatch(name) or name.startswith("AIRLOCK_") or name in {"PATH", "HOME", "PORT", "HOST", "HOSTNAME"}
        for name in selected_env
    ):
        raise ValueError("invalid or duplicate application environment name")
    for route in selected_routes:
        route_path = route.split(":", 1)[1] if ":" in route else ""
        if not ROUTE.fullmatch(route) or "://" in route or route_path.startswith("//") or ".." in route_path.split("/"):
            raise ValueError("toolRoutes must contain exact METHOD:/path entries")
    return {
        "schema": PLAN_SCHEMA,
        "ready": bool(selected_command),
        "runtime": selected_runtime,
        "command": selected_command,
        "commandInferred": inferred,
        "description": selected_description.strip(),
        "port": selected_port,
        "healthPath": selected_health,
        "environment": selected_env,
        "toolRoutes": selected_routes,
        "automaticCapabilities": [
            "native_authentication",
            "caller_identity",
            "web_proxy",
            "readiness",
            "process_lifecycle",
        ],
        "applicationStorage": {
            "mode": "none",
            "note": "Airlock object storage is not exposed as application credentials. Declare an existing database or object-store URL by environment name only when the app needs it.",
        },
    }


def _source_archive(source: Path) -> tuple[bytes, dict[str, str], list[str]]:
    archive = io.BytesIO()
    hashes: dict[str, str] = {}
    skipped: list[str] = []
    total_bytes = 0
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zipped:
        for path in _source_files(source):
            relative = path.relative_to(source)
            if any(part in EXCLUDED or part.startswith(".env") for part in relative.parts):
                continue
            if path.is_symlink():
                raise ValueError(f"symlinks must be resolved explicitly: {relative}")
            if not path.is_file():
                continue
            name = relative.as_posix()
            if not name or any(ord(character) < 32 for character in name):
                raise ValueError("source filenames may not contain control characters")
            if path.suffix.lower() in PRIVATE_SUFFIXES:
                skipped.append(name)
                continue
            data = path.read_bytes()
            if len(data) > 32 * 1024 * 1024:
                raise ValueError(f"file exceeds source package limit: {name}")
            total_bytes += len(data)
            if len(hashes) >= MAX_SOURCE_FILES or total_bytes > MAX_SOURCE_BYTES:
                raise ValueError("source package exceeds the file-count or uncompressed-size limit")
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | stat.S_IMODE(path.stat().st_mode)) << 16
            zipped.writestr(info, data)
            hashes[name] = hashlib.sha256(data).hexdigest()
    payload = archive.getvalue()
    if not hashes or len(payload) > 32 * 1024 * 1024:
        raise ValueError("empty or oversized source package")
    return payload, hashes, skipped


def _setup_script(runtime: str, payload: bytes) -> str:
    encoded = base64.b64encode(payload).decode("ascii")
    common = """#!/bin/sh
set -eu
apt-get update
RUNTIME_PACKAGES
rm -rf /var/lib/apt/lists/*
mkdir -p /opt/airlock-app/app
python3 - <<'AIRLOCK_SOURCE'
import base64, io, os, zipfile
with zipfile.ZipFile(io.BytesIO(base64.b64decode("PAYLOAD"))) as archive:
    archive.extractall('/opt/airlock-app/app')
    for entry in archive.infolist():
        os.chmod('/opt/airlock-app/app/' + entry.filename, (entry.external_attr >> 16) & 0o777)
AIRLOCK_SOURCE
cd /opt/airlock-app/app
RUNTIME_SETUP
"""
    if runtime == "python":
        packages = "apt-get install -y --no-install-recommends python3 python3-venv"
        setup = """python3 -m venv /opt/airlock-app/venv
/opt/airlock-app/venv/bin/pip install --no-cache-dir --upgrade pip
if [ -f requirements.txt ]; then
    /opt/airlock-app/venv/bin/pip install --no-cache-dir -r requirements.txt
elif [ -f pyproject.toml ] || [ -f setup.py ]; then
    /opt/airlock-app/venv/bin/pip install --no-cache-dir .
fi"""
    else:
        packages = "apt-get install -y --no-install-recommends python3 nodejs npm"
        setup = """if [ -f package-lock.json ] || [ -f npm-shrinkwrap.json ]; then
    npm ci --include=dev
else
    npm install --include=dev
fi
if node -e 'const p=require("./package.json"); process.exit(p.scripts && p.scripts.build ? 0 : 1)'; then
    npm run build
fi"""
    return common.replace("RUNTIME_PACKAGES", packages).replace("RUNTIME_SETUP", setup).replace("PAYLOAD", encoded)


def _toolchain_versions() -> dict[str, str]:
    repository = Path(__file__).resolve().parents[2]
    try:
        version_source = (repository / "version.go").read_text(encoding="utf-8")
        go_mod = (repository / "go.mod").read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError("importer must run from an Airlock source checkout") from exc
    airlock = re.search(r'const Version = "([0-9][^"]*)"', version_source)
    go_version = re.search(r"(?m)^go ([0-9.]+)$", go_mod)
    agentsdk = re.search(r"(?m)^\s*github\.com/airlockrun/agentsdk v([^\s]+)$", go_mod)
    goai = re.search(r"(?m)^\s*github\.com/airlockrun/goai v([^\s]+)$", go_mod)
    if not all((airlock, go_version, agentsdk, goai)):
        raise ValueError("Airlock toolchain versions could not be resolved")
    if airlock.group(1) != agentsdk.group(1):
        raise ValueError("Airlock and Agent SDK versions are not aligned")
    return {
        "@AIRLOCK_VERSION@": airlock.group(1),
        "@GO_VERSION@": go_version.group(1),
        "@AGENTSDK_VERSION@": agentsdk.group(1),
        "@GOAI_VERSION@": goai.group(1),
    }


def package(source: str | Path, output: str | Path, import_plan: dict[str, Any]) -> dict[str, Any]:
    source, output = Path(source).resolve(), Path(output).resolve()
    if (
        import_plan.get("schema") != PLAN_SCHEMA
        or not import_plan.get("ready")
        or import_plan.get("runtime") not in SUPPORTED_RUNTIMES
        or not isinstance(import_plan.get("command"), list)
        or not import_plan["command"]
        or not all(isinstance(item, str) and item for item in import_plan["command"])
    ):
        raise ValueError("a reviewed plan with an explicit or safely inferred launch command is required")
    if output.exists() or output == source or source in output.parents:
        raise ValueError("output must be a new directory outside the source project")
    output_archive = Path(str(output) + ".tar.gz")
    if output_archive.exists():
        raise ValueError("output archive already exists")
    payload, hashes, skipped = _source_archive(source)
    templates = Path(__file__).resolve().parent / "template"
    versions = _toolchain_versions()
    config = {key: import_plan[key] for key in ("runtime", "description", "command", "port", "healthPath", "environment", "toolRoutes")}
    output.mkdir(parents=True)
    try:
        for path in templates.rglob("*"):
            if path.is_file():
                target = output / str(path.relative_to(templates)).removesuffix(".tmpl")
                target.parent.mkdir(parents=True, exist_ok=True)
                if path.suffix == ".tmpl":
                    content = path.read_text(encoding="utf-8")
                    for marker, value in versions.items():
                        content = content.replace(marker, value)
                    target.write_text(content, encoding="utf-8")
                else:
                    shutil.copyfile(path, target)
        (output / "app.json").write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (output / "source-manifest.json").write_text(json.dumps({"schema": PLAN_SCHEMA, "runtime": import_plan["runtime"], "sha256": hashes, "excludedDataFiles": skipped}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (output / "setup.sh").write_text(_setup_script(import_plan["runtime"], payload), encoding="utf-8")
        (output / "setup.sh").chmod(0o755)
        with output_archive.open("xb") as stream, tarfile.open(fileobj=stream, mode="w:gz") as tar:
            for path in sorted(output.rglob("*")):
                if path.is_file():
                    tar.add(path, arcname=str(path.relative_to(output)), recursive=False)
    except Exception:
        output_archive.unlink(missing_ok=True)
        shutil.rmtree(output)
        raise
    return {
        "output": str(output),
        "archive": str(output_archive),
        "runtime": import_plan["runtime"],
        "sourceFiles": len(hashes),
        "excludedDataFiles": skipped,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    parser.add_argument("--plan", action="store_true", help="Print the machine-readable import plan without writing files")
    parser.add_argument("--runtime", choices=sorted(SUPPORTED_RUNTIMES))
    parser.add_argument("--command", help="Existing argv; use {port}, or read PORT/HOST from the environment")
    parser.add_argument("--description")
    parser.add_argument("--port", type=int)
    parser.add_argument("--health-path")
    parser.add_argument("--env", action="append", default=[], help="Private environment variable name; never a value")
    parser.add_argument("--tool-route", action="append", default=[], help="Exact METHOD:/path explicitly approved for model calls")
    args = parser.parse_args()
    import_plan = plan(
        args.source,
        runtime=args.runtime,
        command=args.command,
        description=args.description,
        port=args.port,
        health_path=args.health_path,
        env=args.env,
        tool_routes=args.tool_route,
    )
    if args.plan:
        print(json.dumps(import_plan, ensure_ascii=False, indent=2))
        return
    if args.output is None:
        parser.error("output is required unless --plan is used")
    print(json.dumps(package(args.source, args.output, import_plan), ensure_ascii=False))


if __name__ == "__main__":
    main()
