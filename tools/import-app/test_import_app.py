import base64
import hashlib
import io
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
import zipfile

from import_app import _toolchain_versions, package, plan


class ImportPlan(unittest.TestCase):
    def test_python_source_is_exact_and_private_files_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            code = b'print("existing application")\n'
            (source / "app.py").write_bytes(code)
            (source / "app.py").chmod(0o755)
            (source / "requirements.txt").write_text("Flask==3.1.3\n")
            (source / ".env").write_text("PRIVATE=not-for-the-image")
            (source / "private.key").write_text("not-for-the-image")

            import_plan = plan(source, command="python3 app.py --port {port}")
            self.assertEqual(import_plan["runtime"], "python")
            self.assertTrue(import_plan["ready"])
            self.assertEqual(import_plan["toolRoutes"], [])
            package(source, root / "output", import_plan)

            manifest = json.loads((root / "output/source-manifest.json").read_text())
            self.assertEqual(manifest["sha256"]["app.py"], hashlib.sha256(code).hexdigest())
            setup = (root / "output/setup.sh").read_text()
            encoded = setup.split('base64.b64decode("', 1)[1].split('"', 1)[0]
            with zipfile.ZipFile(io.BytesIO(base64.b64decode(encoded))) as archive:
                self.assertEqual(archive.read("app.py"), code)
                self.assertEqual(archive.getinfo("app.py").external_attr >> 16 & 0o777, 0o755)
                self.assertEqual(set(archive.namelist()), {"app.py", "requirements.txt"})
            self.assertNotIn("not-for-the-image", setup)
            self.assertEqual((source / "app.py").read_bytes(), code)
            generated_go_mod = (root / "output/go.mod").read_text()
            versions = _toolchain_versions()
            self.assertIn(f"github.com/airlockrun/agentsdk v{versions['@AGENTSDK_VERSION@']}", generated_go_mod)
            self.assertIn(f"github.com/airlockrun/goai v{versions['@GOAI_VERSION@']}", generated_go_mod)
            with tarfile.open(root / "output.tar.gz") as archive:
                self.assertIn("setup.sh", archive.getnames())
                self.assertIn("main.go", archive.getnames())
                self.assertIn("app.json", archive.getnames())

    def test_typescript_start_script_is_detected_without_exporting_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            (source / "src").mkdir(parents=True)
            code = b'console.log("existing TypeScript application")\n'
            (source / "src/server.ts").write_bytes(code)
            (source / "tsconfig.json").write_text("{}\n")
            (source / "package.json").write_text(json.dumps({
                "scripts": {"build": "tsc", "start": "node dist/server.js"},
                "devDependencies": {"typescript": "5.9.3"},
            }))
            (source / "package-lock.json").write_text('{"lockfileVersion":3}\n')

            import_plan = plan(source)
            self.assertEqual(import_plan["runtime"], "typescript")
            self.assertEqual(import_plan["command"], ["npm", "run", "start"])
            self.assertTrue(import_plan["commandInferred"])
            self.assertEqual(import_plan["toolRoutes"], [])
            self.assertIn("native_authentication", import_plan["automaticCapabilities"])
            self.assertIn("process_lifecycle", import_plan["automaticCapabilities"])
            self.assertEqual(import_plan["applicationStorage"]["mode"], "none")
            package(source, root / "output", import_plan)

            setup = (root / "output/setup.sh").read_text()
            config = json.loads((root / "output/app.json").read_text())
            source_manifest = json.loads((root / "output/source-manifest.json").read_text())
            self.assertIn("npm ci --include=dev", setup)
            self.assertIn("npm run build", setup)
            self.assertEqual(config["runtime"], "typescript")
            self.assertEqual(config["command"], ["npm", "run", "start"])
            self.assertEqual(source_manifest["sha256"]["src/server.ts"], hashlib.sha256(code).hexdigest())
            self.assertEqual((source / "src/server.ts").read_bytes(), code)

    def test_manifest_is_ai_editable_but_capabilities_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "app.py").write_text("print('ok')\n")
            (source / "airlock.app.json").write_text(json.dumps({
                "runtime": "python",
                "command": ["python3", "app.py"],
                "environment": ["DATABASE_URL"],
                "toolRoutes": ["GET:/health", "POST:/calculate"],
            }))
            import_plan = plan(source, tool_routes=["GET:/version"])
            self.assertEqual(import_plan["environment"], ["DATABASE_URL"])
            self.assertEqual(import_plan["toolRoutes"], ["GET:/health", "POST:/calculate", "GET:/version"])
            self.assertNotIn("DATABASE_URL", json.dumps(import_plan["applicationStorage"]))

    def test_python_plan_without_command_is_inspectable_but_not_packagable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "app.py").write_text("print('no universal launch convention')\n")
            import_plan = plan(source)
            self.assertFalse(import_plan["ready"])
            self.assertEqual(import_plan["command"], [])
            with self.assertRaises(ValueError):
                package(source, root / "output", import_plan)

    def test_ambiguous_runtime_routes_targets_and_symlinks_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "app.py").write_text("print('python')\n")
            (source / "package.json").write_text('{"scripts":{"start":"node app.js"}}')
            (source / "tsconfig.json").write_text("{}\n")
            with self.assertRaises(ValueError):
                plan(source, command="python3 app.py")
            with self.assertRaises(ValueError):
                plan(source, runtime="python", command="python3 app.py", tool_routes=["GET:/../secret"])
            import_plan = plan(source, runtime="python", command="python3 app.py")
            with self.assertRaises(ValueError):
                package(source, source, import_plan)
            (source / "linked").symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                package(source, root / "output", import_plan)
            self.assertFalse((root / "output").exists())


if __name__ == "__main__":
    unittest.main()
