import csv
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from validation.tools.base import AnalysisTool

KICS_REPO = "https://github.com/Checkmarx/kics.git"
KICS_LIBRARY_FILES = ("ansible.rego", "common.rego")


def _derive_query_id(type_name: str) -> str:
    h = hashlib.sha256(type_name.encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


class KICSTool(AnalysisTool):
    name = "kics"
    supported_extensions = {
        ".yml": "ansible",
        ".yaml": "ansible",
    }

    @classmethod
    def install(cls, base_dir: Path) -> None:
        base_dir = Path(base_dir)
        validation_kics = base_dir / "validation" / "KICS"
        libraries_dir = validation_kics / "libraries"
        bin_dir = validation_kics / "bin"
        need_libs = not libraries_dir.exists() or not all(
            (libraries_dir / f).exists() for f in KICS_LIBRARY_FILES
        )
        need_binary = (
            shutil.which("kics") is None and not (bin_dir / "kics").exists()
        )
        if need_libs or need_binary:
            with tempfile.TemporaryDirectory() as tmp:
                clone_dir = Path(tmp) / "kics"
                subprocess.run(
                    ["git", "clone", "--depth", "1", KICS_REPO, str(clone_dir)],
                    check=True,
                    capture_output=True,
                )
                if need_libs:
                    libraries_dir.mkdir(parents=True, exist_ok=True)
                    assets_libs = clone_dir / "assets" / "libraries"
                    for name in KICS_LIBRARY_FILES:
                        src = assets_libs / name
                        if src.exists():
                            shutil.copy2(src, libraries_dir / name)
                if need_binary:
                    bin_dir.mkdir(parents=True, exist_ok=True)
                    out_binary = bin_dir / "kics"
                    subprocess.run(
                        ["go", "mod", "tidy"],
                        cwd=clone_dir,
                        check=True,
                        capture_output=True,
                        timeout=120,
                    )
                    subprocess.run(
                        ["go", "generate", "./..."],
                        cwd=clone_dir,
                        check=True,
                        capture_output=True,
                        timeout=120,
                    )
                    subprocess.run(
                        [
                            "go",
                            "build",
                            "-o",
                            str(out_binary.resolve()),
                            "cmd/console/main.go",
                        ],
                        cwd=clone_dir,
                        check=True,
                        capture_output=True,
                        timeout=180,
                    )
        bin_dir.mkdir(parents=True, exist_ok=True)
        if (bin_dir / "kics").exists():
            kics_bin = str((bin_dir / "kics").resolve().parent)
            os.environ["PATH"] = kics_bin + os.pathsep + os.environ.get("PATH", "")
        if not libraries_dir.exists() or not all(
            (libraries_dir / f).exists() for f in KICS_LIBRARY_FILES
        ):
            raise FileNotFoundError(
                f"KICS installation verification failed: libraries missing at {libraries_dir}."
            )
        if not (bin_dir / "kics").exists() and shutil.which("kics") is None:
            raise FileNotFoundError(
                "KICS installation verification failed: kics binary not found. "
                f"Expected at {bin_dir / 'kics'} or on PATH."
            )

    def __init__(self, base_dir: Path):
        self._base_dir = Path(base_dir)
        self._validation_dir = self._base_dir / "validation"
        self._queries_dir = self._validation_dir / "KICS" / "queries"
        self._libraries_dir = self._validation_dir / "KICS" / "libraries"
        self._bin_dir = self._validation_dir / "KICS" / "bin"
        if not self._libraries_dir.exists():
            raise FileNotFoundError(
                f"KICS libraries not found at {self._libraries_dir}. "
                "Run KICSTool.install(base_dir) first or copy assets/libraries there. See README."
            )
        kics_cmd = shutil.which("kics")
        if not kics_cmd and (self._bin_dir / "kics").exists():
            kics_cmd = str((self._bin_dir / "kics").resolve())
        if not kics_cmd:
            raise FileNotFoundError(
                "kics CLI not found on PATH and not at "
                f"{self._bin_dir / 'kics'}. Run KICSTool.install(base_dir) first or install KICS. See README."
            )
        self._kics_cmd = kics_cmd

    def get_rego_lib_path(self) -> Path:
        path = self._libraries_dir / "ansible.rego"
        if not path.exists():
            raise FileNotFoundError(f"KICS Ansible library not found at {path}")
        return path

    def get_ir_description_path(self) -> Path:
        return self._base_dir / "prompt_data" / "kics_ansible_ir.txt"

    def get_example_rules_paths(self) -> list[Path]:
        examples_dir = self._base_dir / "prompt_data" / "example_queries" / "kics"
        if not examples_dir.exists():
            raise FileNotFoundError(
                f"KICS example queries not found at {examples_dir}. "
                "Add 1-2 KICS query.rego examples there. See README."
            )
        paths = sorted(examples_dir.glob("*.rego"))
        if len(paths) < 1:
            raise FileNotFoundError(
                f"No .rego files in {examples_dir}. Add at least one KICS query example."
            )
        return paths[:2]

    def write_rule(self, type_name: str, rego_content: str) -> None:
        query_dir = self._queries_dir / "Ansible" / "common" / type_name
        query_dir.mkdir(parents=True, exist_ok=True)
        (query_dir / "query.rego").write_text(rego_content, encoding="utf-8")
        query_id = _derive_query_id(type_name)
        metadata = {
            "id": query_id,
            "queryName": type_name,
            "severity": "HIGH",
            "category": "Access Control",
            "descriptionText": f"Custom rule: {type_name}",
            "platform": "Ansible",
            "descriptionID": query_id[:8],
            "cloudProvider": "common",
        }
        (query_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2), encoding="utf-8"
        )

    def run_lint(
        self,
        tech: str,
        unit_type: str,
        script_path: Path,
        csv_path: Path,
    ) -> None:
        script_path = Path(script_path)
        scan_path = script_path.parent if script_path.is_file() else script_path
        if csv_path.exists():
            csv_path.unlink()
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            cmd = [
                self._kics_cmd,
                "scan",
                "-p", str(scan_path.resolve()),
                "-t", "Ansible",
                "-q", str(self._queries_dir.resolve()),
                "-b", str(self._libraries_dir.resolve()),
                "-o", str(out_dir),
                "--report-formats", "json",
                "--no-progress",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode not in (0, 1, 2):
                raise RuntimeError(
                    f"kics scan failed with code {result.returncode}\n{result.stderr or result.stdout}"
                )
            results_json = out_dir / "results.json"
            rows = []
            if results_json.exists():
                data = json.loads(results_json.read_text(encoding="utf-8"))
                script_name = script_path.name
                for q in data.get("queries", []):
                    query_name = (q.get("query_name") or "").strip()
                    for f in q.get("files", []):
                        fn = f.get("file_name") or ""
                        if script_name in fn or fn.endswith(script_name):
                            line_val = f.get("line")
                            if line_val is not None:
                                rows.append({"ERROR": query_name, "LINE": str(line_val)})
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["ERROR", "LINE"])
                writer.writeheader()
                writer.writerows(rows)

    def extract_ir(self, file_path: str, unit_type: str) -> str:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        scan_path = path.parent if path.is_file() else path
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmpdir = Path(tmp)
                payload_file = tmpdir / "payload.json"
                cmd = [
                    self._kics_cmd,
                    "scan",
                    "-p", str(scan_path.resolve()),
                    "-t", "Ansible",
                    "-d", str(payload_file.resolve()),
                    "-o", str(tmpdir),
                    "--report-formats", "json",
                    "--no-progress",
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=60
                )
                if result.returncode not in (0, 1, 2) or not payload_file.exists():
                    return path.read_text(encoding="utf-8")
                payload = json.loads(payload_file.read_text(encoding="utf-8"))
                documents = payload.get("document", [])
                if not isinstance(documents, list):
                    documents = []
                for doc in documents:
                    doc_file = doc.get("file", "")
                    if path.name in doc_file or doc_file.endswith(path.name):
                        return json.dumps(doc, indent=2)
                if documents:
                    return json.dumps(documents, indent=2)
                return path.read_text(encoding="utf-8")
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            return path.read_text(encoding="utf-8")
