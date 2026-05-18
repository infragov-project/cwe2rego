import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import yaml

from validation.tools.base import AnalysisTool

KICS_REPO = "https://github.com/Checkmarx/kics.git"
KICS_VERSION = "v2.1.20"
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
        local_binary = bin_dir / "kics"

        need_binary = True
        if local_binary.exists():
            try:
                version_result = subprocess.run(
                    [str(local_binary.resolve()), "version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                reported_version = (
                    (version_result.stdout or "") + (version_result.stderr or "")
                )
                expected_versions = (KICS_VERSION, KICS_VERSION.lstrip("v"))
                need_binary = not any(v in reported_version for v in expected_versions)
            except OSError:
                need_binary = True

        need_libs = not libraries_dir.exists() or not all(
            (libraries_dir / f).exists() for f in KICS_LIBRARY_FILES
        )
        if need_libs or need_binary:
            with tempfile.TemporaryDirectory() as tmp:
                clone_dir = Path(tmp) / "kics"
                subprocess.run(
                    [
                        "git",
                        "clone",
                        "--branch",
                        KICS_VERSION,
                        "--depth",
                        "1",
                        "--single-branch",
                        KICS_REPO,
                        str(clone_dir),
                    ],
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
                            "-ldflags",
                            (
                                "-X github.com/Checkmarx/kics/v2/internal/constants.Version="
                                f"{KICS_VERSION} "
                                "-X github.com/Checkmarx/kics/v2/internal/constants.SCMCommit="
                                f"{KICS_VERSION}"
                            ),
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
        if not (bin_dir / "kics").exists():
            raise FileNotFoundError(
                "KICS installation verification failed: kics binary not found. "
                f"Expected at {bin_dir / 'kics'}."
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
        kics_cmd = None
        if (self._bin_dir / "kics").exists():
            kics_cmd = str((self._bin_dir / "kics").resolve())
        else:
            kics_cmd = shutil.which("kics")
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

    def get_rego_lib_paths(self) -> list[Path]:
        paths = [self._libraries_dir / f for f in KICS_LIBRARY_FILES]
        for p in paths:
            if not p.exists():
                raise FileNotFoundError(f"KICS library not found at {p}")
        return paths

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

    def remove_rule(self, type_name: str) -> None:
        query_dir = self._queries_dir / "Ansible" / "common" / type_name
        if not query_dir.exists():
            return
        shutil.rmtree(query_dir)
        for parent in (query_dir.parent, query_dir.parent.parent, self._queries_dir):
            if parent.exists() and parent.is_dir() and not any(parent.iterdir()):
                parent.rmdir()

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
            VALID_EXIT_CODES = (0, 20, 30, 40, 50, 60)
            if result.returncode not in VALID_EXIT_CODES:
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
                    "-q", str(self._queries_dir.resolve()),
                    "-b", str(self._libraries_dir.resolve()),
                    "-d", str(payload_file.resolve()),
                    "-o", str(tmpdir),
                    "--report-formats", "json",
                    "--no-progress",
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=60
                )
                valid_exit_codes = (0, 20, 30, 40, 50, 60)
                if result.returncode not in valid_exit_codes or not payload_file.exists():
                    return ""
                payload = json.loads(payload_file.read_text(encoding="utf-8"))
                documents = payload.get("document", [])
                if not isinstance(documents, list):
                    documents = []
                if path.is_file():
                    resolved_path = path.resolve()
                    for doc in documents:
                        doc_file = doc.get("file", "")
                        if doc_file and Path(doc_file).resolve() == resolved_path:
                            return json.dumps(doc, indent=2)
                    return ""
                if documents:
                    return json.dumps(documents, indent=2)
                return ""
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            return ""

    # Consts
    _ALWAYS_KEEP = {"file", "id"}

    def _parse_yaml_with_lines(self, filepath: str) -> dict[str, tuple[int, int]]:
        """
        Parse YAML file and return mapping of dot-separated paths to (start_line, end_line).
        Lines are 1-indexed (converted from yaml marks which are 0-indexed).
        
        Handles multi-document YAML by composing all documents.
        """
        try:
            with open(filepath, encoding="utf-8") as f:
                root = yaml.compose(f)
        except Exception:
            # If parsing fails, return empty map
            return {}
        
        if root is None:
            return {}
        
        result = {}
        self._walk_yaml_node(root, "", result)
        return result

    def _walk_yaml_node(self, node, path: str, out: dict) -> None:
        """Recursively walk YAML node tree and record paths with line ranges."""
        if node is None:
            return
        
        # Both marks are 0-indexed, convert to 1-indexed
        s = node.start_mark.line + 1
        e = node.end_mark.line + 1
        
        if isinstance(node, yaml.MappingNode):
            for key_node, val_node in node.value:
                # Get key string
                key_str = key_node.value if hasattr(key_node, 'value') else str(key_node)
                new_path = f"{path}.{key_str}" if path else key_str
                self._walk_yaml_node(val_node, new_path, out)
        elif isinstance(node, yaml.SequenceNode):
            for i, item in enumerate(node.value):
                new_path = f"{path}[{i}]"
                self._walk_yaml_node(item, new_path, out)
        
        out[path] = (s, e)

    def _resolve_paths(self, target_line: int, yaml_map: dict[str, tuple[int, int]]) -> list[str]:
        """
        Find all YAML paths that contain the target line.
        Return sorted by specificity (deepest/most specific first).
        """
        hits = [
            path for path, (s, e) in yaml_map.items()
            if s <= target_line <= e
        ]
        # Sort by specificity: more dots and brackets = more specific
        hits.sort(key=lambda p: p.count('.') + p.count('['), reverse=True)
        return hits

    def _escalate(self, path: str) -> str:
        """
        Escalate a path to the semantic granularity appropriate for IR.
        
        Rules (in order):
        R1: Inside a playbooks task → escalate to playbooks[i]
        R2: Root-level sequence → map [i] to playbooks[i] (YAML sequences wrap in playbooks key)
        R3: Inside a nested object → escalate to top-level key
        R4: Already at top-level → no change
        """
        if not path:
            return path
        
        parts = self._split_path(path)
        
        # R1: Check if inside a playbooks task
        for i, part in enumerate(parts):
            if part.startswith("playbooks["):
                return self._join_path(parts[:i+1])
        
        # R2: Root-level sequence index → map to playbooks[i]
        # If path starts with [i], it's a root sequence that wraps to playbooks[i] in IR
        if len(parts) >= 1 and parts[0].startswith("["):
            # Extract index and create playbooks path
            return f"playbooks{parts[0]}"
        
        # R3/R4: Return top-level key
        if len(parts) >= 1:
            return parts[0]
        
        return path

    def _split_path(self, path: str) -> list[str]:
        """Split dot-separated path into parts, preserving [i] indices."""
        if not path:
            return []
        # Split on dots; brackets are kept attached to their keys
        # e.g. "playbooks[0].get_url.validate_certs" → ["playbooks[0]", "get_url", "validate_certs"]
        parts = path.split('.')
        return [p for p in parts if p]  # Remove empty strings

    def _join_path(self, parts: list[str]) -> str:
        """Join path parts back into dot-separated path."""
        return '.'.join(parts) if parts else ""

    def _parse_indexed(self, indexed_str: str) -> tuple[str, int]:
        """
        Parse 'playbooks[0]' → ('playbooks', 0).
        """
        match = re.match(r'(\w+)\[(\d+)\]', indexed_str)
        if match:
            return match.group(1), int(match.group(2))
        return indexed_str, -1

    def _prune(self, ir: dict, escalated_paths: set[str]) -> dict:
        """
        Prune IR to keep only:
        - Keys in _ALWAYS_KEEP (file, id)
        - Top-level keys matched in escalated_paths
        
        For playbooks[i] paths, append only that task to result["playbooks"].
        """
        result = {k: v for k, v in ir.items() if k in self._ALWAYS_KEEP}
        
        # Sort paths for consistent ordering
        sorted_paths = sorted(escalated_paths)
        
        # Collect indices for playbooks, if any
        playbook_indices = []
        other_keys = set()
        
        for path in sorted_paths:
            parts = self._split_path(path)
            top_key = parts[0] if parts else path
            
            if "[" in top_key:
                # Parse playbooks[i]
                key, idx = self._parse_indexed(top_key)
                if key == "playbooks" and idx >= 0:
                    playbook_indices.append(idx)
            else:
                # Top-level dict key (Shape B, or top-level playbook keys)
                other_keys.add(top_key)
        
        # Add playbooks (preserving order)
        if playbook_indices and "playbooks" in ir:
            result["playbooks"] = []
            playbook_indices = sorted(set(playbook_indices))
            for idx in playbook_indices:
                if idx < len(ir["playbooks"]):
                    result["playbooks"].append(ir["playbooks"][idx])
        
        # Add other top-level keys
        for key in other_keys:
            if key in ir:
                result[key] = ir[key]
        
        return result

    def count_ir_nodes(self, ir: dict) -> int:
        """
        Recursively count all nodes in KICS IR structure.
        Includes nested keys and values at all depths.
        """
        return self._count_nodes_recursive(ir)

    def _count_nodes_recursive(self, node: any) -> int:
        """Recursively count nodes in KICS IR structure."""
        if not isinstance(node, dict):
            return 0
        count = 1  # Count this dict node itself
        for value in node.values():
            if isinstance(value, dict):
                count += self._count_nodes_recursive(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        count += self._count_nodes_recursive(item)
        return count

    def slice_ir(
        self,
        ir: dict,
        false_positive_lines: list[int],
        false_negative_lines: list[int]
    ) -> dict:
        """
        Slice the IR to keep only nodes relevant to given line numbers.
        
        Algorithm:
        1. Parse original YAML with line tracking
        2. Resolve each smell line to YAML paths
        3. Escalate paths to semantic granularity
        4. Prune IR keeping only matched + essential keys
        
        Args:
            ir: The intermediate representation dict
            false_positive_lines: List of line numbers for false positives
            false_negative_lines: List of line numbers for false negatives
            
        Returns:
            Sliced IR dict with only relevant nodes
        """
        # Get file path from IR
        filepath = ir.get("file")
        if not filepath:
            # No file path, return IR as-is
            return ir
        
        # Parse YAML to get line → path mappings
        yaml_map = self._parse_yaml_with_lines(filepath)
        if not yaml_map:
            # Failed to parse YAML, return IR as-is
            return ir
        
        # Combine all smell lines
        smell_lines = set(false_positive_lines) | set(false_negative_lines)
        if not smell_lines:
            # No smell lines, return IR as-is
            return ir
        
        # Resolve and escalate paths
        escalated = set()
        for line in smell_lines:
            paths = self._resolve_paths(line, yaml_map)
            if paths:
                # Take deepest match and escalate
                escalated.add(self._escalate(paths[0]))
        
        # If no paths resolved, return IR as-is
        if not escalated:
            return ir
        
        # Prune and return
        return self._prune(ir, escalated)

