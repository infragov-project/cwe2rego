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

    def clear_all_rules(self) -> None:
        common_dir = self._queries_dir / "Ansible" / "common"
        if common_dir.exists():
            shutil.rmtree(common_dir)

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
                            return json.dumps({"document": [doc]}, indent=2)
                    return ""
                if documents:
                    return json.dumps({"document": documents}, indent=2)
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

    def _walk_yaml_node(self, node, path: str, out: dict, effective_start: int = None) -> None:
        """Recursively walk YAML node tree and record paths with line ranges.

        effective_start: 0-indexed line of the mapping key that introduced this node.
        When a key and its value are on different lines (e.g. a block list or mapping),
        the key line is the logical start of the path entry, not the value's first line.
        """
        if node is None:
            return

        s = (effective_start if effective_start is not None else node.start_mark.line) + 1
        e = node.end_mark.line + 1

        if isinstance(node, yaml.MappingNode):
            for key_node, val_node in node.value:
                key_str = key_node.value if hasattr(key_node, 'value') else str(key_node)
                new_path = f"{path}.{key_str}" if path else key_str
                # Pass the key's line so the path covers the key line, not just the value
                self._walk_yaml_node(val_node, new_path, out, key_node.start_mark.line)
        elif isinstance(node, yaml.SequenceNode):
            for i, item in enumerate(node.value):
                new_path = f"{path}[{i}]"
                self._walk_yaml_node(item, new_path, out)

        out[path] = (s, e)

    def _resolve_paths(self, target_line: int, yaml_map: dict[str, tuple[int, int]]) -> list[str]:
        """
        Find all YAML paths that contain the target line.
        Return sorted by specificity (deepest first; ties broken by smallest line range).
        """
        hits = [
            path for path, (s, e) in yaml_map.items()
            if s <= target_line <= e
        ]
        hits.sort(key=lambda p: (-(p.count('.') + p.count('[')), yaml_map[p][1] - yaml_map[p][0]))
        return hits

    def _path_to_steps(self, yaml_path: str) -> list:
        """Convert a YAML dot-path to a list of IR traversal steps (str keys and int indices).

        The only structural translation needed: a root sequence index [i] maps to
        playbooks[i] in the KICS IR (YAML root sequences wrap under the 'playbooks' key).
        All deeper components map directly.

        E.g. '[0].tasks[1].shell' → ['playbooks', 0, 'tasks', 1, 'shell']
             'vars_prompt[0].name' → ['vars_prompt', 0, 'name']
        """
        if not yaml_path:
            return []

        # Root [i] → playbooks[i]
        m = re.match(r'^\[(\d+)\](\.(.*))?$', yaml_path)
        if m:
            idx = int(m.group(1))
            rest = m.group(3) or ''
            yaml_path = f'playbooks[{idx}]' + (f'.{rest}' if rest else '')

        steps: list = []
        for part in yaml_path.split('.'):
            if not part:
                continue
            m2 = re.match(r'^([^.\[\]]+)(?:\[(\d+)\])?$', part)
            if m2:
                steps.append(m2.group(1))
                if m2.group(2) is not None:
                    steps.append(int(m2.group(2)))
            else:
                m3 = re.match(r'^\[(\d+)\]$', part)
                if m3:
                    steps.append(int(m3.group(1)))
        return steps

    def _prune_with_paths(self, node: any, paths_steps: list[list]) -> any:
        """Recursively prune keeping only the ancestor path and the full subtree at each target.

        Mirrors the GLITCH IR slicing approach:
        - At each level, keep only the child(ren) on the path to a smell line.
        - Once the path is exhausted (target reached), keep the node and all its children.
        - Multiple smell lines are merged at shared ancestors: both branches are kept.
        - If the only targeted key in a dict is 'name', keep the entire dict — 'name'
          should be a task/block label,  the real smell is probably the absence
          of another field in that block.

        paths_steps: list of step-sequences, each being [str|int, ...].
        """
        # Any exhausted path → this node is a target; keep everything
        if any(len(p) == 0 for p in paths_steps):
            return node

        if isinstance(node, dict):
            # Group remaining paths by their next key step
            key_groups: dict[str, list[list]] = {}
            for path in paths_steps:
                step = path[0]
                if isinstance(step, str):
                    key_groups.setdefault(step, []).append(path[1:])

            # 'name' is a task/block label, not the smell itself. When it is the
            # only targeted key the real smell should be the absence of another field in
            # this block, so keep the entire dict to give the LLM full context.
            if set(key_groups.keys()) == {"name"}:
                return node

            result = {k: v for k, v in node.items() if k in self._ALWAYS_KEEP}
            for key, sub_paths in key_groups.items():
                if key in node:
                    result[key] = self._prune_with_paths(node[key], sub_paths)
            return result

        elif isinstance(node, list):
            # Group remaining paths by their next index step
            index_groups: dict[int, list[list]] = {}
            for path in paths_steps:
                step = path[0]
                if isinstance(step, int):
                    index_groups.setdefault(step, []).append(path[1:])
            if not index_groups:
                return node
            return [
                self._prune_with_paths(node[idx], index_groups[idx])
                for idx in sorted(index_groups.keys())
                if idx < len(node)
            ] or node

        return node

    def count_ir_nodes(self, ir: dict) -> int:
        """
        Recursively count all nodes in KICS IR structure.
        Includes nested keys and values at all depths.
        """
        return self._count_nodes_recursive(ir)

    def _count_nodes_recursive(self, node: any) -> int:
        """Recursively count all JSON values (dicts, lists, scalars) in the IR."""
        if isinstance(node, dict):
            return 1 + sum(self._count_nodes_recursive(v) for v in node.values())
        elif isinstance(node, list):
            return 1 + sum(self._count_nodes_recursive(item) for item in node)
        else:
            return 1  # scalar

    def slice_ir(
        self,
        ir: dict,
        false_positive_lines: list[int],
        false_negative_lines: list[int]
    ) -> dict:
        """
        Slice the IR to keep only nodes relevant to given line numbers.

        Handles the KICS document-wrapper format {"document": [doc, ...]}.
        Each inner document is sliced independently and the wrapper is preserved.

        Algorithm (GLITCH-style):
        1. Parse original YAML with line tracking
        2. Resolve each smell line to its deepest YAML path
        3. Convert path to IR traversal steps (root [i] → playbooks[i])
        4. Prune IR keeping ancestors-on-path + full subtree at each target node
        """
        if "document" in ir and isinstance(ir.get("document"), list):
            return {
                "document": [
                    self._slice_doc(doc, false_positive_lines, false_negative_lines)
                    for doc in ir["document"]
                ]
            }
        return self._slice_doc(ir, false_positive_lines, false_negative_lines)

    def _slice_doc(
        self,
        doc: dict,
        false_positive_lines: list[int],
        false_negative_lines: list[int],
    ) -> dict:
        filepath = doc.get("file")
        if not filepath:
            return doc

        yaml_map = self._parse_yaml_with_lines(filepath)
        if not yaml_map:
            return doc

        smell_lines = set(false_positive_lines) | set(false_negative_lines)
        if not smell_lines:
            return doc

        all_path_steps = []
        for line in smell_lines:
            paths = self._resolve_paths(line, yaml_map)
            if paths:
                steps = self._path_to_steps(paths[0])
                if steps:
                    all_path_steps.append(steps)

        if not all_path_steps:
            return doc

        return self._prune_with_paths(doc, all_path_steps)

