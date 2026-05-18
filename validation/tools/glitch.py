import subprocess
import sys
from pathlib import Path
from typing import Any
from click.testing import CliRunner

from validation.tools.base import AnalysisTool

GLITCH_REPO = "https://github.com/sr-lab/GLITCH.git"

# Unknown line sentinels: if a node's line is in this set, it has no reliable location
UNKNOWN_SENTINELS = {-33550336, 2**32, 2**63 - 1, 2**63, -(2**63), 0}


class GlitchTool(AnalysisTool):
    name = "glitch"
    supported_extensions = {
        ".yml": "ansible",
        ".yaml": "ansible",
        ".rb": "chef",
        ".pp": "puppet",
    }

    def _count_nodes_recursive(self, node: Any) -> int:
        """Recursively count nodes in GLITCH IR structure."""
        if not isinstance(node, dict):
            return 0
        count = 1
        for value in node.values():
            if isinstance(value, dict):
                count += self._count_nodes_recursive(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        count += self._count_nodes_recursive(item)
        return count

    def count_ir_nodes(self, ir: dict) -> int:
        """Count the number of nodes in GLITCH IR structure."""
        return self._count_nodes_recursive(ir)

    @classmethod
    def install(cls, base_dir: Path) -> None:
        base_dir = Path(base_dir)
        validation_dir = base_dir / "validation"
        glitch_dir = validation_dir / "GLITCH"
        if not (glitch_dir.exists() and (glitch_dir / "glitch").is_dir()):
            validation_dir.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--depth", "1", GLITCH_REPO, str(glitch_dir)],
                check=True,
                capture_output=True,
            )
        if not glitch_dir.exists() or not (glitch_dir / "glitch").is_dir():
            raise FileNotFoundError(
                f"GLITCH installation verification failed: {glitch_dir} missing or invalid."
            )

    def __init__(self, base_dir: Path):
        self._base_dir = Path(base_dir)
        self._validation_dir = self._base_dir / "validation"
        glitch_dir = self._validation_dir / "GLITCH"
        if not glitch_dir.exists():
            raise FileNotFoundError(
                f"GLITCH not found at {glitch_dir}. Run {self.__class__.__name__}.install(base_dir) first or clone per README."
            )
        sys.path.insert(0, str(glitch_dir))

    def get_rego_lib_path(self) -> Path:
        return self._base_dir / "prompt_data" / "rego_library" / "glitch_lib.rego"

    def get_ir_description_path(self) -> Path:
        return self._base_dir / "prompt_data" / "inter.txt"

    def get_example_rules_paths(self) -> list[Path]:
        return [
            self._base_dir / "prompt_data" / "example_queries" / "sec_full_permission_filesystem.rego",
            self._base_dir / "prompt_data" / "example_queries" / "sec_obsolete_command.rego",
        ]

    def write_rule(self, type_name: str, rego_content: str) -> None:
        rule_path = (
            self._validation_dir
            / "GLITCH"
            / "glitch"
            / "rego"
            / "queries"
            / "security"
            / f"{type_name}.rego"
        )
        rule_path.parent.mkdir(parents=True, exist_ok=True)
        rule_path.write_text(rego_content, encoding="utf-8")

    def remove_rule(self, type_name: str) -> None:
        rule_path = (
            self._validation_dir
            / "GLITCH"
            / "glitch"
            / "rego"
            / "queries"
            / "security"
            / f"{type_name}.rego"
        )
        if rule_path.exists():
            rule_path.unlink()
        for parent in (rule_path.parent, rule_path.parent.parent):
            if parent.exists() and parent.is_dir() and not any(parent.iterdir()):
                parent.rmdir()

    def run_lint(
        self,
        tech: str,
        unit_type: str,
        script_path: Path,
        csv_path: Path,
    ) -> None:
        from glitch.__main__ import lint as glitch_lint

        runner = CliRunner(mix_stderr=False)
        if csv_path.exists():
            csv_path.unlink()
        result = runner.invoke(
            glitch_lint,
            [
                "--tech",
                tech,
                "--type",
                unit_type,
                "--csv",
                "--smell-types",
                "security",
                str(script_path),
                str(csv_path),
            ],
        )
        if result.stderr:
            print(result.stderr, end="", flush=True)
        if result.exception or result.exit_code != 0:
            if result.stdout:
                print(result.stdout, end="", flush=True)
            if result.exception:
                raise result.exception
            raise RuntimeError(
                f"glitch lint exited with code {result.exit_code}"
            )

    def extract_ir(self, file_path: str, unit_type: str) -> str:
        """
        Extract the Intermediate Representation (IR) from the given file path using GLITCH's repr command via CliRunner.

        Args:
            file_path: Path to the file to extract IR from
            unit_type: The file type as expected by GLITCH (e.g., "script", "task", "vars")
        Returns:
            JSON string representation of the IR
        Raises:
            ValueError: If the file type is not supported
            RuntimeError: If GLITCH repr command fails
        """
        from glitch.__main__ import repr as glitch_repr

        tech = self.get_file_type(file_path)
        if tech is None:
            raise ValueError(
                f"Unsupported file type: {Path(file_path).suffix}"
            )
        runner = CliRunner()
        result = runner.invoke(
            glitch_repr,
            [
                "--tech",
                tech,
                "--type",
                unit_type,
                file_path,
            ],
        )
        if result.exception:
            raise result.exception
        if result.exit_code != 0:
            raise RuntimeError(
                f"GLITCH repr failed with exit code {result.exit_code}\n"
                f"Output: {result.output}"
            )
        return result.output

    def slice_ir(
        self,
        ir: dict,
        false_positive_lines: list[int],
        false_negative_lines: list[int]
    ) -> dict:
        """
        Slice the IR to keep only nodes relevant to given line numbers.

        Combines false_positive_lines and false_negative_lines into a target set,
        finds all nodes covering those lines, applies escalation rules for semantic
        coupling and SWITCH/IF chains, then prunes the tree to keep only matched
        nodes and their ancestors.

        Args:
            ir: The intermediate representation dict
            false_positive_lines: List of line numbers for false positives
            false_negative_lines: List of line numbers for false negatives

        Returns:
            Sliced IR dict with only relevant code
        """
        # Deduplicate targets
        targets = set(false_positive_lines) | set(false_negative_lines)
        if not targets:
            return ir

        # Pass 1: Find matched nodes with their ancestry paths
        matches_by_id = self._find_matches(ir, targets)
        if not matches_by_id:
            return ir

        # Collect all matched node ids and their descendants
        matched_ids = set()
        ancestor_ids = set()

        def collect_descendants(node):
            """Recursively collect id of node and all its descendants."""
            if not isinstance(node, dict):
                return
            matched_ids.add(id(node))
            for value in node.values():
                if isinstance(value, dict):
                    collect_descendants(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            collect_descendants(item)

        for matched_node, ancestry_path in (
            item for match_list in matches_by_id.values() for item in [(m, a) for m, a in match_list]
        ):
            collect_descendants(matched_node)
            for ancestor in ancestry_path:
                ancestor_ids.add(id(ancestor))

        # Combine relevant ids: ancestors + matched (no siblings)
        relevant_ids = ancestor_ids | matched_ids

        # Pass 2: Prune
        sliced = self._prune(ir, relevant_ids, matched_ids)

        # Pass 3: Clean up unnecessary metadata fields
        return self._clean_ir(sliced)

    def _find_matches(self, ir: dict, targets: set[int]) -> dict:
        """
        Find all nodes covering target lines using DFS, returning greatest-depth matches.

        Returns:
            {target_line: [(matched_node, ancestry_path, depth), ...]} for all deepest matches per line
        """
        matches_by_id = {}  # {target_line: [(node, ancestry, depth), ...]}

        def is_valid_line(line):
            """Check if line is a valid location (not sentinel and positive)."""
            return line is not None and line not in UNKNOWN_SENTINELS and line > 0

        def dfs(node, ancestry, depth):
            """DFS to find nodes covering target lines, tracking depth."""
            if not isinstance(node, dict):
                return

            # Get line range of this node
            line = node.get("line")
            end_line = node.get("end_line")

            # Check if this node covers any target
            # Accept if: both line and end_line are valid, OR line is valid and target equals line (handles single-line nodes like comments)
            if is_valid_line(line):
                for target in targets:
                    covers_target = False
                    if is_valid_line(end_line):
                        # Normal case: line range is valid
                        covers_target = line <= target <= end_line
                    elif target == line:
                        # Special case: end_line is unknown/sentinel, but target matches the line (single-line nodes)
                        covers_target = True
                    
                    if covers_target:
                        # Update or add match only if it's deeper than existing matches
                        if target not in matches_by_id:
                            matches_by_id[target] = []
                        
                        existing_depths = [d for _, _, d in matches_by_id[target]]
                        if not existing_depths or depth > max(existing_depths):
                            # Deeper match found, replace all existing
                            matches_by_id[target] = [(node, ancestry, depth)]
                        elif depth == max(existing_depths):
                            # Same depth, add to list of matches
                            matches_by_id[target].append((node, ancestry, depth))

            # Recurse into children
            new_ancestry = ancestry + [node]
            for value in node.values():
                if isinstance(value, dict):
                    dfs(value, new_ancestry, depth + 1)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            dfs(item, new_ancestry, depth + 1)

        dfs(ir, [], 0)

        # Apply escalation rules
        final_matches = {}
        for target, match_list in matches_by_id.items():
            final_matches[target] = []
            for matched_node, ancestry, _ in match_list:
                escalated_node = matched_node
                escalated_ancestry = ancestry

                # Escalation rule 1: Semantic coupling
                if len(ancestry) >= 1:
                    parent = ancestry[-1]
                    
                    # BinaryOperation escalation: if matched is an operand
                    # Check for operand fields rather than ir_type, since concrete types don't have ir_type="BinaryOperation"
                    if matched_node is parent.get("left") or \
                       matched_node is parent.get("right"):
                        escalated_node = parent
                        escalated_ancestry = ancestry[:-1]

                # Escalation rule 2: Attribute/Variable node escalation
                # If a node is within an Attribute or Variable's line range, escalate to that node
                for ancestor in reversed(escalated_ancestry):
                    if ancestor.get("ir_type") in ("Attribute", "Variable"):
                        attr_line = ancestor.get("line")
                        attr_end = ancestor.get("end_line")
                        matched_line = escalated_node.get("line")
                        # Escalate if matched node is within Attribute/Variable's line range
                        if attr_line is not None and attr_line > 0 and matched_line is not None and matched_line > 0:
                            if attr_line <= matched_line <= attr_end:
                                escalated_node = ancestor
                                ancestor_index = ancestry.index(ancestor)
                                escalated_ancestry = ancestry[:ancestor_index]
                                break

                # Escalation rule 3: SWITCH chain
                for ancestor in reversed(escalated_ancestry):
                    if ancestor.get("ir_type") == "ConditionalStatement" and \
                       ancestor.get("is_top") is True and ancestor.get("type") == "SWITCH":
                        escalated_node = ancestor
                        # Keep ancestry up to (but not including) this ancestor
                        ancestor_index = escalated_ancestry.index(ancestor)
                        escalated_ancestry = escalated_ancestry[:ancestor_index]
                        break

                final_matches[target].append((escalated_node, escalated_ancestry))

        return final_matches

    def _prune(self, node: dict, relevant: set[int], matched: set[int]) -> dict:
        """
        Recursively rebuild the IR tree, keeping:
        - Matched nodes (fully intact)
        - Ancestors of matched (structural, recursively pruned children)

        Args:
            node: Current node being processed
            relevant: Set of id()s of relevant nodes (ancestors + matched)
            matched: Set of id()s of matched nodes and their descendants

        Returns:
            Pruned node dict, or None if pruned away
        """
        if not isinstance(node, dict):
            return node

        node_id = id(node)

        # If this node is matched, keep it fully intact
        if node_id in matched:
            return node

        # If this node is not relevant, prune it
        if node_id not in relevant:
            return None

        # This node is an ancestor: rebuild it with pruned children
        result = {}
        
        # Check if this is a key-value pair dict (has both "key" and "value" fields)
        is_kv_pair = "key" in node and "value" in node and len(node) == 2
        keep_kv_pair_as_is = False
        
        if is_kv_pair:
            key_node = node.get("key")
            value_node = node.get("value")
            key_matched = isinstance(key_node, dict) and id(key_node) in matched
            value_matched = isinstance(value_node, dict) and id(value_node) in matched
            keep_kv_pair_as_is = key_matched or value_matched
        
        for key, value in node.items():
            if isinstance(value, dict):
                # Single-node dict fields
                if keep_kv_pair_as_is:
                    # For key-value pairs where at least one part is matched, keep both as-is
                    result[key] = value
                else:
                    # For other dict fields, recursively prune
                    pruned = self._prune(value, relevant, matched)
                    result[key] = pruned
            elif isinstance(value, list):
                # List fields: keep items if relevant, or if they're descendants of relevant nodes
                pruned_list = []
                for item in value:
                    if isinstance(item, dict):
                        pruned_item = self._prune(item, relevant, matched)
                        if pruned_item is not None:
                            pruned_list.append(pruned_item)
                    else:
                        pruned_list.append(item)
                result[key] = pruned_list
            else:
                # Keep all scalars (line, end_line, code, etc.)
                result[key] = value

        return result

    def _clean_ir(self, node: dict) -> dict:
        """
        Recursively remove unnecessary metadata fields from IR nodes.
        
        Removes: column, end_column, end_line
        Keeps: line (semantically important), code, ir_type, and all other fields
        
        Args:
            node: IR node to clean
            
        Returns:
            Cleaned IR node with unnecessary fields removed
        """
        if not isinstance(node, dict):
            return node
        
        # Fields to remove
        fields_to_remove = {"column", "end_column", "end_line"}
        
        result = {}
        for key, value in node.items():
            if key in fields_to_remove:
                # Skip these fields
                continue
            elif isinstance(value, dict):
                # Recursively clean nested dicts
                result[key] = self._clean_ir(value)
            elif isinstance(value, list):
                # Recursively clean items in lists
                cleaned_list = []
                for item in value:
                    if isinstance(item, dict):
                        cleaned_list.append(self._clean_ir(item))
                    else:
                        cleaned_list.append(item)
                result[key] = cleaned_list
            else:
                # Keep all other scalar values
                result[key] = value
        
        return result

