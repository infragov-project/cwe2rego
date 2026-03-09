import subprocess
import sys
from pathlib import Path
from click.testing import CliRunner

from validation.tools.base import AnalysisTool

GLITCH_REPO = "https://github.com/sr-lab/GLITCH.git"


class GlitchTool(AnalysisTool):
    name = "glitch"
    supported_extensions = {
        ".yml": "ansible",
        ".yaml": "ansible",
        ".rb": "chef",
        ".pp": "puppet",
    }

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
