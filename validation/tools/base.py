from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict


class AnalysisTool(ABC):
    """Abstract base for analysis tools (e.g. GLITCH) used to deploy rules, run lint, and extract IR."""

    name: str = ""
    supported_extensions: Dict[str, str] = {}

    @classmethod
    def install(cls, base_dir: Path) -> None:
        """Install the tool (e.g. clone repo or fetch assets) if not already present. Idempotent. Override in subclasses."""
        pass

    @abstractmethod
    def get_rego_lib_path(self) -> Path:
        """Path to the Rego helper library used for prompt construction and OPA check."""
        pass

    @abstractmethod
    def get_ir_description_path(self) -> Path:
        """Path to the file describing the tool's intermediate representation."""
        pass

    @abstractmethod
    def get_example_rules_paths(self) -> list[Path]:
        """Paths to example Rego rules for the generation prompt."""
        pass

    @abstractmethod
    def write_rule(self, type_name: str, rego_content: str) -> None:
        """Deploy the generated rule to the tool's expected location."""
        pass

    def remove_rule(self, type_name: str) -> None:
        """Remove the deployed rule so the tool's query/rule directory stays empty. No-op if not applicable."""
        pass

    @abstractmethod
    def run_lint(
        self,
        tech: str,
        unit_type: str,
        script_path: Path,
        csv_path: Path,
    ) -> None:
        """Run the linter on the script; output is written to csv_path."""
        pass

    @abstractmethod
    def extract_ir(self, file_path: str, unit_type: str) -> str:
        """Extract IR from the file (or raw content if the tool has no IR)."""
        pass

    def get_file_type(self, file_path: str) -> str | None:
        """Return the tech name for the file (e.g. 'ansible') from its extension, or None if unsupported."""
        ext = Path(file_path).suffix.lower()
        return self.supported_extensions.get(ext)
