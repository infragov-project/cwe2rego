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

    def get_rego_lib_paths(self) -> list[Path]:
        """Paths to Rego helper libraries for prompt construction. Default: single get_rego_lib_path()."""
        return [self.get_rego_lib_path()]

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

    def slice_ir(
        self,
        ir: dict,
        false_positive_lines: list[int],
        false_negative_lines: list[int],
        file_path: str | None = None,
    ) -> dict:
        """
        Slice the IR to keep only nodes relevant to given line numbers.

        Default implementation returns the IR unchanged. Tools can override to provide slicing.

        Args:
            ir: The intermediate representation dict
            false_positive_lines: List of line numbers for false positives
            false_negative_lines: List of line numbers for false negatives
            file_path: Optional file path (may be used by some tools)

        Returns:
            Sliced IR dict with only relevant code (or unchanged IR if not implemented)
        """
        return ir

    def count_ir_nodes(self, ir: dict) -> int:
        """
        Count the number of nodes in the IR structure.
        
        Tool-specific implementation. Must be overridden by subclasses if they support node counting.
        Default implementation returns 0 (no counting).
        
        Args:
            ir: The intermediate representation dict
            
        Returns:
            Number of nodes in the IR, or 0 if not supported
        """
        return 0

    def get_file_type(self, file_path: str) -> str | None:
        """Return the tech name for the file (e.g. 'ansible') from its extension, or None if unsupported."""
        ext = Path(file_path).suffix.lower()
        return self.supported_extensions.get(ext)

    def get_supported_technologies(self) -> list[str]:
        """Return the distinct technology names supported by this tool."""
        return sorted({tech for tech in self.supported_extensions.values() if tech})

    def resolve_technologies(
        self,
        requested_technologies: list[str] | None,
    ) -> tuple[list[str], list[str]]:
        """Resolve requested technologies into (selected, unsupported)."""
        supported = self.get_supported_technologies()
        if requested_technologies is None:
            return supported, []

        normalized: list[str] = []
        for tech in requested_technologies:
            tech_value = str(tech).strip().lower()
            if tech_value and tech_value not in normalized:
                normalized.append(tech_value)

        if not normalized:
            return supported, []

        unsupported = [tech for tech in normalized if tech not in supported]
        selected = [tech for tech in normalized if tech in supported]
        if not selected:
            raise ValueError(
                "No valid technologies selected for "
                f"{self.name}. Supported values: {', '.join(supported)}"
            )

        return selected, unsupported

    def get_extensions_for_technologies(
        self,
        technologies: list[str] | None = None,
    ) -> list[str]:
        """Return supported file extensions for the provided technologies."""
        selected = technologies if technologies is not None else self.get_supported_technologies()
        selected_set = set(selected)
        return sorted(
            ext
            for ext, tech in self.supported_extensions.items()
            if tech in selected_set
        )

    @staticmethod
    def format_technologies(technologies: list[str]) -> str:
        """Format technologies for user-facing prompt/context strings."""
        return ", ".join(tech.title() for tech in technologies)
