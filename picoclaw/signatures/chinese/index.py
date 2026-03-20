"""Load and query Chinese framework signatures."""

import json
from pathlib import Path
from typing import Any


class ChineseSignatureLoader:
    """Load and query Chinese AI framework detection signatures."""

    def __init__(self, signatures_dir: Path | None = None):
        """Initialize the signature loader.

        Args:
            signatures_dir: Directory containing signature JSON files.
                           Defaults to the directory containing this file.
        """
        if signatures_dir is None:
            signatures_dir = Path(__file__).parent
        self.signatures_dir = Path(signatures_dir)
        self._cache: dict[str, dict] = {}

    def load_all(self) -> dict[str, dict]:
        """Load all framework signatures from the signatures directory.

        Returns:
            Dictionary mapping framework names to their signature data.
        """
        if self._cache:
            return self._cache

        for json_file in self.signatures_dir.glob("*.json"):
            try:
                with open(json_file, encoding="utf-8") as f:
                    data = json.load(f)
                    framework_name = data.get("framework", json_file.stem)
                    self._cache[framework_name.lower()] = data
            except (json.JSONDecodeError, KeyError) as e:
                # Skip invalid JSON files
                continue

        return self._cache

    def get_framework(self, name: str) -> dict[str, Any]:
        """Get signature data for a specific framework.

        Args:
            name: Framework name (case-insensitive).

        Returns:
            Framework signature data, or empty dict if not found.
        """
        signatures = self.load_all()
        return signatures.get(name.lower(), {})

    def detect_framework(
        self, response_headers: dict[str, str], body: dict[str, Any]
    ) -> list[str]:
        """Detect which Chinese AI framework(s) match the given response.

        Args:
            response_headers: HTTP response headers.
            body: Response body as a dictionary.

        Returns:
            List of detected framework names.
        """
        detected = []
        signatures = self.load_all()

        for framework_name, sig_data in signatures.items():
            if self._match_signature(sig_data, response_headers, body):
                detected.append(sig_data.get("framework", framework_name))

        return detected

    def _match_signature(
        self,
        sig_data: dict[str, Any],
        response_headers: dict[str, str],
        body: dict[str, Any],
    ) -> bool:
        """Check if signature data matches the response.

        Args:
            sig_data: Signature data for a framework.
            response_headers: HTTP response headers.
            body: Response body.

        Returns:
            True if the signature matches.
        """
        # Check version detection signatures
        version_detection = sig_data.get("version_detection", {})

        # Check header patterns
        headers_patterns = version_detection.get("headers", {})
        for header_name, pattern in headers_patterns.items():
            header_value = response_headers.get(header_name, "")
            # Simple pattern matching (could be enhanced with regex)
            if pattern.endswith("*"):
                if not header_value.startswith(pattern[:-1]):
                    return False
            elif pattern.startswith("*"):
                if not header_value.endswith(pattern[1:]):
                    return False
            elif pattern not in header_value:
                return False

        return True

    def get_cves(self, framework: str) -> list[dict[str, Any]]:
        """Get known CVEs for a specific framework.

        Args:
            framework: Framework name (case-insensitive).

        Returns:
            List of CVE dictionaries for the framework.
        """
        sig_data = self.get_framework(framework)
        return sig_data.get("cves", [])

    def get_recommended_checks(self, framework: str) -> list[str]:
        """Get recommended security checks for a framework.

        Args:
            framework: Framework name (case-insensitive).

        Returns:
            List of recommended check names.
        """
        sig_data = self.get_framework(framework)
        return sig_data.get("recommended_checks", [])

    def list_frameworks(self) -> list[str]:
        """List all available Chinese AI frameworks.

        Returns:
            List of framework names.
        """
        signatures = self.load_all()
        return [sig.get("framework", name) for name, sig in signatures.items()]

    def get_vendor(self, framework: str) -> str:
        """Get the vendor for a specific framework.

        Args:
            framework: Framework name (case-insensitive).

        Returns:
            Vendor name, or empty string if not found.
        """
        sig_data = self.get_framework(framework)
        return sig_data.get("vendor", "")


# Module-level convenience functions
_loader = ChineseSignatureLoader()


def load_all() -> dict[str, dict]:
    """Load all framework signatures."""
    return _loader.load_all()


def get_framework(name: str) -> dict[str, Any]:
    """Get signature data for a specific framework."""
    return _loader.get_framework(name)


def detect_framework(response_headers: dict[str, str], body: dict[str, Any]) -> list[str]:
    """Detect which Chinese AI framework(s) match the given response."""
    return _loader.detect_framework(response_headers, body)


def get_cves(framework: str) -> list[dict[str, Any]]:
    """Get known CVEs for a specific framework."""
    return _loader.get_cves(framework)