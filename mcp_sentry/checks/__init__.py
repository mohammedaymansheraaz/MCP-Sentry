"""Check registry and base classes for MCP-Sentry vulnerability checks."""

from abc import ABC, abstractmethod

from mcp_sentry.models import Finding, ServerSurface


class BaseCheck(ABC):
    """Abstract base class for all MCP vulnerability checks."""

    check_id: str
    name: str
    description: str

    @abstractmethod
    def run(self, surface: ServerSurface) -> list[Finding]:
        """Run the check against the given server surface.
        
        Args:
            surface: The normalized attack surface of the server.
            
        Returns:
            A list of Findings (empty list if no vulnerabilities found).
        """
        pass


# Global registry of all available checks
CHECK_REGISTRY: list[type[BaseCheck]] = []


def register_check(check_cls: type[BaseCheck]) -> type[BaseCheck]:
    """Decorator to register a check class in the global registry."""
    CHECK_REGISTRY.append(check_cls)
    return check_cls


def get_all_checks() -> list[BaseCheck]:
    """Instantiate and return all registered checks."""
    return [cls() for cls in CHECK_REGISTRY]


def get_checks_by_ids(ids: list[str]) -> list[BaseCheck]:
    """Instantiate and return a filtered list of registered checks."""
    return [cls() for cls in CHECK_REGISTRY if cls.check_id in ids]

# Import checks to register them
from mcp_sentry.checks import (
    credential_leak,
    hbv,
    path_traversal,
    ssrf,
    transport_security,
    unvalidated_input,
    weak_auth,
)
