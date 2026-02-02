"""Abstract base class for all reconnaissance modules."""

from abc import ABC, abstractmethod
from typing import AsyncIterator, Any
import shutil


class BaseModule(ABC):
    """Base class that all recon modules must inherit from."""

    name: str = "base"
    description: str = "Base module"
    required_tools: list[str] = []

    def __init__(self, config: dict):
        """Initialize the module with configuration.

        Args:
            config: Global configuration dictionary containing tool paths, etc.
        """
        self.config = config
        self.tools_config = config.get("tools", {})

    @abstractmethod
    async def run(
        self, target: str, module_config: dict, log_callback: callable = None
    ) -> AsyncIterator[str]:
        """Execute the reconnaissance module.

        Args:
            target: The target domain to scan.
            module_config: Module-specific configuration from the profile.
            log_callback: Optional callback for logging output lines.

        Yields:
            Output lines from the tool execution.
        """
        pass

    @abstractmethod
    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse the raw tool output into structured data.

        Args:
            raw_output: Raw output string from the tool.

        Returns:
            List of dictionaries containing parsed results.
        """
        pass

    def is_available(self) -> bool:
        """Check if all required tools are available on the system.

        Returns:
            True if all required tools are found, False otherwise.
        """
        for tool in self.required_tools:
            tool_path = self.tools_config.get(tool)
            if tool_path:
                if not shutil.which(tool_path) and not shutil.which(tool):
                    return False
            elif not shutil.which(tool):
                return False
        return True

    def get_tool_path(self, tool_name: str) -> str:
        """Get the path to a tool, preferring config path over system path.

        Args:
            tool_name: Name of the tool.

        Returns:
            Path to the tool executable.
        """
        configured_path = self.tools_config.get(tool_name)
        if configured_path and shutil.which(configured_path):
            return configured_path
        system_path = shutil.which(tool_name)
        if system_path:
            return system_path
        return tool_name

    def get_missing_tools(self) -> list[str]:
        """Get list of required tools that are not available.

        Returns:
            List of missing tool names.
        """
        missing = []
        for tool in self.required_tools:
            tool_path = self.tools_config.get(tool)
            if tool_path:
                if not shutil.which(tool_path) and not shutil.which(tool):
                    missing.append(tool)
            elif not shutil.which(tool):
                missing.append(tool)
        return missing
