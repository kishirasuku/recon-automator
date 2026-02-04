"""Subdomain enumeration module using subfinder."""

from typing import AsyncIterator, Any
from .base import BaseModule
from core.runner import run_command


class SubdomainModule(BaseModule):
    """Subdomain enumeration using subfinder."""

    name = "subdomain"
    description = "Enumerate subdomains using subfinder"
    required_tools = ["subfinder"]

    async def run(
        self, target: str, module_config: dict, log_callback: callable = None
    ) -> AsyncIterator[str]:
        """Run subfinder against the target domain.

        Args:
            target: Target domain.
            module_config: Module configuration.
            log_callback: Callback for log messages.

        Yields:
            Output lines from subfinder.
        """
        tool_path = self.get_tool_path("subfinder")
        timeout = module_config.get("timeout", 120)

        # Sources known to cause crashes
        default_exclude = ["digitorus"]
        exclude_sources = module_config.get("exclude_sources", default_exclude)

        cmd = [
            tool_path,
            "-d", target,
            "-silent",
        ]

        # Add source exclusions if specified
        if exclude_sources:
            cmd.extend(["-es", ",".join(exclude_sources)])

        if log_callback:
            log_callback(f"[subdomain] Running: {' '.join(cmd)}")

        async for line in run_command(cmd, timeout=timeout, log_callback=log_callback):
            yield line

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse subfinder output into structured data.

        Args:
            raw_output: Raw output from subfinder.

        Returns:
            List of subdomain dictionaries.
        """
        results = []
        seen = set()

        for line in raw_output.strip().split("\n"):
            subdomain = line.strip().lower()
            if subdomain and subdomain not in seen:
                seen.add(subdomain)
                results.append({
                    "subdomain": subdomain,
                    "type": "subdomain",
                })

        return results
