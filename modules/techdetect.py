"""Technology detection module using whatweb or httpx."""

import re
import json
from typing import AsyncIterator, Any
from .base import BaseModule
from core.runner import run_command


class TechDetectModule(BaseModule):
    """Technology detection using whatweb or httpx."""

    name = "techdetect"
    description = "Detect web technologies using whatweb/httpx"
    required_tools = ["whatweb"]  # Primary tool

    def __init__(self, config: dict):
        """Initialize with config, checking for alternative tools."""
        super().__init__(config)
        # httpx can be used as fallback
        self.use_httpx = False
        if not self.is_available():
            self.required_tools = ["httpx"]
            if self.is_available():
                self.use_httpx = True
            else:
                self.required_tools = ["whatweb"]  # Reset for error reporting

    async def run(
        self, target: str, module_config: dict, log_callback: callable = None
    ) -> AsyncIterator[str]:
        """Run technology detection against the target.

        Args:
            target: Target domain.
            module_config: Module configuration.
            log_callback: Callback for log messages.

        Yields:
            Output lines from the tool.
        """
        timeout = module_config.get("timeout", 120)

        # Ensure target has protocol
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        if self.use_httpx:
            async for line in self._run_httpx(target, timeout, log_callback):
                yield line
        else:
            async for line in self._run_whatweb(target, timeout, log_callback):
                yield line

    async def _run_whatweb(
        self, target: str, timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Run whatweb for technology detection."""
        tool_path = self.get_tool_path("whatweb")

        cmd = [
            tool_path,
            "--color=never",
            "-a", "3",        # Aggression level
            "--log-json=-",  # JSON output to stdout
            target,
        ]

        if log_callback:
            log_callback(f"[techdetect] Running: {' '.join(cmd)}")

        async for line in run_command(cmd, timeout=timeout, log_callback=log_callback):
            yield line

    async def _run_httpx(
        self, target: str, timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Run httpx for technology detection."""
        tool_path = self.get_tool_path("httpx")

        cmd = [
            tool_path,
            "-u", target,
            "-tech-detect",
            "-json",
            "-silent",
        ]

        if log_callback:
            log_callback(f"[techdetect] Running: {' '.join(cmd)}")

        async for line in run_command(cmd, timeout=timeout, log_callback=log_callback):
            yield line

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse tool output into structured data.

        Args:
            raw_output: Raw output from whatweb or httpx.

        Returns:
            List of technology dictionaries.
        """
        results = []
        seen = set()

        for line in raw_output.strip().split("\n"):
            if not line.strip():
                continue

            # Try parsing as JSON (whatweb --log-json or httpx -json)
            try:
                data = json.loads(line)

                # httpx format
                if "tech" in data:
                    for tech in data.get("tech", []):
                        if tech not in seen:
                            seen.add(tech)
                            results.append({
                                "technology": tech,
                                "url": data.get("url", ""),
                                "type": "technology",
                            })

                # whatweb format
                elif "plugins" in data:
                    url = data.get("target", "")
                    for plugin_name, plugin_data in data.get("plugins", {}).items():
                        if plugin_name not in seen:
                            seen.add(plugin_name)
                            version = ""
                            if isinstance(plugin_data, dict):
                                version_list = plugin_data.get("version", [])
                                if version_list:
                                    version = version_list[0]

                            results.append({
                                "technology": plugin_name,
                                "version": version,
                                "url": url,
                                "type": "technology",
                            })

            except json.JSONDecodeError:
                # Try parsing whatweb plain text output
                # Format: http://example.com [200 OK] Country[US] IP[1.2.3.4] ...
                if line.startswith("http"):
                    tech_pattern = re.compile(r"(\w+(?:-\w+)*)\[([^\]]*)\]")
                    for match in tech_pattern.finditer(line):
                        tech_name = match.group(1)
                        tech_value = match.group(2)

                        if tech_name not in seen and tech_name not in ["Country", "IP"]:
                            seen.add(tech_name)
                            results.append({
                                "technology": tech_name,
                                "version": tech_value,
                                "type": "technology",
                            })

        return results
