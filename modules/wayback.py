"""Wayback URLs module using waybackurls or gau."""

from typing import AsyncIterator, Any
from urllib.parse import urlparse
from .base import BaseModule
from core.runner import run_command


class WaybackModule(BaseModule):
    """Historical URL discovery using waybackurls or gau."""

    name = "wayback"
    description = "Discover historical URLs using waybackurls/gau"
    required_tools = ["waybackurls"]  # Primary tool

    def __init__(self, config: dict):
        """Initialize with config, checking for alternative tools."""
        super().__init__(config)
        # gau can be used as fallback
        self.use_gau = False
        if not self.is_available():
            self.required_tools = ["gau"]
            if self.is_available():
                self.use_gau = True
            else:
                self.required_tools = ["waybackurls"]  # Reset for error reporting

    async def run(
        self, target: str, module_config: dict, log_callback: callable = None
    ) -> AsyncIterator[str]:
        """Run wayback URL collection against the target.

        Args:
            target: Target domain.
            module_config: Module configuration.
            log_callback: Callback for log messages.

        Yields:
            Output lines (URLs) from the tool.
        """
        timeout = module_config.get("timeout", 300)
        limit = module_config.get("limit", 0)  # 0 = no limit

        if self.use_gau:
            async for line in self._run_gau(target, timeout, limit, log_callback):
                yield line
        else:
            async for line in self._run_waybackurls(target, timeout, log_callback):
                yield line

    async def _run_waybackurls(
        self, target: str, timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Run waybackurls for URL discovery."""
        tool_path = self.get_tool_path("waybackurls")

        # waybackurls reads domain from stdin, but we can use echo pipe
        # Instead, we'll run it with the domain directly
        cmd = [tool_path, target]

        if log_callback:
            log_callback(f"[wayback] Running: {' '.join(cmd)}")

        async for line in run_command(cmd, timeout=timeout, log_callback=log_callback):
            yield line

    async def _run_gau(
        self, target: str, timeout: int, limit: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Run gau for URL discovery."""
        tool_path = self.get_tool_path("gau")

        cmd = [tool_path, target]

        if log_callback:
            log_callback(f"[wayback] Running: {' '.join(cmd)}")

        count = 0
        async for line in run_command(cmd, timeout=timeout, log_callback=log_callback):
            yield line
            count += 1
            if limit > 0 and count >= limit:
                break

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse wayback output into structured data.

        Args:
            raw_output: Raw output (URLs, one per line).

        Returns:
            List of URL dictionaries with metadata.
        """
        results = []
        seen = set()

        for line in raw_output.strip().split("\n"):
            url = line.strip()
            if not url or url in seen:
                continue

            seen.add(url)

            # Parse URL for additional info
            try:
                parsed = urlparse(url)
                domain = parsed.netloc
                path = parsed.path
                extension = ""
                if "." in path:
                    extension = path.rsplit(".", 1)[-1].lower()

                # Categorize by extension
                category = "page"
                if extension in ["js"]:
                    category = "javascript"
                elif extension in ["css"]:
                    category = "stylesheet"
                elif extension in ["json", "xml"]:
                    category = "data"
                elif extension in ["jpg", "jpeg", "png", "gif", "svg", "ico"]:
                    category = "image"
                elif extension in ["pdf", "doc", "docx", "xls", "xlsx"]:
                    category = "document"
                elif extension in ["php", "asp", "aspx", "jsp"]:
                    category = "dynamic"
                elif "api" in path.lower():
                    category = "api"

                results.append({
                    "url": url,
                    "domain": domain,
                    "path": path,
                    "extension": extension,
                    "category": category,
                    "type": "wayback",
                })

            except Exception:
                results.append({
                    "url": url,
                    "domain": "unknown",
                    "path": "",
                    "extension": "",
                    "category": "unknown",
                    "type": "wayback",
                })

        return results
