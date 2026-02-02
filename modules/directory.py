"""Directory enumeration module using gobuster."""

import re
from typing import AsyncIterator, Any
from .base import BaseModule
from core.runner import run_command


class DirectoryModule(BaseModule):
    """Directory enumeration using gobuster."""

    name = "directory"
    description = "Enumerate directories and files using gobuster"
    required_tools = ["gobuster"]

    async def run(
        self, target: str, module_config: dict, log_callback: callable = None
    ) -> AsyncIterator[str]:
        """Run gobuster against the target.

        Args:
            target: Target domain/URL.
            module_config: Module configuration.
            log_callback: Callback for log messages.

        Yields:
            Output lines from gobuster.
        """
        tool_path = self.get_tool_path("gobuster")
        timeout = module_config.get("timeout", 600)
        threads = module_config.get("threads", 30)

        # Get wordlist
        wordlist_key = module_config.get("wordlist", "common")
        wordlists = self.config.get("wordlists", {})
        wordlist_path = wordlists.get(wordlist_key)

        if not wordlist_path:
            # Default paths
            if wordlist_key == "medium":
                wordlist_path = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            else:
                wordlist_path = "/usr/share/wordlists/dirb/common.txt"

        # Ensure target has protocol
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        cmd = [
            tool_path,
            "dir",
            "-u", target,
            "-w", wordlist_path,
            "-t", str(threads),
            "-q",               # Quiet mode (no banner)
            "--no-progress",    # No progress output
            "-e",               # Print full URLs
            "-r",               # Follow redirects
        ]

        if log_callback:
            log_callback(f"[directory] Running: {' '.join(cmd)}")
            log_callback(f"[directory] Using wordlist: {wordlist_path}")

        async for line in run_command(cmd, timeout=timeout, log_callback=log_callback):
            yield line

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse gobuster output into structured data.

        Args:
            raw_output: Raw output from gobuster.

        Returns:
            List of directory/file dictionaries.
        """
        results = []
        seen = set()

        # Gobuster output format: URL (Status: CODE) [Size: BYTES]
        pattern = re.compile(
            r"(https?://\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]"
        )

        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            match = pattern.search(line)
            if match:
                url = match.group(1)
                status = int(match.group(2))
                size = int(match.group(3))

                if url not in seen:
                    seen.add(url)
                    results.append({
                        "url": url,
                        "status_code": status,
                        "size": size,
                        "type": "directory",
                    })
            elif line.startswith("http"):
                # Simple format without status/size
                url = line.split()[0]
                if url not in seen:
                    seen.add(url)
                    results.append({
                        "url": url,
                        "status_code": 200,
                        "size": 0,
                        "type": "directory",
                    })

        return results
