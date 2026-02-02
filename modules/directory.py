"""Directory enumeration module using gobuster."""

import re
from urllib.parse import urlparse
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
        """Run gobuster against the target(s).

        Args:
            target: Target domain/URL (used if no subdomains provided).
            module_config: Module configuration with optional 'targets' list.
            log_callback: Callback for log messages.

        Yields:
            Output lines from gobuster.
        """
        # Get targets - either from alive subdomains or main target
        targets = module_config.get("targets", [])
        if not targets:
            targets = [target]

        tool_path = self.get_tool_path("gobuster")
        timeout_per_target = module_config.get("timeout", 300)
        threads = module_config.get("threads", 30)

        # Get wordlist
        wordlist_key = module_config.get("wordlist", "common")
        wordlists = self.config.get("wordlists", {})
        wordlist_path = wordlists.get(wordlist_key)

        if not wordlist_path:
            if wordlist_key == "medium":
                wordlist_path = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            else:
                wordlist_path = "/usr/share/wordlists/dirb/common.txt"

        if log_callback:
            log_callback(f"[directory] Scanning {len(targets)} target(s)")
            log_callback(f"[directory] Using wordlist: {wordlist_path}")

        for current_target in targets:
            # Ensure target has protocol
            if not current_target.startswith(("http://", "https://")):
                current_target = f"https://{current_target}"

            if log_callback:
                log_callback(f"[directory] Scanning: {current_target}")

            # Output marker for target grouping
            yield f"__TARGET__:{current_target}"

            cmd = [
                tool_path,
                "dir",
                "-u", current_target,
                "-w", wordlist_path,
                "-t", str(threads),
                "-q",
                "--no-progress",
                "-e",
                "-r",
            ]

            try:
                async for line in run_command(cmd, timeout=timeout_per_target, log_callback=log_callback):
                    yield line
            except Exception as e:
                if log_callback:
                    log_callback(f"[directory] Error scanning {current_target}: {e}")
                yield f"__ERROR__:{current_target}:{str(e)}"

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse gobuster output into structured data grouped by target.

        Args:
            raw_output: Raw output from gobuster.

        Returns:
            List of directory/file dictionaries with target info.
        """
        results = []
        seen = set()
        current_target = "unknown"

        # Gobuster output format: URL (Status: CODE) [Size: BYTES]
        pattern = re.compile(
            r"(https?://\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]"
        )

        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            # Check for target marker
            if line.startswith("__TARGET__:"):
                current_target = line.replace("__TARGET__:", "")
                continue

            # Skip error markers
            if line.startswith("__ERROR__:"):
                continue

            match = pattern.search(line)
            if match:
                url = match.group(1)
                status = int(match.group(2))
                size = int(match.group(3))

                # Extract subdomain from URL
                parsed = urlparse(url)
                subdomain = parsed.netloc

                unique_key = f"{url}"
                if unique_key not in seen:
                    seen.add(unique_key)
                    results.append({
                        "url": url,
                        "subdomain": subdomain,
                        "target": current_target,
                        "path": parsed.path,
                        "status_code": status,
                        "size": size,
                        "type": "directory",
                    })
            elif line.startswith("http"):
                url = line.split()[0]
                parsed = urlparse(url)
                subdomain = parsed.netloc

                unique_key = f"{url}"
                if unique_key not in seen:
                    seen.add(unique_key)
                    results.append({
                        "url": url,
                        "subdomain": subdomain,
                        "target": current_target,
                        "path": parsed.path,
                        "status_code": 200,
                        "size": 0,
                        "type": "directory",
                    })

        return results
