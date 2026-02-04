"""Directory enumeration module using feroxbuster."""

import json
from urllib.parse import urlparse
from typing import AsyncIterator, Any
from .base import BaseModule
from core.runner import run_command


class DirectoryModule(BaseModule):
    """Directory enumeration using feroxbuster."""

    name = "directory"
    description = "Enumerate directories and files using feroxbuster"
    required_tools = ["feroxbuster"]

    async def run(
        self, target: str, module_config: dict, log_callback: callable = None
    ) -> AsyncIterator[str]:
        """Run feroxbuster against the target(s).

        Args:
            target: Target domain/URL (used if no subdomains provided).
            module_config: Module configuration with optional 'targets' list.
            log_callback: Callback for log messages.

        Yields:
            Output lines from feroxbuster (JSON format).
        """
        # Get targets - either from alive subdomains or main target
        targets = module_config.get("targets", [])
        if not targets:
            targets = [target]

        # Limit number of targets to scan
        max_targets = module_config.get("max_targets", 10)
        if len(targets) > max_targets:
            if log_callback:
                log_callback(f"[directory] Limiting targets from {len(targets)} to {max_targets}")
            targets = targets[:max_targets]

        tool_path = self.get_tool_path("feroxbuster")
        timeout_per_target = module_config.get("timeout", 300)
        threads = module_config.get("threads", 50)
        depth = module_config.get("depth", 2)

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

            # Build feroxbuster command
            # Use shorter time limit for feroxbuster itself (80% of timeout)
            ferox_time_limit = max(60, int(timeout_per_target * 0.8))
            if log_callback:
                log_callback(f"[directory] Timeout: {timeout_per_target}s, Threads: {threads}, Depth: {depth}")
            cmd = [
                tool_path,
                "-u", current_target,
                "-w", wordlist_path,
                "-t", str(threads),
                "-d", str(depth),
                "--silent",            # Only print URLs/JSON, turn off logging
                "--json",              # JSON output for easy parsing
                "--no-state",          # Don't save/restore state
                "-k",                  # Allow insecure TLS
                "--auto-tune",         # Automatically tune request rate
                "-n",                  # No recursion (use -d for depth control)
                "--time-limit", f"{ferox_time_limit}s",  # Enforce time limit
            ]

            # Add status code filter if specified
            status_codes = module_config.get("status_codes", "")
            if status_codes:
                cmd.extend(["-s", status_codes])

            if log_callback:
                log_callback(f"[directory] Command: {' '.join(cmd)}")

            line_count = 0
            try:
                async for line in run_command(cmd, timeout=timeout_per_target, log_callback=log_callback):
                    line_count += 1
                    yield line

                if log_callback:
                    log_callback(f"[directory] Received {line_count} lines from feroxbuster")
            except Exception as e:
                if log_callback:
                    log_callback(f"[directory] Error scanning {current_target}: {e}")
                yield f"__ERROR__:{current_target}:{str(e)}"

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse feroxbuster JSON output into structured data grouped by target.

        Args:
            raw_output: Raw output from feroxbuster (JSON lines).

        Returns:
            List of directory/file dictionaries with target info.
        """
        results = []
        seen = set()
        current_target = "unknown"

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

            # Try to parse JSON (feroxbuster --json output)
            try:
                data = json.loads(line)

                # feroxbuster outputs different types: "response", "statistics", etc.
                if data.get("type") != "response":
                    continue

                url = data.get("url", "")
                status = data.get("status", 0)
                content_length = data.get("content_length", 0)
                line_count = data.get("line_count", 0)
                word_count = data.get("word_count", 0)
                path = data.get("path", "")

                # Skip if no URL
                if not url:
                    continue

                # Extract subdomain from URL
                parsed = urlparse(url)
                subdomain = parsed.netloc

                unique_key = url
                if unique_key not in seen:
                    seen.add(unique_key)
                    results.append({
                        "url": url,
                        "subdomain": subdomain,
                        "target": current_target,
                        "path": path or parsed.path,
                        "status_code": status,
                        "size": content_length,
                        "lines": line_count,
                        "words": word_count,
                        "type": "directory",
                    })

            except json.JSONDecodeError:
                # Fallback: try to parse plain text output
                # Format: STATUS METHOD LINESl WORDSw SIZEc URL
                # Example: 200      GET      123l      456w     7890c http://example.com/path
                parts = line.split()
                if len(parts) >= 6 and parts[0].isdigit():
                    try:
                        status = int(parts[0])
                        # method = parts[1]
                        url = parts[-1]

                        if not url.startswith("http"):
                            continue

                        # Parse size info
                        size = 0
                        for part in parts[2:-1]:
                            if part.endswith("c"):
                                try:
                                    size = int(part[:-1])
                                except ValueError:
                                    pass

                        parsed = urlparse(url)
                        subdomain = parsed.netloc

                        unique_key = url
                        if unique_key not in seen:
                            seen.add(unique_key)
                            results.append({
                                "url": url,
                                "subdomain": subdomain,
                                "target": current_target,
                                "path": parsed.path,
                                "status_code": status,
                                "size": size,
                                "lines": 0,
                                "words": 0,
                                "type": "directory",
                            })
                    except (ValueError, IndexError):
                        pass

        return results
