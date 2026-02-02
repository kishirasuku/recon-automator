"""Subdomain probe module to check which subdomains are alive."""

import asyncio
from typing import AsyncIterator, Any
from .base import BaseModule
from core.runner import run_command


class ProbeModule(BaseModule):
    """Check which subdomains are alive/responding."""

    name = "probe"
    description = "Check subdomain availability using httpx"
    required_tools = ["httpx"]

    def __init__(self, config: dict):
        """Initialize with config."""
        super().__init__(config)
        # Can also use curl as fallback
        if not self.is_available():
            self.required_tools = ["curl"]

    async def run(
        self, target: str, module_config: dict, log_callback: callable = None
    ) -> AsyncIterator[str]:
        """Probe subdomains to check if they're alive.

        Args:
            target: Not used directly - uses subdomains from module_config.
            module_config: Module configuration with 'subdomains' list.
            log_callback: Callback for log messages.

        Yields:
            Output lines with alive subdomain info.
        """
        subdomains = module_config.get("subdomains", [])
        if not subdomains:
            # If no subdomains provided, just probe the main target
            subdomains = [target]

        timeout = module_config.get("timeout", 120)

        if log_callback:
            log_callback(f"[probe] Checking {len(subdomains)} subdomains...")

        if "httpx" in self.required_tools:
            async for line in self._run_httpx(subdomains, timeout, log_callback):
                yield line
        else:
            async for line in self._run_curl(subdomains, timeout, log_callback):
                yield line

    async def _run_httpx(
        self, subdomains: list[str], timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Use httpx to probe subdomains."""
        tool_path = self.get_tool_path("httpx")

        # Create temp file with subdomains or use stdin
        # httpx can read from stdin with -l -
        cmd = [
            tool_path,
            "-silent",
            "-json",
            "-timeout", "10",
            "-retries", "1",
            "-no-fallback",
        ]

        if log_callback:
            log_callback(f"[probe] Running httpx on {len(subdomains)} targets")

        # Run httpx with subdomains piped to stdin
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )

            # Prepare input - one subdomain per line with protocol
            input_data = "\n".join(
                f"https://{s}" if not s.startswith(("http://", "https://")) else s
                for s in subdomains
            )

            stdout, _ = await asyncio.wait_for(
                process.communicate(input_data.encode()),
                timeout=timeout
            )

            for line in stdout.decode("utf-8", errors="replace").split("\n"):
                if line.strip():
                    yield line.strip()

        except asyncio.TimeoutError:
            if log_callback:
                log_callback(f"[probe] Timeout after {timeout}s")
        except Exception as e:
            if log_callback:
                log_callback(f"[probe] Error: {e}")

    async def _run_curl(
        self, subdomains: list[str], timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Fallback to curl for probing."""
        tool_path = self.get_tool_path("curl")

        for subdomain in subdomains:
            if not subdomain.startswith(("http://", "https://")):
                url = f"https://{subdomain}"
            else:
                url = subdomain

            cmd = [
                tool_path,
                "-s",
                "-o", "/dev/null",
                "-w", f"{subdomain}|%{{http_code}}|%{{time_total}}",
                "-m", "10",  # timeout
                "--connect-timeout", "5",
                "-L",  # follow redirects
                url,
            ]

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await process.communicate()
                result = stdout.decode().strip()
                if result:
                    yield result
            except Exception:
                yield f"{subdomain}|000|0"

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse probe output into structured data.

        Args:
            raw_output: Raw output from probe.

        Returns:
            List of subdomain status dictionaries.
        """
        import json
        results = []
        seen = set()

        for line in raw_output.strip().split("\n"):
            if not line.strip():
                continue

            # Try httpx JSON format
            try:
                data = json.loads(line)
                url = data.get("url", "")
                status = data.get("status_code", 0)
                # Extract subdomain from URL
                subdomain = url.replace("https://", "").replace("http://", "").split("/")[0]

                if subdomain and subdomain not in seen:
                    seen.add(subdomain)
                    results.append({
                        "subdomain": subdomain,
                        "url": url,
                        "status_code": status,
                        "alive": 200 <= status < 500,
                        "type": "probe",
                    })
                continue
            except json.JSONDecodeError:
                pass

            # Try curl format: subdomain|status_code|time
            if "|" in line:
                parts = line.split("|")
                if len(parts) >= 2:
                    subdomain = parts[0]
                    try:
                        status = int(parts[1])
                    except ValueError:
                        status = 0

                    if subdomain and subdomain not in seen:
                        seen.add(subdomain)
                        results.append({
                            "subdomain": subdomain,
                            "url": f"https://{subdomain}",
                            "status_code": status,
                            "alive": 200 <= status < 500,
                            "type": "probe",
                        })

        return results
