"""Subdomain probe module to check which subdomains are alive."""

import asyncio
import sys
from typing import AsyncIterator, Any
from .base import BaseModule


class ProbeModule(BaseModule):
    """Check which subdomains are alive/responding."""

    name = "probe"
    description = "Check subdomain availability using httpx or curl"
    required_tools = []  # Will be set dynamically

    def __init__(self, config: dict):
        """Initialize with config."""
        super().__init__(config)
        import shutil

        # Check available tools
        self._use_httpx = False
        self._use_curl = False

        # Check for httpx first
        httpx_path = self.tools_config.get("httpx", "httpx")
        if shutil.which(httpx_path) or shutil.which("httpx"):
            self._use_httpx = True
            self.required_tools = ["httpx"]
        else:
            # Try curl as fallback
            curl_path = self.tools_config.get("curl", "curl")
            if shutil.which(curl_path) or shutil.which("curl"):
                self._use_curl = True
                self.required_tools = ["curl"]
            else:
                # No external tools - will use Python fallback
                self.required_tools = []

    def is_available(self) -> bool:
        """Override to always return True since we have Python fallback."""
        if self._use_httpx or self._use_curl:
            return True
        # Python fallback is always available
        return True

    async def run(
        self, target: str, module_config: dict, log_callback: callable = None
    ) -> AsyncIterator[str]:
        """Probe subdomains to check if they're alive.

        Args:
            target: Main target domain.
            module_config: Module configuration with 'subdomains' list.
            log_callback: Callback for log messages.

        Yields:
            Output lines with subdomain probe results.
        """
        subdomains = module_config.get("subdomains", [])
        if not subdomains:
            subdomains = [target]

        timeout = module_config.get("timeout", 120)

        if log_callback:
            log_callback(f"[probe] Received {len(subdomains)} subdomains to check")
            log_callback(f"[probe] Subdomains: {subdomains[:5]}{'...' if len(subdomains) > 5 else ''}")

        results_count = 0

        if self._use_httpx:
            if log_callback:
                log_callback("[probe] Using httpx")
            async for line in self._run_httpx(subdomains, timeout, log_callback):
                results_count += 1
                yield line
        elif self._use_curl:
            if log_callback:
                log_callback("[probe] Using curl")
            async for line in self._run_curl(subdomains, timeout, log_callback):
                results_count += 1
                yield line
        else:
            if log_callback:
                log_callback("[probe] Using Python fallback (no httpx/curl found)")
            async for line in self._run_python_probe(subdomains, timeout, log_callback):
                results_count += 1
                yield line

        if log_callback:
            log_callback(f"[probe] Generated {results_count} results")

    async def _run_httpx(
        self, subdomains: list[str], timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Use httpx to probe subdomains."""
        tool_path = self.get_tool_path("httpx")

        cmd = [
            tool_path,
            "-silent",
            "-json",
            "-timeout", "10",
            "-retries", "1",
        ]

        if log_callback:
            log_callback(f"[probe] Running httpx on {len(subdomains)} targets")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Probe both http and https for each subdomain
            targets = []
            for s in subdomains:
                if s.startswith(("http://", "https://")):
                    targets.append(s)
                else:
                    targets.append(f"https://{s}")
                    targets.append(f"http://{s}")
            input_data = "\n".join(targets)

            stdout, stderr = await asyncio.wait_for(
                process.communicate(input_data.encode()),
                timeout=timeout
            )

            if stderr and log_callback:
                err_text = stderr.decode("utf-8", errors="replace").strip()
                if err_text:
                    log_callback(f"[probe] httpx stderr: {err_text[:200]}")

            output = stdout.decode("utf-8", errors="replace")
            for line in output.split("\n"):
                if line.strip():
                    yield line.strip()

        except asyncio.TimeoutError:
            if log_callback:
                log_callback(f"[probe] Timeout after {timeout}s")
        except FileNotFoundError:
            if log_callback:
                log_callback(f"[probe] httpx not found at {tool_path}")
        except Exception as e:
            if log_callback:
                log_callback(f"[probe] httpx error: {e}")

    async def _run_curl(
        self, subdomains: list[str], timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Fallback to curl for probing."""
        tool_path = self.get_tool_path("curl")
        null_device = "NUL" if sys.platform == "win32" else "/dev/null"

        for i, subdomain in enumerate(subdomains):
            # Determine URLs to try
            if subdomain.startswith(("http://", "https://")):
                urls_to_try = [subdomain]
            else:
                urls_to_try = [f"https://{subdomain}", f"http://{subdomain}"]

            status_code = "000"
            for url in urls_to_try:
                # Windows-compatible curl command
                cmd = [
                    tool_path,
                    "-s",
                    "-o", null_device,
                    "-w", "%{http_code}",
                    "-m", "10",
                    "--connect-timeout", "5",
                    "-L",
                    "-k",  # Allow insecure connections
                    url,
                ]

                try:
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    stdout, _ = await asyncio.wait_for(
                        process.communicate(),
                        timeout=15
                    )
                    code = stdout.decode().strip()
                    # If we got a valid response (not 000), use it
                    if code and code != "000":
                        status_code = code
                        break
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    if log_callback:
                        log_callback(f"[probe] curl error for {url}: {e}")
                    continue

            yield f"{subdomain}|{status_code}"

            if log_callback and (i + 1) % 10 == 0:
                log_callback(f"[probe] Checked {i + 1}/{len(subdomains)} subdomains")

    async def _run_python_probe(
        self, subdomains: list[str], timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Pure Python fallback using asyncio."""
        import ssl
        import urllib.request
        import urllib.error

        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        async def check_subdomain(subdomain: str) -> str:
            loop = asyncio.get_running_loop()

            def do_request():
                # Try HTTPS first, then HTTP
                for scheme in ["https", "http"]:
                    if subdomain.startswith(("http://", "https://")):
                        url = subdomain
                    else:
                        url = f"{scheme}://{subdomain}"
                    try:
                        req = urllib.request.Request(
                            url,
                            method="HEAD",
                            headers={"User-Agent": "Mozilla/5.0 ReconAutomator/1.0"}
                        )
                        with urllib.request.urlopen(req, timeout=10, context=ssl_context) as resp:
                            return resp.getcode()
                    except urllib.error.HTTPError as e:
                        return e.code
                    except Exception:
                        continue
                return 0

            try:
                status = await asyncio.wait_for(
                    loop.run_in_executor(None, do_request),
                    timeout=15
                )
                return f"{subdomain}|{status}"
            except asyncio.TimeoutError:
                return f"{subdomain}|000"
            except Exception:
                return f"{subdomain}|000"

        # Process subdomains with concurrency limit
        semaphore = asyncio.Semaphore(10)

        async def limited_check(subdomain):
            async with semaphore:
                return await check_subdomain(subdomain)

        tasks = [limited_check(s) for s in subdomains]

        for i, coro in enumerate(asyncio.as_completed(tasks)):
            result = await coro
            yield result

            if log_callback and (i + 1) % 10 == 0:
                log_callback(f"[probe] Checked {i + 1}/{len(subdomains)} subdomains")

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

            # Try httpx JSON format first
            try:
                data = json.loads(line)
                url = data.get("url", "")
                status = data.get("status_code", 0)
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

            # Try pipe-delimited format: subdomain|status_code
            if "|" in line:
                parts = line.split("|")
                if len(parts) >= 2:
                    subdomain = parts[0].strip()
                    try:
                        status = int(parts[1].strip())
                    except ValueError:
                        status = 0

                    if subdomain and subdomain not in seen:
                        seen.add(subdomain)
                        results.append({
                            "subdomain": subdomain,
                            "url": f"https://{subdomain}",
                            "status_code": status,
                            "alive": status > 0 and 200 <= status < 500,
                            "type": "probe",
                        })

        return results
