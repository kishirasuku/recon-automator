"""JavaScript analysis module using linkfinder and secretfinder."""

import re
import json
import tempfile
from pathlib import Path
from typing import AsyncIterator, Any
from urllib.parse import urlparse, urljoin
from .base import BaseModule
from core.runner import run_command


class JSAnalyzeModule(BaseModule):
    """JavaScript file analysis for endpoints and secrets."""

    name = "jsanalyze"
    description = "Analyze JavaScript files for endpoints and secrets"
    required_tools = ["linkfinder"]  # Primary tool

    def __init__(self, config: dict):
        """Initialize with config, checking for alternative tools."""
        super().__init__(config)
        self.has_secretfinder = self._check_secretfinder()

    def _check_secretfinder(self) -> bool:
        """Check if secretfinder is available."""
        import shutil
        tool_path = self.tools_config.get("secretfinder")
        if tool_path:
            return bool(shutil.which(tool_path) or shutil.which("secretfinder"))
        return bool(shutil.which("secretfinder"))

    async def run(
        self, target: str, module_config: dict, log_callback: callable = None
    ) -> AsyncIterator[str]:
        """Run JavaScript analysis against the target.

        This module can work in two modes:
        1. Direct URL mode: Analyze JS files from a target URL
        2. File list mode: Analyze a list of JS URLs (from wayback/other modules)

        Args:
            target: Target domain or URL.
            module_config: Module configuration.
            log_callback: Callback for log messages.

        Yields:
            Output lines from the analysis tools.
        """
        timeout = module_config.get("timeout", 300)
        js_urls = module_config.get("js_urls", [])
        scan_secrets = module_config.get("scan_secrets", True)
        max_files = module_config.get("max_files", 50)

        # If no JS URLs provided, try to discover from target
        if not js_urls:
            if not target.startswith(("http://", "https://")):
                target = f"https://{target}"
            js_urls = [target]

        # Filter and validate URLs
        valid_js_urls = []
        for url in js_urls:
            # Skip obviously invalid URLs
            if not url or len(url) < 10:
                continue
            # Ensure URL has proper scheme
            if not url.startswith(("http://", "https://")):
                continue
            # Skip URLs with obviously invalid domains
            parsed = urlparse(url)
            if not parsed.netloc or "." not in parsed.netloc:
                continue
            valid_js_urls.append(url)

        # Limit the number of files to analyze
        js_urls = valid_js_urls[:max_files]

        if log_callback:
            log_callback(f"[jsanalyze] Analyzing {len(js_urls)} targets")

        # Run linkfinder on each URL/target
        for url in js_urls:
            if log_callback:
                log_callback(f"[jsanalyze] Processing: {url}")

            # Run linkfinder
            async for line in self._run_linkfinder(url, timeout, log_callback):
                yield f"ENDPOINT:{line}"

            # Run secretfinder if available and enabled
            if self.has_secretfinder and scan_secrets:
                async for line in self._run_secretfinder(url, timeout, log_callback):
                    yield f"SECRET:{line}"

    async def _run_linkfinder(
        self, target: str, timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Run linkfinder to extract endpoints from JavaScript.

        Args:
            target: Target URL or JS file URL.
            timeout: Command timeout.
            log_callback: Log callback function.

        Yields:
            Discovered endpoints.
        """
        tool_path = self.get_tool_path("linkfinder")

        cmd = [
            "python3" if not tool_path.endswith(".py") else "python3",
            tool_path if tool_path.endswith(".py") else f"{tool_path}.py",
            "-i", target,
            "-o", "cli",
        ]

        # Handle case where linkfinder is installed as a command
        import shutil
        if shutil.which("linkfinder"):
            cmd = ["linkfinder", "-i", target, "-o", "cli"]
        elif shutil.which("linkfinder.py"):
            cmd = ["python3", "linkfinder.py", "-i", target, "-o", "cli"]

        if log_callback:
            log_callback(f"[jsanalyze] Running linkfinder: {' '.join(cmd)}")

        try:
            async for line in run_command(cmd, timeout=timeout, log_callback=log_callback):
                line = line.strip()
                if not line:
                    continue
                # Skip error messages from linkfinder
                if any(err in line.lower() for err in [
                    "error:", "usage:", "invalid input", "ssl error",
                    "urlopen error", "connection refused", "timed out"
                ]):
                    if log_callback:
                        log_callback(f"[jsanalyze] Skipping error: {line[:80]}")
                    continue
                yield line
        except Exception as e:
            if log_callback:
                log_callback(f"[jsanalyze] Error running linkfinder on {target}: {e}")

    async def _run_secretfinder(
        self, target: str, timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Run secretfinder to detect secrets in JavaScript.

        Args:
            target: Target URL or JS file URL.
            timeout: Command timeout.
            log_callback: Log callback function.

        Yields:
            Discovered secrets.
        """
        tool_path = self.get_tool_path("secretfinder")

        cmd = [
            "python3",
            tool_path if tool_path else "SecretFinder.py",
            "-i", target,
            "-o", "cli",
        ]

        # Handle case where secretfinder is installed as a command
        import shutil
        if shutil.which("secretfinder"):
            cmd = ["secretfinder", "-i", target, "-o", "cli"]
        elif shutil.which("SecretFinder.py"):
            cmd = ["python3", "SecretFinder.py", "-i", target, "-o", "cli"]

        if log_callback:
            log_callback(f"[jsanalyze] Running secretfinder: {' '.join(cmd)}")

        async for line in run_command(cmd, timeout=timeout, log_callback=log_callback):
            if line.strip():
                yield line.strip()

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse tool output into structured data.

        Args:
            raw_output: Raw output from linkfinder and secretfinder.

        Returns:
            List of finding dictionaries.
        """
        results = []
        seen_endpoints = set()
        seen_secrets = set()

        # Patterns for categorizing endpoints
        api_patterns = [
            r"/api/",
            r"/v\d+/",
            r"/graphql",
            r"/rest/",
            r"/ajax/",
        ]

        # Patterns for identifying potential secrets
        secret_patterns = {
            "aws_access_key": r"AKIA[0-9A-Z]{16}",
            "aws_secret_key": r"[0-9a-zA-Z/+]{40}",
            "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
            "github_token": r"gh[pousr]_[A-Za-z0-9_]{36}",
            "slack_token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
            "jwt_token": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*",
            "private_key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "generic_api_key": r"['\"][a-zA-Z0-9_-]*[aA][pP][iI]_?[kK][eE][yY]['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
            "generic_secret": r"['\"][a-zA-Z0-9_-]*[sS][eE][cC][rR][eE][tT]['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
            "bearer_token": r"[bB]earer\s+[a-zA-Z0-9_\-\.]+",
        }

        for line in raw_output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue

            # Parse endpoint lines (from linkfinder)
            if line.startswith("ENDPOINT:"):
                endpoint = line[9:].strip()
                if endpoint and endpoint not in seen_endpoints:
                    seen_endpoints.add(endpoint)

                    # Categorize the endpoint
                    category = "endpoint"
                    if any(re.search(p, endpoint, re.I) for p in api_patterns):
                        category = "api_endpoint"
                    elif endpoint.endswith((".js", ".jsx", ".ts", ".tsx")):
                        category = "javascript"
                    elif endpoint.endswith((".json", ".xml")):
                        category = "data"
                    elif "admin" in endpoint.lower():
                        category = "admin"
                    elif "auth" in endpoint.lower() or "login" in endpoint.lower():
                        category = "auth"
                    elif "upload" in endpoint.lower():
                        category = "upload"
                    elif "config" in endpoint.lower():
                        category = "config"

                    # Determine sensitivity
                    sensitivity = "low"
                    sensitive_keywords = [
                        "admin", "config", "secret", "password", "token",
                        "key", "auth", "private", "internal", "debug",
                    ]
                    if any(kw in endpoint.lower() for kw in sensitive_keywords):
                        sensitivity = "high"
                    elif category in ["api_endpoint", "auth", "upload"]:
                        sensitivity = "medium"

                    results.append({
                        "finding": endpoint,
                        "category": category,
                        "sensitivity": sensitivity,
                        "source": "linkfinder",
                        "type": "js_endpoint",
                    })

            # Parse secret lines (from secretfinder)
            elif line.startswith("SECRET:"):
                secret_line = line[7:].strip()
                if secret_line and secret_line not in seen_secrets:
                    seen_secrets.add(secret_line)

                    # Try to identify the secret type
                    secret_type = "unknown"
                    for stype, pattern in secret_patterns.items():
                        if re.search(pattern, secret_line):
                            secret_type = stype
                            break

                    results.append({
                        "finding": secret_line,
                        "category": "secret",
                        "secret_type": secret_type,
                        "sensitivity": "critical",
                        "source": "secretfinder",
                        "type": "js_secret",
                    })

            # Handle raw output (no prefix)
            else:
                # Check if it looks like an endpoint
                if line.startswith("/") or line.startswith("http"):
                    if line not in seen_endpoints:
                        seen_endpoints.add(line)
                        results.append({
                            "finding": line,
                            "category": "endpoint",
                            "sensitivity": "low",
                            "source": "unknown",
                            "type": "js_endpoint",
                        })
                # Check if it matches any secret pattern
                else:
                    for stype, pattern in secret_patterns.items():
                        if re.search(pattern, line):
                            if line not in seen_secrets:
                                seen_secrets.add(line)
                                results.append({
                                    "finding": line,
                                    "category": "secret",
                                    "secret_type": stype,
                                    "sensitivity": "critical",
                                    "source": "pattern_match",
                                    "type": "js_secret",
                                })
                            break

        return results

    def get_js_urls_from_wayback(self, wayback_results: list[dict]) -> list[str]:
        """Extract JavaScript URLs from wayback module results.

        This helper method can be used to filter JS files from wayback results
        for deeper analysis.

        Args:
            wayback_results: Results from the wayback module.

        Returns:
            List of JavaScript file URLs.
        """
        js_urls = []
        seen = set()

        for result in wayback_results:
            url = result.get("url", "")
            category = result.get("category", "")
            extension = result.get("extension", "")

            if category == "javascript" or extension in ["js", "jsx", "ts", "tsx"]:
                if url and url not in seen:
                    seen.add(url)
                    js_urls.append(url)

        return js_urls
