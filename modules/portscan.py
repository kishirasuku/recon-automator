"""Port scanning module using nmap."""

import re
from typing import AsyncIterator, Any
from .base import BaseModule
from core.runner import run_command


class PortScanModule(BaseModule):
    """Port scanning using nmap."""

    name = "portscan"
    description = "Scan for open ports using nmap"
    required_tools = ["nmap"]

    async def run(
        self, target: str, module_config: dict, log_callback: callable = None
    ) -> AsyncIterator[str]:
        """Run nmap against the target.

        Args:
            target: Target domain or IP.
            module_config: Module configuration.
            log_callback: Callback for log messages.

        Yields:
            Output lines from nmap.
        """
        tool_path = self.get_tool_path("nmap")
        ports = module_config.get("ports", "top-1000")
        timeout = module_config.get("timeout", 300)

        cmd = [tool_path]

        # Handle port specification
        if ports == "top-1000":
            cmd.extend(["--top-ports", "1000"])
        elif ports == "1-65535":
            cmd.extend(["-p-"])
        else:
            cmd.extend(["-p", ports])

        # Add common options for faster scanning
        cmd.extend([
            "-T4",           # Aggressive timing
            "-sV",           # Service version detection
            "--open",        # Only show open ports
            "-oG", "-",      # Grepable output to stdout
            target,
        ])

        if log_callback:
            log_callback(f"[portscan] Running: {' '.join(cmd)}")

        async for line in run_command(cmd, timeout=timeout, log_callback=log_callback):
            yield line

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse nmap grepable output into structured data.

        Args:
            raw_output: Raw grepable output from nmap.

        Returns:
            List of port dictionaries.
        """
        results = []

        # Parse grepable format: Host: IP () Ports: 80/open/tcp//http//nginx/
        port_pattern = re.compile(
            r"(\d+)/open/([^/]*)//?([^/]*)?//?([^/]*)?"
        )

        for line in raw_output.split("\n"):
            if "Ports:" in line:
                # Extract host
                host_match = re.search(r"Host:\s+(\S+)", line)
                host = host_match.group(1) if host_match else "unknown"

                # Extract ports section
                ports_section = line.split("Ports:")[1] if "Ports:" in line else ""

                for match in port_pattern.finditer(ports_section):
                    port = match.group(1)
                    protocol = match.group(2) or "tcp"
                    service = match.group(3) or "unknown"
                    version = match.group(4) or ""

                    results.append({
                        "host": host,
                        "port": int(port),
                        "protocol": protocol,
                        "service": service,
                        "version": version.strip(),
                        "type": "port",
                    })

        return results
