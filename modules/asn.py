"""ASN (Autonomous System Number) investigation module."""

import asyncio
import re
from typing import AsyncIterator, Any
from .base import BaseModule


class ASNModule(BaseModule):
    """Discover ASN information for target domains."""

    name = "asn"
    description = "Investigate ASN and IP ranges using asnmap or whois"
    required_tools = []  # Will be set dynamically

    def __init__(self, config: dict):
        """Initialize with config."""
        super().__init__(config)
        import shutil

        self._use_asnmap = False
        self._use_amass = False
        self._asnmap_bin = None

        # Check for asnmap first (projectdiscovery tool)
        asnmap_path = self.tools_config.get("asnmap", "asnmap")
        asnmap_bin = shutil.which(asnmap_path) or shutil.which("asnmap")
        if asnmap_bin:
            self._use_asnmap = True
            self._asnmap_bin = asnmap_bin
            self.required_tools = ["asnmap"]
        else:
            # Check for amass as fallback
            amass_path = self.tools_config.get("amass", "amass")
            if shutil.which(amass_path) or shutil.which("amass"):
                self._use_amass = True
                self.required_tools = ["amass"]
            else:
                # Will use Python fallback with whois
                self.required_tools = []

    def is_available(self) -> bool:
        """Override to always return True since we have Python fallback."""
        return True

    async def run(
        self, target: str, module_config: dict, log_callback: callable = None
    ) -> AsyncIterator[str]:
        """Run ASN investigation.

        Args:
            target: Target domain.
            module_config: Module configuration.
            log_callback: Callback for log messages.

        Yields:
            Output lines with ASN information.
        """
        timeout = module_config.get("timeout", 120)
        subdomains = module_config.get("subdomains", [target])

        if log_callback:
            log_callback(f"[asn] Investigating ASN for {len(subdomains)} targets")

        if self._use_asnmap:
            if log_callback:
                log_callback("[asn] Using asnmap")
            async for line in self._run_asnmap(subdomains, timeout, log_callback):
                yield line
        elif self._use_amass:
            if log_callback:
                log_callback("[asn] Using amass")
            async for line in self._run_amass(target, timeout, log_callback):
                yield line
        else:
            if log_callback:
                log_callback("[asn] Using Python fallback (DNS/socket lookup)")
            async for line in self._run_python_asn(subdomains, timeout, log_callback):
                yield line

    async def _run_asnmap(
        self, subdomains: list[str], timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Use asnmap to get ASN information."""
        tool_path = self._asnmap_bin

        cmd = [
            tool_path,
            "-silent",
            "-json",
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            input_data = "\n".join(subdomains)
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input_data.encode()),
                timeout=timeout
            )

            if stderr and log_callback:
                err_text = stderr.decode("utf-8", errors="replace").strip()
                if err_text:
                    log_callback(f"[asn] asnmap stderr: {err_text[:200]}")

            output = stdout.decode("utf-8", errors="replace")
            for line in output.split("\n"):
                if line.strip():
                    yield line.strip()

        except asyncio.TimeoutError:
            if log_callback:
                log_callback(f"[asn] Timeout after {timeout}s")
        except Exception as e:
            if log_callback:
                log_callback(f"[asn] asnmap error: {e}")

    async def _run_amass(
        self, target: str, timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Use amass intel for ASN discovery."""
        tool_path = self.get_tool_path("amass")

        cmd = [
            tool_path,
            "intel",
            "-d", target,
            "-asn",
        ]

        if log_callback:
            log_callback(f"[asn] Running: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            output = stdout.decode("utf-8", errors="replace")
            for line in output.split("\n"):
                if line.strip():
                    yield line.strip()

        except asyncio.TimeoutError:
            if log_callback:
                log_callback(f"[asn] Timeout after {timeout}s")
        except Exception as e:
            if log_callback:
                log_callback(f"[asn] amass error: {e}")

    async def _run_python_asn(
        self, subdomains: list[str], timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Python fallback using socket and basic lookups."""
        import socket

        seen_ips = set()
        loop = asyncio.get_running_loop()

        for subdomain in subdomains[:10]:  # Limit to first 10 to avoid slowness
            try:
                # Resolve domain to IP
                def resolve():
                    try:
                        return socket.gethostbyname(subdomain)
                    except Exception:
                        return None

                ip = await asyncio.wait_for(
                    loop.run_in_executor(None, resolve),
                    timeout=10
                )

                if ip and ip not in seen_ips:
                    seen_ips.add(ip)
                    yield f"{subdomain}|{ip}|unknown|unknown"

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                if log_callback:
                    log_callback(f"[asn] Error resolving {subdomain}: {e}")

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse ASN output into structured data.

        Args:
            raw_output: Raw output from ASN tools.

        Returns:
            List of ASN information dictionaries.
        """
        import json
        results = []
        seen = set()

        for line in raw_output.strip().split("\n"):
            if not line.strip():
                continue

            # Try JSON format (asnmap)
            try:
                data = json.loads(line)
                asn = data.get("as_number", data.get("asn", ""))
                as_name = data.get("as_name", data.get("org", ""))
                as_country = data.get("as_country", data.get("country", ""))
                cidr = data.get("as_range", data.get("cidr", ""))
                input_val = data.get("input", "")

                key = f"{asn}_{input_val}"
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "input": input_val,
                        "asn": str(asn),
                        "as_name": as_name,
                        "as_country": as_country,
                        "cidr": cidr,
                        "type": "asn",
                    })
                continue
            except json.JSONDecodeError:
                pass

            # Try pipe-delimited format (Python fallback)
            if "|" in line:
                parts = line.split("|")
                if len(parts) >= 2:
                    subdomain = parts[0].strip()
                    ip = parts[1].strip() if len(parts) > 1 else ""
                    asn = parts[2].strip() if len(parts) > 2 else "unknown"
                    org = parts[3].strip() if len(parts) > 3 else "unknown"

                    key = f"{ip}_{subdomain}"
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "input": subdomain,
                            "ip": ip,
                            "asn": asn,
                            "as_name": org,
                            "as_country": "",
                            "cidr": "",
                            "type": "asn",
                        })
                continue

            # Try amass format: ASN, CIDR, Description
            if re.match(r'^\d+,', line):
                parts = line.split(',')
                if len(parts) >= 2:
                    asn = parts[0].strip()
                    cidr = parts[1].strip() if len(parts) > 1 else ""
                    desc = parts[2].strip() if len(parts) > 2 else ""

                    key = f"AS{asn}"
                    if key not in seen:
                        seen.add(key)
                        results.append({
                            "input": "",
                            "asn": f"AS{asn}",
                            "as_name": desc,
                            "as_country": "",
                            "cidr": cidr,
                            "type": "asn",
                        })

        return results
