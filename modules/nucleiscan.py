"""Nuclei vulnerability scanning module using paramanalyze results."""

import json
from pathlib import Path
from typing import AsyncIterator, Any
from .base import BaseModule
from core.runner import run_command


class NucleiScanModule(BaseModule):
    """Run nuclei scans on URLs identified by paramanalyze."""

    name = "nucleiscan"
    description = "Scan for vulnerabilities using nuclei templates"
    required_tools = ["nuclei"]

    # Map paramanalyze categories to nuclei template tags
    CATEGORY_TEMPLATES = {
        "sqli": ["sqli", "sql-injection"],
        "xss": ["xss", "cross-site-scripting"],
        "lfi": ["lfi", "file-inclusion", "path-traversal"],
        "ssrf": ["ssrf", "server-side-request-forgery"],
        "redirect": ["redirect", "open-redirect"],
        "rce": ["rce", "command-injection", "code-injection"],
        "idor": ["idor", "insecure-direct-object-reference"],
        "debug": ["exposure", "debug", "config"],
    }

    # Severity levels
    SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]

    def __init__(self, config: dict):
        """Initialize with config."""
        super().__init__(config)
        self.nuclei_config = config.get("nucleiscan", {})

    async def run(
        self, target: str, module_config: dict, log_callback: callable = None
    ) -> AsyncIterator[str]:
        """Run nuclei scans based on paramanalyze results.

        Args:
            target: Target domain.
            module_config: Module configuration.
            log_callback: Callback for log messages.

        Yields:
            JSON lines with nuclei findings.
        """
        # Get paramanalyze results or URLs
        param_results = module_config.get("param_results", [])
        urls_by_category = module_config.get("urls_by_category", {})

        if not param_results and not urls_by_category:
            if log_callback:
                log_callback("[nucleiscan] No paramanalyze results provided")
            return

        # Build URLs by category from param_results if not provided directly
        if not urls_by_category and param_results:
            urls_by_category = self._group_urls_by_category(param_results)

        # Configuration
        timeout = module_config.get("timeout", 600)
        rate_limit = module_config.get("rate_limit", 50)
        severity_filter = module_config.get("severity", ["critical", "high", "medium"])
        custom_templates = module_config.get("custom_templates", [])
        scan_dir = module_config.get("scan_dir")

        if log_callback:
            total_urls = sum(len(urls) for urls in urls_by_category.values())
            log_callback(f"[nucleiscan] Scanning {total_urls} URLs across {len(urls_by_category)} categories")
            log_callback(f"[nucleiscan] Severity filter: {', '.join(severity_filter)}")

        # Run nuclei for each category
        for category, urls in urls_by_category.items():
            if not urls:
                continue

            if log_callback:
                log_callback(f"[nucleiscan] Scanning {category} ({len(urls)} URLs)")

            # Get templates for this category
            templates = self._get_templates_for_category(category, custom_templates)

            if not templates:
                if log_callback:
                    log_callback(f"[nucleiscan] No templates for category: {category}")
                continue

            # Write URLs to temp file
            if scan_dir:
                urls_file = Path(scan_dir) / f"nuclei_targets_{category}.txt"
            else:
                urls_file = Path(f"/tmp/nuclei_targets_{category}.txt")

            urls_file.parent.mkdir(parents=True, exist_ok=True)
            with open(urls_file, "w", encoding="utf-8") as f:
                f.write("\n".join(urls))

            # Run nuclei
            async for line in self._run_nuclei(
                urls_file=urls_file,
                templates=templates,
                severity_filter=severity_filter,
                rate_limit=rate_limit,
                timeout=timeout,
                category=category,
                log_callback=log_callback,
            ):
                yield line

        if log_callback:
            log_callback("[nucleiscan] Scan complete")

    def _group_urls_by_category(self, param_results: list[dict]) -> dict[str, set[str]]:
        """Group URLs by vulnerability category.

        Args:
            param_results: List of paramanalyze results.

        Returns:
            Dictionary mapping category to set of URLs.
        """
        urls_by_category: dict[str, set[str]] = {}

        for item in param_results:
            category = item.get("category", "unknown")
            sample_urls = item.get("sample_urls", [])

            if category not in urls_by_category:
                urls_by_category[category] = set()

            urls_by_category[category].update(sample_urls)

        return {k: list(v) for k, v in urls_by_category.items()}

    def _get_templates_for_category(
        self, category: str, custom_templates: list[str]
    ) -> list[str]:
        """Get nuclei template tags for a category.

        Args:
            category: Vulnerability category.
            custom_templates: Custom template paths/tags.

        Returns:
            List of template tags/paths.
        """
        templates = []

        # Add category-specific templates
        if category in self.CATEGORY_TEMPLATES:
            templates.extend(self.CATEGORY_TEMPLATES[category])

        # Add custom templates if specified for this category
        for custom in custom_templates:
            if custom.startswith(f"{category}:"):
                # Format: "category:/path/to/template"
                templates.append(custom.split(":", 1)[1])
            elif ":" not in custom:
                # No category prefix, apply to all
                templates.append(custom)

        return templates

    async def _run_nuclei(
        self,
        urls_file: Path,
        templates: list[str],
        severity_filter: list[str],
        rate_limit: int,
        timeout: int,
        category: str,
        log_callback: callable,
    ) -> AsyncIterator[str]:
        """Run nuclei with specified configuration.

        Args:
            urls_file: Path to file containing URLs.
            templates: List of template tags/paths.
            severity_filter: List of severity levels to include.
            rate_limit: Requests per second limit.
            timeout: Timeout in seconds.
            category: Category name for logging.
            log_callback: Log callback.

        Yields:
            JSON lines with findings.
        """
        tool_path = self.get_tool_path("nuclei")

        cmd = [
            tool_path,
            "-l", str(urls_file),
            "-jsonl",                    # JSON lines output
            "-silent",                   # Minimal output
            "-nc",                       # No color
            "-rate-limit", str(rate_limit),
        ]

        # Add severity filter
        if severity_filter:
            cmd.extend(["-severity", ",".join(severity_filter)])

        # Add templates
        for template in templates:
            if template.startswith("/") or template.endswith(".yaml"):
                # It's a path
                cmd.extend(["-t", template])
            else:
                # It's a tag
                cmd.extend(["-tags", template])

        if log_callback:
            log_callback(f"[nucleiscan] Running: {' '.join(cmd[:8])}...")

        finding_count = 0
        try:
            async for line in run_command(cmd, timeout=timeout, log_callback=log_callback):
                if line.strip():
                    try:
                        # Parse and enrich the finding
                        finding = json.loads(line)
                        finding["scan_category"] = category
                        finding_count += 1
                        yield json.dumps(finding)
                    except json.JSONDecodeError:
                        # Not JSON, might be error or status message
                        if log_callback and "error" in line.lower():
                            log_callback(f"[nucleiscan] {line}")

        except Exception as e:
            if log_callback:
                log_callback(f"[nucleiscan] Error running nuclei: {e}")

        if log_callback:
            log_callback(f"[nucleiscan] {category}: {finding_count} findings")

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse nuclei JSON output into structured data.

        Args:
            raw_output: Raw JSON lines output from nuclei.

        Returns:
            List of finding dictionaries.
        """
        results = []
        seen = set()

        for line in raw_output.strip().split("\n"):
            if not line.strip():
                continue

            try:
                finding = json.loads(line)

                # Extract key fields
                template_id = finding.get("template-id", finding.get("templateID", ""))
                matched_at = finding.get("matched-at", finding.get("matched", ""))
                host = finding.get("host", "")

                # Create unique key to avoid duplicates
                unique_key = f"{template_id}_{matched_at}"
                if unique_key in seen:
                    continue
                seen.add(unique_key)

                # Get info from finding
                info = finding.get("info", {})

                results.append({
                    "template_id": template_id,
                    "name": info.get("name", template_id),
                    "severity": info.get("severity", "unknown"),
                    "description": info.get("description", ""),
                    "matched_at": matched_at,
                    "host": host,
                    "category": finding.get("scan_category", ""),
                    "tags": info.get("tags", []),
                    "reference": info.get("reference", []),
                    "curl_command": finding.get("curl-command", ""),
                    "extracted_results": finding.get("extracted-results", []),
                    "matcher_name": finding.get("matcher-name", ""),
                    "type": "nuclei_finding",
                })

            except json.JSONDecodeError:
                pass

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        results.sort(key=lambda x: (
            severity_order.get(x.get("severity", "unknown"), 5),
            x.get("template_id", "")
        ))

        return results

    def get_statistics(self, results: list[dict]) -> dict:
        """Get statistics from nuclei results.

        Args:
            results: Parsed results.

        Returns:
            Statistics dictionary.
        """
        stats = {
            "total_findings": len(results),
            "by_severity": {},
            "by_category": {},
            "by_template": {},
            "unique_hosts": set(),
        }

        for item in results:
            severity = item.get("severity", "unknown")
            category = item.get("category", "unknown")
            template_id = item.get("template_id", "unknown")
            host = item.get("host", "")

            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1
            stats["by_template"][template_id] = stats["by_template"].get(template_id, 0) + 1

            if host:
                stats["unique_hosts"].add(host)

        stats["unique_hosts"] = len(stats["unique_hosts"])

        return stats
