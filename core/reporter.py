"""Result aggregation and export functionality."""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any
from loguru import logger

from core.history import HistoryManager, ScanIndex


class ReconReporter:
    """Handles result aggregation and export to various formats."""

    def __init__(self, output_dir: str = "./output"):
        """Initialize the reporter.

        Args:
            output_dir: Base directory for output files.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.history_manager = HistoryManager(output_dir)
        self.scan_index = ScanIndex(output_dir)

    def create_scan_directory(self, target: str) -> Path:
        """Create a directory for a scan's results.

        Args:
            target: Target domain.

        Returns:
            Path to the created directory.
        """
        # Sanitize target for filesystem
        safe_target = target.replace("://", "_").replace("/", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_dir = self.output_dir / f"{safe_target}_{timestamp}"
        scan_dir.mkdir(parents=True, exist_ok=True)
        return scan_dir

    def export_results(
        self,
        results: dict[str, dict],
        target: str,
        profile: str,
        scan_dir: Path | None = None,
    ) -> Path:
        """Export scan results to files.

        Args:
            results: Dictionary mapping module names to their results.
            target: Target domain.
            profile: Profile name used for the scan.
            scan_dir: Optional specific directory; creates new if None.

        Returns:
            Path to the scan directory.
        """
        if scan_dir is None:
            scan_dir = self.create_scan_directory(target)

        logger.info(f"Exporting results to {scan_dir}")

        # Load history and merge results
        scan_timestamp = datetime.now().isoformat()
        history = self.history_manager.load_history(target)
        results = self.history_manager.merge_results(history, results, scan_timestamp)
        self.history_manager.save_history(target, history)

        # Export combined JSON
        self._export_json(results, target, profile, scan_dir)

        # Export individual text files
        self._export_subdomains(results, scan_dir)
        self._export_inactive_subdomains(results, scan_dir)
        self._export_asn(results, scan_dir)
        self._export_ports(results, scan_dir)
        self._export_technologies(results, scan_dir)
        self._export_directories(results, scan_dir)
        self._export_wayback(results, scan_dir)
        self._export_screenshots(results, scan_dir)
        self._export_jsanalyze(results, scan_dir)
        self._export_paramanalyze(results, scan_dir)

        # Export summary
        self._export_summary(results, target, profile, scan_dir)

        # Register scan in global index
        modules_run = [
            name for name, result in results.items()
            if not name.startswith("_") and result.get("status") == "completed"
        ]
        results_summary = {
            name: result.get("count", 0)
            for name, result in results.items()
            if not name.startswith("_") and result.get("status") == "completed"
        }
        self.scan_index.register_scan(
            domain=target,
            profile=profile,
            modules_run=modules_run,
            scan_dir=str(scan_dir),
            results_summary=results_summary,
        )

        return scan_dir

    def _export_json(
        self,
        results: dict[str, dict],
        target: str,
        profile: str,
        scan_dir: Path,
    ):
        """Export all results to a single JSON file."""
        output = {
            "target": target,
            "profile": profile,
            "timestamp": datetime.now().isoformat(),
            "modules": {},
        }

        for module_name, module_result in results.items():
            output["modules"][module_name] = {
                "status": module_result.get("status", "unknown"),
                "count": module_result.get("count", 0),
                "results": module_result.get("output", []),
            }

        json_path = scan_dir / "results.json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        logger.info(f"Exported JSON: {json_path}")

    def _export_subdomains(self, results: dict[str, dict], scan_dir: Path):
        """Export subdomains to text file with new/removed markers."""
        subdomain_result = results.get("subdomain", {})
        if subdomain_result.get("status") != "completed":
            return

        items = subdomain_result.get("output", [])
        if not items:
            return

        lines = []
        new_count = 0
        removed_count = 0

        # Sort: new first, then existing, then removed
        sorted_items = sorted(items, key=lambda x: (
            x.get("is_removed", False),
            not x.get("is_new", False),
            x.get("subdomain", "")
        ))

        for item in sorted_items:
            subdomain = item.get("subdomain", "")
            if not subdomain:
                continue

            if item.get("is_new", False):
                lines.append(f"[NEW] {subdomain}")
                new_count += 1
            elif item.get("is_removed", False):
                lines.append(f"[REMOVED] {subdomain}")
                removed_count += 1
            else:
                lines.append(f"       {subdomain}")

        if lines:
            path = scan_dir / "subdomains.txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"# Subdomains (New: {new_count}, Removed: {removed_count})\n\n")
                f.write("\n".join(lines))
            logger.info(f"Exported {len(lines)} subdomains ({new_count} new, {removed_count} removed): {path}")

    def _export_inactive_subdomains(self, results: dict[str, dict], scan_dir: Path):
        """Export inactive/unused subdomains to a separate file."""
        inactive_result = results.get("_inactive_subdomains", {})
        if inactive_result.get("status") != "completed":
            return

        inactive = [
            item["subdomain"]
            for item in inactive_result.get("output", [])
            if "subdomain" in item
        ]

        if inactive:
            path = scan_dir / "inactive_subdomains.txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write("# Inactive/Unused Subdomains\n")
                f.write("# These subdomains did not respond to HTTP requests\n\n")
                f.write("\n".join(sorted(set(inactive))))
            logger.info(f"Exported {len(inactive)} inactive subdomains: {path}")

    def _export_asn(self, results: dict[str, dict], scan_dir: Path):
        """Export ASN information to text file."""
        asn_result = results.get("asn", {})
        if asn_result.get("status") != "completed":
            return

        items = asn_result.get("output", [])
        if not items:
            return

        lines = [
            "# ASN Information",
            "# Autonomous System Numbers and IP Ranges",
            "",
        ]

        # Group by ASN
        by_asn: dict[str, list[dict]] = {}
        for item in items:
            asn = item.get("asn", "unknown")
            if asn not in by_asn:
                by_asn[asn] = []
            by_asn[asn].append(item)

        for asn in sorted(by_asn.keys()):
            asn_items = by_asn[asn]
            first = asn_items[0]
            as_name = first.get("as_name", "")
            as_country = first.get("as_country", "")
            cidr = first.get("cidr", "")

            lines.append("=" * 50)
            lines.append(f"ASN: {asn}")
            if as_name:
                lines.append(f"Organization: {as_name}")
            if as_country:
                lines.append(f"Country: {as_country}")
            if cidr:
                lines.append(f"CIDR: {cidr}")
            lines.append("-" * 50)

            for item in asn_items:
                input_val = item.get("input", "")
                ip = item.get("ip", "")
                if input_val:
                    line = f"  {input_val}"
                    if ip:
                        line += f" -> {ip}"
                    lines.append(line)

            lines.append("")

        if lines:
            path = scan_dir / "asn.txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines).rstrip())
            logger.info(f"Exported {len(items)} ASN records: {path}")

    def _export_ports(self, results: dict[str, dict], scan_dir: Path):
        """Export ports to text file."""
        port_result = results.get("portscan", {})
        if port_result.get("status") != "completed":
            return

        lines = []
        for item in port_result.get("output", []):
            if "port" in item:
                host = item.get("host", "unknown")
                port = item["port"]
                service = item.get("service", "")
                version = item.get("version", "")
                line = f"{host}:{port}"
                if service:
                    line += f" ({service}"
                    if version:
                        line += f" {version}"
                    line += ")"
                lines.append(line)

        if lines:
            path = scan_dir / "ports.txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            logger.info(f"Exported {len(lines)} ports: {path}")

    def _export_technologies(self, results: dict[str, dict], scan_dir: Path):
        """Export technologies to text file with domain information."""
        tech_result = results.get("techdetect", {})
        if tech_result.get("status") != "completed":
            return

        # Group technologies by URL/domain
        tech_by_url: dict[str, list[str]] = {}
        for item in tech_result.get("output", []):
            if "technology" in item:
                tech = item["technology"]
                version = item.get("version", "")
                url = item.get("url", "unknown")

                if version:
                    tech_str = f"{tech} ({version})"
                else:
                    tech_str = tech

                if url not in tech_by_url:
                    tech_by_url[url] = []
                if tech_str not in tech_by_url[url]:
                    tech_by_url[url].append(tech_str)

        if tech_by_url:
            lines = []
            for url, techs in sorted(tech_by_url.items()):
                lines.append(f"[{url}]")
                for tech in sorted(techs):
                    lines.append(f"  - {tech}")
                lines.append("")  # Empty line between URLs

            path = scan_dir / "technologies.txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines).rstrip())
            total_techs = sum(len(t) for t in tech_by_url.values())
            logger.info(f"Exported {total_techs} technologies from {len(tech_by_url)} URLs: {path}")

    def _export_directories(self, results: dict[str, dict], scan_dir: Path):
        """Export discovered directories to text file, grouped by subdomain."""
        dir_result = results.get("directory", {})
        if dir_result.get("status") != "completed":
            return

        # Group directories by subdomain
        by_subdomain: dict[str, list[dict]] = {}
        for item in dir_result.get("output", []):
            if "url" in item:
                subdomain = item.get("subdomain", "unknown")
                if subdomain not in by_subdomain:
                    by_subdomain[subdomain] = []
                by_subdomain[subdomain].append(item)

        if not by_subdomain:
            return

        lines = []
        total_count = 0
        total_new = 0
        total_removed = 0

        for subdomain in sorted(by_subdomain.keys()):
            items = by_subdomain[subdomain]
            total_count += len(items)

            # Sort: new first, then existing, then removed
            sorted_items = sorted(items, key=lambda x: (
                x.get("is_removed", False),
                not x.get("is_new", False),
                x.get("url", "")
            ))

            new_count = sum(1 for i in items if i.get("is_new", False))
            removed_count = sum(1 for i in items if i.get("is_removed", False))
            total_new += new_count
            total_removed += removed_count

            lines.append("=" * 60)
            lines.append(f"[{subdomain}]")
            lines.append(f"Found: {len(items)} (New: {new_count}, Removed: {removed_count})")
            lines.append("=" * 60)

            for item in sorted_items:
                url = item["url"]
                status = item.get("status_code", "")
                size = item.get("size", "")
                path = item.get("path", "")

                # Add status marker
                if item.get("is_new", False):
                    marker = "[NEW]    "
                elif item.get("is_removed", False):
                    marker = "[REMOVED]"
                else:
                    marker = "         "

                line = f"  {marker} {path or url}"
                if status:
                    line += f" [{status}]"
                if size:
                    line += f" ({size} bytes)"
                lines.append(line)

            lines.append("")  # Empty line between subdomains

        if lines:
            path = scan_dir / "directories.txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"# Directories (Total New: {total_new}, Total Removed: {total_removed})\n\n")
                f.write("\n".join(lines).rstrip())
            logger.info(f"Exported {total_count} directories ({total_new} new, {total_removed} removed): {path}")

    def _export_wayback(self, results: dict[str, dict], scan_dir: Path):
        """Export wayback URLs to text file, grouped by domain."""
        wayback_result = results.get("wayback", {})
        if wayback_result.get("status") != "completed":
            return

        # Group URLs by domain
        by_domain: dict[str, list[dict]] = {}
        for item in wayback_result.get("output", []):
            if "url" in item:
                domain = item.get("domain", "unknown")
                if domain not in by_domain:
                    by_domain[domain] = []
                by_domain[domain].append(item)

        if not by_domain:
            return

        lines = []
        total_count = 0

        for domain in sorted(by_domain.keys()):
            items = by_domain[domain]
            total_count += len(items)

            lines.append("=" * 60)
            lines.append(f"[{domain}]")
            lines.append(f"Found: {len(items)} URLs")
            lines.append("=" * 60)

            for item in items:
                url = item["url"]
                category = item.get("category", "")
                if category and category != "page":
                    lines.append(f"  {url}  [{category}]")
                else:
                    lines.append(f"  {url}")

            lines.append("")  # Empty line between domains

        if lines:
            path = scan_dir / "wayback.txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines).rstrip())
            logger.info(f"Exported {total_count} wayback URLs from {len(by_domain)} domains: {path}")

    def _export_screenshots(self, results: dict[str, dict], scan_dir: Path):
        """Export screenshot information to text file."""
        screenshot_result = results.get("screenshot", {})
        if screenshot_result.get("status") != "completed":
            return

        items = screenshot_result.get("output", [])
        if not items:
            return

        lines = [
            "# Screenshots",
            "# Captured screenshots of alive subdomains",
            "",
        ]

        for item in items:
            target = item.get("target", "")
            path = item.get("path", "")
            if target:
                lines.append(f"{target}")
                if path:
                    lines.append(f"  -> {path}")
                lines.append("")

        if lines:
            path = scan_dir / "screenshots.txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines).rstrip())
            logger.info(f"Exported {len(items)} screenshot records: {path}")

    def _export_jsanalyze(self, results: dict[str, dict], scan_dir: Path):
        """Export JavaScript analysis results to text files."""
        jsanalyze_result = results.get("jsanalyze", {})
        if jsanalyze_result.get("status") != "completed":
            return

        items = jsanalyze_result.get("output", [])
        if not items:
            return

        # Separate endpoints and secrets
        endpoints = []
        secrets = []

        for item in items:
            item_type = item.get("type", "")
            if item_type == "js_endpoint":
                endpoints.append(item)
            elif item_type == "js_secret":
                secrets.append(item)

        # Export endpoints
        if endpoints:
            lines = [
                "# JavaScript Endpoints",
                "# Extracted from JavaScript files using LinkFinder",
                "",
            ]

            # Group by category
            by_category: dict[str, list[dict]] = {}
            for ep in endpoints:
                category = ep.get("category", "endpoint")
                if category not in by_category:
                    by_category[category] = []
                by_category[category].append(ep)

            # Sort categories by sensitivity
            category_order = ["api_endpoint", "auth", "admin", "config", "upload", "endpoint", "javascript", "data"]
            sorted_categories = sorted(by_category.keys(), key=lambda c: (
                category_order.index(c) if c in category_order else len(category_order),
                c
            ))

            for category in sorted_categories:
                cat_items = by_category[category]
                lines.append("=" * 50)
                lines.append(f"[{category.upper()}] ({len(cat_items)} items)")
                lines.append("=" * 50)

                # Sort by sensitivity (high first)
                sorted_items = sorted(cat_items, key=lambda x: (
                    {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("sensitivity", "low"), 4),
                    x.get("finding", "")
                ))

                for item in sorted_items:
                    finding = item.get("finding", "")
                    sensitivity = item.get("sensitivity", "low")
                    marker = ""
                    if sensitivity == "high":
                        marker = "[!] "
                    elif sensitivity == "medium":
                        marker = "[*] "
                    lines.append(f"  {marker}{finding}")

                lines.append("")

            path = scan_dir / "js_endpoints.txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines).rstrip())
            logger.info(f"Exported {len(endpoints)} JS endpoints: {path}")

        # Export secrets
        if secrets:
            lines = [
                "# JavaScript Secrets",
                "# Potential secrets and API keys found in JavaScript files",
                "# WARNING: Verify these findings manually - false positives are common",
                "",
            ]

            # Group by secret type
            by_type: dict[str, list[dict]] = {}
            for secret in secrets:
                secret_type = secret.get("secret_type", "unknown")
                if secret_type not in by_type:
                    by_type[secret_type] = []
                by_type[secret_type].append(secret)

            for secret_type in sorted(by_type.keys()):
                type_items = by_type[secret_type]
                lines.append("=" * 50)
                lines.append(f"[{secret_type.upper()}] ({len(type_items)} items)")
                lines.append("=" * 50)

                for item in type_items:
                    finding = item.get("finding", "")
                    source = item.get("source", "unknown")
                    lines.append(f"  {finding}")
                    lines.append(f"    Source: {source}")
                    lines.append("")

            path = scan_dir / "js_secrets.txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines).rstrip())
            logger.info(f"Exported {len(secrets)} potential JS secrets: {path}")

    def _export_paramanalyze(self, results: dict[str, dict], scan_dir: Path):
        """Export parameter analysis results to text files."""
        param_result = results.get("paramanalyze", {})
        if param_result.get("status") != "completed":
            return

        items = param_result.get("output", [])
        if not items:
            return

        # Group by category
        by_category: dict[str, list[dict]] = {}
        for item in items:
            category = item.get("category", "unknown")
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(item)

        # Severity order for sorting
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        # Write individual files per category and a combined file
        all_lines = [
            "# Vulnerable Parameter Analysis",
            "# Parameters that may be susceptible to various attacks",
            f"# Total parameters found: {len(items)}",
            "",
        ]

        # Sort categories by severity
        sorted_categories = sorted(by_category.keys(), key=lambda c: (
            min(severity_order.get(i.get("severity", "low"), 4) for i in by_category[c]),
            c
        ))

        for category in sorted_categories:
            cat_items = by_category[category]
            if not cat_items:
                continue

            # Get severity from first item
            severity = cat_items[0].get("severity", "medium").upper()
            description = cat_items[0].get("description", category)

            # Category header
            lines = [
                "=" * 60,
                f"[{severity}] {description}",
                f"Parameters: {len(cat_items)}",
                "=" * 60,
                "",
            ]

            # Sort by count within category
            sorted_items = sorted(cat_items, key=lambda x: -x.get("count", 0))

            for item in sorted_items:
                param = item.get("param", "")
                count = item.get("count", 0)
                sample_urls = item.get("sample_urls", [])
                marker = "[NEW] " if item.get("is_new", False) else ""

                lines.append(f"{marker}{param}= (found in {count} URLs)")
                for url in sample_urls[:3]:
                    lines.append(f"    {url}")
                if len(sample_urls) > 3:
                    lines.append(f"    ... and {len(sample_urls) - 3} more")
                lines.append("")

            all_lines.extend(lines)

            # Write category-specific file
            cat_path = scan_dir / f"params_{category}.txt"
            with open(cat_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines).rstrip())

        # Write combined file
        combined_path = scan_dir / "params_all.txt"
        with open(combined_path, "w", encoding="utf-8") as f:
            f.write("\n".join(all_lines).rstrip())

        # Export Nuclei-compatible URL lists
        nuclei_dir = scan_dir / "nuclei"
        nuclei_dir.mkdir(exist_ok=True)

        for category, cat_items in by_category.items():
            urls = set()
            for item in cat_items:
                urls.update(item.get("sample_urls", []))
            if urls:
                nuclei_path = nuclei_dir / f"{category}.txt"
                with open(nuclei_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(sorted(urls)))

        # Export Burp-compatible URL list
        all_urls = set()
        for item in items:
            all_urls.update(item.get("sample_urls", []))
        if all_urls:
            burp_path = scan_dir / "burp_targets.txt"
            with open(burp_path, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(all_urls)))

        logger.info(f"Exported {len(items)} vulnerable parameters: {combined_path}")

    def _export_summary(
        self,
        results: dict[str, dict],
        target: str,
        profile: str,
        scan_dir: Path,
    ):
        """Export a human-readable summary."""
        lines = [
            "=" * 60,
            "RECON AUTOMATOR - SCAN SUMMARY",
            "=" * 60,
            f"Target: {target}",
            f"Profile: {profile}",
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "-" * 60,
            "MODULE RESULTS",
            "-" * 60,
        ]

        for module_name, module_result in results.items():
            status = module_result.get("status", "unknown")
            count = module_result.get("count", 0)
            status_icon = "✓" if status == "completed" else "✗" if status == "failed" else "○"
            lines.append(f"{status_icon} {module_name}: {status} ({count} results)")

        lines.extend([
            "",
            "-" * 60,
            "FILES GENERATED",
            "-" * 60,
        ])

        for file in scan_dir.iterdir():
            if file.is_file():
                size = file.stat().st_size
                lines.append(f"  {file.name} ({size} bytes)")

        lines.extend([
            "",
            "=" * 60,
        ])

        path = scan_dir / "summary.txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        logger.info(f"Exported summary: {path}")

    def get_output_directories(self) -> list[Path]:
        """Get list of existing scan output directories.

        Returns:
            List of directory paths.
        """
        if not self.output_dir.exists():
            return []
        return sorted(
            [d for d in self.output_dir.iterdir() if d.is_dir()],
            key=lambda x: x.stat().st_mtime,
            reverse=True,
        )
