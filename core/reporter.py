"""Result aggregation and export functionality."""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any
from loguru import logger


class ReconReporter:
    """Handles result aggregation and export to various formats."""

    def __init__(self, output_dir: str = "./output"):
        """Initialize the reporter.

        Args:
            output_dir: Base directory for output files.
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

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

        # Export combined JSON
        self._export_json(results, target, profile, scan_dir)

        # Export individual text files
        self._export_subdomains(results, scan_dir)
        self._export_ports(results, scan_dir)
        self._export_technologies(results, scan_dir)
        self._export_directories(results, scan_dir)
        self._export_wayback(results, scan_dir)

        # Export summary
        self._export_summary(results, target, profile, scan_dir)

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
        """Export subdomains to text file."""
        subdomain_result = results.get("subdomain", {})
        if subdomain_result.get("status") != "completed":
            return

        subdomains = [
            item["subdomain"]
            for item in subdomain_result.get("output", [])
            if "subdomain" in item
        ]

        if subdomains:
            path = scan_dir / "subdomains.txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(set(subdomains))))
            logger.info(f"Exported {len(subdomains)} subdomains: {path}")

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
        """Export discovered directories to text file."""
        dir_result = results.get("directory", {})
        if dir_result.get("status") != "completed":
            return

        lines = []
        for item in dir_result.get("output", []):
            if "url" in item:
                url = item["url"]
                status = item.get("status_code", "")
                size = item.get("size", "")
                line = url
                if status:
                    line += f" [{status}]"
                if size:
                    line += f" ({size} bytes)"
                lines.append(line)

        if lines:
            path = scan_dir / "directories.txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            logger.info(f"Exported {len(lines)} directories: {path}")

    def _export_wayback(self, results: dict[str, dict], scan_dir: Path):
        """Export wayback URLs to text file."""
        wayback_result = results.get("wayback", {})
        if wayback_result.get("status") != "completed":
            return

        urls = [
            item["url"]
            for item in wayback_result.get("output", [])
            if "url" in item
        ]

        if urls:
            path = scan_dir / "wayback.txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(urls))
            logger.info(f"Exported {len(urls)} wayback URLs: {path}")

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
