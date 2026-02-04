"""History management for tracking scan results over time."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from loguru import logger


class ScanIndex:
    """Global index of all scanned domains."""

    def __init__(self, output_dir: str = "./output"):
        """Initialize the scan index.

        Args:
            output_dir: Base directory for output files.
        """
        self.output_dir = Path(output_dir)
        self.index_path = self.output_dir / ".scandb" / "index.json"

    def _ensure_dir(self):
        """Ensure the index directory exists."""
        self.index_path.parent.mkdir(parents=True, exist_ok=True)

    def load_index(self) -> dict:
        """Load the global scan index.

        Returns:
            Index dictionary.
        """
        if self.index_path.exists():
            try:
                with open(self.index_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load scan index: {e}")

        return {"domains": {}, "last_updated": datetime.now().isoformat()}

    def save_index(self, index: dict):
        """Save the global scan index.

        Args:
            index: Index dictionary to save.
        """
        self._ensure_dir()
        index["last_updated"] = datetime.now().isoformat()

        with open(self.index_path, "w", encoding="utf-8") as f:
            json.dump(index, f, indent=2, ensure_ascii=False)

    def register_scan(
        self,
        domain: str,
        profile: str,
        modules_run: list[str],
        scan_dir: str,
        results_summary: dict,
    ):
        """Register a completed scan in the index.

        Args:
            domain: Target domain.
            profile: Profile used for the scan.
            modules_run: List of modules that were run.
            scan_dir: Directory where results are stored.
            results_summary: Summary of results (counts per module).
        """
        index = self.load_index()
        timestamp = datetime.now().isoformat()

        if domain not in index["domains"]:
            index["domains"][domain] = {
                "first_scan": timestamp,
                "last_scan": timestamp,
                "scan_count": 0,
                "scans": [],
            }

        domain_entry = index["domains"][domain]
        domain_entry["last_scan"] = timestamp
        domain_entry["scan_count"] += 1

        # Add scan record (keep last 20 scans)
        scan_record = {
            "timestamp": timestamp,
            "profile": profile,
            "modules_run": modules_run,
            "directory": str(scan_dir),
            "results_summary": results_summary,
        }
        domain_entry["scans"].insert(0, scan_record)
        domain_entry["scans"] = domain_entry["scans"][:20]

        self.save_index(index)
        logger.info(f"Registered scan for {domain} in index")

    def get_all_domains(self) -> list[dict]:
        """Get list of all scanned domains with summary info.

        Also scans for existing history.json files that aren't in the index.

        Returns:
            List of domain info dictionaries, sorted by last scan date.
        """
        index = self.load_index()
        domains_dict = {}

        # Get domains from index
        for domain, info in index.get("domains", {}).items():
            domains_dict[domain] = {
                "domain": domain,
                "first_scan": info.get("first_scan", ""),
                "last_scan": info.get("last_scan", ""),
                "scan_count": info.get("scan_count", 0),
                "last_profile": info["scans"][0]["profile"] if info.get("scans") else "",
            }

        # Also scan for existing history.json files in output directory
        if self.output_dir.exists():
            for item in self.output_dir.iterdir():
                if item.is_dir() and not item.name.startswith("."):
                    history_file = item / "history.json"
                    if history_file.exists():
                        try:
                            with open(history_file, "r", encoding="utf-8") as f:
                                history = json.load(f)
                            domain = history.get("domain", item.name)
                            if domain not in domains_dict:
                                domains_dict[domain] = {
                                    "domain": domain,
                                    "first_scan": history.get("first_seen", ""),
                                    "last_scan": history.get("last_updated", ""),
                                    "scan_count": history.get("scan_count", 1),
                                    "last_profile": "",
                                }
                        except (json.JSONDecodeError, IOError):
                            pass

            # Also check for scan directories (target_timestamp format)
            for item in self.output_dir.iterdir():
                if item.is_dir() and not item.name.startswith("."):
                    # Check if it's a timestamp-based directory
                    results_file = item / "results.json"
                    if results_file.exists():
                        try:
                            with open(results_file, "r", encoding="utf-8") as f:
                                results = json.load(f)
                            domain = results.get("target", "")
                            timestamp = results.get("timestamp", "")
                            if domain and domain not in domains_dict:
                                domains_dict[domain] = {
                                    "domain": domain,
                                    "first_scan": timestamp,
                                    "last_scan": timestamp,
                                    "scan_count": 1,
                                    "last_profile": results.get("profile", ""),
                                }
                            elif domain and timestamp > domains_dict[domain].get("last_scan", ""):
                                domains_dict[domain]["last_scan"] = timestamp
                                domains_dict[domain]["scan_count"] += 1
                        except (json.JSONDecodeError, IOError):
                            pass

        # Convert to list and sort by last scan date (most recent first)
        domains = list(domains_dict.values())
        domains.sort(key=lambda x: x.get("last_scan", ""), reverse=True)
        return domains

    def get_domain_scans(self, domain: str) -> list[dict]:
        """Get all scans for a specific domain.

        Args:
            domain: Target domain.

        Returns:
            List of scan records.
        """
        index = self.load_index()
        domain_info = index.get("domains", {}).get(domain, {})
        return domain_info.get("scans", [])

    def get_domain_info(self, domain: str) -> Optional[dict]:
        """Get info for a specific domain.

        Args:
            domain: Target domain.

        Returns:
            Domain info dictionary or None.
        """
        index = self.load_index()
        return index.get("domains", {}).get(domain)


class HistoryManager:
    """Manages historical scan data for comparing results over time."""

    def __init__(self, output_dir: str = "./output"):
        """Initialize the history manager.

        Args:
            output_dir: Base directory for output files.
        """
        self.output_dir = Path(output_dir)

    def get_domain_dir(self, domain: str) -> Path:
        """Get the directory for a specific domain.

        Args:
            domain: Target domain.

        Returns:
            Path to domain directory.
        """
        safe_domain = domain.replace("://", "_").replace("/", "_").replace(":", "_")
        return self.output_dir / safe_domain

    def get_history_path(self, domain: str) -> Path:
        """Get the path to the history file for a domain.

        Args:
            domain: Target domain.

        Returns:
            Path to history.json file.
        """
        return self.get_domain_dir(domain) / "history.json"

    def load_history(self, domain: str) -> dict:
        """Load existing history for a domain.

        Args:
            domain: Target domain.

        Returns:
            History dictionary or empty structure if none exists.
        """
        history_path = self.get_history_path(domain)

        if history_path.exists():
            try:
                with open(history_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load history for {domain}: {e}")

        # Return empty history structure
        return {
            "domain": domain,
            "first_seen": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "scan_count": 0,
            "subdomains": {},
            "probe": {},
            "asn": {},
            "ports": {},
            "technologies": {},
            "directories": {},
            "wayback": {},
            "screenshots": {},
        }

    def save_history(self, domain: str, history: dict):
        """Save history for a domain.

        Args:
            domain: Target domain.
            history: History dictionary to save.
        """
        domain_dir = self.get_domain_dir(domain)
        domain_dir.mkdir(parents=True, exist_ok=True)

        history_path = self.get_history_path(domain)
        history["last_updated"] = datetime.now().isoformat()

        with open(history_path, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)

        logger.info(f"Saved history for {domain}: {history_path}")

    def merge_results(
        self,
        history: dict,
        results: dict[str, dict],
        scan_timestamp: str,
    ) -> dict[str, dict]:
        """Merge new scan results with history and mark items as new/existing/removed.

        Args:
            history: Existing history dictionary.
            results: New scan results.
            scan_timestamp: Timestamp of the current scan.

        Returns:
            Updated results with status markers (is_new, is_removed, first_seen, last_seen).
        """
        history["scan_count"] = history.get("scan_count", 0) + 1

        # Process each module type
        module_handlers = {
            "subdomain": self._merge_subdomains,
            "probe": self._merge_probe,
            "asn": self._merge_asn,
            "portscan": self._merge_ports,
            "techdetect": self._merge_technologies,
            "directory": self._merge_directories,
            "wayback": self._merge_wayback,
            "screenshot": self._merge_screenshots,
            "jsanalyze": self._merge_jsanalyze,
            "paramanalyze": self._merge_paramanalyze,
        }

        for module_name, handler in module_handlers.items():
            if module_name in results and results[module_name].get("status") == "completed":
                results[module_name] = handler(
                    history,
                    results[module_name],
                    scan_timestamp,
                )

        return results

    def _merge_subdomains(
        self, history: dict, result: dict, timestamp: str
    ) -> dict:
        """Merge subdomain results with history."""
        history_data = history.setdefault("subdomains", {})
        current_items = set()

        for item in result.get("output", []):
            subdomain = item.get("subdomain", "")
            if not subdomain:
                continue

            current_items.add(subdomain)
            key = subdomain

            if key in history_data:
                # Existing item
                item["is_new"] = False
                item["first_seen"] = history_data[key].get("first_seen", timestamp)
                item["last_seen"] = timestamp
                history_data[key]["last_seen"] = timestamp
                history_data[key]["is_removed"] = False
            else:
                # New item
                item["is_new"] = True
                item["first_seen"] = timestamp
                item["last_seen"] = timestamp
                history_data[key] = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "is_removed": False,
                    "data": item,
                }

        # Mark removed items and add them to output
        for key, hist_item in history_data.items():
            if key not in current_items and not hist_item.get("is_removed", False):
                hist_item["is_removed"] = True
                hist_item["removed_at"] = timestamp
                # Add removed item to output
                removed_item = hist_item.get("data", {"subdomain": key}).copy()
                removed_item["is_new"] = False
                removed_item["is_removed"] = True
                removed_item["first_seen"] = hist_item.get("first_seen", "")
                removed_item["last_seen"] = hist_item.get("last_seen", "")
                result["output"].append(removed_item)

        return result

    def _merge_probe(self, history: dict, result: dict, timestamp: str) -> dict:
        """Merge probe results with history."""
        history_data = history.setdefault("probe", {})
        current_items = set()

        for item in result.get("output", []):
            subdomain = item.get("subdomain", "")
            if not subdomain:
                continue

            current_items.add(subdomain)
            key = subdomain

            if key in history_data:
                item["is_new"] = False
                item["first_seen"] = history_data[key].get("first_seen", timestamp)
                item["last_seen"] = timestamp
                # Update status if changed
                old_alive = history_data[key].get("alive", False)
                new_alive = item.get("alive", False)
                item["status_changed"] = old_alive != new_alive
                history_data[key]["last_seen"] = timestamp
                history_data[key]["alive"] = new_alive
                history_data[key]["is_removed"] = False
            else:
                item["is_new"] = True
                item["first_seen"] = timestamp
                item["last_seen"] = timestamp
                item["status_changed"] = False
                history_data[key] = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "alive": item.get("alive", False),
                    "is_removed": False,
                    "data": item,
                }

        # Add removed items
        for key, hist_item in history_data.items():
            if key not in current_items and not hist_item.get("is_removed", False):
                hist_item["is_removed"] = True
                hist_item["removed_at"] = timestamp
                removed_item = hist_item.get("data", {"subdomain": key}).copy()
                removed_item["is_new"] = False
                removed_item["is_removed"] = True
                removed_item["first_seen"] = hist_item.get("first_seen", "")
                removed_item["last_seen"] = hist_item.get("last_seen", "")
                result["output"].append(removed_item)

        return result

    def _merge_asn(self, history: dict, result: dict, timestamp: str) -> dict:
        """Merge ASN results with history."""
        history_data = history.setdefault("asn", {})
        current_items = set()

        for item in result.get("output", []):
            asn = item.get("asn", "")
            input_val = item.get("input", "")
            key = f"{asn}_{input_val}"
            if not key:
                continue

            current_items.add(key)

            if key in history_data:
                item["is_new"] = False
                item["first_seen"] = history_data[key].get("first_seen", timestamp)
                item["last_seen"] = timestamp
                history_data[key]["last_seen"] = timestamp
                history_data[key]["is_removed"] = False
            else:
                item["is_new"] = True
                item["first_seen"] = timestamp
                item["last_seen"] = timestamp
                history_data[key] = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "is_removed": False,
                    "data": item,
                }

        for key, hist_item in history_data.items():
            if key not in current_items and not hist_item.get("is_removed", False):
                hist_item["is_removed"] = True
                hist_item["removed_at"] = timestamp
                removed_item = hist_item.get("data", {}).copy()
                removed_item["is_new"] = False
                removed_item["is_removed"] = True
                removed_item["first_seen"] = hist_item.get("first_seen", "")
                removed_item["last_seen"] = hist_item.get("last_seen", "")
                result["output"].append(removed_item)

        return result

    def _merge_ports(self, history: dict, result: dict, timestamp: str) -> dict:
        """Merge port scan results with history."""
        history_data = history.setdefault("ports", {})
        current_items = set()

        for item in result.get("output", []):
            host = item.get("host", "")
            port = item.get("port", "")
            key = f"{host}:{port}"
            if not key or key == ":":
                continue

            current_items.add(key)

            if key in history_data:
                item["is_new"] = False
                item["first_seen"] = history_data[key].get("first_seen", timestamp)
                item["last_seen"] = timestamp
                history_data[key]["last_seen"] = timestamp
                history_data[key]["is_removed"] = False
            else:
                item["is_new"] = True
                item["first_seen"] = timestamp
                item["last_seen"] = timestamp
                history_data[key] = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "is_removed": False,
                    "data": item,
                }

        for key, hist_item in history_data.items():
            if key not in current_items and not hist_item.get("is_removed", False):
                hist_item["is_removed"] = True
                hist_item["removed_at"] = timestamp
                removed_item = hist_item.get("data", {}).copy()
                removed_item["is_new"] = False
                removed_item["is_removed"] = True
                removed_item["first_seen"] = hist_item.get("first_seen", "")
                removed_item["last_seen"] = hist_item.get("last_seen", "")
                result["output"].append(removed_item)

        return result

    def _merge_technologies(self, history: dict, result: dict, timestamp: str) -> dict:
        """Merge technology detection results with history."""
        history_data = history.setdefault("technologies", {})
        current_items = set()

        for item in result.get("output", []):
            url = item.get("url", "")
            tech = item.get("technology", "")
            key = f"{url}_{tech}"
            if not url or not tech:
                continue

            current_items.add(key)

            if key in history_data:
                item["is_new"] = False
                item["first_seen"] = history_data[key].get("first_seen", timestamp)
                item["last_seen"] = timestamp
                history_data[key]["last_seen"] = timestamp
                history_data[key]["is_removed"] = False
            else:
                item["is_new"] = True
                item["first_seen"] = timestamp
                item["last_seen"] = timestamp
                history_data[key] = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "is_removed": False,
                    "data": item,
                }

        for key, hist_item in history_data.items():
            if key not in current_items and not hist_item.get("is_removed", False):
                hist_item["is_removed"] = True
                hist_item["removed_at"] = timestamp
                removed_item = hist_item.get("data", {}).copy()
                removed_item["is_new"] = False
                removed_item["is_removed"] = True
                removed_item["first_seen"] = hist_item.get("first_seen", "")
                removed_item["last_seen"] = hist_item.get("last_seen", "")
                result["output"].append(removed_item)

        return result

    def _merge_directories(self, history: dict, result: dict, timestamp: str) -> dict:
        """Merge directory enumeration results with history."""
        history_data = history.setdefault("directories", {})
        current_items = set()

        for item in result.get("output", []):
            url = item.get("url", "")
            if not url:
                continue

            current_items.add(url)
            key = url

            if key in history_data:
                item["is_new"] = False
                item["first_seen"] = history_data[key].get("first_seen", timestamp)
                item["last_seen"] = timestamp
                history_data[key]["last_seen"] = timestamp
                history_data[key]["is_removed"] = False
            else:
                item["is_new"] = True
                item["first_seen"] = timestamp
                item["last_seen"] = timestamp
                history_data[key] = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "is_removed": False,
                    "data": item,
                }

        for key, hist_item in history_data.items():
            if key not in current_items and not hist_item.get("is_removed", False):
                hist_item["is_removed"] = True
                hist_item["removed_at"] = timestamp
                removed_item = hist_item.get("data", {}).copy()
                removed_item["is_new"] = False
                removed_item["is_removed"] = True
                removed_item["first_seen"] = hist_item.get("first_seen", "")
                removed_item["last_seen"] = hist_item.get("last_seen", "")
                result["output"].append(removed_item)

        return result

    def _merge_wayback(self, history: dict, result: dict, timestamp: str) -> dict:
        """Merge wayback URL results with history."""
        history_data = history.setdefault("wayback", {})
        current_items = set()

        for item in result.get("output", []):
            url = item.get("url", "")
            if not url:
                continue

            current_items.add(url)
            key = url

            if key in history_data:
                item["is_new"] = False
                item["first_seen"] = history_data[key].get("first_seen", timestamp)
                item["last_seen"] = timestamp
                history_data[key]["last_seen"] = timestamp
                history_data[key]["is_removed"] = False
            else:
                item["is_new"] = True
                item["first_seen"] = timestamp
                item["last_seen"] = timestamp
                history_data[key] = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "is_removed": False,
                    "data": item,
                }

        # Note: For wayback, we don't mark as removed since URLs are historical
        # They might not appear in every scan but are still valid historical data

        return result

    def _merge_screenshots(self, history: dict, result: dict, timestamp: str) -> dict:
        """Merge screenshot results with history."""
        history_data = history.setdefault("screenshots", {})
        current_items = set()

        for item in result.get("output", []):
            target = item.get("target", "")
            if not target:
                continue

            current_items.add(target)
            key = target

            if key in history_data:
                item["is_new"] = False
                item["first_seen"] = history_data[key].get("first_seen", timestamp)
                item["last_seen"] = timestamp
                history_data[key]["last_seen"] = timestamp
                history_data[key]["is_removed"] = False
                history_data[key]["path"] = item.get("path", "")
            else:
                item["is_new"] = True
                item["first_seen"] = timestamp
                item["last_seen"] = timestamp
                history_data[key] = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "is_removed": False,
                    "path": item.get("path", ""),
                    "data": item,
                }

        for key, hist_item in history_data.items():
            if key not in current_items and not hist_item.get("is_removed", False):
                hist_item["is_removed"] = True
                hist_item["removed_at"] = timestamp
                removed_item = hist_item.get("data", {"target": key}).copy()
                removed_item["is_new"] = False
                removed_item["is_removed"] = True
                removed_item["first_seen"] = hist_item.get("first_seen", "")
                removed_item["last_seen"] = hist_item.get("last_seen", "")
                result["output"].append(removed_item)

        return result

    def _merge_jsanalyze(self, history: dict, result: dict, timestamp: str) -> dict:
        """Merge JavaScript analysis results with history."""
        history_data = history.setdefault("jsanalyze", {})
        current_items = set()

        for item in result.get("output", []):
            finding = item.get("finding", "")
            item_type = item.get("type", "")
            if not finding:
                continue

            key = f"{item_type}_{finding}"
            current_items.add(key)

            if key in history_data:
                item["is_new"] = False
                item["first_seen"] = history_data[key].get("first_seen", timestamp)
                item["last_seen"] = timestamp
                history_data[key]["last_seen"] = timestamp
                history_data[key]["is_removed"] = False
            else:
                item["is_new"] = True
                item["first_seen"] = timestamp
                item["last_seen"] = timestamp
                history_data[key] = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "is_removed": False,
                    "data": item,
                }

        for key, hist_item in history_data.items():
            if key not in current_items and not hist_item.get("is_removed", False):
                hist_item["is_removed"] = True
                hist_item["removed_at"] = timestamp
                removed_item = hist_item.get("data", {}).copy()
                removed_item["is_new"] = False
                removed_item["is_removed"] = True
                removed_item["first_seen"] = hist_item.get("first_seen", "")
                removed_item["last_seen"] = hist_item.get("last_seen", "")
                result["output"].append(removed_item)

        return result

    def _merge_paramanalyze(self, history: dict, result: dict, timestamp: str) -> dict:
        """Merge parameter analysis results with history."""
        history_data = history.setdefault("paramanalyze", {})
        current_items = set()

        for item in result.get("output", []):
            param = item.get("param", "")
            category = item.get("category", "")
            if not param:
                continue

            key = f"{category}_{param}"
            current_items.add(key)

            if key in history_data:
                item["is_new"] = False
                item["first_seen"] = history_data[key].get("first_seen", timestamp)
                item["last_seen"] = timestamp
                history_data[key]["last_seen"] = timestamp
                history_data[key]["is_removed"] = False
                # Update count if higher
                if item.get("count", 0) > history_data[key].get("count", 0):
                    history_data[key]["count"] = item.get("count", 0)
            else:
                item["is_new"] = True
                item["first_seen"] = timestamp
                item["last_seen"] = timestamp
                history_data[key] = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "is_removed": False,
                    "count": item.get("count", 0),
                    "data": item,
                }

        for key, hist_item in history_data.items():
            if key not in current_items and not hist_item.get("is_removed", False):
                hist_item["is_removed"] = True
                hist_item["removed_at"] = timestamp
                removed_item = hist_item.get("data", {}).copy()
                removed_item["is_new"] = False
                removed_item["is_removed"] = True
                removed_item["first_seen"] = hist_item.get("first_seen", "")
                removed_item["last_seen"] = hist_item.get("last_seen", "")
                result["output"].append(removed_item)

        return result

    def get_statistics(self, domain: str) -> dict:
        """Get statistics for a domain's scan history.

        Args:
            domain: Target domain.

        Returns:
            Statistics dictionary.
        """
        history = self.load_history(domain)

        stats = {
            "domain": domain,
            "first_seen": history.get("first_seen", ""),
            "last_updated": history.get("last_updated", ""),
            "scan_count": history.get("scan_count", 0),
            "totals": {},
        }

        for module in ["subdomains", "probe", "asn", "ports", "technologies", "directories", "wayback", "screenshots", "jsanalyze", "paramanalyze"]:
            module_data = history.get(module, {})
            total = len(module_data)
            active = sum(1 for v in module_data.values() if not v.get("is_removed", False))
            removed = total - active
            stats["totals"][module] = {
                "total": total,
                "active": active,
                "removed": removed,
            }

        return stats
