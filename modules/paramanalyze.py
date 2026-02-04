"""Parameter analysis module for finding potentially vulnerable URL parameters."""

import re
import json
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode
from typing import AsyncIterator, Any
from .base import BaseModule


class ParamAnalyzeModule(BaseModule):
    """Analyze URLs for potentially vulnerable parameters."""

    name = "paramanalyze"
    description = "Analyze URLs for XSS, SQLi, LFI and other vulnerability candidates"
    required_tools = []  # No external tools required

    # Built-in vulnerability patterns (gf-compatible)
    VULN_PATTERNS = {
        "sqli": {
            "severity": "critical",
            "description": "SQL Injection candidates",
            "params": [
                "id", "user", "userid", "uid", "name", "username", "login",
                "order", "sort", "column", "field", "table", "from", "sel",
                "query", "q", "search", "keyword", "where", "params",
                "category", "cat", "dir", "action", "act", "module",
                "page", "report", "view", "item", "menu", "ref", "title",
                "year", "month", "day", "date", "num", "row", "limit", "offset",
            ],
            "patterns": [
                r".*id$", r".*_id$", r".*Id$", r".*ID$",
            ],
        },
        "xss": {
            "severity": "high",
            "description": "Cross-Site Scripting candidates",
            "params": [
                "q", "s", "search", "query", "keyword", "keywords", "term",
                "message", "msg", "comment", "text", "body", "content",
                "name", "username", "user", "email", "mail",
                "title", "subject", "desc", "description",
                "callback", "cb", "jsonp", "func", "function",
                "error", "err", "errormsg", "alert", "warning",
                "preview", "display", "show", "output", "print",
                "redirect", "url", "uri", "link", "next", "goto",
                "html", "data", "input", "value", "val", "var",
            ],
            "patterns": [
                r".*name$", r".*Name$", r".*msg$", r".*text$",
            ],
        },
        "lfi": {
            "severity": "critical",
            "description": "Local/Remote File Inclusion candidates",
            "params": [
                "file", "filename", "path", "filepath", "folder",
                "page", "pg", "p", "include", "inc", "require",
                "doc", "document", "docs", "pdf", "root",
                "template", "tpl", "tmpl", "theme", "skin", "style",
                "load", "read", "retrieve", "download", "fetch",
                "view", "show", "display", "content", "cont",
                "dir", "directory", "location", "loc",
                "lang", "language", "locale", "module", "mod",
                "config", "conf", "cfg", "setting",
            ],
            "patterns": [
                r".*file$", r".*path$", r".*dir$", r".*doc$",
                r".*File$", r".*Path$", r".*Dir$",
            ],
        },
        "ssrf": {
            "severity": "critical",
            "description": "Server-Side Request Forgery candidates",
            "params": [
                "url", "uri", "link", "src", "source", "href",
                "dest", "destination", "target", "to",
                "redirect", "redir", "return", "returnUrl", "return_url",
                "out", "view", "show", "display",
                "site", "website", "host", "domain", "server",
                "proxy", "proxyUrl", "proxy_url",
                "fetch", "load", "request", "req",
                "callback", "api", "endpoint",
                "image", "img", "imageUrl", "image_url",
                "feed", "rss", "atom", "xml",
            ],
            "patterns": [
                r".*[Uu]rl$", r".*[Uu]ri$", r".*[Ll]ink$",
            ],
        },
        "redirect": {
            "severity": "medium",
            "description": "Open Redirect candidates",
            "params": [
                "next", "url", "target", "rurl", "dest", "destination",
                "redir", "redirect", "redirect_uri", "redirect_url",
                "return", "returnUrl", "return_url", "returnTo", "return_to",
                "goto", "go", "jump", "jumpTo", "link", "linkTo",
                "to", "out", "continue", "continueTo", "path",
                "forward", "forwardTo", "success", "successUrl",
                "login", "logout", "signin", "signout",
                "callback", "cb", "checkout", "checkout_url",
            ],
            "patterns": [
                r".*[Rr]edirect.*", r".*[Rr]eturn.*", r".*[Uu]rl$",
            ],
        },
        "rce": {
            "severity": "critical",
            "description": "Remote Code Execution / Command Injection candidates",
            "params": [
                "cmd", "command", "exec", "execute", "run",
                "ping", "query", "jump", "code", "reg",
                "do", "func", "function", "arg", "option",
                "load", "process", "step", "read", "feature",
                "exe", "module", "payload", "daemon", "upload",
                "dir", "download", "log", "ip", "cli", "host",
            ],
            "patterns": [
                r".*[Cc]md$", r".*[Cc]ommand$", r".*[Ee]xec$",
            ],
        },
        "idor": {
            "severity": "high",
            "description": "Insecure Direct Object Reference candidates",
            "params": [
                "id", "user", "userid", "user_id", "uid",
                "account", "accountid", "account_id", "acct",
                "profile", "profileid", "profile_id", "pid",
                "doc", "docid", "doc_id", "document", "documentid",
                "order", "orderid", "order_id", "ordernum",
                "file", "fileid", "file_id", "filename",
                "report", "reportid", "report_id",
                "invoice", "invoiceid", "invoice_id",
                "message", "messageid", "message_id", "msg", "msgid",
                "no", "num", "number", "key", "token", "session",
            ],
            "patterns": [
                r".*[Ii]d$", r".*_id$", r".*ID$", r"^\d+$",
            ],
        },
        "debug": {
            "severity": "medium",
            "description": "Debug/Information Disclosure candidates",
            "params": [
                "debug", "dbg", "test", "testing",
                "admin", "administrator", "root", "superuser",
                "config", "configuration", "conf", "cfg", "setup",
                "env", "environment", "dev", "development",
                "trace", "log", "logging", "verbose", "mode",
                "info", "information", "status", "state",
                "secret", "key", "apikey", "api_key", "token",
                "password", "passwd", "pwd", "pass",
            ],
            "patterns": [
                r".*[Dd]ebug.*", r".*[Tt]est.*", r".*[Aa]dmin.*",
            ],
        },
    }

    def __init__(self, config: dict):
        """Initialize with config and load custom patterns if available."""
        super().__init__(config)
        self.custom_patterns = self._load_custom_patterns()
        self.gf_patterns = self._load_gf_patterns()

    def _load_custom_patterns(self) -> dict:
        """Load custom patterns from config."""
        return self.config.get("paramanalyze", {}).get("custom_patterns", {})

    def _load_gf_patterns(self) -> dict:
        """Load gf patterns from ~/.gf directory if available."""
        gf_patterns = {}
        gf_dir = Path.home() / ".gf"

        if gf_dir.exists():
            for pattern_file in gf_dir.glob("*.json"):
                try:
                    with open(pattern_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    pattern_name = pattern_file.stem
                    if "flags" in data and "patterns" in data:
                        gf_patterns[pattern_name] = {
                            "severity": "medium",
                            "description": f"gf pattern: {pattern_name}",
                            "regex_patterns": data.get("patterns", []),
                        }
                except (json.JSONDecodeError, IOError):
                    pass

        return gf_patterns

    async def run(
        self, target: str, module_config: dict, log_callback: callable = None
    ) -> AsyncIterator[str]:
        """Analyze URLs for vulnerable parameters.

        This module requires results from other modules (wayback, directory, jsanalyze).
        Pass URLs via module_config["urls"].

        Args:
            target: Target domain.
            module_config: Module configuration with 'urls' list.
            log_callback: Callback for log messages.

        Yields:
            JSON lines with analysis results.
        """
        urls = module_config.get("urls", [])
        if not urls:
            if log_callback:
                log_callback("[paramanalyze] No URLs provided for analysis")
            return

        if log_callback:
            log_callback(f"[paramanalyze] Analyzing {len(urls)} URLs for vulnerable parameters")

        # Analyze all URLs
        results = self._analyze_urls(urls, log_callback)

        # Yield results as JSON lines
        for category, data in results.items():
            yield json.dumps({
                "category": category,
                "severity": data["severity"],
                "description": data["description"],
                "params": data["params"],
            })

        if log_callback:
            total_params = sum(len(d["params"]) for d in results.values())
            log_callback(f"[paramanalyze] Found {total_params} potentially vulnerable parameters")

    def _analyze_urls(self, urls: list[str], log_callback: callable = None) -> dict:
        """Analyze URLs and categorize vulnerable parameters.

        Args:
            urls: List of URLs to analyze.
            log_callback: Callback for log messages.

        Returns:
            Dictionary with categorized results.
        """
        results = {
            cat: {
                "severity": info["severity"],
                "description": info["description"],
                "params": {},
            }
            for cat, info in self.VULN_PATTERNS.items()
        }

        # Add gf pattern categories
        for gf_name, gf_info in self.gf_patterns.items():
            if gf_name not in results:
                results[gf_name] = {
                    "severity": gf_info["severity"],
                    "description": gf_info["description"],
                    "params": {},
                }

        for url in urls:
            try:
                parsed = urlparse(url)
                if not parsed.query:
                    continue

                params = parse_qs(parsed.query)

                for param_name in params.keys():
                    # Check against built-in patterns
                    for category, pattern_info in self.VULN_PATTERNS.items():
                        if self._param_matches(param_name, pattern_info):
                            if param_name not in results[category]["params"]:
                                results[category]["params"][param_name] = {
                                    "count": 0,
                                    "urls": [],
                                }
                            results[category]["params"][param_name]["count"] += 1
                            if len(results[category]["params"][param_name]["urls"]) < 10:
                                results[category]["params"][param_name]["urls"].append(url)

                    # Check against gf patterns (regex-based)
                    for gf_name, gf_info in self.gf_patterns.items():
                        if self._matches_gf_pattern(url, gf_info):
                            if param_name not in results[gf_name]["params"]:
                                results[gf_name]["params"][param_name] = {
                                    "count": 0,
                                    "urls": [],
                                }
                            results[gf_name]["params"][param_name]["count"] += 1
                            if len(results[gf_name]["params"][param_name]["urls"]) < 10:
                                results[gf_name]["params"][param_name]["urls"].append(url)

            except Exception as e:
                if log_callback:
                    log_callback(f"[paramanalyze] Error parsing URL: {e}")

        # Sort params by count within each category
        for category in results:
            results[category]["params"] = dict(
                sorted(
                    results[category]["params"].items(),
                    key=lambda x: x[1]["count"],
                    reverse=True
                )
            )

        return results

    def _param_matches(self, param_name: str, pattern_info: dict) -> bool:
        """Check if a parameter matches a vulnerability pattern.

        Args:
            param_name: Parameter name to check.
            pattern_info: Pattern info dictionary.

        Returns:
            True if matches.
        """
        # Check exact matches (case-insensitive)
        param_lower = param_name.lower()
        if param_lower in [p.lower() for p in pattern_info.get("params", [])]:
            return True

        # Check regex patterns
        for pattern in pattern_info.get("patterns", []):
            if re.match(pattern, param_name):
                return True

        return False

    def _matches_gf_pattern(self, url: str, gf_info: dict) -> bool:
        """Check if a URL matches a gf pattern.

        Args:
            url: URL to check.
            gf_info: gf pattern info.

        Returns:
            True if matches.
        """
        for pattern in gf_info.get("regex_patterns", []):
            try:
                if re.search(pattern, url):
                    return True
            except re.error:
                pass
        return False

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse analysis output into structured data.

        Args:
            raw_output: Raw JSON lines output.

        Returns:
            List of categorized parameter findings.
        """
        results = []

        for line in raw_output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                category = data.get("category", "unknown")
                severity = data.get("severity", "medium")
                description = data.get("description", "")

                for param_name, param_info in data.get("params", {}).items():
                    results.append({
                        "param": param_name,
                        "category": category,
                        "severity": severity,
                        "description": description,
                        "count": param_info.get("count", 0),
                        "sample_urls": param_info.get("urls", [])[:5],
                        "type": "vuln_param",
                    })

            except json.JSONDecodeError:
                pass

        # Sort by severity then count
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        results.sort(key=lambda x: (
            severity_order.get(x.get("severity", "low"), 4),
            -x.get("count", 0)
        ))

        return results

    def export_for_nuclei(self, results: list[dict], output_dir: Path) -> dict[str, Path]:
        """Export results as Nuclei-compatible URL lists.

        Args:
            results: Parsed results.
            output_dir: Directory to write files.

        Returns:
            Dictionary mapping category to file path.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        files = {}

        # Group by category
        by_category: dict[str, set[str]] = {}
        for item in results:
            category = item.get("category", "unknown")
            for url in item.get("sample_urls", []):
                if category not in by_category:
                    by_category[category] = set()
                by_category[category].add(url)

        # Write files
        for category, urls in by_category.items():
            if urls:
                file_path = output_dir / f"nuclei_{category}.txt"
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(sorted(urls)))
                files[category] = file_path

        return files

    def export_for_burp(self, results: list[dict], output_dir: Path) -> Path:
        """Export results as Burp Suite compatible format.

        Args:
            results: Parsed results.
            output_dir: Directory to write files.

        Returns:
            Path to the generated file.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        file_path = output_dir / "burp_targets.txt"

        # Collect all unique URLs
        urls = set()
        for item in results:
            urls.update(item.get("sample_urls", []))

        with open(file_path, "w", encoding="utf-8") as f:
            for url in sorted(urls):
                f.write(f"{url}\n")

        return file_path

    def get_statistics(self, results: list[dict]) -> dict:
        """Get statistics from analysis results.

        Args:
            results: Parsed results.

        Returns:
            Statistics dictionary.
        """
        stats = {
            "total_params": len(results),
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_category": {},
            "total_urls": 0,
        }

        urls_seen = set()
        for item in results:
            severity = item.get("severity", "low")
            category = item.get("category", "unknown")

            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

            if category not in stats["by_category"]:
                stats["by_category"][category] = 0
            stats["by_category"][category] += 1

            urls_seen.update(item.get("sample_urls", []))

        stats["total_urls"] = len(urls_seen)

        return stats
