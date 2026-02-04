"""Custom GUI widgets for the Recon Automator."""

import customtkinter as ctk
from typing import Callable, Optional


class LogViewer(ctk.CTkFrame):
    """Scrollable log viewer widget with auto-scroll."""

    def __init__(
        self,
        master,
        height: int = 300,
        **kwargs,
    ):
        """Initialize the log viewer.

        Args:
            master: Parent widget.
            height: Height in pixels.
        """
        super().__init__(master, **kwargs)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Text widget with scrollbar
        self.textbox = ctk.CTkTextbox(
            self,
            height=height,
            font=("Consolas", 11),
            wrap="word",
            state="disabled",
        )
        self.textbox.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)

        # Auto-scroll flag
        self.auto_scroll = True

    def append(self, text: str):
        """Append text to the log.

        Args:
            text: Text to append.
        """
        self.textbox.configure(state="normal")
        self.textbox.insert("end", text + "\n")
        if self.auto_scroll:
            self.textbox.see("end")
        self.textbox.configure(state="disabled")

    def clear(self):
        """Clear all log content."""
        self.textbox.configure(state="normal")
        self.textbox.delete("1.0", "end")
        self.textbox.configure(state="disabled")

    def get_content(self) -> str:
        """Get all log content.

        Returns:
            Full log text.
        """
        return self.textbox.get("1.0", "end").strip()


class ModuleStatusPanel(ctk.CTkFrame):
    """Panel showing status of all modules."""

    STATUS_COLORS = {
        "pending": "gray",
        "running": "#FFA500",  # Orange
        "completed": "#00AA00",  # Green
        "failed": "#FF0000",  # Red
        "cancelled": "#888888",  # Gray
        "skipped": "#666666",  # Dark gray
    }

    def __init__(self, master, modules: list[str], **kwargs):
        """Initialize the status panel.

        Args:
            master: Parent widget.
            modules: List of module names.
        """
        super().__init__(master, **kwargs)

        self.module_labels: dict[str, ctk.CTkLabel] = {}
        self.status_labels: dict[str, ctk.CTkLabel] = {}

        # Header
        header = ctk.CTkLabel(
            self,
            text="Module Status",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        header.grid(row=0, column=0, columnspan=2, pady=(5, 10), sticky="w")

        # Module rows
        for i, module in enumerate(modules, start=1):
            name_label = ctk.CTkLabel(
                self,
                text=module.capitalize(),
                font=ctk.CTkFont(size=12),
            )
            name_label.grid(row=i, column=0, sticky="w", padx=(5, 10), pady=2)
            self.module_labels[module] = name_label

            status_label = ctk.CTkLabel(
                self,
                text="Idle",
                font=ctk.CTkFont(size=12),
                text_color="gray",
            )
            status_label.grid(row=i, column=1, sticky="e", padx=(10, 5), pady=2)
            self.status_labels[module] = status_label

    def update_status(self, module: str, status: str):
        """Update the status of a module.

        Args:
            module: Module name.
            status: New status string.
        """
        if module in self.status_labels:
            label = self.status_labels[module]
            label.configure(
                text=status.capitalize(),
                text_color=self.STATUS_COLORS.get(status, "gray"),
            )

    def reset_all(self):
        """Reset all module statuses to idle."""
        for module in self.status_labels:
            self.update_status(module, "pending")
            self.status_labels[module].configure(text="Idle", text_color="gray")


class ProgressIndicator(ctk.CTkFrame):
    """Progress indicator with label and progress bar."""

    def __init__(self, master, **kwargs):
        """Initialize the progress indicator.

        Args:
            master: Parent widget.
        """
        super().__init__(master, **kwargs)

        self.grid_columnconfigure(0, weight=1)

        # Status label
        self.status_label = ctk.CTkLabel(
            self,
            text="Ready",
            font=ctk.CTkFont(size=12),
        )
        self.status_label.grid(row=0, column=0, sticky="w", pady=(0, 5))

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self)
        self.progress_bar.grid(row=1, column=0, sticky="ew")
        self.progress_bar.set(0)

        # Track state
        self._is_running = False

    def start(self, message: str = "Running..."):
        """Start the progress animation.

        Args:
            message: Status message to display.
        """
        self._is_running = True
        self.status_label.configure(text=message)
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()

    def stop(self, message: str = "Complete"):
        """Stop the progress animation.

        Args:
            message: Status message to display.
        """
        self._is_running = False
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(1)
        self.status_label.configure(text=message)

    def reset(self, message: str = "Ready"):
        """Reset to initial state.

        Args:
            message: Status message to display.
        """
        self._is_running = False
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_bar.set(0)
        self.status_label.configure(text=message)

    @property
    def is_running(self) -> bool:
        """Check if progress is running."""
        return self._is_running


class ToolAvailabilityPanel(ctk.CTkFrame):
    """Panel showing availability of required tools."""

    def __init__(self, master, tool_status: dict[str, dict], **kwargs):
        """Initialize the tool availability panel.

        Args:
            master: Parent widget.
            tool_status: Dict mapping module names to availability info.
        """
        super().__init__(master, **kwargs)

        # Header
        header = ctk.CTkLabel(
            self,
            text="Tool Availability",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        header.grid(row=0, column=0, columnspan=2, pady=(5, 10), sticky="w")

        row = 1
        for module, info in tool_status.items():
            available = info.get("available", False)
            icon = "✓" if available else "✗"
            color = "#00AA00" if available else "#FF0000"

            label = ctk.CTkLabel(
                self,
                text=f"{icon} {module.capitalize()}",
                font=ctk.CTkFont(size=11),
                text_color=color,
            )
            label.grid(row=row, column=0, sticky="w", padx=5, pady=1)

            if not available:
                missing = info.get("missing_tools", [])
                if missing:
                    missing_label = ctk.CTkLabel(
                        self,
                        text=f"(missing: {', '.join(missing)})",
                        font=ctk.CTkFont(size=10),
                        text_color="gray",
                    )
                    missing_label.grid(row=row, column=1, sticky="w", padx=5, pady=1)

            row += 1


class TargetInput(ctk.CTkFrame):
    """Target domain input field with validation."""

    def __init__(
        self,
        master,
        on_submit: Callable[[str], None] | None = None,
        **kwargs,
    ):
        """Initialize the target input.

        Args:
            master: Parent widget.
            on_submit: Callback when Enter is pressed.
        """
        super().__init__(master, **kwargs)

        self.grid_columnconfigure(1, weight=1)

        # Label
        label = ctk.CTkLabel(
            self,
            text="Target:",
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        label.grid(row=0, column=0, padx=(0, 10), sticky="w")

        # Entry
        self.entry = ctk.CTkEntry(
            self,
            placeholder_text="example.com",
            font=ctk.CTkFont(size=13),
        )
        self.entry.grid(row=0, column=1, sticky="ew")

        if on_submit:
            self.entry.bind("<Return>", lambda e: on_submit(self.get()))

    def get(self) -> str:
        """Get the current target value.

        Returns:
            Target domain string.
        """
        return self.entry.get().strip()

    def set(self, value: str):
        """Set the target value.

        Args:
            value: Target domain string.
        """
        self.entry.delete(0, "end")
        self.entry.insert(0, value)

    def set_enabled(self, enabled: bool):
        """Enable or disable the input.

        Args:
            enabled: Whether to enable the input.
        """
        self.entry.configure(state="normal" if enabled else "disabled")


class ProfileSelector(ctk.CTkFrame):
    """Dropdown selector for scan profiles."""

    def __init__(
        self,
        master,
        profiles: list[str],
        on_change: Callable[[str], None] | None = None,
        **kwargs,
    ):
        """Initialize the profile selector.

        Args:
            master: Parent widget.
            profiles: List of profile names.
            on_change: Callback when selection changes.
        """
        super().__init__(master, **kwargs)

        self.grid_columnconfigure(1, weight=1)

        # Label
        label = ctk.CTkLabel(
            self,
            text="Profile:",
            font=ctk.CTkFont(size=13, weight="bold"),
        )
        label.grid(row=0, column=0, padx=(0, 10), sticky="w")

        # Dropdown
        self.dropdown = ctk.CTkOptionMenu(
            self,
            values=profiles,
            font=ctk.CTkFont(size=12),
            command=on_change,
        )
        self.dropdown.grid(row=0, column=1, sticky="w")

        # Set default
        if profiles:
            self.dropdown.set(profiles[0])

    def get(self) -> str:
        """Get the currently selected profile.

        Returns:
            Profile name.
        """
        return self.dropdown.get()

    def set(self, value: str):
        """Set the selected profile.

        Args:
            value: Profile name.
        """
        self.dropdown.set(value)

    def set_enabled(self, enabled: bool):
        """Enable or disable the selector.

        Args:
            enabled: Whether to enable the selector.
        """
        self.dropdown.configure(state="normal" if enabled else "disabled")

    def set_callback(self, callback: Callable[[str], None]):
        """Set or update the change callback.

        Args:
            callback: Function to call when selection changes.
        """
        self.dropdown.configure(command=callback)


class ResultsViewer(ctk.CTkToplevel):
    """Window for viewing scan results."""

    TAB_NAMES = {
        "subdomain": "Subdomains",
        "probe": "Probe Results",
        "asn": "ASN Info",
        "portscan": "Ports",
        "techdetect": "Technologies",
        "directory": "Directories",
        "wayback": "Wayback URLs",
        "jsanalyze": "JS Analysis",
        "paramanalyze": "Vuln Params",
        "nucleiscan": "Nuclei Results",
        "screenshot": "Screenshots",
    }

    def __init__(self, master, results: dict, target: str, **kwargs):
        """Initialize the results viewer.

        Args:
            master: Parent widget.
            results: Scan results dictionary.
            target: Target domain.
        """
        super().__init__(master, **kwargs)

        self.title(f"Results - {target}")
        self.geometry("800x600")
        self.minsize(600, 400)

        self.results = results
        self.target = target

        self._create_widgets()

        # Bring window to front
        self.lift()
        self.focus_force()

    def _create_widgets(self):
        """Create the viewer widgets."""
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header
        header = ctk.CTkLabel(
            self,
            text=f"Scan Results: {self.target}",
            font=ctk.CTkFont(size=18, weight="bold"),
        )
        header.grid(row=0, column=0, pady=10, padx=10, sticky="w")

        # Tab view
        self.tabview = ctk.CTkTabview(self)
        self.tabview.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        # Create tabs for each module
        for module_name, tab_title in self.TAB_NAMES.items():
            module_result = self.results.get(module_name, {})
            if module_result.get("status") == "completed":
                tab = self.tabview.add(tab_title)
                self._populate_tab(tab, module_name, module_result)

        # Summary tab
        summary_tab = self.tabview.add("Summary")
        self._populate_summary(summary_tab)

    def _populate_tab(self, tab: ctk.CTkFrame, module_name: str, result: dict):
        """Populate a tab with module results.

        Args:
            tab: Tab frame.
            module_name: Name of the module.
            result: Module result dictionary.
        """
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        # Count label
        count = result.get("count", 0)
        count_label = ctk.CTkLabel(
            tab,
            text=f"Found: {count} results",
            font=ctk.CTkFont(size=12),
        )
        count_label.grid(row=0, column=0, sticky="w", pady=(5, 10))

        # Results textbox
        textbox = ctk.CTkTextbox(
            tab,
            font=("Consolas", 11),
            wrap="none",
        )
        textbox.grid(row=1, column=0, sticky="nsew")

        # Format and insert results
        content = self._format_results(module_name, result.get("output", []))
        textbox.insert("1.0", content)
        textbox.configure(state="disabled")

    def _format_results(self, module_name: str, output: list) -> str:
        """Format module output for display.

        Args:
            module_name: Name of the module.
            output: List of result items.

        Returns:
            Formatted string.
        """
        lines = []

        if module_name == "subdomain":
            # Sort: new first, then existing, then removed
            sorted_output = sorted(output, key=lambda x: (
                x.get("is_removed", False),
                not x.get("is_new", False),
                x.get("subdomain", "")
            ))
            for item in sorted_output:
                subdomain = item.get("subdomain", "")
                if item.get("is_new", False):
                    lines.append(f"[NEW]     {subdomain}")
                elif item.get("is_removed", False):
                    lines.append(f"[REMOVED] {subdomain}")
                else:
                    lines.append(f"          {subdomain}")

        elif module_name == "probe":
            alive = []
            dead = []
            for item in output:
                subdomain = item.get("subdomain", "")
                status = item.get("status_code", 0)
                # Add new/removed marker
                if item.get("is_new", False):
                    marker = "[NEW] "
                elif item.get("is_removed", False):
                    marker = "[REM] "
                else:
                    marker = ""

                if item.get("alive", False):
                    alive.append(f"{marker}[ALIVE] {subdomain} (HTTP {status})")
                else:
                    dead.append(f"{marker}[DEAD]  {subdomain} (HTTP {status})")

            if alive:
                lines.append("=== ALIVE SUBDOMAINS ===")
                lines.extend(alive)
                lines.append("")
            if dead:
                lines.append("=== INACTIVE SUBDOMAINS ===")
                lines.extend(dead)

        elif module_name == "portscan":
            for item in output:
                host = item.get("host", "unknown")
                port = item.get("port", "")
                service = item.get("service", "")
                version = item.get("version", "")
                line = f"{host}:{port}"
                if service:
                    line += f"  [{service}"
                    if version:
                        line += f" {version}"
                    line += "]"
                lines.append(line)

        elif module_name == "techdetect":
            # Group by URL
            by_url: dict[str, list[str]] = {}
            for item in output:
                url = item.get("url", "unknown")
                tech = item.get("technology", "")
                version = item.get("version", "")
                if version:
                    tech_str = f"{tech} ({version})"
                else:
                    tech_str = tech
                if url not in by_url:
                    by_url[url] = []
                by_url[url].append(tech_str)

            for url, techs in sorted(by_url.items()):
                lines.append(f"[{url}]")
                for tech in sorted(techs):
                    lines.append(f"  - {tech}")
                lines.append("")

        elif module_name == "directory":
            # Group by subdomain
            by_subdomain: dict[str, list[dict]] = {}
            for item in output:
                subdomain = item.get("subdomain", "unknown")
                if subdomain not in by_subdomain:
                    by_subdomain[subdomain] = []
                by_subdomain[subdomain].append(item)

            for subdomain in sorted(by_subdomain.keys()):
                items = by_subdomain[subdomain]
                lines.append("=" * 50)
                lines.append(f"[{subdomain}] - {len(items)} results")
                lines.append("=" * 50)
                for item in items:
                    path = item.get("path", item.get("url", ""))
                    status = item.get("status_code", "")
                    size = item.get("size", "")
                    line = f"  {path}"
                    if status:
                        line += f"  [{status}]"
                    if size:
                        line += f"  ({size} bytes)"
                    lines.append(line)
                lines.append("")

        elif module_name == "wayback":
            # Group by domain
            by_domain: dict[str, list[dict]] = {}
            for item in output:
                domain = item.get("domain", "unknown")
                if domain not in by_domain:
                    by_domain[domain] = []
                by_domain[domain].append(item)

            for domain in sorted(by_domain.keys()):
                items = by_domain[domain]
                lines.append("=" * 50)
                lines.append(f"[{domain}] - {len(items)} URLs")
                lines.append("=" * 50)
                for item in items:
                    url = item.get("url", "")
                    category = item.get("category", "")
                    if category and category not in ["unknown", "page"]:
                        lines.append(f"  {url}  [{category}]")
                    else:
                        lines.append(f"  {url}")
                lines.append("")

        elif module_name == "asn":
            # Group by ASN
            by_asn: dict[str, list[dict]] = {}
            for item in output:
                asn = item.get("asn", "unknown")
                if asn not in by_asn:
                    by_asn[asn] = []
                by_asn[asn].append(item)

            for asn in sorted(by_asn.keys()):
                items = by_asn[asn]
                first = items[0]
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

                for item in items:
                    input_val = item.get("input", "")
                    ip = item.get("ip", "")
                    if input_val:
                        line = f"  {input_val}"
                        if ip:
                            line += f" -> {ip}"
                        lines.append(line)
                lines.append("")

        elif module_name == "screenshot":
            for item in output:
                target = item.get("target", "")
                path = item.get("path", "")
                if target:
                    lines.append(f"[OK] {target}")
                    if path:
                        lines.append(f"     File: {path}")
                    lines.append("")

        elif module_name == "jsanalyze":
            # Separate endpoints and secrets
            endpoints = []
            secrets = []
            for item in output:
                item_type = item.get("type", "")
                if item_type == "js_endpoint":
                    endpoints.append(item)
                elif item_type == "js_secret":
                    secrets.append(item)

            # Show secrets first (critical)
            if secrets:
                lines.append("=" * 50)
                lines.append(f"POTENTIAL SECRETS ({len(secrets)} found)")
                lines.append("=" * 50)
                for item in secrets:
                    finding = item.get("finding", "")
                    secret_type = item.get("secret_type", "unknown")
                    source = item.get("source", "")
                    marker = "[NEW] " if item.get("is_new", False) else ""
                    lines.append(f"{marker}[{secret_type.upper()}]")
                    lines.append(f"  {finding}")
                    if source:
                        lines.append(f"  Source: {source}")
                    lines.append("")

            # Show endpoints grouped by category
            if endpoints:
                # Group by category
                by_category: dict[str, list[dict]] = {}
                for ep in endpoints:
                    category = ep.get("category", "endpoint")
                    if category not in by_category:
                        by_category[category] = []
                    by_category[category].append(ep)

                # Sort categories by importance
                category_order = ["api_endpoint", "auth", "admin", "config", "upload", "endpoint", "javascript", "data"]
                sorted_categories = sorted(by_category.keys(), key=lambda c: (
                    category_order.index(c) if c in category_order else len(category_order),
                    c
                ))

                lines.append("=" * 50)
                lines.append(f"ENDPOINTS ({len(endpoints)} found)")
                lines.append("=" * 50)

                for category in sorted_categories:
                    cat_items = by_category[category]
                    lines.append(f"\n[{category.upper()}] ({len(cat_items)} items)")
                    lines.append("-" * 40)

                    # Sort by sensitivity
                    sorted_items = sorted(cat_items, key=lambda x: (
                        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("sensitivity", "low"), 4),
                        x.get("finding", "")
                    ))

                    for item in sorted_items:
                        finding = item.get("finding", "")
                        sensitivity = item.get("sensitivity", "low")
                        marker = ""
                        if item.get("is_new", False):
                            marker = "[NEW] "
                        if sensitivity == "high":
                            marker += "[!] "
                        elif sensitivity == "medium":
                            marker += "[*] "
                        lines.append(f"  {marker}{finding}")

        elif module_name == "paramanalyze":
            # Group by category
            by_category: dict[str, list[dict]] = {}
            for item in output:
                category = item.get("category", "unknown")
                if category not in by_category:
                    by_category[category] = []
                by_category[category].append(item)

            # Severity order
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

            # Sort categories by severity
            sorted_categories = sorted(by_category.keys(), key=lambda c: (
                min(severity_order.get(i.get("severity", "low"), 4) for i in by_category[c]),
                c
            ))

            for category in sorted_categories:
                cat_items = by_category[category]
                if not cat_items:
                    continue

                severity = cat_items[0].get("severity", "medium").upper()
                description = cat_items[0].get("description", category)

                lines.append("=" * 55)
                lines.append(f"[{severity}] {description}")
                lines.append(f"Parameters: {len(cat_items)}")
                lines.append("=" * 55)

                # Sort by count
                sorted_items = sorted(cat_items, key=lambda x: -x.get("count", 0))

                for item in sorted_items:
                    param = item.get("param", "")
                    count = item.get("count", 0)
                    sample_urls = item.get("sample_urls", [])
                    marker = "[NEW] " if item.get("is_new", False) else ""

                    lines.append(f"  {marker}{param}= ({count} URLs)")
                    for url in sample_urls[:2]:
                        lines.append(f"      {url}")
                    if len(sample_urls) > 2:
                        lines.append(f"      ... +{len(sample_urls) - 2} more")
                lines.append("")

        elif module_name == "nucleiscan":
            # Group by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
            by_severity: dict[str, list[dict]] = {}
            for item in output:
                severity = item.get("severity", "unknown")
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(item)

            # Sort severities
            sorted_severities = sorted(by_severity.keys(), key=lambda s: severity_order.get(s, 5))

            for severity in sorted_severities:
                sev_items = by_severity[severity]
                if not sev_items:
                    continue

                # Color coding hint in header
                if severity == "critical":
                    header = f"[!!!] CRITICAL ({len(sev_items)} findings)"
                elif severity == "high":
                    header = f"[!!] HIGH ({len(sev_items)} findings)"
                elif severity == "medium":
                    header = f"[!] MEDIUM ({len(sev_items)} findings)"
                else:
                    header = f"[{severity.upper()}] ({len(sev_items)} findings)"

                lines.append("=" * 55)
                lines.append(header)
                lines.append("=" * 55)

                for item in sev_items:
                    template_id = item.get("template_id", "unknown")
                    name = item.get("name", template_id)
                    matched_at = item.get("matched_at", "")
                    category = item.get("category", "")
                    marker = "[NEW] " if item.get("is_new", False) else ""

                    lines.append(f"\n  {marker}{name}")
                    lines.append(f"    Template: {template_id}")
                    lines.append(f"    URL:      {matched_at}")
                    if category:
                        lines.append(f"    Scan Cat: {category}")

                lines.append("")

        else:
            # Fallback for unknown modules
            for item in output:
                lines.append(str(item))

        return "\n".join(lines)

    def _populate_summary(self, tab: ctk.CTkFrame):
        """Populate the summary tab.

        Args:
            tab: Summary tab frame.
        """
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)

        textbox = ctk.CTkTextbox(
            tab,
            font=("Consolas", 12),
            wrap="word",
        )
        textbox.grid(row=0, column=0, sticky="nsew", pady=5)

        lines = [
            "=" * 50,
            "SCAN SUMMARY",
            "=" * 50,
            f"Target: {self.target}",
            "",
            "-" * 50,
            "MODULE RESULTS",
            "-" * 50,
        ]

        total_findings = 0
        for module_name, tab_title in self.TAB_NAMES.items():
            result = self.results.get(module_name, {})
            status = result.get("status", "not run")
            count = result.get("count", 0)
            total_findings += count

            if status == "completed":
                icon = "[OK]"
            elif status == "failed":
                icon = "[FAIL]"
            elif status == "cancelled":
                icon = "[CANCEL]"
            else:
                icon = "[--]"

            lines.append(f"{icon} {tab_title}: {count} results")

        # Show inactive subdomains count
        inactive_result = self.results.get("_inactive_subdomains", {})
        if inactive_result.get("status") == "completed":
            inactive_count = inactive_result.get("count", 0)
            if inactive_count > 0:
                lines.append("")
                lines.append(f"[!] Inactive subdomains: {inactive_count}")

        lines.extend([
            "",
            "-" * 50,
            f"Total findings: {total_findings}",
            "=" * 50,
        ])

        textbox.insert("1.0", "\n".join(lines))
        textbox.configure(state="disabled")
