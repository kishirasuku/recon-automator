"""Main application window for Recon Automator."""

import asyncio
import threading
import queue
from pathlib import Path
from typing import Optional
import customtkinter as ctk
import yaml
from loguru import logger

from core.runner import ReconRunner
from core.reporter import ReconReporter
from core.history import ScanIndex, HistoryManager
from modules import get_all_modules, check_module_availability, MODULE_REGISTRY
from gui.widgets import (
    LogViewer,
    ModuleStatusPanel,
    ProgressIndicator,
    ToolAvailabilityPanel,
    TargetInput,
    ProfileSelector,
    ResultsViewer,
)


class ReconAutomatorApp(ctk.CTk):
    """Main application window."""

    def __init__(self, config_path: str = "config/settings.yaml"):
        """Initialize the application.

        Args:
            config_path: Path to the configuration file.
        """
        super().__init__()

        # Load configuration
        self.config = self._load_config(config_path)

        # Initialize components
        self.runner = ReconRunner(max_concurrent=3)
        output_dir = self.config.get("output", {}).get("directory", "./output")
        self.reporter = ReconReporter(output_dir)
        self.scan_index = ScanIndex(output_dir)
        self.history_manager = HistoryManager(output_dir)

        # Module selection state
        self.module_vars: dict[str, ctk.BooleanVar] = {}

        # Async event loop in separate thread
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.loop_thread: Optional[threading.Thread] = None

        # Thread-safe message queue for GUI updates
        self.message_queue: queue.Queue = queue.Queue()

        # State
        self.is_scanning = False
        self.current_scan_dir: Optional[Path] = None
        self.last_results: Optional[dict] = None
        self.last_target: Optional[str] = None

        # Window setup
        self.title("Recon Automator")
        self.geometry("900x700")
        self.minsize(800, 600)

        # Configure appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Build UI
        self._create_widgets()
        self._setup_callbacks()
        self._start_event_loop()
        self._process_message_queue()

    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file.

        Args:
            config_path: Path to config file.

        Returns:
            Configuration dictionary.
        """
        try:
            with open(config_path, "r") as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            logger.warning(f"Config file not found: {config_path}, using defaults")
            return self._default_config()
        except yaml.YAMLError as e:
            logger.error(f"Error parsing config: {e}")
            return self._default_config()

    def _default_config(self) -> dict:
        """Return default configuration."""
        return {
            "tools": {},
            "profiles": {
                "quick": {"timeout": 300, "modules": {}},
                "standard": {"timeout": 900, "modules": {}},
                "deep": {"timeout": 3600, "modules": {}},
            },
            "wordlists": {},
            "output": {"directory": "./output"},
        }

    def _create_widgets(self):
        """Create all GUI widgets."""
        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(4, weight=1)  # Changed from 3 to 4 for module selection row

        # --- Top Section: Target and Profile ---
        top_frame = ctk.CTkFrame(self)
        top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        top_frame.grid_columnconfigure(0, weight=1)

        # Target input row with history button
        target_row = ctk.CTkFrame(top_frame, fg_color="transparent")
        target_row.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        target_row.grid_columnconfigure(0, weight=1)

        self.target_input = TargetInput(target_row, on_submit=self._on_start_scan)
        self.target_input.grid(row=0, column=0, sticky="ew")

        # History button
        self.history_button = ctk.CTkButton(
            target_row,
            text="History",
            command=self._on_show_history,
            font=ctk.CTkFont(size=12),
            height=32,
            width=80,
        )
        self.history_button.grid(row=0, column=1, padx=(10, 0))

        # Profile selector and options row
        options_frame = ctk.CTkFrame(top_frame, fg_color="transparent")
        options_frame.grid(row=1, column=0, sticky="ew")

        profiles = list(self.config.get("profiles", {}).keys())
        if not profiles:
            profiles = ["quick", "standard", "deep"]
        self.profile_selector = ProfileSelector(options_frame, profiles)
        self.profile_selector.grid(row=0, column=0, sticky="w")
        self.profile_selector.set_callback(self._on_profile_changed)

        # Screenshot checkbox
        self.screenshot_var = ctk.BooleanVar(value=False)
        self.screenshot_checkbox = ctk.CTkCheckBox(
            options_frame,
            text="Capture Screenshots",
            variable=self.screenshot_var,
            font=ctk.CTkFont(size=12),
        )
        self.screenshot_checkbox.grid(row=0, column=1, padx=(20, 0), sticky="w")

        # --- Module Selection Section ---
        module_frame = ctk.CTkFrame(self)
        module_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)

        module_label = ctk.CTkLabel(
            module_frame,
            text="Modules:",
            font=ctk.CTkFont(size=12, weight="bold"),
        )
        module_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        # Create checkboxes for each module
        checkbox_frame = ctk.CTkFrame(module_frame, fg_color="transparent")
        checkbox_frame.grid(row=0, column=1, sticky="w", padx=5)

        module_names = list(MODULE_REGISTRY.keys())
        for i, module_name in enumerate(module_names):
            var = ctk.BooleanVar(value=True)
            self.module_vars[module_name] = var
            cb = ctk.CTkCheckBox(
                checkbox_frame,
                text=module_name,
                variable=var,
                font=ctk.CTkFont(size=11),
                width=100,
            )
            cb.grid(row=0, column=i, padx=5, pady=2)

        # Update checkboxes based on current profile
        self._on_profile_changed(self.profile_selector.get())

        # --- Control Buttons ---
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=5)

        self.start_button = ctk.CTkButton(
            button_frame,
            text="Start Scan",
            command=self._on_start_scan,
            font=ctk.CTkFont(size=14, weight="bold"),
            height=40,
            width=150,
        )
        self.start_button.grid(row=0, column=0, padx=(0, 10))

        self.cancel_button = ctk.CTkButton(
            button_frame,
            text="Cancel",
            command=self._on_cancel_scan,
            font=ctk.CTkFont(size=14),
            height=40,
            width=100,
            fg_color="#AA0000",
            hover_color="#880000",
            state="disabled",
        )
        self.cancel_button.grid(row=0, column=1, padx=(0, 10))

        self.view_results_button = ctk.CTkButton(
            button_frame,
            text="View Results",
            command=self._on_view_results,
            font=ctk.CTkFont(size=14),
            height=40,
            width=120,
            fg_color="#006600",
            hover_color="#004400",
            state="disabled",
        )
        self.view_results_button.grid(row=0, column=2, padx=(0, 10))

        self.export_button = ctk.CTkButton(
            button_frame,
            text="Open Output",
            command=self._on_open_output,
            font=ctk.CTkFont(size=14),
            height=40,
            width=120,
        )
        self.export_button.grid(row=0, column=3)

        # --- Progress ---
        self.progress = ProgressIndicator(self)
        self.progress.grid(row=3, column=0, sticky="ew", padx=10, pady=10)

        # --- Main Content Area ---
        content_frame = ctk.CTkFrame(self, fg_color="transparent")
        content_frame.grid(row=4, column=0, sticky="nsew", padx=10, pady=(0, 10))
        content_frame.grid_columnconfigure(0, weight=3)
        content_frame.grid_columnconfigure(1, weight=1)
        content_frame.grid_rowconfigure(0, weight=1)

        # Log viewer (left side)
        self.log_viewer = LogViewer(content_frame, height=300)
        self.log_viewer.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        # Side panel (right side)
        side_panel = ctk.CTkFrame(content_frame)
        side_panel.grid(row=0, column=1, sticky="nsew")
        side_panel.grid_rowconfigure(1, weight=1)

        # Module status
        module_names = list(MODULE_REGISTRY.keys())
        self.module_status = ModuleStatusPanel(side_panel, module_names)
        self.module_status.grid(row=0, column=0, sticky="new", padx=10, pady=10)

        # Tool availability
        tool_status = check_module_availability(self.config)
        self.tool_panel = ToolAvailabilityPanel(side_panel, tool_status)
        self.tool_panel.grid(row=1, column=0, sticky="new", padx=10, pady=10)

    def _setup_callbacks(self):
        """Setup runner callbacks for GUI updates."""
        self.runner.set_log_callback(self._queue_log)
        self.runner.set_progress_callback(self._queue_progress)

    def _queue_log(self, message: str):
        """Queue a log message for GUI update.

        Args:
            message: Log message.
        """
        self.message_queue.put(("log", message))

    def _queue_progress(self, module: str, status: str):
        """Queue a progress update for GUI update.

        Args:
            module: Module name.
            status: Status string.
        """
        self.message_queue.put(("progress", (module, status)))

    def _process_message_queue(self):
        """Process messages from the queue to update GUI."""
        try:
            while True:
                msg_type, data = self.message_queue.get_nowait()
                if msg_type == "log":
                    self.log_viewer.append(data)
                elif msg_type == "progress":
                    module, status = data
                    self.module_status.update_status(module, status)
                elif msg_type == "scan_complete":
                    self._on_scan_complete(data)
        except queue.Empty:
            pass

        # Schedule next check
        self.after(100, self._process_message_queue)

    def _start_event_loop(self):
        """Start the async event loop in a background thread."""
        def run_loop():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_forever()

        self.loop_thread = threading.Thread(target=run_loop, daemon=True)
        self.loop_thread.start()

    def _on_start_scan(self, target: str | None = None):
        """Handle start scan button click."""
        if self.is_scanning:
            return

        target = target or self.target_input.get()
        if not target:
            self.log_viewer.append("[ERROR] Please enter a target domain")
            return

        # Validate target (basic check)
        if " " in target or not "." in target:
            self.log_viewer.append("[ERROR] Invalid target format. Use: example.com")
            return

        profile = self.profile_selector.get()
        profile_config = self.config.get("profiles", {}).get(profile, {}).copy()

        # Apply module selections from checkboxes
        if "modules" not in profile_config:
            profile_config["modules"] = {}

        for module_name, var in self.module_vars.items():
            if module_name not in profile_config["modules"]:
                profile_config["modules"][module_name] = {}
            profile_config["modules"][module_name]["enabled"] = var.get()

        # Handle screenshot option (override with checkbox)
        enable_screenshot = self.screenshot_var.get()
        profile_config["modules"]["screenshot"] = {"enabled": enable_screenshot}

        # Store target for results viewer
        self.last_target = target

        # Update UI state
        self.is_scanning = True
        self.start_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.view_results_button.configure(state="disabled")
        self.history_button.configure(state="disabled")
        self.target_input.set_enabled(False)
        self.profile_selector.set_enabled(False)
        self.screenshot_checkbox.configure(state="disabled")
        self._set_module_checkboxes_enabled(False)
        self.module_status.reset_all()
        self.log_viewer.clear()
        self.progress.start(f"Scanning {target}...")

        # Create scan output directory
        self.current_scan_dir = self.reporter.create_scan_directory(target)
        self.log_viewer.append(f"Output directory: {self.current_scan_dir}")

        # Get modules
        modules = get_all_modules(self.config)

        # Run scan in async loop
        scan_dir = self.current_scan_dir
        async def run_scan():
            try:
                results = await self.runner.run_scan(
                    modules, target, profile_config, scan_dir=scan_dir
                )
                # Export results
                self.reporter.export_results(
                    results, target, profile, scan_dir
                )
                self.message_queue.put(("scan_complete", results))
            except Exception as e:
                logger.exception("Scan failed")
                self.message_queue.put(("log", f"[ERROR] Scan failed: {e}"))
                self.message_queue.put(("scan_complete", {}))

        asyncio.run_coroutine_threadsafe(run_scan(), self.loop)

    def _on_cancel_scan(self):
        """Handle cancel button click."""
        if not self.is_scanning:
            return

        self.log_viewer.append("Cancelling scan...")

        async def cancel():
            await self.runner.cancel_scan()
            self.message_queue.put(("scan_complete", {}))

        asyncio.run_coroutine_threadsafe(cancel(), self.loop)

    def _on_scan_complete(self, results: dict):
        """Handle scan completion.

        Args:
            results: Scan results dictionary.
        """
        self.is_scanning = False
        self.start_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        self.history_button.configure(state="normal")
        self.target_input.set_enabled(True)
        self.profile_selector.set_enabled(True)
        self.screenshot_checkbox.configure(state="normal")
        self._set_module_checkboxes_enabled(True)

        if results:
            self.last_results = results
            self.view_results_button.configure(state="normal")
            completed = sum(1 for r in results.values() if r.get("status") == "completed")
            total = len(results)
            self.progress.stop(f"Complete: {completed}/{total} modules")
            self.log_viewer.append(f"\nScan complete. Results saved to: {self.current_scan_dir}")
        else:
            self.progress.reset("Cancelled")

    def _set_module_checkboxes_enabled(self, enabled: bool):
        """Enable or disable all module checkboxes.

        Args:
            enabled: Whether to enable or disable.
        """
        state = "normal" if enabled else "disabled"
        # Find all checkboxes in the module frame and update their state
        for widget in self.winfo_children():
            if isinstance(widget, ctk.CTkFrame):
                for child in widget.winfo_children():
                    if isinstance(child, ctk.CTkFrame):
                        for grandchild in child.winfo_children():
                            if isinstance(grandchild, ctk.CTkCheckBox):
                                grandchild.configure(state=state)

    def _on_profile_changed(self, profile: str):
        """Handle profile selection change - update module checkboxes.

        Args:
            profile: Selected profile name.
        """
        profile_config = self.config.get("profiles", {}).get(profile, {})
        modules_config = profile_config.get("modules", {})

        for module_name, var in self.module_vars.items():
            mod_config = modules_config.get(module_name, {})
            enabled = mod_config.get("enabled", True)
            var.set(enabled)

    def _on_show_history(self):
        """Show history dialog with previously scanned domains."""
        domains = self.scan_index.get_all_domains()

        if not domains:
            self.log_viewer.append("[INFO] No scan history found")
            return

        # Create history dialog
        dialog = ctk.CTkToplevel(self)
        dialog.title("Scan History")
        dialog.geometry("500x400")
        dialog.transient(self)
        dialog.grab_set()

        # Header
        header = ctk.CTkLabel(
            dialog,
            text="Select a domain to load:",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        header.pack(pady=10)

        # Scrollable frame for domain list
        scroll_frame = ctk.CTkScrollableFrame(dialog, width=460, height=280)
        scroll_frame.pack(padx=10, pady=5, fill="both", expand=True)

        def select_domain(domain: str):
            self.target_input.set(domain)
            self._load_domain_history(domain)
            dialog.destroy()

        for domain_info in domains:
            domain = domain_info["domain"]
            last_scan = domain_info.get("last_scan", "")[:10]
            scan_count = domain_info.get("scan_count", 0)

            frame = ctk.CTkFrame(scroll_frame)
            frame.pack(fill="x", padx=5, pady=2)

            label = ctk.CTkLabel(
                frame,
                text=f"{domain}  ({scan_count} scans, last: {last_scan})",
                font=ctk.CTkFont(size=12),
            )
            label.pack(side="left", padx=10, pady=5)

            btn = ctk.CTkButton(
                frame,
                text="Load",
                width=60,
                command=lambda d=domain: select_domain(d),
            )
            btn.pack(side="right", padx=10, pady=5)

        # Close button
        close_btn = ctk.CTkButton(
            dialog,
            text="Close",
            command=dialog.destroy,
        )
        close_btn.pack(pady=10)

    def _load_domain_history(self, domain: str):
        """Load historical data for a domain and enable View Results.

        Args:
            domain: Domain to load history for.
        """
        history = self.history_manager.load_history(domain)

        if history.get("scan_count", 0) > 0:
            # Convert history to results format for viewing
            self.last_target = domain
            self.last_results = self._history_to_results(history)
            self.view_results_button.configure(state="normal")
            self.log_viewer.append(f"[INFO] Loaded history for {domain} ({history.get('scan_count', 0)} scans)")
        else:
            self.log_viewer.append(f"[INFO] No history found for {domain}")

    def _history_to_results(self, history: dict) -> dict:
        """Convert history format to results format for display.

        Args:
            history: History dictionary from HistoryManager.

        Returns:
            Results dictionary compatible with ResultsViewer.
        """
        results = {}

        # Map history keys to module names
        mappings = {
            "subdomains": "subdomain",
            "probe": "probe",
            "asn": "asn",
            "ports": "portscan",
            "technologies": "techdetect",
            "directories": "directory",
            "wayback": "wayback",
            "screenshots": "screenshot",
            "jsanalyze": "jsanalyze",
        }

        for hist_key, module_name in mappings.items():
            hist_data = history.get(hist_key, {})
            if hist_data:
                output = []
                for key, item in hist_data.items():
                    data = item.get("data", {})
                    if not data:
                        continue
                    data["first_seen"] = item.get("first_seen", "")
                    data["last_seen"] = item.get("last_seen", "")
                    data["is_removed"] = item.get("is_removed", False)
                    output.append(data)

                results[module_name] = {
                    "status": "completed",
                    "output": output,
                    "count": len(output),
                }

        return results

    def _on_view_results(self):
        """Open the results viewer window."""
        if not self.last_results or not self.last_target:
            self.log_viewer.append("[ERROR] No results to display")
            return

        ResultsViewer(self, self.last_results, self.last_target)

    def _on_open_output(self):
        """Open the output directory in file manager."""
        import subprocess
        import sys

        output_dir = Path(self.config.get("output", {}).get("directory", "./output"))
        output_dir = output_dir.resolve()

        if not output_dir.exists():
            output_dir.mkdir(parents=True)

        # Open file manager
        if sys.platform == "win32":
            subprocess.run(["explorer", str(output_dir)])
        elif sys.platform == "darwin":
            subprocess.run(["open", str(output_dir)])
        else:
            subprocess.run(["xdg-open", str(output_dir)])

    def on_closing(self):
        """Handle window close event."""
        if self.loop and self.loop.is_running():
            async def cleanup():
                """Clean up all pending tasks."""
                # Cancel running scan if any
                if self.is_scanning:
                    await self.runner.cancel_scan()

                # Cancel all remaining tasks
                tasks = [t for t in asyncio.all_tasks(self.loop)
                         if t is not asyncio.current_task()]
                for task in tasks:
                    task.cancel()

                # Wait for all tasks to complete
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

            # Run cleanup and wait for it to complete
            future = asyncio.run_coroutine_threadsafe(cleanup(), self.loop)
            try:
                future.result(timeout=5.0)  # Wait up to 5 seconds
            except Exception:
                pass  # Ignore errors during cleanup

            # Stop event loop
            self.loop.call_soon_threadsafe(self.loop.stop)

        self.destroy()


def run_app(config_path: str = "config/settings.yaml"):
    """Run the application.

    Args:
        config_path: Path to configuration file.
    """
    app = ReconAutomatorApp(config_path)
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
