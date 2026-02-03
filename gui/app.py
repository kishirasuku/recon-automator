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
        self.reporter = ReconReporter(
            self.config.get("output", {}).get("directory", "./output")
        )

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
        self.grid_rowconfigure(3, weight=1)

        # --- Top Section: Target and Profile ---
        top_frame = ctk.CTkFrame(self)
        top_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        top_frame.grid_columnconfigure(0, weight=1)

        # Target input
        self.target_input = TargetInput(top_frame, on_submit=self._on_start_scan)
        self.target_input.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        # Profile selector and options row
        options_frame = ctk.CTkFrame(top_frame, fg_color="transparent")
        options_frame.grid(row=1, column=0, sticky="ew")

        profiles = list(self.config.get("profiles", {}).keys())
        if not profiles:
            profiles = ["quick", "standard", "deep"]
        self.profile_selector = ProfileSelector(options_frame, profiles)
        self.profile_selector.grid(row=0, column=0, sticky="w")

        # Screenshot checkbox
        self.screenshot_var = ctk.BooleanVar(value=False)
        self.screenshot_checkbox = ctk.CTkCheckBox(
            options_frame,
            text="Capture Screenshots",
            variable=self.screenshot_var,
            font=ctk.CTkFont(size=12),
        )
        self.screenshot_checkbox.grid(row=0, column=1, padx=(20, 0), sticky="w")

        # --- Control Buttons ---
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)

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
        self.progress.grid(row=2, column=0, sticky="ew", padx=10, pady=10)

        # --- Main Content Area ---
        content_frame = ctk.CTkFrame(self, fg_color="transparent")
        content_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))
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

        # Handle screenshot option
        enable_screenshot = self.screenshot_var.get()
        if "modules" not in profile_config:
            profile_config["modules"] = {}
        profile_config["modules"]["screenshot"] = {"enabled": enable_screenshot}

        # Store target for results viewer
        self.last_target = target

        # Update UI state
        self.is_scanning = True
        self.start_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.view_results_button.configure(state="disabled")
        self.target_input.set_enabled(False)
        self.profile_selector.set_enabled(False)
        self.screenshot_checkbox.configure(state="disabled")
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
        self.target_input.set_enabled(True)
        self.profile_selector.set_enabled(True)
        self.screenshot_checkbox.configure(state="normal")

        if results:
            self.last_results = results
            self.view_results_button.configure(state="normal")
            completed = sum(1 for r in results.values() if r.get("status") == "completed")
            total = len(results)
            self.progress.stop(f"Complete: {completed}/{total} modules")
            self.log_viewer.append(f"\nScan complete. Results saved to: {self.current_scan_dir}")
        else:
            self.progress.reset("Cancelled")

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
        if self.is_scanning:
            # Cancel running scan
            asyncio.run_coroutine_threadsafe(self.runner.cancel_scan(), self.loop)

        # Stop event loop
        if self.loop:
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
