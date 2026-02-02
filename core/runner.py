"""Async task execution engine for running recon modules."""

import asyncio
from typing import Callable, Optional
from datetime import datetime
from loguru import logger


class ReconRunner:
    """Manages async execution of reconnaissance modules."""

    def __init__(self, max_concurrent: int = 3):
        """Initialize the runner.

        Args:
            max_concurrent: Maximum number of modules to run concurrently.
        """
        self.max_concurrent = max_concurrent
        self.semaphore: Optional[asyncio.Semaphore] = None
        self.running_tasks: dict[str, asyncio.Task] = {}
        self.results: dict[str, dict] = {}
        self.cancelled = False
        self._log_callback: Optional[Callable[[str], None]] = None
        self._progress_callback: Optional[Callable[[str, str], None]] = None

    def set_log_callback(self, callback: Callable[[str], None]):
        """Set callback for log output.

        Args:
            callback: Function to call with log messages.
        """
        self._log_callback = callback

    def set_progress_callback(self, callback: Callable[[str, str], None]):
        """Set callback for progress updates.

        Args:
            callback: Function to call with (module_name, status) updates.
        """
        self._progress_callback = callback

    def log(self, message: str):
        """Log a message to both loguru and the callback.

        Args:
            message: Message to log.
        """
        logger.info(message)
        if self._log_callback:
            timestamp = datetime.now().strftime("%H:%M:%S")
            self._log_callback(f"[{timestamp}] {message}")

    def update_progress(self, module_name: str, status: str):
        """Update progress for a module.

        Args:
            module_name: Name of the module.
            status: Current status (pending, running, completed, failed, cancelled).
        """
        if self._progress_callback:
            self._progress_callback(module_name, status)

    async def run_module(
        self,
        module,
        target: str,
        module_config: dict,
    ) -> dict:
        """Run a single module with semaphore control.

        Args:
            module: Module instance to run.
            target: Target domain.
            module_config: Module-specific configuration.

        Returns:
            Dictionary with module results.
        """
        module_name = module.name

        async with self.semaphore:
            if self.cancelled:
                self.update_progress(module_name, "cancelled")
                return {"status": "cancelled", "output": [], "raw": ""}

            self.log(f"Starting module: {module_name}")
            self.update_progress(module_name, "running")

            raw_output = []
            try:
                async for line in module.run(target, module_config, self.log):
                    if self.cancelled:
                        self.update_progress(module_name, "cancelled")
                        return {"status": "cancelled", "output": [], "raw": ""}
                    raw_output.append(line)

                raw_text = "\n".join(raw_output)
                parsed = module.parse_output(raw_text)

                self.log(f"Completed module: {module_name} ({len(parsed)} results)")
                self.update_progress(module_name, "completed")

                return {
                    "status": "completed",
                    "output": parsed,
                    "raw": raw_text,
                    "count": len(parsed),
                }

            except asyncio.CancelledError:
                self.log(f"Module cancelled: {module_name}")
                self.update_progress(module_name, "cancelled")
                return {"status": "cancelled", "output": [], "raw": ""}

            except Exception as e:
                self.log(f"Module failed: {module_name} - {str(e)}")
                self.update_progress(module_name, "failed")
                logger.exception(f"Error in module {module_name}")
                return {"status": "failed", "error": str(e), "output": [], "raw": ""}

    async def run_scan(
        self,
        modules: list,
        target: str,
        profile_config: dict,
    ) -> dict[str, dict]:
        """Run all enabled modules for a scan.

        Args:
            modules: List of module instances to run.
            target: Target domain.
            profile_config: Profile configuration with module settings.

        Returns:
            Dictionary mapping module names to their results.
        """
        self.cancelled = False
        self.results = {}
        self.semaphore = asyncio.Semaphore(self.max_concurrent)

        module_configs = profile_config.get("modules", {})

        # Filter enabled modules
        enabled_modules = []
        for module in modules:
            mod_config = module_configs.get(module.name, {})
            if mod_config.get("enabled", True):
                if module.is_available():
                    enabled_modules.append((module, mod_config))
                    self.update_progress(module.name, "pending")
                else:
                    missing = module.get_missing_tools()
                    self.log(f"Skipping {module.name}: missing tools {missing}")
                    self.update_progress(module.name, "skipped")

        if not enabled_modules:
            self.log("No modules available to run")
            return {}

        self.log(f"Running {len(enabled_modules)} modules on target: {target}")

        # Create tasks for all modules
        tasks = []
        for module, mod_config in enabled_modules:
            task = asyncio.create_task(
                self.run_module(module, target, mod_config),
                name=module.name,
            )
            self.running_tasks[module.name] = task
            tasks.append((module.name, task))

        # Wait for all tasks to complete
        for module_name, task in tasks:
            try:
                result = await task
                self.results[module_name] = result
            except asyncio.CancelledError:
                self.results[module_name] = {
                    "status": "cancelled",
                    "output": [],
                    "raw": "",
                }

        self.running_tasks.clear()
        return self.results

    async def cancel_scan(self):
        """Cancel all running modules."""
        self.cancelled = True
        self.log("Cancelling scan...")

        for name, task in self.running_tasks.items():
            if not task.done():
                task.cancel()
                self.log(f"Cancelled task: {name}")

        # Wait for all tasks to finish cancelling
        if self.running_tasks:
            await asyncio.gather(
                *self.running_tasks.values(),
                return_exceptions=True,
            )

        self.running_tasks.clear()
        self.log("Scan cancelled")


async def run_command(
    cmd: list[str],
    timeout: Optional[int] = None,
    log_callback: Optional[Callable[[str], None]] = None,
):
    """Run a command asynchronously, yielding output lines.

    Args:
        cmd: Command and arguments as a list.
        timeout: Optional timeout in seconds.
        log_callback: Optional callback for logging.

    Yields:
        Output lines from the command.
    """
    logger.debug(f"Running command: {' '.join(cmd)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        async def read_output():
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                decoded = line.decode("utf-8", errors="replace").rstrip()
                if decoded:
                    yield decoded

        if timeout:
            try:
                async for line in read_output():
                    yield line
                await asyncio.wait_for(process.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                if log_callback:
                    log_callback(f"Command timed out after {timeout}s")
        else:
            async for line in read_output():
                yield line
            await process.wait()

    except FileNotFoundError:
        error_msg = f"Command not found: {cmd[0]}"
        logger.error(error_msg)
        if log_callback:
            log_callback(error_msg)
    except Exception as e:
        error_msg = f"Command failed: {str(e)}"
        logger.error(error_msg)
        if log_callback:
            log_callback(error_msg)
