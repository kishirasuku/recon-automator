"""Screenshot module for capturing subdomain web pages."""

import asyncio
import sys
from pathlib import Path
from typing import AsyncIterator, Any
from .base import BaseModule


class ScreenshotModule(BaseModule):
    """Capture screenshots of discovered subdomains."""

    name = "screenshot"
    description = "Capture screenshots using gowitness or playwright"
    required_tools = []  # Will be set dynamically

    def __init__(self, config: dict):
        """Initialize with config."""
        super().__init__(config)
        import shutil

        self._use_gowitness = False
        self._use_cutycapt = False
        self._gowitness_bin = None

        # Check for gowitness first
        gowitness_path = self.tools_config.get("gowitness", "gowitness")
        gowitness_bin = shutil.which(gowitness_path) or shutil.which("gowitness")
        if gowitness_bin:
            self._use_gowitness = True
            self._gowitness_bin = gowitness_bin
            self.required_tools = ["gowitness"]
        else:
            # Check for cutycapt as fallback (common on Linux)
            cutycapt_path = self.tools_config.get("cutycapt", "cutycapt")
            if shutil.which(cutycapt_path) or shutil.which("cutycapt"):
                self._use_cutycapt = True
                self.required_tools = ["cutycapt"]
            else:
                # Will try Python with playwright/selenium
                self.required_tools = []

    def is_available(self) -> bool:
        """Check if screenshot capability is available."""
        if self._use_gowitness or self._use_cutycapt:
            return True
        # Check for playwright
        try:
            import playwright
            return True
        except ImportError:
            pass
        return False

    async def run(
        self, target: str, module_config: dict, log_callback: callable = None
    ) -> AsyncIterator[str]:
        """Capture screenshots of subdomains.

        Args:
            target: Target domain.
            module_config: Module configuration with 'targets' list and 'output_dir'.
            log_callback: Callback for log messages.

        Yields:
            Output lines with screenshot information.
        """
        timeout = module_config.get("timeout", 300)
        targets = module_config.get("targets", [])
        output_dir = module_config.get("output_dir", "./screenshots")

        if not targets:
            if log_callback:
                log_callback("[screenshot] No targets provided")
            return

        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        if log_callback:
            log_callback(f"[screenshot] Capturing {len(targets)} targets")
            log_callback(f"[screenshot] Output directory: {output_dir}")

        if self._use_gowitness:
            if log_callback:
                log_callback("[screenshot] Using gowitness")
            async for line in self._run_gowitness(targets, output_dir, timeout, log_callback):
                yield line
        elif self._use_cutycapt:
            if log_callback:
                log_callback("[screenshot] Using cutycapt")
            async for line in self._run_cutycapt(targets, output_dir, timeout, log_callback):
                yield line
        else:
            if log_callback:
                log_callback("[screenshot] Using Python fallback (playwright)")
            async for line in self._run_playwright(targets, output_dir, timeout, log_callback):
                yield line

    async def _run_gowitness(
        self, targets: list[str], output_dir: str, timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Use gowitness for screenshots."""
        tool_path = self._gowitness_bin

        # Create a temporary file with URLs
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for target in targets:
                if not target.startswith(("http://", "https://")):
                    f.write(f"https://{target}\n")
                    f.write(f"http://{target}\n")
                else:
                    f.write(f"{target}\n")
            urls_file = f.name

        try:
            cmd = [
                tool_path,
                "file",
                "-f", urls_file,
                "--screenshot-path", output_dir,
                "--timeout", "10",
            ]

            if log_callback:
                log_callback(f"[screenshot] Running gowitness on {len(targets)} targets")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            # Find generated screenshots
            screenshot_dir = Path(output_dir)
            for png_file in screenshot_dir.glob("*.png"):
                # Extract domain from filename
                filename = png_file.stem
                yield f"{filename}|{png_file}"

            if log_callback:
                count = len(list(screenshot_dir.glob("*.png")))
                log_callback(f"[screenshot] Captured {count} screenshots")

        except asyncio.TimeoutError:
            if log_callback:
                log_callback(f"[screenshot] Timeout after {timeout}s")
        except Exception as e:
            if log_callback:
                log_callback(f"[screenshot] gowitness error: {e}")
        finally:
            # Clean up temp file
            try:
                Path(urls_file).unlink()
            except Exception:
                pass

    async def _run_cutycapt(
        self, targets: list[str], output_dir: str, timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Use cutycapt for screenshots (one at a time)."""
        tool_path = self.get_tool_path("cutycapt")
        output_path = Path(output_dir)

        for i, target in enumerate(targets):
            if not target.startswith(("http://", "https://")):
                url = f"https://{target}"
            else:
                url = target

            # Sanitize filename
            safe_name = target.replace("://", "_").replace("/", "_").replace(":", "_")
            screenshot_path = output_path / f"{safe_name}.png"

            cmd = [
                tool_path,
                f"--url={url}",
                f"--out={screenshot_path}",
                "--delay=2000",
                "--max-wait=10000",
            ]

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                await asyncio.wait_for(
                    process.communicate(),
                    timeout=30
                )

                if screenshot_path.exists():
                    yield f"{target}|{screenshot_path}"

                if log_callback and (i + 1) % 5 == 0:
                    log_callback(f"[screenshot] Captured {i + 1}/{len(targets)}")

            except asyncio.TimeoutError:
                if log_callback:
                    log_callback(f"[screenshot] Timeout for {target}")
            except Exception as e:
                if log_callback:
                    log_callback(f"[screenshot] Error for {target}: {e}")

    async def _run_playwright(
        self, targets: list[str], output_dir: str, timeout: int, log_callback: callable
    ) -> AsyncIterator[str]:
        """Use playwright for screenshots."""
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            if log_callback:
                log_callback("[screenshot] playwright not installed. Run: pip install playwright && playwright install chromium")
            return

        output_path = Path(output_dir)

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    viewport={"width": 1280, "height": 720},
                    ignore_https_errors=True,
                )

                for i, target in enumerate(targets):
                    if not target.startswith(("http://", "https://")):
                        url = f"https://{target}"
                    else:
                        url = target

                    # Sanitize filename
                    safe_name = target.replace("://", "_").replace("/", "_").replace(":", "_").replace("?", "_")
                    screenshot_path = output_path / f"{safe_name}.png"

                    try:
                        page = await context.new_page()
                        await page.goto(url, timeout=15000, wait_until="domcontentloaded")
                        await page.screenshot(path=str(screenshot_path))
                        await page.close()

                        yield f"{target}|{screenshot_path}"

                        if log_callback and (i + 1) % 5 == 0:
                            log_callback(f"[screenshot] Captured {i + 1}/{len(targets)}")

                    except Exception as e:
                        if log_callback:
                            log_callback(f"[screenshot] Error for {target}: {str(e)[:50]}")

                await browser.close()

        except Exception as e:
            if log_callback:
                log_callback(f"[screenshot] Playwright error: {e}")

    def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse screenshot output into structured data.

        Args:
            raw_output: Raw output (target|path pairs).

        Returns:
            List of screenshot dictionaries.
        """
        results = []
        seen = set()

        for line in raw_output.strip().split("\n"):
            if not line.strip():
                continue

            if "|" in line:
                parts = line.split("|", 1)
                target = parts[0].strip()
                path = parts[1].strip() if len(parts) > 1 else ""

                if target and target not in seen:
                    seen.add(target)
                    results.append({
                        "target": target,
                        "path": path,
                        "type": "screenshot",
                    })

        return results
