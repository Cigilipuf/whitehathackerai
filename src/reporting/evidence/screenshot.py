"""WhiteHatHacker AI — Screenshot Capture Module.

Captures screenshots of web pages using headless browsers or
command-line tools for evidence documentation.
"""

from __future__ import annotations

import asyncio
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class ScreenshotResult(BaseModel):
    """Result of a screenshot capture."""

    url: str
    file_path: str = ""
    width: int = 1920
    height: int = 1080
    captured_at: str = ""
    tool_used: str = ""
    success: bool = False
    error: str = ""
    file_size_bytes: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScreenshotConfig(BaseModel):
    """Configuration for screenshot capture."""

    output_dir: str = "output/screenshots"
    width: int = 1920
    height: int = 1080
    timeout_seconds: int = 30
    full_page: bool = True
    format: str = "png"  # png or jpg
    quality: int = 90  # for jpg
    delay_ms: int = 2000  # wait for page load
    user_agent: str = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )


# ---------------------------------------------------------------------------
# Screenshot backends
# ---------------------------------------------------------------------------

class ScreenshotCapture:
    """Capture screenshots using available tools."""

    def __init__(self, config: ScreenshotConfig | None = None) -> None:
        self.config = config or ScreenshotConfig()
        self._backend = self._detect_backend()

    def _detect_backend(self) -> str:
        """Detect best available screenshot backend."""
        # Check for cutycapt (common on Kali)
        if shutil.which("cutycapt"):
            return "cutycapt"
        # Check for wkhtmltoimage
        if shutil.which("wkhtmltoimage"):
            return "wkhtmltoimage"
        # Check for chromium headless
        for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
            if shutil.which(name):
                return name
        # Check for firefox headless
        if shutil.which("firefox"):
            return "firefox"
        logger.warning("No screenshot backend found. Install cutycapt, chromium, or firefox.")
        return "none"

    @property
    def is_available(self) -> bool:
        return self._backend != "none"

    # ---- Main capture ----------------------------------------------------

    async def capture(
        self,
        url: str,
        *,
        output_name: str = "",
        annotation: str = "",
    ) -> ScreenshotResult:
        """Capture a screenshot of the given URL."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        if not output_name:
            # Sanitise URL for filename
            safe_name = (
                url.replace("https://", "")
                .replace("http://", "")
                .replace("/", "_")
                .replace("?", "_")
                .replace("&", "_")
                .replace(":", "_")[:100]
            )
            output_name = f"{safe_name}_{timestamp}"

        ext = self.config.format.lower()
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"{output_name}.{ext}"

        result = ScreenshotResult(
            url=url,
            file_path=str(output_path),
            width=self.config.width,
            height=self.config.height,
            captured_at=timestamp,
            tool_used=self._backend,
        )

        if not self.is_available:
            result.error = "No screenshot backend available"
            logger.warning(f"Cannot capture screenshot: {result.error}")
            return result

        try:
            if self._backend == "cutycapt":
                await self._capture_cutycapt(url, output_path)
            elif self._backend == "wkhtmltoimage":
                await self._capture_wkhtmltoimage(url, output_path)
            elif self._backend in ("chromium", "chromium-browser",
                                   "google-chrome", "google-chrome-stable"):
                await self._capture_chromium(url, output_path)
            elif self._backend == "firefox":
                await self._capture_firefox(url, output_path)

            if output_path.exists():
                result.success = True
                result.file_size_bytes = output_path.stat().st_size
                if annotation:
                    result.metadata["annotation"] = annotation
                logger.info(f"Screenshot captured: {output_path} ({result.file_size_bytes} bytes)")
            else:
                result.error = "Output file not created"

        except asyncio.TimeoutError:
            result.error = f"Timeout after {self.config.timeout_seconds}s"
            logger.warning(f"Screenshot timeout: {url}")
        except Exception as exc:
            result.error = str(exc)
            logger.error(f"Screenshot error for {url}: {exc}")

        return result

    # ---- Backend implementations -----------------------------------------

    async def _capture_cutycapt(self, url: str, output: Path) -> None:
        cmd = [
            "cutycapt",
            f"--url={url}",
            f"--out={output}",
            f"--min-width={self.config.width}",
            f"--min-height={self.config.height}",
            f"--delay={self.config.delay_ms}",
            "--insecure",
        ]
        await self._run_command(cmd)

    async def _capture_wkhtmltoimage(self, url: str, output: Path) -> None:
        cmd = [
            "wkhtmltoimage",
            "--width", str(self.config.width),
            "--height", str(self.config.height),
            "--quality", str(self.config.quality),
            "--javascript-delay", str(self.config.delay_ms),
            "--no-stop-slow-scripts",
            "--disable-smart-width",
            url,
            str(output),
        ]
        await self._run_command(cmd)

    async def _capture_chromium(self, url: str, output: Path) -> None:
        cmd = [
            self._backend,
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            f"--window-size={self.config.width},{self.config.height}",
            f"--screenshot={output}",
            f"--user-agent={self.config.user_agent}",
            "--hide-scrollbars",
            url,
        ]
        await self._run_command(cmd)

    async def _capture_firefox(self, url: str, output: Path) -> None:
        cmd = [
            "firefox",
            "--headless",
            f"--window-size={self.config.width},{self.config.height}",
            f"--screenshot={output}",
            url,
        ]
        await self._run_command(cmd)

    async def _run_command(self, cmd: list[str]) -> None:
        """Execute a command with timeout."""
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(
                process.communicate(),
                timeout=self.config.timeout_seconds,
            )
        except asyncio.TimeoutError:
            process.kill()
            raise

    # ---- Batch capture ---------------------------------------------------

    async def capture_multiple(
        self,
        urls: list[str],
        *,
        max_concurrent: int = 3,
    ) -> list[ScreenshotResult]:
        """Capture screenshots of multiple URLs with concurrency limit."""
        semaphore = asyncio.Semaphore(max_concurrent)
        results: list[ScreenshotResult] = []

        async def _capture_one(u: str) -> ScreenshotResult:
            async with semaphore:
                return await self.capture(u)

        tasks = [_capture_one(url) for url in urls]
        results = await asyncio.gather(*tasks)
        logger.info(
            f"Batch screenshot: {sum(1 for r in results if r.success)}/{len(urls)} successful"
        )
        return list(results)

    # ---- Evidence helpers ------------------------------------------------

    @staticmethod
    def create_evidence_entry(result: ScreenshotResult) -> dict[str, Any]:
        """Create an evidence dict from a screenshot result."""
        return {
            "type": "screenshot",
            "url": result.url,
            "file": result.file_path,
            "timestamp": result.captured_at,
            "tool": result.tool_used,
            "size_bytes": result.file_size_bytes,
            "success": result.success,
        }
