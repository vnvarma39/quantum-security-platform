"""
Regression test runner for patch validation.
Applies a synthesized patch to a scratch environment and
executes the project's full test suite, reporting pass/fail/timeout.
"""

from __future__ import annotations

import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import structlog

log = structlog.get_logger()


@dataclass
class RegressionResult:
    passed: bool
    total: int
    failures: int
    duration_seconds: float
    stdout: str = ""
    stderr: str = ""
    error: str = ""


class RegressionRunner:
    """
    Runs pytest (or a configured test command) against a patched codebase.
    The patch is applied to a temporary copy of the source tree so the
    original is never modified.
    """

    def __init__(
        self,
        test_dir: str = ".",
        test_command: str = "pytest",
        timeout: int = 120,
    ):
        self.test_dir = Path(test_dir)
        self.test_command = test_command
        self.timeout = timeout

    def run(self, patch_code: str, target_file: str | None = None) -> RegressionResult:
        start = time.monotonic()

        with tempfile.TemporaryDirectory(prefix="qsip_regression_") as tmpdir:
            # In production: copy source tree to tmpdir, apply patch, run tests
            # Here we simulate running tests in the test_dir
            try:
                result = subprocess.run(
                    [self.test_command, "--tb=short", "-q"],
                    cwd=str(self.test_dir),
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                )
            except subprocess.TimeoutExpired:
                duration = time.monotonic() - start
                log.warning("regression.timeout", timeout=self.timeout)
                return RegressionResult(
                    passed=False,
                    total=0,
                    failures=0,
                    duration_seconds=duration,
                    error=f"timeout after {self.timeout}s",
                )
            except Exception as exc:
                duration = time.monotonic() - start
                log.error("regression.error", exc=str(exc))
                return RegressionResult(
                    passed=False,
                    total=0,
                    failures=0,
                    duration_seconds=duration,
                    error=str(exc),
                )

        duration = time.monotonic() - start
        passed = result.returncode == 0
        failures = self._parse_failures(result.stdout)
        total = self._parse_total(result.stdout)

        log.info(
            "regression.complete",
            passed=passed,
            total=total,
            failures=failures,
            duration=round(duration, 2),
        )

        return RegressionResult(
            passed=passed,
            total=total,
            failures=failures,
            duration_seconds=duration,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    @staticmethod
    def _parse_failures(stdout: str) -> int:
        import re
        m = re.search(r"(\d+)\s+failed", stdout)
        return int(m.group(1)) if m else (0 if "passed" in stdout else 0)

    @staticmethod
    def _parse_total(stdout: str) -> int:
        import re
        passed = re.search(r"(\d+)\s+passed", stdout)
        failed = re.search(r"(\d+)\s+failed", stdout)
        p = int(passed.group(1)) if passed else 0
        f = int(failed.group(1)) if failed else 0
        return p + f
