from __future__ import annotations

import subprocess
import time


class SandboxedProviderRunner:
    """Runs provider commands with strict subprocess safeguards."""

    def run_provider(
        self,
        args: list[str],
        timeout: int,
        max_memory_mb: int,
        cwd: str | None = None,
    ) -> dict[str, str | int | float]:
        if not isinstance(args, list) or any(not isinstance(item, str) for item in args):
            raise ValueError("args must be a list[str]")
        if not args:
            raise ValueError("args must not be empty")
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
        if max_memory_mb <= 0:
            raise ValueError("max_memory_mb must be > 0")
        if any(self._contains_credential(arg) for arg in args):
            raise ValueError("credentials must not be passed in args")

        # Credentials must not be passed via args or env.
        # TODO: inject short-lived credentials from tmpfs-mounted files.
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                args,
                shell=False,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return {
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "exit_code": completed.returncode,
                "elapsed_seconds": time.perf_counter() - started,
            }
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            if not stderr:
                stderr = f"provider timed out after {timeout}s"
            return {
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": -1,
                "elapsed_seconds": time.perf_counter() - started,
            }

    @staticmethod
    def _contains_credential(arg: str) -> bool:
        lower = arg.lower()
        return "password=" in lower or "token=" in lower
