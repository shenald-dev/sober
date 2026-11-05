"""
Live file watcher daemon for real-time SOBER auditing during AI vibe-coding sessions.
Monitors repository source files and continuously updates the sobriety score as AI edits code.
"""

import logging
import time
from collections.abc import Callable
from pathlib import Path

from sober.core.scanner import get_all_code_files


class LiveSoberWatcher:
    """Monitors repository source files and triggers audit callbacks upon modifications."""

    def __init__(self, target_dir: Path, poll_interval: float = 0.5):
        self.target_dir = target_dir
        self.poll_interval = poll_interval
        self._last_mtimes: dict[str, float] = self._get_mtimes()

    def _get_mtimes(self) -> dict[str, float]:
        mtimes = {}
        files = get_all_code_files(self.target_dir)
        for f in files:
            try:
                mtimes[str(f.path)] = f.path.stat().st_mtime
            except OSError:
                logging.debug(f"Failed to stat {f.path}", exc_info=True)
        return mtimes

    def watch(
        self,
        on_change_callback: Callable[[], None],
        max_iterations: int | None = None,
    ):
        """Watch loop. Calls on_change_callback whenever a file is modified."""
        iterations = 0

        while True:
            time.sleep(self.poll_interval)
            current_mtimes = self._get_mtimes()

            changed = False
            if set(current_mtimes.keys()) != set(self._last_mtimes.keys()):
                changed = True
            else:
                for path_str, mtime in current_mtimes.items():
                    if mtime > self._last_mtimes.get(path_str, 0):
                        changed = True
                        break

            if changed:
                self._last_mtimes = current_mtimes
                on_change_callback()

            iterations += 1
            if max_iterations is not None and iterations >= max_iterations:
                break
