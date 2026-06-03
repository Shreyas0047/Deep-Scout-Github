from __future__ import annotations

import threading
import time
from enum import Enum
from typing import Optional

from rich.console import Group
from rich.live import Live
from rich.table import Table
from rich.text import Text


class RepoState(Enum):
    QUEUED = "queued"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class RepoProgress:
    def __init__(self, name: str):
        self.name = name
        self.state = RepoState.QUEUED
        self.total_files = 0
        self.scanned_files = 0
        self.secrets_count = 0
        self.error: Optional[str] = None
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

    @property
    def duration(self) -> float:
        if self.end_time:
            return self.end_time - (self.start_time or self.end_time)
        if self.start_time:
            return time.monotonic() - self.start_time
        return 0.0

    @property
    def progress_pct(self) -> float:
        if self.total_files > 0:
            return min(self.scanned_files / self.total_files, 1.0)
        return 0.0

    def progress_bar_str(self, width: int = 15) -> str:
        filled = int(self.progress_pct * width)
        bar = "━" * filled + "╸" + "━" * (width - filled - 1) if filled < width else "━" * width
        pct = int(self.progress_pct * 100)
        return f"{pct:3d}% {bar}"


class ScanProgress:
    def __init__(self, org: str, total_repos: int):
        self.org = org
        self.total_repos = total_repos
        self.repos: dict[str, RepoProgress] = {}
        self._lock = threading.Lock()

    def start_repo(self, name: str):
        with self._lock:
            rp = RepoProgress(name)
            rp.state = RepoState.SCANNING
            rp.start_time = time.monotonic()
            self.repos[name] = rp

    def set_total_files(self, name: str, total: int):
        with self._lock:
            rp = self.repos.get(name)
            if rp:
                rp.total_files = total

    def inc_file(self, name: str):
        with self._lock:
            rp = self.repos.get(name)
            if rp:
                rp.scanned_files += 1

    def inc_secret(self, name: str):
        with self._lock:
            rp = self.repos.get(name)
            if rp:
                rp.secrets_count += 1

    def complete_repo(self, name: str):
        with self._lock:
            rp = self.repos.get(name)
            if rp:
                rp.state = RepoState.COMPLETED
                rp.end_time = time.monotonic()

    def fail_repo(self, name: str, error: str):
        with self._lock:
            rp = self.repos.get(name)
            if rp:
                rp.state = RepoState.FAILED
                rp.end_time = time.monotonic()
                rp.error = error

    @property
    def active_count(self) -> int:
        with self._lock:
            return sum(1 for r in self.repos.values() if r.state == RepoState.SCANNING)

    @property
    def done_count(self) -> int:
        with self._lock:
            return sum(1 for r in self.repos.values() if r.state in (RepoState.COMPLETED, RepoState.FAILED))

    def get_sorted_repos(self) -> list[RepoProgress]:
        with self._lock:
            scanning_first = sorted(
                self.repos.values(),
                key=lambda r: (
                    0 if r.state == RepoState.SCANNING else 1 if r.state == RepoState.QUEUED else 2,
                    r.start_time or 0.0,
                ),
            )
            return scanning_first


_STYLE_MAP = {
    RepoState.QUEUED: "dim white",
    RepoState.SCANNING: "bold cyan",
    RepoState.COMPLETED: "green",
    RepoState.FAILED: "bold red",
}

_ICON_MAP = {
    RepoState.QUEUED: " ",
    RepoState.SCANNING: "→",
    RepoState.COMPLETED: "✓",
    RepoState.FAILED: "✗",
}


def _render_progress_table(progress: ScanProgress) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column("Status", width=2, no_wrap=True)
    table.add_column("Repository", width=32, no_wrap=True)
    table.add_column("Progress", width=22, no_wrap=True)
    table.add_column("Files", width=13, justify="right", no_wrap=True)
    table.add_column("Secrets", width=7, justify="right", no_wrap=True)
    table.add_column("Duration", width=7, justify="right", no_wrap=True)

    repos = progress.get_sorted_repos()
    for rp in repos:
        style = _STYLE_MAP.get(rp.state, "white")
        icon = _ICON_MAP.get(rp.state, " ")

        repo_str = Text(rp.name, style=style)

        if rp.total_files > 0 and rp.total_files < 100000:
            files_str = Text(f"{rp.scanned_files}/{rp.total_files}", style=style)
        elif rp.total_files > 0:
            files_str = Text(f"{rp.scanned_files}", style=style)
        else:
            files_str = Text(f"{rp.scanned_files}", style="dim")

        secrets_str = Text(str(rp.secrets_count), style="bold yellow" if rp.secrets_count > 0 else "dim")
        duration_str = Text(f"{rp.duration:.1f}s", style="dim")
        bar_str = Text(rp.progress_bar_str(), style=style)

        table.add_row(icon, repo_str, bar_str, files_str, secrets_str, duration_str)

    return table


def run_progress_display(
    progress: ScanProgress,
    rate_limit_remaining: int,
    rate_limit_total: int,
    authenticated_user: str = "",
):
    start_time = time.monotonic()

    header = Table.grid(padding=(0, 1))
    header.add_column()
    header.add_row(Text(f"🔍 Deep-Scout GitHub v1.0.0 — Scanning organization: {progress.org}", style="bold"))
    if authenticated_user:
        header.add_row(Text(f"   Authenticated as: @{authenticated_user}", style="dim"))
    header.add_row(
        Text(f"   Rate limit: {rate_limit_remaining} / {rate_limit_total} remaining", style="dim")
    )
    header.add_row(
        Text(f"   📦 Repositories found: {progress.total_repos}", style="white")
    )
    header.add_row(Text(""))

    divider = Text("─" * 80, style="dim")

    with Live(Group(header, divider), refresh_per_second=5, vertical_overflow="visible") as live:
        while progress.done_count < progress.total_repos:
            time.sleep(0.15)

            combined_elapsed = time.monotonic() - start_time
            table = _render_progress_table(progress)

            summary = Text(
                f"\n📊 Summary: {progress.done_count}/{progress.total_repos} repos | "
                f"{combined_elapsed:.0f}s elapsed",
                style="dim",
            )

            live.update(Group(header, table, divider, summary), refresh=True)

        table = _render_progress_table(progress)
        combined_elapsed = time.monotonic() - start_time
        summary = Text(
            f"\n📊 Summary: {progress.done_count}/{progress.total_repos} repos scanned | "
            f"{combined_elapsed:.0f}s total",
            style="bold green",
        )
        live.update(Group(header, table, divider, summary), refresh=True)
