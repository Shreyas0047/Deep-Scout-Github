from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


def shallow_clone(url: str, depth: int = 100, cache_dir: str | None = None, ttl_hours: int = 24) -> str:
    repo_hash = str(abs(hash(url)))
    if cache_dir:
        cache_path = Path(cache_dir) / repo_hash
        if cache_path.exists():
            age_hours = (time.time() - cache_path.stat().st_mtime) / 3600
            if age_hours < ttl_hours:
                return str(cache_path)
            shutil.rmtree(cache_path, ignore_errors=True)

    tmp = Path(tempfile.mkdtemp(prefix="deep-scout-"))
    clone_path = tmp / "repo"

    cmd = ["git", "clone"]
    if depth > 0:
        cmd.extend(["--depth", str(depth)])
    cmd.extend([url, str(clone_path)])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"git clone failed: {result.stderr.strip()}")

    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
        shutil.move(str(clone_path), cache_path)
        shutil.rmtree(tmp, ignore_errors=True)
        return str(cache_path)

    return str(clone_path)


def cleanup(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)
