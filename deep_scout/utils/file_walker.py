from __future__ import annotations

import os
from fnmatch import fnmatch
from pathlib import Path

_BINARY_EXTENSIONS: set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".zst",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv",
    ".pyc", ".pyo", ".pyd",
    ".so", ".dll", ".dylib", ".exe", ".bin",
    ".o", ".a", ".lib",
    ".DS_Store",
    ".ttf", ".otf",
    ".webp",
}

_TEXT_EXTENSIONS: set[str] = {
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".env",
    ".sh", ".bash", ".zsh", ".txt", ".md", ".cfg", ".conf",
    ".xml", ".pem", ".key", ".crt",
    ".html", ".css", ".scss", ".less",
    ".sql", ".r", ".m", ".swift", ".kt", ".rs",
    ".gradle", ".properties",
    ".yaml", ".yml",
}

_READ_SIZE = 8192


def _looks_binary(file_path: str) -> bool:
    ext = Path(file_path).suffix.lower()
    if ext in _BINARY_EXTENSIONS:
        return True
    if ext in _TEXT_EXTENSIONS:
        return False
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(_READ_SIZE)
        return b"\0" in chunk
    except OSError:
        return True


def walk_files(
    root: str,
    scan_extensions: set[str] | None = None,
    exclude_paths: list[str] | None = None,
    include_paths: list[str] | None = None,
    max_file_bytes: int = 5 * 1024 * 1024,
) -> list[str]:
    files: list[str] = []
    root_path = Path(root)

    for dirpath_str, dirnames, filenames in os.walk(root):
        dirpath = Path(dirpath_str)

        if exclude_paths:
            rel_dir = str(dirpath.relative_to(root_path)) if dirpath != root_path else ""
            dirnames[:] = [
                d for d in dirnames
                if not any(fnmatch(str(dirpath / d), p) for p in exclude_paths)
                and not any(fnmatch(d, p) for p in exclude_paths if "/" not in p.rstrip("/"))
            ]

        for fname in filenames:
            fpath = str(dirpath / fname)

            if exclude_paths and any(fnmatch(fpath, p) for p in exclude_paths):
                continue

            if include_paths and not any(fnmatch(fpath, p) for p in include_paths):
                continue

            if scan_extensions:
                ext = Path(fname).suffix.lower()
                if ext not in scan_extensions:
                    continue

            try:
                fsize = os.path.getsize(fpath)
            except OSError:
                continue
            if fsize > max_file_bytes:
                continue
            if fsize == 0:
                continue

            if _looks_binary(fpath):
                continue

            files.append(fpath)

    return files
