from __future__ import annotations

import concurrent.futures
import os
from pathlib import Path
from typing import Optional

from deep_scout.detectors.entropy import EntropyDetector
from deep_scout.detectors.regex import RegexDetector
from deep_scout.github.client import GitHubClient
from deep_scout.reporting.base import Finding
from deep_scout.ui.progress import ScanProgress
from deep_scout.utils.file_walker import walk_files
from deep_scout.utils.git import cleanup, shallow_clone
from deep_scout.utils.whitelist import Whitelist


class Scanner:
    def __init__(self, config: dict):
        self.config = config
        gh_conf = config["github"]
        token = os.environ.get("GITHUB_TOKEN") or ""
        self.client = GitHubClient(
            token=token,
            base_url=gh_conf.get("base_url", "https://api.github.com"),
            timeout=gh_conf.get("timeout_seconds", 30),
            max_retries=gh_conf.get("max_retries", 3),
            requests_per_second=config["performance"].get("github_requests_per_second", 10),
        )

        detection = config["detection"]
        self.regex_detector = RegexDetector(
            custom_patterns=detection.get("custom_patterns")
        ) if detection.get("enable_regex", True) else None
        self.entropy_detector = EntropyDetector(
            threshold=detection.get("entropy_threshold", 4.5),
            min_length=detection.get("min_secret_length", 16),
            max_length=detection.get("max_secret_length", 256),
            enable_context_analysis=detection.get("enable_context_analysis", True),
        ) if detection.get("enable_entropy", True) else None
        self.whitelist = Whitelist(
            custom_rules=detection.get("custom_whitelist")
        )

        perf = config["performance"]
        self.parallel_workers = perf.get("parallel_workers", 0) or os.cpu_count() * 2
        self.parallel_repos = perf.get("parallel_repos", 3)

        scan_cfg = config["scanning"]
        self.scan_extensions = set(scan_cfg.get("scan_extensions", [])) or None
        self.exclude_paths = scan_cfg.get("exclude_paths", [])
        self.include_paths = scan_cfg.get("include_paths", []) or None
        self.max_file_size_mb = scan_cfg.get("max_file_size_mb", 5)
        self.max_commit_depth = scan_cfg.get("max_commit_depth", 100)

    def scan_repo(self, repo_name: str, repo_url: str, org: str, progress: Optional[ScanProgress] = None) -> list[Finding]:
        if progress:
            progress.start_repo(repo_name)

        cache_dir = self.config["performance"].get("cache_dir") if self.config["performance"].get("cache_enabled") else None
        cache_ttl = self.config["performance"].get("cache_ttl_hours", 24)

        try:
            clone_path = shallow_clone(
                url=repo_url,
                depth=self.max_commit_depth,
                cache_dir=cache_dir,
                ttl_hours=cache_ttl,
            )
        except RuntimeError as e:
            if progress:
                progress.fail_repo(repo_name, str(e))
            raise

        try:
            files = walk_files(
                root=clone_path,
                scan_extensions=self.scan_extensions,
                exclude_paths=self.exclude_paths,
                include_paths=self.include_paths if self.include_paths else None,
                max_file_bytes=self.max_file_size_mb * 1024 * 1024,
            )

            if progress:
                progress.set_total_files(repo_name, len(files))

            findings: list[Finding] = []
            for fpath in files:
                rel_path = os.path.relpath(fpath, clone_path)
                file_findings = self._scan_file(fpath, rel_path, repo_name, progress)
                findings.extend(file_findings)
                if progress:
                    progress.inc_file(repo_name)

            if progress:
                progress.complete_repo(repo_name)

            return findings
        except Exception as e:
            if progress:
                progress.fail_repo(repo_name, str(e))
            raise
        finally:
            if not cache_dir:
                cleanup(clone_path)

    def _scan_file(self, fpath: str, rel_path: str, repo_name: str, progress: Optional[ScanProgress] = None) -> list[Finding]:
        findings: list[Finding] = []

        try:
            with open(fpath, "r", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return findings

        for line_num, line in enumerate(lines, start=1):
            line = line.rstrip("\n\r")

            raw_results = []

            if self.regex_detector:
                raw_results.extend(self.regex_detector.scan_line(line, line_num, rel_path, repo_name))

            if self.entropy_detector:
                raw_results.extend(self.entropy_detector.scan_line(line, line_num, rel_path, repo_name))

            if not raw_results:
                continue

            filtered = self.whitelist.filter_findings(raw_results, file_path=rel_path)

            for r in filtered:
                findings.append(Finding(
                    repository=r["repository"],
                    file_path=r["file_path"],
                    line_number=r["line_number"],
                    secret_type=r["secret_type"],
                    detection_method=r["detection_method"],
                    severity=r["severity"],
                    confidence=r.get("confidence", 1.0),
                    value_preview=r.get("full_value", "")[:8] + "***" + r.get("full_value", "")[-8:],
                    full_value=r.get("full_value", ""),
                    context_line=r.get("context_line", ""),
                ))
                if progress:
                    progress.inc_secret(repo_name)

        return findings

    def deduplicate(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str, str]] = set()
        deduped: list[Finding] = []
        for f in findings:
            key = (f.repository, f.file_path, f.full_value)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    def scan_org(self, org: str, repo_filter: str | None = None, progress: Optional[ScanProgress] = None) -> list[Finding]:
        repos = self.client.list_organization_repos(org)

        scanning_config = self.config["scanning"]
        exclude_patterns = scanning_config.get("exclude_repos", [])

        filtered_repos = []
        for r in repos:
            if repo_filter and r.name != repo_filter:
                continue
            if r.is_archived:
                continue
            if any(Path(r.name).match(p) for p in exclude_patterns):
                continue
            filtered_repos.append(r)

        all_findings: list[Finding] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.parallel_repos) as executor:
            future_map = {
                executor.submit(self.scan_repo, r.name, r.clone_url, org, progress): r
                for r in filtered_repos
            }
            for future in concurrent.futures.as_completed(future_map):
                repo = future_map[future]
                try:
                    repo_findings = future.result()
                    all_findings.extend(repo_findings)
                except Exception as e:
                    pass

        all_findings = self.deduplicate(all_findings)
        return all_findings
