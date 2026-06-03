from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import requests


@dataclass
class Repository:
    name: str
    full_name: str
    url: str
    clone_url: str
    is_private: bool
    is_archived: bool
    is_fork: bool
    size_kb: int
    default_branch: str


class GitHubClient:
    def __init__(
        self,
        token: str,
        base_url: str = "https://api.github.com",
        timeout: int = 30,
        max_retries: int = 3,
        requests_per_second: int = 10,
    ):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "deep-scout-github/1.0.0",
        })
        self.timeout = timeout
        self.max_retries = max_retries
        self.rate_limit_remaining = 0
        self.rate_limit_reset = 0
        self._min_interval = 1.0 / requests_per_second
        self._last_request = 0.0

    def _throttle(self):
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()

    def _handle_rate_limits(self, response: requests.Response):
        self.rate_limit_remaining = int(response.headers.get("X-RateLimit-Remaining", 0))
        self.rate_limit_reset = int(response.headers.get("X-RateLimit-Reset", 0))

        if self.rate_limit_remaining == 0 and self.rate_limit_reset > 0:
            sleep_time = max(self.rate_limit_reset - time.time(), 0) + 1
            time.sleep(sleep_time)

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{path}" if path.startswith("/") else path
        for attempt in range(self.max_retries):
            self._throttle()
            try:
                resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
                self._handle_rate_limits(resp)
                if resp.status_code == 403 and self.rate_limit_remaining == 0:
                    continue
                if resp.status_code >= 500 and attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                resp.raise_for_status()
                return resp
            except requests.RequestException as e:
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(2 ** attempt)
        raise RuntimeError("Unreachable")

    def get(self, path: str, **kwargs) -> requests.Response:
        return self._request("GET", path, **kwargs)

    def get_paginated(self, path: str, per_page: int = 100, **kwargs) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        page = 1
        while True:
            resp = self.get(path, params={"per_page": per_page, "page": page, **kwargs.get("params", {})})
            data = resp.json()
            if not isinstance(data, list):
                results.append(data)
                break
            results.extend(data)
            if len(data) < per_page:
                break
            page += 1
        return results

    def list_organization_repos(self, org: str) -> list[Repository]:
        data = self.get_paginated(f"/orgs/{org}/repos", type="all", sort="full_name")
        repos = []
        for item in data:
            repos.append(Repository(
                name=item["name"],
                full_name=item["full_name"],
                url=item["html_url"],
                clone_url=item["clone_url"],
                is_private=item["private"],
                is_archived=item.get("archived", False),
                is_fork=item["fork"],
                size_kb=item["size"],
                default_branch=item.get("default_branch", "main"),
            ))
        return repos

    def get_repo(self, org: str, repo: str) -> Repository:
        resp = self.get(f"/repos/{org}/{repo}")
        item = resp.json()
        return Repository(
            name=item["name"],
            full_name=item["full_name"],
            url=item["html_url"],
            clone_url=item["clone_url"],
            is_private=item["private"],
            is_archived=item.get("archived", False),
            is_fork=item["fork"],
            size_kb=item["size"],
            default_branch=item.get("default_branch", "main"),
        )

    def check_rate_limit(self) -> tuple[int, int]:
        resp = self.get("/rate_limit")
        data = resp.json()
        core = data["resources"]["core"]
        return core["remaining"], core["reset"]
