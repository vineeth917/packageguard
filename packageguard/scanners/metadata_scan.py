"""
Metadata analysis scanner.

Fetches package metadata from PyPI and GitHub and turns real provenance
signals into findings that the UI can render consistently.
"""

import logging
import re
from datetime import datetime, timezone

import httpx

from packageguard import Finding
from packageguard.config import config

logger = logging.getLogger(__name__)

PYPI_TIMEOUT = 15
GITHUB_ACCEPT = "application/vnd.github+json"


async def scan_metadata(package_name: str, version: str = None) -> list[Finding]:
    """Fetch PyPI metadata and derive trust signals from real package metadata."""
    findings: list[Finding] = []
    data = await _fetch_pypi_metadata(package_name, version)
    package_level = await _fetch_pypi_metadata(package_name, None)
    if data is None:
        return [
            Finding(
                severity="high",
                category="suspicious_metadata",
                description=f"Package '{package_name}' not found on PyPI",
            )
        ]

    info = data.get("info", {})
    releases = (package_level or data).get("releases", {}) or {}
    actual_version = version or info.get("version", "unknown")
    author = info.get("author", "") or info.get("maintainer", "")
    author_email = info.get("author_email", "") or info.get("maintainer_email", "")
    license_info = info.get("license", "") or ""
    classifiers = info.get("classifiers", []) or []
    description = (info.get("description", "") or "").strip()

    if description:
        findings.append(Finding(
            severity="info",
            category="suspicious_metadata",
            description="Package description is present on PyPI",
        ))
    else:
        findings.append(Finding(
            severity="medium",
            category="suspicious_metadata",
            description="Package description is empty on PyPI",
        ))

    if author or author_email:
        maintainer_bits = ", ".join(part for part in (author, author_email) if part)
        findings.append(Finding(
            severity="info",
            category="suspicious_metadata",
            description=f"Maintainer metadata present: {maintainer_bits}",
        ))
    else:
        findings.append(Finding(
            severity="medium",
            category="suspicious_metadata",
            description="Package has no author or maintainer metadata listed",
        ))

    if license_info or any("License" in classifier for classifier in classifiers):
        findings.append(Finding(
            severity="info",
            category="suspicious_metadata",
            description=f"License metadata present: {license_info or 'classifier-defined'}",
        ))
    else:
        findings.append(Finding(
            severity="low",
            category="suspicious_metadata",
            description="Package has no license specified",
        ))

    release_count = len(releases)
    if release_count <= 1:
        findings.append(Finding(
            severity="high",
            category="suspicious_metadata",
            description=f"Package has only {release_count} published release",
        ))
    elif release_count < 5:
        findings.append(Finding(
            severity="medium",
            category="suspicious_metadata",
            description=f"Package has only {release_count} published releases",
        ))
    else:
        findings.append(Finding(
            severity="info",
            category="suspicious_metadata",
            description=f"Package has {release_count} published releases on PyPI",
        ))

    github = _extract_github_repo(info)
    if not github:
        findings.append(Finding(
            severity="high",
            category="version_mismatch",
            description="No GitHub repository linked in PyPI metadata",
        ))
        return findings

    repo_data = await _fetch_github_repo(*github)
    if repo_data is None:
        findings.append(Finding(
            severity="medium",
            category="suspicious_metadata",
            description=f"Could not fetch GitHub metadata for {github[0]}/{github[1]}",
        ))
        return findings

    findings.extend(_build_repo_findings(repo_data))
    findings.extend(await _check_github_tag(*github, actual_version))
    return findings


async def _fetch_pypi_metadata(package_name: str, version: str | None) -> dict | None:
    url = f"{config.PYPI_API_URL}/{package_name}/{version}/json" if version else f"{config.PYPI_API_URL}/{package_name}/json"
    async with httpx.AsyncClient(timeout=PYPI_TIMEOUT) as client:
        try:
            resp = await client.get(url)
        except httpx.RequestError as exc:
            logger.error("Failed to fetch PyPI metadata for %s: %s", package_name, exc)
            return None
    if resp.status_code != 200:
        logger.warning("PyPI metadata request for %s returned %s", package_name, resp.status_code)
        return None
    return resp.json()


def _extract_github_repo(info: dict) -> tuple[str, str] | None:
    project_urls = info.get("project_urls") or {}
    homepage = project_urls.get("Homepage") or info.get("home_page") or ""
    urls = [homepage, *project_urls.values()]
    for url in urls:
        match = re.search(r"github\.com/([^/]+)/([^/\s#?]+)", url or "", re.IGNORECASE)
        if match:
            return match.group(1), match.group(2).removesuffix(".git")
    return None


async def _fetch_github_repo(owner: str, repo: str) -> dict | None:
    url = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {"Accept": GITHUB_ACCEPT}
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(url, headers=headers)
        except httpx.RequestError as exc:
            logger.warning("GitHub repo lookup failed for %s/%s: %s", owner, repo, exc)
            return None
    if resp.status_code != 200:
        logger.warning("GitHub repo lookup returned %s for %s/%s", resp.status_code, owner, repo)
        return None
    return resp.json()


def _build_repo_findings(repo_data: dict) -> list[Finding]:
    findings: list[Finding] = []
    owner_repo = repo_data.get("full_name", "unknown/unknown")
    stars = int(repo_data.get("stargazers_count", 0) or 0)
    forks = int(repo_data.get("forks_count", 0) or 0)
    issues = int(repo_data.get("open_issues_count", 0) or 0)
    created_at = _parse_iso_datetime(repo_data.get("created_at"))
    updated_at = _parse_iso_datetime(repo_data.get("updated_at"))

    findings.append(Finding(
        severity="info",
        category="suspicious_metadata",
        description=f"GitHub repo {owner_repo}: {stars} stars, {forks} forks, {issues} open issues",
    ))

    if stars > 10000:
        findings.append(Finding(
            severity="info",
            category="suspicious_metadata",
            description=f"Highly trusted package with {stars} GitHub stars",
        ))
    elif stars > 1000:
        findings.append(Finding(
            severity="info",
            category="suspicious_metadata",
            description=f"Well-maintained package with {stars} GitHub stars",
        ))
    elif stars < 50:
        findings.append(Finding(
            severity="medium",
            category="suspicious_metadata",
            description=f"GitHub repository has limited community adoption ({stars} stars)",
        ))

    if created_at:
        age_days = (datetime.now(timezone.utc) - created_at).days
        if age_days < 30:
            findings.append(Finding(
                severity="medium",
                category="suspicious_metadata",
                description="Package source repository was created very recently",
            ))
        else:
            findings.append(Finding(
                severity="info",
                category="suspicious_metadata",
                description=f"Repository has existed since {created_at.year}",
            ))

    if updated_at:
        findings.append(Finding(
            severity="info",
            category="suspicious_metadata",
            description=f"Repository was updated recently on {updated_at.date().isoformat()}",
        ))

    return findings


async def _check_github_tag(owner: str, repo: str, version: str) -> list[Finding]:
    """Check whether a matching tag exists on GitHub for the scanned version."""
    url = f"https://api.github.com/repos/{owner}/{repo}/tags"
    headers = {"Accept": GITHUB_ACCEPT}
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.get(url, headers=headers)
        except httpx.RequestError as exc:
            logger.warning("GitHub tags lookup failed for %s/%s: %s", owner, repo, exc)
            return []
    if resp.status_code != 200:
        return []

    tags = resp.json()
    tag_names = {tag.get("name", "") for tag in tags if tag.get("name")}
    version_tags = {version, f"v{version}", f"V{version}", f"release-{version}"}
    if version_tags & tag_names:
        return [Finding(
            severity="info",
            category="version_mismatch",
            description=f"GitHub tag found for version {version}",
        )]
    return [Finding(
        severity="high",
        category="version_mismatch",
        description=f"No matching GitHub tag for this version ({version})",
    )]


def _parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
