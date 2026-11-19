# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///
"""Scan the uv.lock files of the repository with `uv audit`.

A finding blocks the merge when its advisory is high or critical, or when its
severity can't be found, unless .github/vulnerability-exceptions.toml lists it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

BLOCKING = {"critical", "high"}
AUDIT = [
    "uv",
    "audit",
    "--frozen",
    "--preview-features",
    "audit-command,json-output",
    "--output-format",
    "json",
]


class ScanError(Exception):
    """A problem that stops the scan, as opposed to a finding."""


@dataclass
class Approval:
    id: str
    issue: str
    reason: str
    used: bool = False


@dataclass
class Finding:
    lock: str
    package: str
    version: str
    id: str
    aliases: list[str]
    summary: str
    fix_versions: list[str]
    ghsa: str | None = None
    severity: str = "unknown"
    withdrawn: bool = False
    exception: Approval | None = None
    ids: set[str] = field(default_factory=set)

    @property
    def blocking(self) -> bool:
        if self.withdrawn or self.exception is not None:
            return False
        return self.severity not in {"low", "medium", "moderate"}


def load_exceptions(path: Path) -> list[Approval]:
    """Read the approved exceptions: an `[[exception]]` table per vulnerability."""
    if not path.is_file():
        return []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise ScanError(f"{path} is not valid TOML: {error}") from error
    unknown = set(data) - {"exception"}
    if unknown:
        raise ScanError(f"{path}: unknown keys {sorted(unknown)}, only [[exception]] tables")
    exceptions = []
    for number, entry in enumerate(data.get("exception", []), start=1):
        where = f"{path}, exception {number}"
        if not isinstance(entry, dict):
            raise ScanError(f"{where}: must be an [[exception]] table")
        extra = set(entry) - {"id", "issue", "reason"}
        if extra:
            raise ScanError(f"{where}: unknown keys {sorted(extra)}")
        for key in ("id", "issue", "reason"):
            value = entry.get(key)
            if not isinstance(value, str) or not value.strip():
                raise ScanError(f"{where}: `{key}` is required and can't be empty")
        if not entry["issue"].startswith("https://"):
            raise ScanError(f"{where}: `issue` must be the link to the issue that approves it")
        exceptions.append(Approval(entry["id"].strip(), entry["issue"], entry["reason"]))
    return exceptions


def lock_files(root: Path) -> list[Path]:
    """The uv.lock files tracked by git, so generated or ignored ones don't count."""
    output = subprocess.run(
        ["git", "ls-files", "-z", "--", "uv.lock", "*/uv.lock"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return sorted(root / name for name in output.split("\0") if name)


def audit(lock: Path, root: Path) -> tuple[list[Finding], list[dict]]:
    """Run `uv audit` next to LOCK and return its findings and adverse statuses."""
    result = subprocess.run(AUDIT, cwd=lock.parent, capture_output=True, text=True, check=False)
    # uv exits with 1 both for findings and for errors: the JSON tells them apart
    try:
        report = json.loads(result.stdout)
        vulnerabilities = report["vulnerabilities"]
    except (json.JSONDecodeError, KeyError, TypeError):
        raise ScanError(
            f"`uv audit` failed for {lock.relative_to(root)}:\n{result.stderr.strip()}"
        ) from None
    name = str(lock.relative_to(root))
    findings = [
        Finding(
            lock=name,
            package=item["dependency"]["name"],
            version=item["dependency"]["version"],
            id=item["id"],
            aliases=list(item.get("aliases") or []),
            summary=item.get("summary") or "",
            fix_versions=list(item.get("fix_versions") or []),
        )
        for item in vulnerabilities
    ]
    return findings, list(report.get("adverse_statuses") or [])


def fetch_advisory(ghsa: str) -> dict:
    """Read one advisory from GitHub's database."""
    request = urllib.request.Request(
        f"https://api.github.com/advisories/{ghsa}",
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            **(
                {"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}"}
                if os.environ.get("GITHUB_TOKEN")
                else {}
            ),
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def classify(findings: list[Finding], exceptions: list[Approval], fetch=fetch_advisory) -> None:
    """Fill in the severity and the exception of each finding."""
    cache: dict[str, dict | None] = {}
    for finding in findings:
        finding.ids = {finding.id, *finding.aliases}
        finding.ghsa = next(
            (i for i in [finding.id, *finding.aliases] if i.startswith("GHSA-")), None
        )
        if finding.ghsa is not None:
            if finding.ghsa not in cache:
                try:
                    cache[finding.ghsa] = fetch(finding.ghsa)
                except (urllib.error.URLError, TimeoutError, ValueError) as error:
                    print(f"::warning::Could not read {finding.ghsa}: {error}")
                    cache[finding.ghsa] = None
            advisory = cache[finding.ghsa]
            if advisory is not None:
                finding.severity = (advisory.get("severity") or "unknown").lower()
                finding.withdrawn = advisory.get("withdrawn_at") is not None
        for exception in exceptions:
            if exception.id in finding.ids:
                finding.exception = exception
                exception.used = True
                break


def command(text: str) -> str:
    """Escape TEXT for the message of a workflow command (::error:: and the like)."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def report(
    findings: list[Finding], exceptions: list[Approval], statuses: list[str], locks: list[str]
) -> str:
    """The job summary, in Markdown."""
    blocking = [f for f in findings if f.blocking]
    lines = ["## Dependency scan", ""]
    lines.append(f"Scanned {', '.join(f'`{lock}`' for lock in locks)} with `uv audit`.")
    lines.append("")
    if not findings:
        lines.append("No known vulnerabilities.")
    else:
        lines.append(
            f"{len(findings)} finding(s), {len(blocking)} blocking: high, critical or of "
            "unknown severity, and not in `.github/vulnerability-exceptions.toml`."
        )
        lines += [
            "",
            "| | Package | Advisory | Severity | Fixed in | Summary |",
            "|---|---|---|---|---|---|",
        ]
        order = {"critical": 0, "high": 1, "unknown": 2, "moderate": 3, "medium": 3, "low": 4}
        for f in sorted(
            findings, key=lambda f: (not f.blocking, order.get(f.severity, 2), f.package)
        ):
            if f.blocking:
                status = "❌ blocking"
            elif f.withdrawn:
                status = "withdrawn"
            elif f.exception is not None:
                status = f"[excepted]({f.exception.issue})"
            else:
                status = "reported"
            advisory = f.ghsa or f.id
            link = f"[{advisory}](https://github.com/advisories/{advisory})" if f.ghsa else advisory
            lines.append(
                f"| {status} | {cell(f.package)} {cell(f.version)} (`{f.lock}`) | {link} | "
                f"{f.severity} | {cell(', '.join(f.fix_versions) or 'no fix yet')} | {cell(f.summary)} |"
            )
    unused = [e for e in exceptions if not e.used]
    if unused:
        lines += ["", "Exceptions that match no finding any more (remove them):", ""]
        lines += [f"- `{e.id}` ({e.issue})" for e in unused]
    if statuses:
        lines += ["", "Other problems that `uv audit` reports (not blocking):", ""]
        lines += [f"- {cell(s)}" for s in statuses]
    return "\n".join(lines) + "\n"


def main() -> int:
    root = Path.cwd()
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    locks = lock_files(root)
    if not locks:
        print("::notice title=Dependency scan::No uv.lock in this repository: nothing to scan.")
        if summary:
            Path(summary).write_text("## Dependency scan\n\nNo `uv.lock`: nothing to scan.\n")
        return 0
    try:
        exceptions = load_exceptions(
            root / os.environ.get("EXCEPTIONS_FILE", ".github/vulnerability-exceptions.toml")
        )
        findings, statuses = [], []
        for lock in locks:
            found, adverse = audit(lock, root)
            findings += found
            statuses += [f"`{lock.relative_to(root)}`: {json.dumps(s)}" for s in adverse]
    except ScanError as error:
        print(f"::error title=Dependency scan::{command(str(error))}")
        return 1
    classify(findings, exceptions)
    text = report(findings, exceptions, statuses, [str(lock.relative_to(root)) for lock in locks])
    print(text)
    if summary:
        Path(summary).write_text(text)
    for f in findings:
        if f.blocking:
            fix = f"fixed in {', '.join(f.fix_versions)}" if f.fix_versions else "no fix yet"
            print(
                f"::error file={f.lock},title={f.severity} vulnerability in {f.package}::"
                + command(f"{f.package} {f.version}: {f.ghsa or f.id} ({fix}). {f.summary}")
            )
    for e in exceptions:
        if not e.used:
            print(
                f"::warning title=Unused exception::{e.id} matches no finding: remove it ({e.issue})"
            )
    return 1 if any(f.blocking for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
