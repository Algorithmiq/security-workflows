# /// script
# requires-python = ">=3.13"
# dependencies = []
# ///
"""Check the packages locked in the uv.lock and Cargo.lock files of the repository against OSV.

Each Python package from a package index, and each Rust crate from crates.io, is looked up by
name and version in the OSV database (https://osv.dev), which is all that leaves the runner.
A finding blocks the merge when it is in a runtime dependency and its severity is high or
critical, or unknown, unless .github/vulnerability-exceptions.toml lists it. The severity is
GitHub's, from the GHSA records that OSV mirrors. Findings in packages that only dependency
groups (dev, test, docs, …) need, and informational RustSec notices (unmaintained, unsound,
notice) that have no GitHub severity, are reported without blocking.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

OSV = "https://api.osv.dev/v1"
# the `source` of the crates of crates.io in Cargo.lock: the git index, and the sparse one
CRATES_IO_SOURCES = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
}
# OSV answers at most this many queries per batch
BATCH = 1000


class ScanError(Exception):
    """A problem that stops the scan, as opposed to a finding."""


@dataclass
class Approval:
    id: str
    issue: str
    reason: str
    used: bool = False


# the start of the severity of an informational notice, for example "informational: unmaintained"
INFORMATIONAL = "informational"


@dataclass
class Finding:
    lock: str
    package: str
    version: str
    id: str
    aliases: list[str]
    summary: str
    fix_versions: list[str]
    runtime: bool = True
    severity: str = "unknown"
    # RustSec's kind of a notice that isn't a vulnerability: unmaintained, unsound or notice
    informational: str | None = None
    withdrawn: bool = False
    exception: Approval | None = None

    @property
    def ids(self) -> set[str]:
        return {self.id, *self.aliases}

    @property
    def ghsa(self) -> str | None:
        return next((i for i in [self.id, *self.aliases] if i.startswith("GHSA-")), None)

    @property
    def blocking(self) -> bool:
        if not self.runtime or self.withdrawn or self.exception is not None:
            return False
        if self.severity.startswith(INFORMATIONAL):
            return False
        return self.severity not in {"low", "moderate", "medium"}


@dataclass(frozen=True)
class Package:
    lock: str
    name: str
    version: str
    runtime: bool = True
    # OSV's name of the ecosystem: PyPI for uv.lock, crates.io for Cargo.lock
    ecosystem: str = "PyPI"


@dataclass
class Osv:
    """OSV's API: the batch query, and the full records, read once each."""

    post: Callable[[str, dict], dict]
    get: Callable[[str], dict]
    records: dict[str, dict] = field(default_factory=dict)

    def vulnerabilities(self, packages: list[Package]) -> list[list[str]]:
        """The ids of the vulnerabilities of each package, in the order of PACKAGES."""
        ids: list[list[str]] = [[] for _ in packages]
        pending = [(index, None) for index in range(len(packages))]
        while pending:
            batch, pending = pending[:BATCH], pending[BATCH:]
            queries = [
                {
                    "package": {"name": packages[i].name, "ecosystem": packages[i].ecosystem},
                    "version": packages[i].version,
                    **({"page_token": token} if token else {}),
                }
                for i, token in batch
            ]
            results = self.post(f"{OSV}/querybatch", {"queries": queries})["results"]
            for (index, _), result in zip(batch, results, strict=True):
                ids[index] += [vuln["id"] for vuln in result.get("vulns", [])]
                if result.get("next_page_token"):
                    pending.append((index, result["next_page_token"]))
        return ids

    def record(self, id: str) -> dict:
        if id not in self.records:
            self.records[id] = self.get(f"{OSV}/vulns/{id}")
        return self.records[id]

    def prefetch(self, ids: set[str]) -> None:
        missing = sorted(ids - set(self.records))
        with ThreadPoolExecutor(max_workers=8) as pool:
            for id, record in zip(missing, pool.map(self.record, missing), strict=True):
                self.records[id] = record


def http_get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.load(response)


def http_post(url: str, body: dict) -> dict:
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


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
    """The uv.lock and Cargo.lock files tracked by git, so generated or ignored ones don't count."""
    output = subprocess.run(
        ["git", "ls-files", "-z", "--", "uv.lock", "*/uv.lock", "Cargo.lock", "*/Cargo.lock"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return sorted(root / name for name in output.split("\0") if name)


def runtime_packages(packages: list[dict]) -> set[tuple[str, str | None]] | None:
    """The (name, version) of the packages that the projects of a lock need at run time.

    The walk starts from the projects (editable or virtual sources) with their extras, and
    follows the dependencies, and the extras they ask for, but not the dependency groups.
    Without a project, it returns None: every package counts as a runtime dependency.
    """
    by_name: dict[str, list[dict]] = defaultdict(list)
    for package in packages:
        by_name[package["name"]].append(package)
    roots = [p for p in packages if {"editable", "virtual"} & set(p.get("source", {}))]
    if not roots:
        return None
    pending = [(p, extra) for p in roots for extra in [None, *p.get("optional-dependencies", {})]]
    seen: set[tuple[str, str | None, str | None]] = set()
    while pending:
        package, extra = pending.pop()
        key = (package["name"], package.get("version"), extra)
        if key in seen:
            continue
        seen.add(key)
        if extra is None:
            dependencies = package.get("dependencies", [])
        else:
            dependencies = package.get("optional-dependencies", {}).get(extra, [])
        for dependency in dependencies:
            for target in by_name[dependency["name"]]:
                # with several versions locked, the dependency names the one it uses
                if dependency.get("version", target.get("version")) != target.get("version"):
                    continue
                pending += [(target, x) for x in [None, *dependency.get("extra", [])]]
    return {(name, version) for name, version, _ in seen}


def read_lock(lock: Path, root: Path) -> dict:
    try:
        return tomllib.loads(lock.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as error:
        raise ScanError(f"{lock.relative_to(root)} is not valid TOML: {error}") from error


def locked_packages(lock: Path, root: Path) -> list[Package]:
    """The packages of LOCK, a uv.lock or a Cargo.lock, that OSV can look up."""
    if lock.name == "Cargo.lock":
        return locked_crates(lock, root)
    return locked_python_packages(lock, root)


def locked_crates(lock: Path, root: Path) -> list[Package]:
    """The crates of the Cargo.lock LOCK that come from crates.io, with their versions.

    The packages of the workspace have no source, and the crates from git, a path or another
    registry may not be on crates.io: they're left out, and their names aren't sent. Version 3
    and 4 of the lock have the same `[[package]]` tables with name, version and source.

    Cargo.lock doesn't say which crates only the development or the build need (that depends
    on the dependency kinds and features, which only cargo resolves), so every crate counts as
    a runtime dependency.
    """
    name = str(lock.relative_to(root))
    return sorted(
        {
            Package(name, package["name"], package["version"], ecosystem="crates.io")
            for package in read_lock(lock, root).get("package", [])
            if package.get("source") in CRATES_IO_SOURCES and "version" in package
        },
        key=lambda p: (p.name, p.version),
    )


def locked_python_packages(lock: Path, root: Path) -> list[Package]:
    """The packages of the uv.lock LOCK that come from a package index, with their versions.

    The project itself and the packages from git, a URL or a local path have no version on
    PyPI to look up, so they're left out.
    """
    data = read_lock(lock, root)
    name = str(lock.relative_to(root))
    runtime = runtime_packages(data.get("package", []))
    return sorted(
        {
            Package(
                name,
                package["name"],
                package["version"],
                runtime is None or (package["name"], package["version"]) in runtime,
            )
            for package in data.get("package", [])
            if "registry" in package.get("source", {}) and "version" in package
        },
        key=lambda p: (p.name, p.version),
    )


def normalize(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def affected_entries(record: dict, package: Package) -> list[dict]:
    """The `affected` entries of RECORD that are about PACKAGE.

    Python names are compared as PEP 503 does, with the case and the separators ignored. Crate
    names are exact: cargo tells `foo-bar` and `foo_bar` apart, and so does OSV.
    """

    def same(name: str) -> bool:
        if package.ecosystem == "crates.io":
            return name == package.name
        return normalize(name) == normalize(package.name)

    return [
        affected
        for affected in record.get("affected", [])
        if affected.get("package", {}).get("ecosystem") == package.ecosystem
        and same(affected.get("package", {}).get("name", ""))
    ]


def fix_versions(record: dict, package: Package) -> list[str]:
    """The versions that fix RECORD for PACKAGE, from its affected ranges."""
    return sorted(
        {
            event["fixed"]
            for affected in affected_entries(record, package)
            for range_ in affected.get("ranges", [])
            for event in range_.get("events", [])
            if "fixed" in event
        }
    )


def informational_kind(record: dict, package: Package) -> str | None:
    """RustSec's kind of RECORD for PACKAGE (unmaintained, unsound, notice), if it has one.

    RustSec marks the advisories that aren't about a vulnerability in
    `affected[].database_specific.informational`, which is null for the others.
    """
    return next(
        (
            kind
            for affected in affected_entries(record, package)
            if (kind := (affected.get("database_specific") or {}).get("informational"))
        ),
        None,
    )


def find(packages: list[Package], osv: Osv) -> list[Finding]:
    """The vulnerabilities of PACKAGES, one finding per vulnerability and package.

    OSV lists a vulnerability once per database (GHSA, PYSEC, …), the records naming each
    other as aliases: the GHSA record is kept, as it has the severity.
    """
    ids = osv.vulnerabilities(packages)
    osv.prefetch({i for found in ids for i in found})
    findings = []
    for package, found in zip(packages, ids, strict=True):
        seen: set[str] = set()
        for id in sorted(found, key=lambda i: (not i.startswith("GHSA-"), i)):
            record = osv.record(id)
            aliases = [a for a in record.get("aliases", []) if a != id]
            if seen & {id, *aliases}:
                continue
            seen |= {id, *aliases}
            findings.append(
                Finding(
                    lock=package.lock,
                    package=package.name,
                    version=package.version,
                    runtime=package.runtime,
                    id=id,
                    aliases=aliases,
                    summary=record.get("summary") or record.get("details", "").split("\n")[0],
                    fix_versions=fix_versions(record, package),
                    informational=informational_kind(record, package),
                    withdrawn=record.get("withdrawn") is not None,
                )
            )
    return findings


def classify(findings: list[Finding], exceptions: list[Approval], osv: Osv) -> None:
    """Fill in the severity and the exception of each finding.

    The severity is GitHub's, from the GHSA record. A RustSec advisory that isn't about a
    vulnerability has no GHSA record: its severity is its informational kind, and it doesn't
    block. A RustSec vulnerability without a GHSA record has an unknown severity, which blocks.
    """
    for finding in findings:
        if finding.ghsa is None:
            if finding.informational:
                finding.severity = f"{INFORMATIONAL}: {finding.informational}"
        else:
            try:
                record = osv.record(finding.ghsa)
            except (urllib.error.URLError, TimeoutError, ValueError) as error:
                print(f"::warning::Could not read {finding.ghsa}: {error}")
            else:
                severity = (record.get("database_specific") or {}).get("severity")
                finding.severity = (severity or "unknown").lower()
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


def report(findings: list[Finding], exceptions: list[Approval], locks: list[str]) -> str:
    """The job summary, in Markdown."""
    blocking = [f for f in findings if f.blocking]
    python = [lock for lock in locks if Path(lock).name != "Cargo.lock"]
    rust = [lock for lock in locks if Path(lock).name == "Cargo.lock"]
    checked = [
        f"the Python packages of {', '.join(f'`{lock}`' for lock in python)}" if python else "",
        f"the Rust crates of {', '.join(f'`{lock}`' for lock in rust)}" if rust else "",
    ]
    lines = ["## Dependency scan", ""]
    lines.append(f"Checked {' and '.join(c for c in checked if c)} against OSV.")
    lines.append("")
    if rust:
        lines += [
            (
                "`Cargo.lock` doesn't say which crates only the development or the build need, "
                "so every crate counts as a runtime dependency."
            ),
            "",
        ]
    if not findings:
        lines.append("No known vulnerabilities.")
    else:
        lines.append(
            f"{len(findings)} finding(s), {len(blocking)} blocking: in a runtime dependency, "
            "high, critical or of unknown severity, and not in "
            "`.github/vulnerability-exceptions.toml`. Findings in packages that only the "
            "dependency groups need (dev, test, docs, …) don't block, and neither do the "
            "informational notices of RustSec (unmaintained, unsound, notice)."
        )
        lines += [
            "",
            "| | Package | Needed at | Advisory | Severity | Fixed in | Summary |",
            "|---|---|---|---|---|---|---|",
        ]
        order = {"critical": 0, "high": 1, "unknown": 2, "moderate": 3, "medium": 3, "low": 4}

        def key(f: Finding) -> tuple:
            if f.severity.startswith(INFORMATIONAL):
                return (not f.blocking, 5, f.package)
            return (not f.blocking, order.get(f.severity, 2), f.package)

        for f in sorted(findings, key=key):
            if f.blocking:
                status = "❌ blocking"
            elif f.withdrawn:
                status = "withdrawn"
            elif f.exception is not None:
                status = f"[excepted]({f.exception.issue})"
            else:
                status = "reported"
            link = f"[{f.id}](https://osv.dev/vulnerability/{f.id})"
            fixed = cell(", ".join(f.fix_versions) or "no fix yet")
            needed = "run time" if f.runtime else "development"
            lines.append(
                f"| {status} | {cell(f.package)} {cell(f.version)} (`{f.lock}`) | {needed} | "
                f"{link} | {f.severity} | {fixed} | {cell(f.summary)} |"
            )
    unused = [e for e in exceptions if not e.used]
    if unused:
        lines += ["", "Exceptions that match no finding any more (remove them):", ""]
        lines += [f"- `{e.id}` ({e.issue})" for e in unused]
    return "\n".join(lines) + "\n"


def main(osv: Osv | None = None) -> int:
    root = Path.cwd()
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    locks = lock_files(root)
    if not locks:
        print(
            "::notice title=Dependency scan::No uv.lock or Cargo.lock in this repository: "
            "nothing to scan."
        )
        if summary:
            Path(summary).write_text(
                "## Dependency scan\n\nNo `uv.lock` or `Cargo.lock`: nothing to scan.\n"
            )
        return 0
    osv = osv or Osv(post=http_post, get=http_get)
    exceptions_file = os.environ.get("EXCEPTIONS_FILE", ".github/vulnerability-exceptions.toml")
    try:
        exceptions = load_exceptions(root / exceptions_file)
        packages = [package for lock in locks for package in locked_packages(lock, root)]
        findings = find(packages, osv)
    except ScanError as error:
        print(f"::error title=Dependency scan::{command(str(error))}")
        return 1
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as error:
        print(f"::error title=Dependency scan::OSV could not be read: {command(str(error))}")
        return 1
    classify(findings, exceptions, osv)
    text = report(findings, exceptions, [str(lock.relative_to(root)) for lock in locks])
    print(text)
    if summary:
        Path(summary).write_text(text)
    for f in findings:
        if f.blocking:
            fix = f"fixed in {', '.join(f.fix_versions)}" if f.fix_versions else "no fix yet"
            print(
                f"::error file={f.lock},title={f.severity} vulnerability in {f.package}::"
                + command(f"{f.package} {f.version}: {f.id} ({fix}). {f.summary}")
            )
    for e in exceptions:
        if not e.used:
            print(
                f"::warning title=Unused exception::{e.id} matches no finding: remove it ({e.issue})"
            )
    return 1 if any(f.blocking for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
