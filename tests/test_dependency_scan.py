"""Tests of scripts/dependency_scan.py, the scan of .github/workflows/dependency-scan.yml.

Run with: uv run --no-project --with pytest --with pyyaml pytest
The end-to-end tests need the network (PyPI and OSV).
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import textwrap
import urllib.error
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "dependency-scan.yml"
SCRIPT = ROOT / "scripts" / "dependency_scan.py"


@pytest.fixture(scope="session")
def script() -> Path:
    return SCRIPT


def test_the_workflow_runs_the_script() -> None:
    """The workflow checks out this repository's scripts/ and runs the scan from there."""
    steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["scan"]["steps"]
    own = next(
        s for s in steps if s.get("with", {}).get("repository") == "${{ job.workflow_repository }}"
    )
    assert own["with"]["ref"] == "${{ job.workflow_sha }}"
    path = own["with"]["path"]
    run = steps[-1]["run"]
    assert run.endswith(f"{path}/{SCRIPT.relative_to(ROOT)}")


@pytest.fixture(scope="session")
def scan(script: Path):
    spec = importlib.util.spec_from_file_location("dependency_scan", script)
    module = importlib.util.module_from_spec(spec)
    sys.modules["dependency_scan"] = module
    spec.loader.exec_module(module)
    return module


# --- the exceptions file ---------------------------------------------------------------


def write(path: Path, text: str) -> Path:
    path.write_text(textwrap.dedent(text), encoding="utf-8")
    return path


def test_no_exceptions_file(scan, tmp_path: Path) -> None:
    assert scan.load_exceptions(tmp_path / "missing.toml") == []


def test_exceptions_are_read(scan, tmp_path: Path) -> None:
    path = write(
        tmp_path / "e.toml",
        """
        [[exception]]
        id = "GHSA-aaaa-bbbb-cccc"
        issue = "https://github.com/example/project/issues/1"
        reason = "Only the test suite imports it."
        """,
    )
    [approval] = scan.load_exceptions(path)
    assert approval.id == "GHSA-aaaa-bbbb-cccc"
    assert approval.issue.endswith("/issues/1")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('[[exception]]\nid = "X"\nissue = "https://e/1"\n', "`reason` is required"),
        (
            '[[exception]]\nid = ""\nissue = "https://e/1"\nreason = "r"\n',
            "`id` is required",
        ),
        ('[[exception]]\nid = "X"\nissue = "#1"\nreason = "r"\n', "link to the issue"),
        (
            '[[exception]]\nid = "X"\nissue = "https://e/1"\nreason = "r"\nuntil = "x"\n',
            "unknown keys",
        ),
        ('[[exceptions]]\nid = "X"\n', "unknown keys"),
        ("[[exception]\n", "not valid TOML"),
    ],
)
def test_invalid_exceptions(scan, tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(scan.ScanError, match=message):
        scan.load_exceptions(write(tmp_path / "e.toml", text))


# --- which findings block ---------------------------------------------------------------


def osv_record(id: str, aliases: list[str], severity: str | None = None, **extra) -> dict:
    record = {
        "id": id,
        "aliases": aliases,
        "summary": f"Summary of {id}",
        "affected": [
            {
                "package": {"name": "Pkg", "ecosystem": "PyPI"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1"}]}
                ],
            }
        ],
        **extra,
    }
    if severity:
        record["database_specific"] = {"severity": severity}
    return record


RECORDS = {
    r["id"]: r
    for r in [
        osv_record("GHSA-crit-crit-crit", [], "CRITICAL"),
        osv_record("GHSA-high-high-high", ["PYSEC-2020-1"], "HIGH"),
        osv_record("PYSEC-2020-1", ["GHSA-high-high-high"]),
        osv_record("GHSA-medi-medi-medi", [], "MODERATE"),
        osv_record("GHSA-loww-loww-loww", [], "LOW"),
        osv_record("PYSEC-2021-2", ["CVE-2021-2"]),
        osv_record("PYSEC-2021-3", ["GHSA-only-alia-sed1"]),
        osv_record("GHSA-only-alia-sed1", ["PYSEC-2021-3"], "MODERATE"),
        osv_record("GHSA-gone-gone-gone", [], "CRITICAL", withdrawn="2025-01-01T00:00:00Z"),
    ]
}


def fake_osv(scan, found: dict[tuple[str, str], list[str]]):
    """An OSV whose batch query answers FOUND, by (name, version), and with RECORDS."""
    queries = []

    def post(url: str, body: dict) -> dict:
        assert url.endswith("/querybatch")
        queries.extend(body["queries"])
        return {
            "results": [
                {"vulns": [{"id": i} for i in found.get((q["package"]["name"], q["version"]), [])]}
                for q in body["queries"]
            ]
        }

    def get(url: str) -> dict:
        id = url.rsplit("/", 1)[1]
        if id not in RECORDS:
            raise urllib.error.URLError("not found")
        return RECORDS[id]

    osv = scan.Osv(post=post, get=get)
    osv.queries = queries
    return osv


def scan_one(scan, ids: list[str], exceptions=()) -> list:
    package = scan.Package("uv.lock", "pkg", "1.0")
    osv = fake_osv(scan, {("pkg", "1.0"): ids})
    findings = scan.find([package], osv)
    scan.classify(findings, list(exceptions), osv)
    return findings


@pytest.mark.parametrize(
    ("ids", "severity", "blocking"),
    [
        (["GHSA-crit-crit-crit"], "critical", True),
        (["GHSA-high-high-high"], "high", True),
        (["GHSA-medi-medi-medi"], "moderate", False),
        (["GHSA-loww-loww-loww"], "low", False),
        # only a PYSEC id, whose GHSA alias has the severity
        (["PYSEC-2021-3"], "moderate", False),
        # no GHSA: the severity is unknown, which blocks
        (["PYSEC-2021-2"], "unknown", True),
        # a withdrawn advisory never blocks
        (["GHSA-gone-gone-gone"], "critical", False),
    ],
)
def test_blocking(scan, ids: list[str], severity: str, blocking: bool) -> None:
    [f] = scan_one(scan, ids)
    assert (f.severity, f.blocking) == (severity, blocking)


def test_aliases_are_one_finding(scan) -> None:
    """OSV lists a vulnerability once per database: the GHSA record is kept."""
    [f] = scan_one(scan, ["PYSEC-2020-1", "GHSA-high-high-high"])
    assert f.id == "GHSA-high-high-high"
    assert f.fix_versions == ["1.1"]


def test_an_unreadable_record_stops_the_scan(scan) -> None:
    with pytest.raises(urllib.error.URLError):
        scan_one(scan, ["GHSA-miss-miss-miss"])


def test_an_exception_matches_an_alias(scan) -> None:
    approval = scan.Approval("CVE-2021-2", "https://e/1", "reason")
    [f] = scan_one(scan, ["PYSEC-2021-2"], [approval])
    assert f.exception is approval
    assert approval.used
    assert not f.blocking


def test_the_report_lists_unused_exceptions(scan) -> None:
    approval = scan.Approval("GHSA-none-none-none", "https://e/1", "reason")
    findings = scan_one(scan, ["GHSA-high-high-high"], [approval])
    text = scan.report(findings, [approval], ["uv.lock"])
    assert "❌ blocking" in text
    assert "match no finding" in text
    assert "GHSA-none-none-none" in text


def test_only_packages_from_an_index_are_looked_up(scan, tmp_path: Path) -> None:
    lock = write(
        tmp_path / "uv.lock",
        """
        version = 1
        [[package]]
        name = "demo"
        version = "0.1.0"
        source = { editable = "." }
        [[package]]
        name = "pkg"
        version = "1.0"
        source = { registry = "https://pypi.org/simple" }
        [[package]]
        name = "private"
        version = "2.0"
        source = { registry = "https://packages.example.com/simple/" }
        [[package]]
        name = "fromgit"
        version = "0.3"
        source = { git = "https://github.com/example/fromgit?rev=abc#abc" }
        """,
    )
    packages = scan.locked_packages(lock, tmp_path)
    assert [(p.name, p.version) for p in packages] == [("pkg", "1.0"), ("private", "2.0")]
    osv = fake_osv(scan, {})
    scan.find(packages, osv)
    # only the name, the ecosystem and the version are sent
    assert osv.queries == [
        {"package": {"name": "pkg", "ecosystem": "PyPI"}, "version": "1.0"},
        {"package": {"name": "private", "ecosystem": "PyPI"}, "version": "2.0"},
    ]


def test_workflow_command_messages_are_escaped(scan) -> None:
    assert scan.command("50% done\nnext") == "50%25 done%0Anext"


# --- runtime and development dependencies ------------------------------------------------

LOCK = """
version = 1
[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests", extra = ["socks"] }, { name = "scipy", version = "1.17.1", source = { registry = "https://pypi.org/simple" } }]
[package.optional-dependencies]
plot = [{ name = "matplotlib" }]
[package.dev-dependencies]
test = [{ name = "pytest" }, { name = "requests" }]
[[package]]
name = "requests"
version = "2.32.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "urllib3" }]
[package.optional-dependencies]
socks = [{ name = "pysocks" }]
security = [{ name = "pyopenssl" }]
[[package]]
name = "urllib3"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "pysocks"
version = "1.7.1"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "pyopenssl"
version = "24.0.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "matplotlib"
version = "3.9.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "pluggy" }]
[[package]]
name = "pluggy"
version = "1.5.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "scipy"
version = "1.17.1"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "scipy"
version = "1.18.1"
source = { registry = "https://pypi.org/simple" }
"""


def test_runtime_and_development_packages(scan, tmp_path: Path) -> None:
    packages = scan.locked_packages(write(tmp_path / "uv.lock", LOCK), tmp_path)
    runtime = {(p.name, p.version) for p in packages if p.runtime}
    assert runtime == {
        ("requests", "2.32.0"),
        ("urllib3", "2.0.0"),  # a dependency of a dependency
        ("pysocks", "1.7.1"),  # an extra that a dependency asks for
        ("matplotlib", "3.9.0"),  # an extra of the project itself
        ("scipy", "1.17.1"),  # only the version the project uses
    }
    development = {(p.name, p.version) for p in packages if not p.runtime}
    # a dependency group, an extra nobody asks for, a version nobody at run time uses
    assert development == {
        ("pytest", "8.0.0"),
        ("pluggy", "1.5.0"),
        ("pyopenssl", "24.0.0"),
        ("scipy", "1.18.1"),
    }


def test_without_a_project_every_package_counts(scan, tmp_path: Path) -> None:
    lock = 'version = 1\n[[package]]\nname = "pkg"\nversion = "1.0"\nsource = { registry = "https://pypi.org/simple" }\n'
    [package] = scan.locked_packages(write(tmp_path / "uv.lock", lock), tmp_path)
    assert package.runtime


def test_development_findings_never_block(scan) -> None:
    package = scan.Package("uv.lock", "pkg", "1.0", runtime=False)
    osv = fake_osv(scan, {("pkg", "1.0"): ["GHSA-crit-crit-crit"]})
    [f] = scan.find([package], osv)
    scan.classify([f], [], osv)
    assert f.severity == "critical"
    assert not f.blocking
    assert "| development |" in scan.report([f], [], ["uv.lock"])


# --- end to end: real lock files and OSV --------------------------------------------------

needs_network = pytest.mark.skipif(
    shutil.which("uv") is None or os.environ.get("OFFLINE") == "1",
    reason="needs uv (to lock the projects) and the network",
)


def git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def project(path: Path, dependencies: list[str]) -> Path:
    """A git repository with a locked project that depends on DEPENDENCIES."""
    path.mkdir(parents=True)
    quoted = ", ".join(f'"{d}"' for d in dependencies)
    (path / "pyproject.toml").write_text(
        f'[project]\nname = "demo"\nversion = "0"\nrequires-python = ">=3.11"\n'
        f"dependencies = [{quoted}]\n",
        encoding="utf-8",
    )
    subprocess.run(["uv", "lock", "--quiet"], cwd=path, check=True)
    git(path, "init", "--quiet")
    git(path, "add", "--all")
    return path


def run(script: Path, cwd: Path) -> subprocess.CompletedProcess:
    summary = cwd.parent / f"{cwd.name}-summary.md"
    env = {
        **os.environ,
        "GITHUB_STEP_SUMMARY": str(summary),
        "EXCEPTIONS_FILE": ".github/vulnerability-exceptions.toml",
    }
    result = subprocess.run(
        ["uv", "run", "--no-config", "--no-project", str(script)],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    result.summary = summary.read_text(encoding="utf-8") if summary.exists() else ""
    return result


def test_nothing_to_scan(script: Path, tmp_path: Path) -> None:
    repository = tmp_path / "empty"
    repository.mkdir()
    git(repository, "init", "--quiet")
    result = run(script, repository)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "nothing to scan" in result.stdout


@needs_network
def test_a_clean_lock_passes(script: Path, tmp_path: Path) -> None:
    result = run(script, project(tmp_path / "clean", ["packaging>=25"]))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "No known vulnerabilities." in result.summary


@needs_network
def test_a_vulnerable_lock_fails_until_excepted(script: Path, tmp_path: Path) -> None:
    # jinja2 2.10 has high-severity advisories, e.g. a sandbox escape
    repository = project(tmp_path / "vulnerable", ["jinja2==2.10"])
    result = run(script, repository)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "::error file=uv.lock,title=high vulnerability in jinja2::" in result.stdout
    assert "❌ blocking" in result.summary

    # approving every blocking advisory makes the scan pass, and lists them as excepted
    ids = sorted(
        {
            line.split(": ", 1)[1].split(" ", 1)[0]
            for line in result.stdout.splitlines()
            if line.startswith("::error file=")
        }
    )
    assert ids
    exceptions = repository / ".github" / "vulnerability-exceptions.toml"
    exceptions.parent.mkdir()
    exceptions.write_text(
        "".join(
            f'[[exception]]\nid = "{i}"\nissue = "https://github.com/example/demo/issues/1"\nreason = "Test."\n\n'
            for i in ids
        ),
        encoding="utf-8",
    )
    result = run(script, repository)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "excepted" in result.summary


@needs_network
def test_a_vulnerable_development_dependency_passes(script: Path, tmp_path: Path) -> None:
    repository = project(tmp_path / "devonly", ["packaging>=25"])
    with (repository / "pyproject.toml").open("a", encoding="utf-8") as file:
        file.write('[dependency-groups]\ndev = ["jinja2==2.10"]\n')
    subprocess.run(["uv", "lock", "--quiet"], cwd=repository, check=True)
    git(repository, "add", "--all")
    result = run(script, repository)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "| development |" in result.summary
    assert "❌ blocking" not in result.summary


@needs_network
def test_every_tracked_lock_is_scanned(script: Path, tmp_path: Path) -> None:
    repository = project(tmp_path / "monorepo", ["packaging>=25"])
    project(repository / "tools", ["jinja2==2.10"])
    shutil.rmtree(repository / "tools" / ".git")
    git(repository, "add", "--all")
    result = run(script, repository)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "tools/uv.lock" in result.summary
