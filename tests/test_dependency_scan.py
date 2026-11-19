"""Tests of the script of .github/workflows/dependency-scan.yml.

The script is the body of a step, so the tests take it from the workflow file: what they
test is what runs.

Run with: uv run --no-project --with pytest --with pyyaml pytest
The end-to-end tests need the network (PyPI, OSV and GitHub's advisory database).
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


def step() -> dict:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    return next(s for s in workflow["jobs"]["scan"]["steps"] if s.get("id") == "scan")


@pytest.fixture(scope="session")
def script(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("script") / "dependency_scan.py"
    path.write_text(step()["run"], encoding="utf-8")
    return path


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


def finding(scan, id: str, aliases: list[str] | None = None):
    return scan.Finding(
        lock="uv.lock",
        package="pkg",
        version="1.0",
        id=id,
        aliases=aliases or [],
        summary="A problem",
        fix_versions=["1.1"],
    )


ADVISORIES = {
    "GHSA-crit-crit-crit": {"severity": "critical", "withdrawn_at": None},
    "GHSA-high-high-high": {"severity": "high", "withdrawn_at": None},
    "GHSA-medi-medi-medi": {"severity": "medium", "withdrawn_at": None},
    "GHSA-loww-loww-loww": {"severity": "low", "withdrawn_at": None},
    "GHSA-gone-gone-gone": {
        "severity": "critical",
        "withdrawn_at": "2025-01-01T00:00:00Z",
    },
}


def fetch(ghsa: str) -> dict:
    if ghsa not in ADVISORIES:
        raise urllib.error.URLError("not found")
    return ADVISORIES[ghsa]


@pytest.mark.parametrize(
    ("id", "aliases", "severity", "blocking"),
    [
        ("GHSA-crit-crit-crit", [], "critical", True),
        ("GHSA-high-high-high", [], "high", True),
        ("GHSA-medi-medi-medi", [], "medium", False),
        ("GHSA-loww-loww-loww", [], "low", False),
        # uv shows the PYSEC id first for some advisories: the GHSA alias is used
        ("PYSEC-2021-1", ["CVE-2021-1", "GHSA-medi-medi-medi"], "medium", False),
        # no GHSA: the severity is unknown, which blocks
        ("PYSEC-2021-2", ["CVE-2021-2"], "unknown", True),
        # the advisory can't be read: unknown, which blocks
        ("GHSA-miss-miss-miss", [], "unknown", True),
        # a withdrawn advisory never blocks
        ("GHSA-gone-gone-gone", [], "critical", False),
    ],
)
def test_blocking(
    scan, id: str, aliases: list[str], severity: str, blocking: bool
) -> None:
    f = finding(scan, id, aliases)
    scan.classify([f], [], fetch=fetch)
    assert (f.severity, f.blocking) == (severity, blocking)


def test_an_exception_matches_an_alias(scan) -> None:
    approval = scan.Approval("CVE-2021-2", "https://e/1", "reason")
    f = finding(scan, "PYSEC-2021-2", ["CVE-2021-2"])
    scan.classify([f], [approval], fetch=fetch)
    assert f.exception is approval
    assert approval.used
    assert not f.blocking


def test_the_report_lists_unused_exceptions(scan) -> None:
    approval = scan.Approval("GHSA-none-none-none", "https://e/1", "reason")
    f = finding(scan, "GHSA-high-high-high")
    scan.classify([f], [approval], fetch=fetch)
    text = scan.report([f], [approval], [], ["uv.lock"])
    assert "❌ blocking" in text
    assert "match no finding" in text
    assert "GHSA-none-none-none" in text


def test_workflow_command_messages_are_escaped(scan) -> None:
    assert scan.command("50% done\nnext") == "50%25 done%0Anext"


# --- end to end: uv audit on real lock files ---------------------------------------------

needs_network = pytest.mark.skipif(
    shutil.which("uv") is None or os.environ.get("OFFLINE") == "1",
    reason="needs uv and the network",
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
        ["uv", "run", "--no-project", "--python", "3.13", "python", str(script)],
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
def test_every_tracked_lock_is_scanned(script: Path, tmp_path: Path) -> None:
    repository = project(tmp_path / "monorepo", ["packaging>=25"])
    project(repository / "tools", ["jinja2==2.10"])
    shutil.rmtree(repository / "tools" / ".git")
    git(repository, "add", "--all")
    result = run(script, repository)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "tools/uv.lock" in result.summary


@pytest.mark.skipif(shutil.which("uvx") is None, reason="needs uvx")
def test_the_script_passes_ruff(script: Path) -> None:
    for command in (["check"], ["format", "--check"]):
        result = subprocess.run(
            ["uvx", "ruff@0.17.5", *command, "--line-length", "100", str(script)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
