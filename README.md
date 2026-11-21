# security-workflows

GitHub Actions workflows that organization rulesets require in Algorithmiq's repositories.
They are public so that one ruleset can run them in every repository, public, internal or
private: a ruleset can only run a workflow whose repository is at least as visible as the
repositories it targets.

This repository holds generic workflow code only. It must never contain secrets, names of
private repositories or packages, or other organization-specific details: those come from the
repository the workflow runs in.

## Dependency scan

[`dependency-scan.yml`](.github/workflows/dependency-scan.yml) checks the Python packages
locked in `uv.lock`, and the Rust crates locked in `Cargo.lock`, against the
[OSV](https://osv.dev) database of known vulnerabilities, on every pull request and in the
merge queue.

### How it works

A ruleset runs the workflow in the repository of the pull request, with that repository's
files and `GITHUB_TOKEN` (read-only), and ignores the filters of its triggers. The scan is
[`scripts/dependency_scan.py`](scripts/dependency_scan.py) of this repository: the job checks
it out from the commit of the workflow file (`job.workflow_repository`, `job.workflow_sha`),
which the ruleset pins, and runs it with `uv run` (Python 3.13, standard library only, as its
inline metadata says). The script:

1. finds the `uv.lock` and `Cargo.lock` files that git tracks, in the root and in any
   directory below it. With neither, it passes with a notice; with one kind, it scans that
   kind;
2. reads the packages of each `uv.lock` that come from a package index, with their versions:
   every extra and dependency group, whatever the index. The project itself and packages from
   git, a URL or a local path are left out: they have no version on PyPI to look up;
3. reads the crates of each `Cargo.lock` that come from crates.io, with their versions. The
   packages of the workspace and the crates from git, a path or another registry are left
   out. Versions 3 and 4 of the lock have the same `[[package]]` tables, and both are read;
4. asks OSV which vulnerabilities affect each name and version in its ecosystem (`PyPI` or
   `crates.io`), and reads their records. OSV lists a vulnerability once per database (GHSA,
   PYSEC, RUSTSEC, …): the GHSA record is kept, as it carries GitHub's severity;
5. writes a table of the findings to the job summary, and an error annotation for each one
   that blocks.

A finding **blocks the merge** when it is in a **runtime dependency** and its severity is
**high** or **critical**, or unknown (no GHSA record): an unknown severity never lets a
vulnerability through. Low and moderate findings are listed without failing the job, and so
are findings in packages that only the dependency groups need (`dev`, `test`, `docs`, …),
which don't ship with the project. A withdrawn advisory never blocks. If OSV can't be read,
the job fails.

The runtime dependencies of a `uv.lock` are those of the projects of the lock (its editable
or virtual packages) and of their extras, followed through the lock, with the extras each
dependency asks for. Whatever a project lists in `[project] dependencies` counts, even tools
that only its developers use: move those to a dependency group. A lock without a project
counts every package as a runtime dependency.

### Rust crates

OSV imports the [RustSec advisory database](https://rustsec.org/) and GitHub's advisories for
crates.io, so a crate is checked with the same database, severity and rules as a Python
package. The differences:

- **Every crate counts as a runtime dependency.** `Cargo.lock` doesn't record which crates
  are dev-dependencies or build-dependencies, nor which features are on: only cargo knows
  that, when it resolves the manifest. A finding in a crate that only the tests or the build
  script use blocks like any other, so use an exception for it, with the reason.
- **Informational advisories don't block.** RustSec also publishes notices that aren't
  vulnerabilities: an `unmaintained` or `unsound` crate, or a `notice`. They have no GHSA
  record, hence no severity. The scan lists them with the kind as the severity
  (`informational: unmaintained`) and never blocks on them. If GitHub has an advisory for the
  same issue, GitHub's severity applies instead.
- **A RustSec vulnerability that GitHub doesn't know blocks**, as its severity is unknown:
  the severity is GitHub's, not the CVSS score of RustSec.
- **Yanked crates aren't reported.** A yanked version isn't an advisory, and OSV doesn't list
  it.
- Crate names are compared exactly: cargo treats `foo-bar` and `foo_bar` as different crates,
  where Python names ignore the case and the separators.

### What leaves the repository

Only the name, the ecosystem (`PyPI` or `crates.io`) and the version of each locked package,
sent to [OSV's API](https://google.github.io/osv.dev/post-v1-querybatch/) with Python's
default User-Agent; then the identifiers of the vulnerabilities found, to read their records.
For Python, that includes packages from private indexes: OSV matches by name, whatever the
index. If a private package shares its name with a public one that has advisories, the
findings of the public one are reported: record them as exceptions. For Rust, only the crates
of crates.io are sent (`registry+https://github.com/rust-lang/crates.io-index` or
`sparse+https://index.crates.io/` as the source in `Cargo.lock`): those names are public.
Crates from git, a path or another registry are never sent, and neither are the names of the
packages of the workspace.

### Exceptions

A finding that is acceptable for a while (no fix yet, code that is never reached, a false
positive) goes in `.github/vulnerability-exceptions.toml` of the repository, one table per
vulnerability:

```toml
[[exception]]
id = "GHSA-xxxx-xxxx-xxxx"  # the GHSA identifier, or any alias (CVE-…, RUSTSEC-…, PYSEC-…)
issue = "https://github.com/<owner>/<repository>/issues/<number>"  # the issue that approves it
reason = "The vulnerable function is only used by the test suite."
```

All three keys are required; any other key is an error. Exceptions are reviewed in pull
requests like any other change, and the history of the file shows who approved what. An
exception that no longer matches a finding gives a warning: remove it.

### Setting it up (organization owners)

1. **Settings → Repository → Rulesets → New branch ruleset**, enforcement **Evaluate** at first.
2. **Target repositories**: by custom property, for example the repositories that must have a
   dependency scan. **Target branches**: the default branch. The rule blocks direct pushes, so
   only target branches that change through pull requests.
3. Rule **Require workflows to pass before merging**: repository
   `Algorithmiq/security-workflows`, workflow `.github/workflows/dependency-scan.yml`, and the
   **full commit SHA** of a reviewed version as the reference, not a branch: a change here
   reaches every targeted repository only when the ruleset moves to it.
4. Once the runs in Evaluate mode look right, switch the enforcement to **Active**. Pull
   requests opened before the ruleset existed run the workflow on their next push.

To move to a new version: review the change here, then update the SHA in the ruleset.

## Development

The tests run `scripts/dependency_scan.py` as the workflow does:

```sh
uv run --no-project --with pytest --with pyyaml pytest
```

The end-to-end tests lock small Python projects with known vulnerable packages, and use
hand-written `Cargo.lock` files with known vulnerable crates (no cargo needed). They need the
network (PyPI and OSV); set `OFFLINE=1` to skip them. CI also runs ruff, actionlint and
zizmor. Changes need a pull request and a review: every targeted repository runs this code.
