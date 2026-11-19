# security-workflows

GitHub Actions workflows that organization rulesets require in Algorithmiq's repositories.
They are public so that one ruleset can run them in every repository, public, internal or
private: a ruleset can only run a workflow whose repository is at least as visible as the
repositories it targets.

This repository holds generic workflow code only. It must never contain secrets, names of
private repositories or packages, or other organization-specific details: those come from the
repository the workflow runs in.

## Dependency scan

[`dependency-scan.yml`](.github/workflows/dependency-scan.yml) checks the Python dependencies
locked in `uv.lock` for known vulnerabilities, on every pull request and in the merge queue.

### How it works

A ruleset runs the workflow in the repository of the pull request, with that repository's
files and `GITHUB_TOKEN` (read-only), and ignores the filters of its triggers. The scan is
[`scripts/dependency_scan.py`](scripts/dependency_scan.py) of this repository: the job checks
it out from the commit of the workflow file (`job.workflow_repository`, `job.workflow_sha`),
which the ruleset pins, and runs it with `uv run` (Python 3.13, standard library only, as its
inline metadata says). The script:

1. finds the `uv.lock` files that git tracks. With none, it passes with a notice;
2. runs [`uv audit`](https://docs.astral.sh/uv/) next to each one (`--frozen`: it reads the
   lock file and installs nothing, so it needs no access to private package indexes). It
   audits every package of the lock, including extras and dependency groups;
3. looks up the severity of each finding in
   [GitHub's advisory database](https://github.com/advisories), by its GHSA identifier (`uv
   audit` reports none);
4. writes a table of the findings to the job summary, and an error annotation for each one
   that blocks.

A finding **blocks the merge** when its advisory is **high** or **critical**, or when its
severity is unknown (no GHSA identifier, or the database can't be read): an unknown severity
never lets a vulnerability through. Low and medium findings are listed without failing the
job. A withdrawn advisory never blocks.

### What leaves the repository

`uv audit` sends the name and version of every locked package to the
[OSV](https://osv.dev) database, including packages from private indexes: OSV matches by name,
whatever the index. The job also sends the GHSA identifiers of the findings to GitHub's API.
Nothing else leaves the runner. If a private package shares its name with a public one that has
advisories, the findings of the public one are reported: record them as exceptions.

### Exceptions

A finding that is acceptable for a while (no fix yet, code that is never reached, a false
positive) goes in `.github/vulnerability-exceptions.toml` of the repository, one table per
vulnerability:

```toml
[[exception]]
id = "GHSA-xxxx-xxxx-xxxx"  # the GHSA identifier, or any alias that the job summary shows
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

### Updating uv

`uv audit` is a preview feature of uv, and its output can change between releases. The
workflow pins uv (`version:` of `setup-uv`), and the tests run the same version. Dependabot
doesn't move that pin: update it by hand, run the tests, and update the ruleset.

## Development

The tests run `scripts/dependency_scan.py` as the workflow does:

```sh
uv run --no-project --with pytest --with pyyaml pytest
```

The end-to-end tests lock small projects with known vulnerable packages and need the network
(PyPI, OSV and GitHub's API); set `GITHUB_TOKEN` for a higher rate limit, and `OFFLINE=1` to
skip them. CI also runs ruff, actionlint and zizmor. Changes need a pull request and a review:
every targeted repository runs this code.
