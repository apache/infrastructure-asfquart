# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import os
import re
import subprocess
import sys
import tomllib
from typing import Final

_SERIES: Final = "0.2"
_DEV: Final = re.compile(rf"{re.escape(_SERIES)}\.(0|[1-9][0-9]*)\.dev0\+dev")
_FIRST: Final = f"{_SERIES}.0.dev0+dev"
_RELEASE: Final = re.compile(rf"{re.escape(_SERIES)}\.(0|[1-9][0-9]*)")
_ZERO: Final = "0" * 40


def _check(label: str, parent: str | None, revision: str) -> list[str]:
    version = _version(revision)
    previous = None if (parent is None) else _version(parent)
    errors = []
    if not (_DEV.fullmatch(version) or _RELEASE.fullmatch(version)):
        errors.append(f"{label}: version {version} must be {_SERIES}.N or {_SERIES}.N.dev0+dev")
    elif (expected := _expected(previous, version)) is not None:
        errors.append(f"{label}: version must be {expected} after {previous}, not {version}")
    locked = _locked_version(revision)
    if locked != version:
        errors.append(f"{label}: uv.lock records version {locked}, not {version}")
    return errors


def _check_commit(commit: str) -> list[str]:
    if _exists(f"{commit}^2"):
        return [f"{commit[:12]}: merge commits are not allowed, so rebase instead"]
    parent = f"{commit}^" if _exists(f"{commit}^") else None
    return _check(commit[:12], parent, commit)


def _check_range(start: str, end: str) -> list[str]:
    span = end if (start == _ZERO) else f"{start}..{end}"
    errors = []
    for commit in _git("rev-list", "--reverse", span).split():
        errors.extend(_check_commit(commit))
        for tag in _git("tag", "--points-at", commit, "--list", "v*").split():
            errors.extend(_check_tag(tag, commit))
    return errors


def _check_tag(tag: str, commit: str) -> list[str]:
    version = _version(commit)
    errors = []
    if not _RELEASE.fullmatch(version):
        errors.append(f"tag {tag}: commit {commit[:12]} has version {version}, which is not a release")
    elif tag != f"v{version}":
        errors.append(f"tag {tag}: commit {commit[:12]} has version {version}, so the tag must be v{version}")
    main = "refs/heads/main" if _exists("refs/heads/main") else "refs/remotes/origin/main"
    if _git_status("merge-base", "--is-ancestor", commit, main) != 0:
        errors.append(f"tag {tag}: commit {commit[:12]} is not on main")
    return errors


def _exists(revision: str) -> bool:
    return _git_status("rev-parse", "--verify", "--quiet", revision) == 0


def _expected(previous: str | None, version: str) -> str | None:
    if previous is None:
        return None if (version == _FIRST) else _FIRST
    if dev := _DEV.fullmatch(previous):
        release = f"{_SERIES}.{dev[1]}"
        return None if (version in {previous, release}) else f"{previous} or {release}"
    if release := _RELEASE.fullmatch(previous):
        bumped = f"{_SERIES}.{int(release[1]) + 1}.dev0+dev"
        return None if (version == bumped) else bumped
    return None if (version == _FIRST) else _FIRST


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, check=True, text=True).stdout


def _git_status(*args: str) -> int:
    return subprocess.run(["git", *args], capture_output=True, check=False).returncode


def _locked_version(revision: str) -> str | None:
    packages = tomllib.loads(_git("show", f"{revision}:uv.lock"))["package"]
    return next((package["version"] for package in packages if package["name"] == "asfquart"), None)


def _version(revision: str) -> str:
    return tomllib.loads(_git("show", f"{revision}:pyproject.toml"))["project"]["version"]


def main() -> None:
    remote_ref = os.environ.get("PRE_COMMIT_REMOTE_BRANCH", "")
    start = os.environ.get("PRE_COMMIT_FROM_REF", _ZERO)
    end = os.environ.get("PRE_COMMIT_TO_REF", "")
    if remote_ref.startswith("refs/tags/v") and end:
        errors = [*_check_commit(end), *_check_tag(remote_ref.removeprefix("refs/tags/"), end)]
    elif remote_ref.startswith("refs/pull/") and end:
        errors = [*_check_range(start, f"{end}^2"), *_check("pull request merge", f"{end}^1", end)]
    elif end:
        errors = _check_range(start, end)
    else:
        errors = _check("staged changes", "HEAD" if _exists("HEAD") else None, "")
    if errors:
        sys.exit("\n".join(f"ERROR: {error}" for error in errors))


if __name__ == "__main__":
    main()
