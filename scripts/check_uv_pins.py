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

import pathlib
import re
import subprocess
import sys
import tomllib
from typing import Final

_SETUP_UV: Final = re.compile(r"uses: astral-sh/setup-uv@([0-9a-f]{40})[^\n]*\n\s+with:\n\s+version: \"latest-known\"")
_UV_BUILD: Final = re.compile(r"uv_build>=(([0-9]+)\.([0-9]+)\.[0-9]+),<([0-9]+\.[0-9]+)")


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


def main() -> None:
    commits = set()
    workflows = pathlib.Path(".github/workflows")
    for workflow in sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")]):
        text = workflow.read_text()
        pinned = _SETUP_UV.findall(text)
        if text.count("astral-sh/setup-uv@") != len(pinned):
            sys.exit(f"ERROR: {workflow}: every setup-uv step must use version latest-known directly after with:")
        commits.update(pinned)
    if len(commits) != 1:
        sys.exit(f"ERROR: the workflows must all use the same setup-uv commit, not {sorted(commits)}")
    requires = tomllib.loads(pathlib.Path("pyproject.toml").read_text())["build-system"]["requires"]
    match = _UV_BUILD.fullmatch(requires[0]) if (len(requires) == 1) else None
    if (match is None) or (match[4] != f"{match[2]}.{int(match[3]) + 1}"):
        sys.exit(f"ERROR: pyproject.toml build requirement must be uv_build>=X.Y.Z,<X.(Y+1), not {requires}")
    uv = subprocess.run(["uv", "self", "version", "--short"], capture_output=True, check=True, text=True).stdout.strip()
    if not (_version(match[1]) <= _version(uv) < _version(match[4])):
        sys.exit(f"ERROR: setup-uv installs uv {uv}, which {requires[0]} does not allow")


if __name__ == "__main__":
    main()
