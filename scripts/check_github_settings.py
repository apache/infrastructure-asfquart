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

import http.client
import json
import os
import sys
from typing import Any, Final

_ENVIRONMENT: Final = "pypi"
_RULESETS: Final = {
    "Main branch": (
        "branch",
        "refs/heads/main",
        frozenset({"deletion", "non_fast_forward"}),
    ),
    "Release tags": ("tag", "refs/tags/v*", frozenset({"deletion", "update"})),
}


def _environment_errors(repository: str) -> list[str]:
    environment = _get(f"/repos/{repository}/environments/{_ENVIRONMENT}")
    if environment["deployment_branch_policy"] != {"protected_branches": False, "custom_branch_policies": True}:
        return [f"the {_ENVIRONMENT} environment is not restricted to custom policies"]
    policies = _get(f"/repos/{repository}/environments/{_ENVIRONMENT}/deployment-branch-policies")
    if [(policy["name"], policy["type"]) for policy in policies["branch_policies"]] != [("v*", "tag")]:
        return [f"the {_ENVIRONMENT} environment is not restricted to v* tags"]
    return []


def _get(path: str) -> Any:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "asfquart-settings-check"}
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    connection = http.client.HTTPSConnection("api.github.com", timeout=30)
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    if response.status != 200:
        sys.exit(f"ERROR: GET {path} returned HTTP {response.status}")
    return json.load(response)


def _ruleset_errors(name: str, ruleset: Any, expected: tuple[str, str, frozenset[str]]) -> list[str]:
    target, ref, rules = expected
    errors = []
    if (ruleset["target"], ruleset["enforcement"]) != (target, "active"):
        errors.append(f"the {name} ruleset is not an active {target} ruleset")
    if ruleset["conditions"]["ref_name"] != {"include": [ref], "exclude": []}:
        errors.append(f"the {name} ruleset does not cover exactly {ref}")
    if not (rules <= {rule["type"] for rule in ruleset["rules"]}):
        errors.append(f"the {name} ruleset does not have the rules {sorted(rules)}")
    return errors


def _rulesets_errors(repository: str) -> list[str]:
    ids = {ruleset["name"]: ruleset["id"] for ruleset in _get(f"/repos/{repository}/rulesets")}
    errors = []
    for name, expected in _RULESETS.items():
        if name not in ids:
            errors.append(f"the {name} ruleset is missing")
            continue
        errors.extend(_ruleset_errors(name, _get(f"/repos/{repository}/rulesets/{ids[name]}"), expected))
    return errors


def main() -> None:
    repository = os.environ["GITHUB_REPOSITORY"]
    errors = [*_rulesets_errors(repository), *_environment_errors(repository)]
    if errors:
        sys.exit("\n".join(f"ERROR: {error}" for error in errors))


if __name__ == "__main__":
    main()
