#!/bin/sh

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

series=0.2

check_branch() {
  if [ "$(git symbolic-ref --short HEAD 2>/dev/null)" != main ]
  then
    fail "switch to main first"
  fi
  if [ -n "$(git status --porcelain --untracked-files=no)" ]
  then
    fail "commit or restore your changes to tracked files first"
  fi
}

check_level() {
  if [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ]
  then
    return
  fi
  if git merge-base --is-ancestor HEAD origin/main
  then
    fail "main is behind origin/main, so run git pull --ff-only first"
  fi
  fail "main has commits that are not on origin/main, so push them and let CI pass first"
}

develop() {
  check_branch
  git pull --quiet --ff-only origin main ||
    fail "could not fast-forward main from origin"
  check_level
  read_version "" develop
  if [ "$(git rev-parse --quiet --verify "refs/tags/v$current^{commit}")" != "$(git rev-parse HEAD)" ]
  then
    fail "the latest commit on main is not tagged v$current"
  fi
  next=$((number + 1))
  set_version "$series.$next.dev0+dev"
  git commit -am "Start $series.$next development" ||
    fail "the commit failed" "undo the version change with git restore pyproject.toml uv.lock"
  git push origin main ||
    fail "the push failed, so the commit is only local" "fix the problem, then run git push origin main"
}

fail() {
  printf 'phase.sh: %s\n' "$@" >&2
  exit 1
}

read_version() {
  current=$(uv version --short) ||
    fail "uv could not read the version"
  number=${current#"$series".}
  number=${number%"$1"}
  case $number in
    '' | 0?* | *[!0-9]*)
      ;;
    *)
      if [ "$current" = "$series.$number$1" ]
      then
        return
      fi
      ;;
  esac
  fail "the version is $current, but $2 needs $series.N$1"
}

release() {
  check_branch
  git fetch --quiet --tags origin ||
    fail "could not fetch from origin"
  check_level
  read_version .dev0+dev release
  version=$series.$number
  if git rev-parse --quiet --verify "refs/tags/v$version" >/dev/null
  then
    fail "v$version already exists"
  fi
  set_version "$version"
  git commit -am "Release $version" ||
    fail "the commit failed" "undo the version change with git restore pyproject.toml uv.lock"
  git tag "v$version" ||
    fail "the tag failed, so the release commit is only local" "fix the problem, then run git tag v$version"
  git push --atomic origin main "v$version" ||
    fail "the push failed, so the release commit and tag are only local" \
      "fix the problem, then run git push --atomic origin main v$version"
}

set_version() {
  uv version --no-config --no-sync "$1" ||
    fail "uv could not set the version to $1"
  if [ "$(git diff --numstat)" != "$(printf '1\t1\tpyproject.toml\n1\t1\tuv.lock')" ]
  then
    fail "uv changed more than the two version lines" "check git diff, then git restore pyproject.toml uv.lock"
  fi
}

usage() {
  fail "usage: scripts/phase.sh release|develop"
}

if [ $# -ne 1 ]
then
  usage
fi
cd "$(dirname "$0")/.." ||
  fail "could not change to the repository root"
command -v uv >/dev/null ||
  fail "uv is not installed"
case $1 in
  release)
    release
    ;;
  develop)
    develop
    ;;
  *)
    usage
    ;;
esac
