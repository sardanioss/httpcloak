#!/usr/bin/env python3
"""Check that every package carries the same version, and the tag's.

A tag pushed before bump-version.sh ran would build packages still saying
the previous version and upload them into that release: PyPI accepts any
wheel whose file name it doesn't already have, so new macOS wheels would
land in an old, live release. This runs before anything is built.

usage: check_version.py [TAG]     TAG like v1.7.4 or v1.7.4-beta.1
"""

import glob
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))


def read(path, pattern):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        m = re.search(pattern, f.read(), re.M)
    if not m:
        sys.exit("FAIL: no version found in bindings/%s" % path)
    return m.group(1)


def main():
    found = {
        "python/pyproject.toml": read("python/pyproject.toml", r'^version = "([^"]+)"'),
        "python/httpcloak/__init__.py": read("python/httpcloak/__init__.py", r'__version__ = "([^"]+)"'),
        "clib/httpcloak.go": read("clib/httpcloak.go", r'^const libVersion = "([^"]+)"'),
        "dotnet/HttpCloak/HttpCloak.csproj": read("dotnet/HttpCloak/HttpCloak.csproj", r"<Version>([^<]+)</Version>"),
        "android/httpcloak/build.gradle.kts": read("android/httpcloak/build.gradle.kts", r'^version = "([^"]+)"'),
    }
    main_pkg = json.load(open(os.path.join(ROOT, "nodejs/package.json")))
    found["nodejs/package.json"] = main_pkg["version"]
    for dep, v in sorted((main_pkg.get("optionalDependencies") or {}).items()):
        found["nodejs/package.json optionalDependencies " + dep] = v
    for p in sorted(glob.glob(os.path.join(ROOT, "nodejs/npm/*/package.json"))):
        found[os.path.relpath(p, ROOT)] = json.load(open(p))["version"]

    versions = set(found.values())
    if len(versions) != 1:
        print("FAIL: the packages disagree on the version:")
        for k, v in sorted(found.items()):
            print("  %-60s %s" % (k, v))
        sys.exit(1)
    version = versions.pop()

    if len(sys.argv) > 1 and sys.argv[1]:
        tag = sys.argv[1].rsplit("/", 1)[-1]
        if tag.lstrip("v") != version:
            sys.exit("FAIL: tag %s but the packages say %s. Run bindings/bump-version.sh %s, commit, and tag that."
                     % (tag, version, tag.lstrip("v")))
    print("ok: every package says %s" % version)


if __name__ == "__main__":
    main()
