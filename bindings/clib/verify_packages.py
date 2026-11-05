#!/usr/bin/env python3
"""Check the native library inside every package the release would publish,
against what that package tells installers it supports.

  wheels   the platform tag: manylinux_X_Y is glibc X.Y, macosx_X_Y is macOS
           X.Y, win_amd64 is Windows
  npm      the platform folder: linux-*, darwin-*, win32-*
  NuGet    the runtimes/<rid>/native folders, all five of them

Each library goes through verify_native.py's static checks. This runs on the
finished artifacts rather than on the build output, so a packaging step that
picked up the wrong file, or none, fails here too.

usage: verify_packages.py --wheels DIR --npm DIR --nuget DIR
"""

import argparse
import glob
import os
import re
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
VERIFY = os.path.join(HERE, "verify_native.py")

# The macOS and glibc floors the packages promise. Keep in step with the
# wheel tags in the workflow and the #cgo darwin flags in httpcloak.go.
NPM_TARGETS = {
    "linux-x64": ("linux", "libhttpcloak-linux-amd64.so"),
    "linux-arm64": ("linux", "libhttpcloak-linux-arm64.so"),
    "darwin-x64": ("darwin", "libhttpcloak-darwin-amd64.dylib"),
    "darwin-arm64": ("darwin", "libhttpcloak-darwin-arm64.dylib"),
    "win32-x64": ("windows", "libhttpcloak-windows-amd64.dll"),
}
NUGET_TARGETS = {
    "linux-x64": ("linux", "libhttpcloak-linux-amd64.so"),
    "linux-arm64": ("linux", "libhttpcloak-linux-arm64.so"),
    "osx-x64": ("darwin", "libhttpcloak-darwin-amd64.dylib"),
    "osx-arm64": ("darwin", "libhttpcloak-darwin-arm64.dylib"),
    "win-x64": ("windows", "libhttpcloak-windows-amd64.dll"),
}
GLIBC_FLOOR = "2.17"
MACOS_FLOOR = "12.0"

failures = []


def check(lib, target_os, max_glibc=GLIBC_FLOOR, max_macos=MACOS_FLOOR, what="", arch=None):
    if not os.path.isfile(lib):
        failures.append("%s: %s is missing" % (what, os.path.basename(lib)))
        print("FAIL: %s: %s is missing" % (what, lib))
        return
    cmd = [sys.executable, VERIFY, lib, "--os", target_os, "--max-glibc", max_glibc, "--max-macos", max_macos]
    if arch:
        cmd += ["--arch", arch]
    if subprocess.call(cmd) != 0:
        failures.append("%s: %s" % (what, os.path.basename(lib)))


def platform_arch(name):
    """CPU an npm platform folder or NuGet RID names: linux-x64 -> amd64."""
    return {"x64": "amd64", "arm64": "arm64"}[name.rsplit("-", 1)[1]]


def wheels(d):
    found = sorted(glob.glob(os.path.join(d, "*.whl")))
    if len(found) != 5:
        failures.append("expected 5 wheels in %s, found %d" % (d, len(found)))
    for whl in found:
        tag = os.path.basename(whl)[:-4].split("-")[-1]
        tmp = tempfile.mkdtemp()
        zipfile.ZipFile(whl).extractall(tmp)
        libs = glob.glob(os.path.join(tmp, "httpcloak", "lib", "libhttpcloak-*"))
        libs = [l for l in libs if not l.endswith(".h")]
        if len(libs) != 1:
            failures.append("%s: expected one native library, found %d" % (whl, len(libs)))
            continue
        arch = "arm64" if tag.endswith(("_aarch64", "_arm64")) else "amd64" if tag.endswith(("_x86_64", "_amd64")) else None
        m = re.match(r"manylinux_(\d+)_(\d+)_", tag)
        if m:
            check(libs[0], "linux", max_glibc="%s.%s" % m.groups(), what=os.path.basename(whl), arch=arch)
            continue
        m = re.match(r"macosx_(\d+)_(\d+)_", tag)
        if m:
            check(libs[0], "darwin", max_macos="%s.%s" % m.groups(), what=os.path.basename(whl), arch=arch)
            continue
        if tag == "win_amd64":
            check(libs[0], "windows", what=os.path.basename(whl), arch=arch)
            continue
        failures.append("%s: unrecognised platform tag %s" % (whl, tag))


def npm(d):
    for platform, (target_os, name) in sorted(NPM_TARGETS.items()):
        check(os.path.join(d, platform, name), target_os, what="npm " + platform, arch=platform_arch(platform))


def nuget(d):
    pkgs = glob.glob(os.path.join(d, "*.nupkg"))
    if len(pkgs) != 1:
        failures.append("expected one .nupkg in %s, found %d" % (d, len(pkgs)))
        return
    tmp = tempfile.mkdtemp()
    zipfile.ZipFile(pkgs[0]).extractall(tmp)
    for rid, (target_os, name) in sorted(NUGET_TARGETS.items()):
        check(os.path.join(tmp, "runtimes", rid, "native", name), target_os, what="NuGet " + rid, arch=platform_arch(rid))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--wheels")
    ap.add_argument("--npm")
    ap.add_argument("--nuget")
    a = ap.parse_args()
    if a.wheels:
        wheels(a.wheels)
    if a.npm:
        npm(a.npm)
    if a.nuget:
        nuget(a.nuget)
    if failures:
        print("\n%d package problem(s):" % len(failures))
        for f in failures:
            print("  " + f)
        sys.exit(1)
    print("\nall packaged native libraries check out")


if __name__ == "__main__":
    main()
