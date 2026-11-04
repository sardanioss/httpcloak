#!/usr/bin/env python3
"""Check that a built httpcloak native library will load on the machines its
package says it supports, before anything is published.

1.7.3 shipped a Windows DLL that imported libgcc_s_seh-1.dll, a MinGW runtime
library no Windows install has, so it failed to load everywhere (#131). The
Linux and macOS libraries had the same class of problem quietly for longer:
wheels tagged for glibc 2.17 and macOS 10.9/11.0 needed glibc 2.34 and macOS
14. Nothing checked what a library needs at load time; this does.

Static checks (any host; needs objdump for ELF and PE, Mach-O is parsed here):
  windows  every imported DLL is one every supported Windows ships
  linux    no glibc symbol version newer than --max-glibc, and only system
           libraries in DT_NEEDED
  darwin   minimum macOS no newer than --max-macos, and only system libraries
  all      the exports the bindings call are present

--load additionally loads the library in this process's OS and calls
httpcloak_version and a session create/free. On Windows the load runs in a
child whose PATH is only the Windows system directories, so a dependency the
build toolchain put on PATH cannot hide a missing one.

Standard library only; runs on the manylinux2014 Python (3.6+).
"""

import argparse
import ctypes
import os
import re
import struct
import subprocess
import sys

# DLLs present on every Windows the package supports (10 and later). The UCRT
# api-ms-win-crt-* sets are in-box from Windows 10, and msvcrt.dll in all.
WINDOWS_SYSTEM_DLLS = re.compile(
    r"^(kernel32|msvcrt|ucrtbase|ws2_32|advapi32|bcrypt|ntdll|user32|winmm|"
    r"api-ms-win-[a-z0-9-]+)\.dll$",
    re.IGNORECASE,
)
LINUX_SYSTEM_LIBS = re.compile(
    r"^(libc|libpthread|libresolv|libdl|libm|librt)\.so\.\d+$|^ld-linux[-a-z0-9_.]*\.so\.\d+$"
)
DARWIN_SYSTEM_LIB = re.compile(r"^(/usr/lib/|/System/Library/Frameworks/)")

# What the bindings call first; a library without these is not ours or is
# broken, whatever else it exports.
REQUIRED_EXPORTS = ("httpcloak_version", "httpcloak_session_new", "httpcloak_session_free", "httpcloak_free_string")


def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)


def objdump(args, path):
    try:
        return subprocess.check_output(["objdump"] + args + [path], stderr=subprocess.STDOUT).decode("utf-8", "replace")
    except (OSError, subprocess.CalledProcessError) as e:
        fail("objdump %s %s: %s" % (" ".join(args), path, e))


def version_tuple(s):
    return tuple(int(x) for x in s.split("."))


def check_windows(path):
    out = objdump(["-p"], path)
    dlls = re.findall(r"DLL Name:\s*(\S+)", out)
    if not dlls:
        fail("%s: no import table found" % path)
    bad = [d for d in dlls if not WINDOWS_SYSTEM_DLLS.match(d)]
    if bad:
        fail("%s imports DLLs a stock Windows does not have: %s" % (path, ", ".join(bad)))
    exports = set(re.findall(r"\]\s+(?:\+base\[\s*\d+\]\s+)?[0-9a-f]+\s+(httpcloak_\w+)", out))
    return dlls, exports


def check_linux(path, max_glibc):
    dyn = objdump(["-p"], path)
    needed = re.findall(r"NEEDED\s+(\S+)", dyn)
    bad = [n for n in needed if not LINUX_SYSTEM_LIBS.match(n)]
    if bad:
        fail("%s needs non-system libraries: %s" % (path, ", ".join(bad)))
    syms = objdump(["-T"], path)
    versions = set(re.findall(r"GLIBC_(\d+(?:\.\d+)+)", syms))
    newest = max(versions, key=version_tuple) if versions else "0"
    if version_tuple(newest) > version_tuple(max_glibc):
        users = sorted(set(re.findall(r"\(GLIBC_%s\)\s+(\S+)" % re.escape(newest), syms)))
        fail("%s needs glibc %s (for %s); its package promises %s" % (path, newest, ", ".join(users[:5]), max_glibc))
    exports = set(re.findall(r"\s(httpcloak_\w+)\s*$", syms, re.MULTILINE))
    return needed, newest, exports


def macho_info(path):
    """Load commands of a 64-bit little-endian Mach-O: dylibs, minimum macOS,
    and exported httpcloak_* names from the symbol table."""
    with open(path, "rb") as f:
        b = f.read()
    if struct.unpack_from("<I", b, 0)[0] != 0xFEEDFACF:
        fail("%s is not a 64-bit Mach-O" % path)
    ncmds = struct.unpack_from("<I", b, 16)[0]
    off, libs, minos, exports = 32, [], None, set()
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", b, off)
        if cmd in (0xC, 0x80000018):  # LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB
            name_off = struct.unpack_from("<I", b, off + 8)[0]
            libs.append(b[off + name_off:off + size].split(b"\0")[0].decode())
        elif cmd == 0x32:  # LC_BUILD_VERSION: platform, minos, sdk
            v = struct.unpack_from("<I", b, off + 12)[0]
            minos = "%d.%d" % (v >> 16, (v >> 8) & 0xFF)
        elif cmd == 0x24:  # LC_VERSION_MIN_MACOSX: version, sdk
            v = struct.unpack_from("<I", b, off + 8)[0]
            minos = "%d.%d" % (v >> 16, (v >> 8) & 0xFF)
        elif cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", b, off + 8)
            for i in range(nsyms):
                n_strx, n_type = struct.unpack_from("<IB", b, symoff + 16 * i)
                if n_type & 0x01 and (n_type & 0x0E) == 0x0E:  # N_EXT, N_SECT
                    name = b[stroff + n_strx:b.index(b"\0", stroff + n_strx)].decode("utf-8", "replace")
                    if name.startswith("_httpcloak_"):
                        exports.add(name[1:])
        off += size
    return libs, minos, exports


def check_darwin(path, max_macos):
    libs, minos, exports = macho_info(path)
    if minos is None:
        fail("%s declares no minimum macOS" % path)
    if version_tuple(minos) > version_tuple(max_macos):
        fail("%s needs macOS %s; its package promises %s" % (path, minos, max_macos))
    bad = [l for l in libs if not DARWIN_SYSTEM_LIB.match(l)]
    if bad:
        fail("%s links non-system libraries: %s" % (path, ", ".join(bad)))
    return libs, minos, exports


def load(path):
    """Load the library here and drive it the way a binding first does."""
    lib = ctypes.CDLL(os.path.abspath(path))
    lib.httpcloak_version.restype = ctypes.c_void_p
    lib.httpcloak_free_string.argtypes = [ctypes.c_void_p]
    lib.httpcloak_session_new.argtypes = [ctypes.c_char_p]
    lib.httpcloak_session_new.restype = ctypes.c_int64
    lib.httpcloak_session_free.argtypes = [ctypes.c_int64]
    p = lib.httpcloak_version()
    if not p:
        fail("httpcloak_version returned NULL")
    version = ctypes.string_at(p).decode()
    lib.httpcloak_free_string(p)
    handle = lib.httpcloak_session_new(b'{"preset":"chrome-latest"}')
    if handle <= 0:
        fail("httpcloak_session_new returned %d" % handle)
    lib.httpcloak_session_free(handle)
    return version


def load_isolated_windows(path):
    """Run load() in a child whose DLL search can only reach Windows itself."""
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join([os.path.join(sysroot, "System32"), sysroot])
    code = subprocess.call([sys.executable, os.path.abspath(__file__), "--load-only", os.path.abspath(path)], env=env)
    if code != 0:
        fail("%s did not load with PATH limited to the Windows system directories" % path)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("lib")
    ap.add_argument("--os", choices=["linux", "darwin", "windows"])
    ap.add_argument("--max-glibc", default="2.17", help="newest glibc the package promises to support")
    ap.add_argument("--max-macos", default="12.0", help="oldest macOS the package promises to support")
    ap.add_argument("--load", action="store_true", help="also load the library on this machine")
    ap.add_argument("--load-only", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()

    if a.load_only:
        print("loaded, version " + load(a.lib))
        return

    if not os.path.isfile(a.lib):
        fail("%s does not exist" % a.lib)
    if a.os == "windows":
        deps, exports = check_windows(a.lib)
        detail = "imports " + ", ".join(deps)
    elif a.os == "linux":
        deps, newest, exports = check_linux(a.lib, a.max_glibc)
        detail = "needs glibc %s (promised %s), libs %s" % (newest, a.max_glibc, ", ".join(deps))
    elif a.os == "darwin":
        deps, minos, exports = check_darwin(a.lib, a.max_macos)
        detail = "needs macOS %s (promised %s)" % (minos, a.max_macos)
    else:
        fail("--os is required")
    missing = [e for e in REQUIRED_EXPORTS if e not in exports]
    if missing:
        fail("%s does not export %s" % (a.lib, ", ".join(missing)))
    print("ok: %s: %s" % (a.lib, detail))

    if a.load:
        if a.os == "windows":
            load_isolated_windows(a.lib)
        else:
            print("loaded, version " + load(a.lib))


if __name__ == "__main__":
    main()
