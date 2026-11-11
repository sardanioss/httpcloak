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

# Every native function a binding calls has to be exported, or that binding
# fails at the call (.NET: "Unable to find an entry point named ..."). The
# names are read from the binding sources when they sit beside this script,
# as they do in the repo; REQUIRED_EXPORTS is the floor without them.
BINDING_SOURCES = ("python/httpcloak/*.py", "nodejs/lib/index.js", "dotnet/HttpCloak/Native.cs")


def binding_symbols():
    import glob
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    names = set()
    for pattern in BINDING_SOURCES:
        for f in glob.glob(os.path.join(root, pattern)):
            with open(f, encoding="utf-8") as fh:
                names |= set(re.findall(r"\bhttpcloak_[a-z0-9_]+\b", fh.read()))
    return names


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
    # Read from the file, like the exports below, so the check needs no
    # objdump on the Windows runner.
    dlls = pe_imports(path)
    if not dlls:
        fail("%s: no import table found" % path)
    bad = [d for d in dlls if not WINDOWS_SYSTEM_DLLS.match(d)]
    if bad:
        fail("%s imports DLLs a stock Windows does not have: %s" % (path, ", ".join(bad)))
    return dlls, pe_exports(path)


def _pe(path):
    """Opens a PE file: its bytes, an RVA-to-offset mapper and the offset of
    its data directory."""
    with open(path, "rb") as f:
        b = f.read()
    if b[:2] != b"MZ":
        fail("%s: not a PE file" % path)
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    if b[pe:pe + 4] != b"PE\0\0":
        fail("%s: not a PE file" % path)
    nsections = struct.unpack_from("<H", b, pe + 6)[0]
    opt_size = struct.unpack_from("<H", b, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", b, opt)[0]
    ddir = opt + (112 if magic == 0x20B else 96)  # PE32+ or PE32
    sections = []
    for i in range(nsections):
        sh = opt + opt_size + 40 * i
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", b, sh + 8)
        sections.append((vaddr, max(vsize, rsize), raddr))

    def off(rva):
        for vaddr, size, raddr in sections:
            if vaddr <= rva < vaddr + size:
                return rva - vaddr + raddr
        fail("%s: RVA 0x%x is outside every section" % (path, rva))

    return b, off, ddir


def _cstr(b, start):
    return b[start:b.index(b"\0", start)].decode("ascii", "replace")


def pe_imports(path):
    """Names of the DLLs a PE file imports, read from its import directory."""
    b, off, ddir = _pe(path)
    import_rva = struct.unpack_from("<I", b, ddir + 8)[0]
    if import_rva == 0:
        return []
    dlls = []
    d = off(import_rva)
    while True:
        orig_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", b, d)
        if name_rva == 0 and first_thunk == 0 and orig_thunk == 0:
            break
        dlls.append(_cstr(b, off(name_rva)))
        d += 20
    return dlls


def pe_exports(path):
    """Exported names of a PE file, read from its export directory.

    Read from the file rather than parsed out of objdump -p, whose export
    table layout changed between binutils releases: 2.44 prints an ordinal
    column the 2.42 on ubuntu-latest does not, and a pattern written for one
    found nothing in the other and failed a good DLL."""
    b, off, ddir = _pe(path)
    export_rva = struct.unpack_from("<I", b, ddir)[0]
    if export_rva == 0:
        return set()
    ed = off(export_rva)
    nnames, _, names_rva = struct.unpack_from("<III", b, ed + 24)
    names = set()
    table = off(names_rva)
    for i in range(nnames):
        names.add(_cstr(b, off(struct.unpack_from("<I", b, table + 4 * i)[0])))
    return {n for n in names if n.startswith("httpcloak_")}


def binary_arch(path):
    """The CPU a library is built for, read from its header: amd64, arm64,
    or the raw machine id for anything else."""
    with open(path, "rb") as f:
        head = f.read(4096)
    if head[:4] == b"\x7fELF":
        machine = struct.unpack_from("<H", head, 18)[0]
        return {62: "amd64", 183: "arm64"}.get(machine, "elf-machine-%d" % machine)
    if head[:4] == b"\xcf\xfa\xed\xfe":
        cpu = struct.unpack_from("<I", head, 4)[0]
        return {0x01000007: "amd64", 0x0100000C: "arm64"}.get(cpu, "macho-cpu-0x%x" % cpu)
    if head[:2] == b"MZ":
        pe = struct.unpack_from("<I", head, 0x3C)[0]
        machine = struct.unpack_from("<H", head, pe + 4)[0]
        return {0x8664: "amd64", 0xAA64: "arm64"}.get(machine, "pe-machine-0x%x" % machine)
    return "unknown"


def check_arch(path, expected):
    """A library built for the wrong CPU passes every other check and then
    fails to load on every machine the package goes to. The expected CPU
    comes from --arch, or else from the file name (libhttpcloak-OS-ARCH)."""
    if not expected:
        m = re.search(r"-(amd64|arm64)\.(?:so|dylib|dll)$", os.path.basename(path))
        expected = m.group(1) if m else None
    if not expected:
        return None
    got = binary_arch(path)
    if got != expected:
        fail("%s is built for %s; its name or package says %s" % (path, got, expected))
    return got


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
    ap.add_argument("--arch", choices=["amd64", "arm64"], help="CPU the package promises; defaults to the one in the file name")
    ap.add_argument("--load", action="store_true", help="also load the library on this machine")
    ap.add_argument("--load-only", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()

    if a.load_only:
        print("loaded, version " + load(a.lib))
        return

    if not os.path.isfile(a.lib):
        fail("%s does not exist" % a.lib)
    arch = check_arch(a.lib, a.arch)
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
    missing = sorted((set(REQUIRED_EXPORTS) | binding_symbols()) - set(exports))
    if missing:
        fail("%s does not export %s" % (a.lib, ", ".join(missing)))
    print("ok: %s: %s%s" % (a.lib, detail, ", %s" % arch if arch else ""))

    if a.load:
        if a.os == "windows":
            load_isolated_windows(a.lib)
        else:
            print("loaded, version " + load(a.lib))


if __name__ == "__main__":
    main()
