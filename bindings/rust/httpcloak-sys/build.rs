//! Builds or locates the httpcloak C library.
//!
//! By default the Go sources in `bindings/clib` are compiled into a static
//! archive with `go build -buildmode=c-archive` and linked into the crate, so a
//! Rust binary needs no shared library at run time. That needs a Go toolchain
//! (1.26 or newer, see `bindings/clib/go.mod`) and a C compiler for cgo.
//!
//! Environment variables:
//!
//! - `HTTPCLOAK_LIB_DIR`: link a prebuilt library from this directory instead
//!   of building one. It may hold `libhttpcloak.a`, `libhttpcloak.so` /
//!   `.dylib` / `httpcloak.dll`, or a release artifact named the way
//!   `bindings/clib/build.sh` names them (`libhttpcloak-linux-amd64.so`).
//! - `HTTPCLOAK_LINK`: `static` or `dynamic`, to choose when the directory
//!   holds both kinds. Building from source is always static.
//! - `HTTPCLOAK_GO_SRC`: the directory holding the clib Go package, when the
//!   crate is not inside the httpcloak repository.
//! - `GO`: the Go binary to run, `go` by default.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    for var in ["HTTPCLOAK_LIB_DIR", "HTTPCLOAK_LINK", "HTTPCLOAK_GO_SRC", "GO"] {
        println!("cargo:rerun-if-env-changed={var}");
    }

    // docs.rs has no Go toolchain, and documentation needs no library.
    if env::var_os("DOCS_RS").is_some() {
        return;
    }

    let target = Target::from_env();
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));

    let linkage = match env::var_os("HTTPCLOAK_LIB_DIR") {
        Some(dir) => link_prebuilt(&PathBuf::from(dir), &target),
        None => build_from_source(&out_dir, &target),
    };

    if linkage == Linkage::Static {
        link_system_libraries(&target);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Linkage {
    Static,
    Dynamic,
}

struct Target {
    os: String,
    arch: String,
    env: String,
    triple: String,
    host: String,
}

impl Target {
    fn from_env() -> Self {
        let var = |name: &str| env::var(name).unwrap_or_default();
        Target {
            os: var("CARGO_CFG_TARGET_OS"),
            arch: var("CARGO_CFG_TARGET_ARCH"),
            env: var("CARGO_CFG_TARGET_ENV"),
            triple: var("TARGET"),
            host: var("HOST"),
        }
    }

    fn goos(&self) -> &str {
        match self.os.as_str() {
            "macos" => "darwin",
            other => other,
        }
    }

    fn goarch(&self) -> &str {
        match self.arch.as_str() {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "x86" => "386",
            "powerpc64" => "ppc64",
            other => other,
        }
    }

    /// The suffix build.sh gives release artifacts: `linux-amd64`.
    fn artifact_suffix(&self) -> String {
        format!("{}-{}", self.goos(), self.goarch())
    }
}

fn link_prebuilt(dir: &Path, target: &Target) -> Linkage {
    if !dir.is_dir() {
        fail(&format!("HTTPCLOAK_LIB_DIR={} is not a directory", dir.display()));
    }
    let wanted = match env::var("HTTPCLOAK_LINK").ok().as_deref() {
        None | Some("") => None,
        Some("static") => Some(Linkage::Static),
        Some("dynamic") => Some(Linkage::Dynamic),
        Some(other) => fail(&format!("HTTPCLOAK_LINK must be \"static\" or \"dynamic\", not {other:?}")),
    };

    let suffix = target.artifact_suffix();
    let (static_ext, dynamic_ext, prefix) = match target.os.as_str() {
        "windows" => ("lib", "dll", ""),
        "macos" | "ios" => ("a", "dylib", "lib"),
        _ => ("a", "so", "lib"),
    };
    // A Go archive is a GNU-style archive even on Windows, where cargo's GNU
    // toolchain looks for libNAME.a.
    let static_names =
        ["libhttpcloak.a".to_string(), format!("libhttpcloak-{suffix}.a"), format!("httpcloak.{static_ext}")];
    let dynamic_names = [
        format!("{prefix}httpcloak.{dynamic_ext}"),
        format!("{prefix}httpcloak-{suffix}.{dynamic_ext}"),
        format!("libhttpcloak-{suffix}.{dynamic_ext}"),
    ];

    let find = |names: &[String]| names.iter().find(|n| dir.join(n).is_file()).cloned();
    let found_static = find(&static_names);
    let found_dynamic = find(&dynamic_names);

    let (linkage, file) = match (wanted, found_static, found_dynamic) {
        (Some(Linkage::Static), Some(s), _) | (None, Some(s), _) => (Linkage::Static, s),
        (Some(Linkage::Dynamic), _, Some(d)) | (None, None, Some(d)) => (Linkage::Dynamic, d),
        (want, _, _) => fail(&format!(
            "no {}httpcloak library for {} in HTTPCLOAK_LIB_DIR={}; looked for {:?}",
            match want {
                Some(Linkage::Static) => "static ",
                Some(Linkage::Dynamic) => "shared ",
                None => "",
            },
            suffix,
            dir.display(),
            match want {
                Some(Linkage::Static) => static_names.to_vec(),
                Some(Linkage::Dynamic) => dynamic_names.to_vec(),
                None => static_names.iter().chain(dynamic_names.iter()).cloned().collect(),
            },
        )),
    };

    println!("cargo:rerun-if-changed={}", dir.join(&file).display());
    println!("cargo:rustc-link-search=native={}", dir.display());
    let name = link_name(&file);
    match linkage {
        Linkage::Static => println!("cargo:rustc-link-lib=static={name}"),
        Linkage::Dynamic => println!("cargo:rustc-link-lib=dylib={name}"),
    }
    if let Some(header) = ["httpcloak.h", "libhttpcloak.h"].iter().map(|h| dir.join(h)).find(|h| h.is_file()) {
        println!("cargo:include={}", header.parent().unwrap().display());
    }
    linkage
}

/// The name `-l` takes for a library file: `libhttpcloak-linux-amd64.so` is
/// `httpcloak-linux-amd64`.
fn link_name(file: &str) -> String {
    let stem = file.rsplit_once('.').map_or(file, |(stem, _)| stem);
    stem.strip_prefix("lib").unwrap_or(stem).to_string()
}

fn build_from_source(out_dir: &Path, target: &Target) -> Linkage {
    if target.os == "windows" && target.env == "msvc" {
        fail(
            "a Go c-archive cannot be linked by the MSVC toolchain; build for a -windows-gnu target, \
             or point HTTPCLOAK_LIB_DIR at a prebuilt library",
        );
    }

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let src = match env::var_os("HTTPCLOAK_GO_SRC") {
        Some(dir) => PathBuf::from(dir),
        None => manifest_dir.join("..").join("..").join("clib"),
    };
    if !src.join("go.mod").is_file() {
        fail(&format!(
            "the httpcloak Go sources were not found at {}; set HTTPCLOAK_GO_SRC to bindings/clib, \
             or HTTPCLOAK_LIB_DIR to a directory holding a prebuilt library",
            src.display()
        ));
    }
    let src = src.canonicalize().unwrap_or(src);
    watch_go_sources(&src);

    let go = env::var_os("GO").unwrap_or_else(|| OsString::from("go"));
    let archive = out_dir.join("libhttpcloak.a");
    let mut cmd = Command::new(&go);
    cmd.current_dir(&src)
        .arg("build")
        .arg("-buildmode=c-archive")
        .arg("-trimpath")
        .arg("-ldflags=-s -w")
        .arg("-o")
        .arg(&archive)
        .arg(".")
        .env("CGO_ENABLED", "1")
        .env("GOOS", target.goos())
        .env("GOARCH", target.goarch());
    if target.arch == "arm" {
        // Rust's 32-bit ARM targets with hard float are ARMv7.
        cmd.env("GOARM", if target.triple.contains("v7") { "7" } else { "6" });
    }
    if target.host != target.triple {
        // cgo has to compile for the target too. Use the compiler cargo and
        // the cc crate would, by the same environment variables.
        let underscored = target.triple.replace('-', "_");
        let cc = [format!("CC_{}", target.triple), format!("CC_{underscored}"), "TARGET_CC".to_string()]
            .into_iter()
            .find_map(|v| {
                println!("cargo:rerun-if-env-changed={v}");
                env::var_os(v)
            });
        match cc {
            Some(cc) => {
                cmd.env("CC", cc);
            }
            None => println!(
                "cargo:warning=cross-compiling httpcloak for {} with Go's default C compiler; \
                 set CC_{} if cgo cannot find one",
                target.triple, underscored
            ),
        }
    }

    let status = match cmd.status() {
        Ok(status) => status,
        Err(e) => fail(&format!(
            "could not run {:?} to build the httpcloak library: {e}. Install Go 1.26 or newer, \
             set GO to its path, or set HTTPCLOAK_LIB_DIR to a prebuilt library",
            go
        )),
    };
    if !status.success() {
        fail(&format!("`go build -buildmode=c-archive` failed in {} ({status})", src.display()));
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=httpcloak");
    println!("cargo:include={}", out_dir.display());
    Linkage::Static
}

/// Tells cargo to rebuild when any Go source the archive is built from changes:
/// the clib package itself and, through its `replace ../..`, the root module.
/// The root is walked one level down rather than watched whole, since it holds
/// this crate's own target directory, which changes on every build.
fn watch_go_sources(src: &Path) {
    println!("cargo:rerun-if-changed={}", src.display());
    let Some(root) = src.parent().and_then(Path::parent) else { return };
    if !root.join("go.mod").is_file() {
        return;
    }
    let skip = ["bindings", "docs", "examples", "tests", ".git", ".github"];
    let Ok(entries) = fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !skip.contains(&name.as_ref()) && !name.starts_with('.') {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        } else if name.ends_with(".go") || name == "go.mod" || name == "go.sum" {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

/// What the Go runtime and cgo need from the platform once the archive is
/// linked statically. A shared library carries these itself.
fn link_system_libraries(target: &Target) {
    let libs: &[&str] = match target.os.as_str() {
        "linux" => &["pthread", "dl", "m", "resolv"],
        "android" => &["dl", "m", "log"],
        "macos" | "ios" => &["resolv"],
        "freebsd" | "netbsd" | "openbsd" | "dragonfly" => &["pthread", "m"],
        "windows" => &["ws2_32", "winmm", "userenv", "bcrypt", "ntdll"],
        _ => &[],
    };
    for lib in libs {
        println!("cargo:rustc-link-lib=dylib={lib}");
    }
    if matches!(target.os.as_str(), "macos" | "ios") {
        for framework in ["CoreFoundation", "Security"] {
            println!("cargo:rustc-link-lib=framework={framework}");
        }
    }
}

fn fail(message: &str) -> ! {
    // A panic's message is lost in cargo's backtrace noise; this way it is the
    // first thing in the build failure.
    eprintln!("error: {message}");
    panic!("httpcloak-sys: {message}");
}
