//! Holds the declarations in src/lib.rs to the header cgo generates for the
//! library they link, so a function added, removed or changed in
//! bindings/clib cannot drift from them unnoticed.

use std::collections::BTreeMap;

/// `name -> (return type, parameter types)`, in C spelling.
type Signatures = BTreeMap<String, (String, Vec<String>)>;

fn header() -> Option<String> {
    let dir = std::path::Path::new(env!("OUT_DIR"));
    ["libhttpcloak.h", "httpcloak.h"].iter().find_map(|h| std::fs::read_to_string(dir.join(h)).ok())
}

fn normalize_c(ty: &str) -> String {
    let ty = ty.replace("const ", "");
    let ty = ty.split_whitespace().collect::<Vec<_>>().join(" ");
    ty.replace(" *", "*").trim().to_string()
}

/// `extern char* httpcloak_version(void);` and the like.
fn parse_header(text: &str) -> Signatures {
    let mut out = Signatures::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("extern ") else { continue };
        let Some((head, params)) = rest.trim_end_matches(';').split_once('(') else { continue };
        let Some(name) = head.split([' ', '*']).next_back().filter(|n| n.starts_with("httpcloak_")) else {
            continue;
        };
        let ret = normalize_c(&head[..head.len() - name.len()]);
        let params = params.trim_end_matches(')');
        let params = if params.trim() == "void" || params.trim().is_empty() {
            Vec::new()
        } else {
            params
                .split(',')
                .map(|p| {
                    // Drop the parameter name: the last identifier.
                    let p = p.trim();
                    let cut = p.rfind([' ', '*']).map_or(0, |i| i + 1);
                    normalize_c(&p[..cut])
                })
                .collect()
        };
        out.insert(name.to_string(), (ret, params));
    }
    out
}

/// The C spelling of a Rust FFI type, as these declarations use them.
fn rust_to_c(ty: &str) -> String {
    let ty = ty.split_whitespace().collect::<Vec<_>>().join(" ");
    match ty.as_str() {
        "" | "()" => "void",
        "i64" => "int64_t",
        "c_int" => "int",
        "*const c_char" | "*mut c_char" => "char*",
        "*const c_void" | "*mut c_void" => "void*",
        "*mut c_int" => "int*",
        "*mut i64" => "int64_t*",
        "*mut FastResponseMeta" => "FastResponseMeta*",
        other => return other.to_string(), // callback typedefs keep their names
    }
    .to_string()
}

/// The `pub fn` declarations in the `extern "C"` block of src/lib.rs.
fn parse_rust(text: &str) -> Signatures {
    let mut out = Signatures::new();
    let block = &text[text.find("extern \"C\" {").expect("no extern block")..];
    let mut rest = block;
    while let Some(i) = rest.find("pub fn ") {
        rest = &rest[i + "pub fn ".len()..];
        let end = rest.find(';').unwrap();
        let decl = &rest[..end];
        let (name, sig) = decl.split_once('(').unwrap();
        let (params, ret) = sig.rsplit_once(')').unwrap();
        let params = params
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| rust_to_c(p.split_once(':').unwrap().1.trim()))
            .collect();
        let ret = rust_to_c(ret.trim().trim_start_matches("->").trim());
        out.insert(name.trim().to_string(), (ret, params));
        rest = &rest[end..];
    }
    out
}

#[test]
fn declarations_match_the_generated_header() {
    let Some(header) = header() else {
        eprintln!("no generated header (a prebuilt library without one); skipping");
        return;
    };
    let c = parse_header(&header);
    let rust = parse_rust(include_str!("../src/lib.rs"));
    assert!(c.len() > 100, "parsed only {} functions from the header", c.len());

    let mut problems = Vec::new();
    for (name, sig) in &c {
        match rust.get(name) {
            None => problems.push(format!("{name} is exported but not declared")),
            Some(r) if r != sig => problems.push(format!("{name}: header has {sig:?}, lib.rs has {r:?}")),
            Some(_) => {}
        }
    }
    for name in rust.keys().filter(|n| !c.contains_key(*n)) {
        problems.push(format!("{name} is declared but no longer exported"));
    }
    assert!(problems.is_empty(), "\n{}", problems.join("\n"));
}

#[test]
fn the_library_links_and_answers() {
    // SAFETY: plain calls; the string is freed with the library's own free.
    unsafe {
        let v = httpcloak_sys::httpcloak_version();
        assert!(!v.is_null());
        let version = std::ffi::CStr::from_ptr(v).to_str().unwrap().to_owned();
        httpcloak_sys::httpcloak_free_string(v);
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
    }
}
