# httpcloak: Full Documentation
"""Regenerate static/llms-full.txt: every docs page, in sidebar order.

Run from docs/: python3 scripts/gen-llms-full.py
Front matter and MDX import lines are dropped; everything else is kept as written.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")

HEADER = """# httpcloak: Full Documentation

This file is the entire httpcloak documentation site, concatenated for easy AI-agent consumption. Sections are listed in the same order as the sidebar at https://httpcloak.dev/. Source: https://github.com/sardanioss/httpcloak/tree/main/docs/docs

---

"""


def sidebar_ids():
    src = open(os.path.join(ROOT, "sidebars.ts"), encoding="utf-8").read()
    ids = []
    # Bare string items and `id: '...'` link targets, in file order.
    for m in re.finditer(r"""(?:id:\\s*)?['"]([a-z0-9][a-z0-9/_-]*)['"]""", src):
        token = m.group(0)
        if token.startswith("id") or re.fullmatch(r"""['"][a-z0-9][a-z0-9/_-]*['"]""", token):
            if m.group(1) not in ids and m.group(1) not in ("category", "doc", "lang"):
                ids.append(m.group(1))
    return ids


def page_path(doc_id):
    for ext in (".md", ".mdx"):
        p = os.path.join(DOCS, doc_id + ext)
        if os.path.exists(p):
            return p
    return None


def clean(text):
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            text = text[end + 5:]
    out, fence = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fence = not fence
        if not fence and re.match(r"^import\s.+\sfrom\s['\"]", line):
            continue
        out.append(line)
    return "\n".join(out).strip("\n") + "\n"


def main():
    parts, seen = [HEADER], set()
    for doc_id in sidebar_ids():
        path = page_path(doc_id)
        if not path or path in seen:
            continue
        seen.add(path)
        rel = os.path.relpath(path, os.path.dirname(ROOT))
        parts.append(f"\n\n<!-- source: {rel} -->\n\n" + clean(open(path, encoding="utf-8").read()))
    missing = sorted(
        os.path.relpath(os.path.join(d, f), DOCS)
        for d, _, fs in os.walk(DOCS) for f in fs
        if f.endswith((".md", ".mdx")) and os.path.join(d, f) not in seen
    )
    open(os.path.join(ROOT, "static", "llms-full.txt"), "w", encoding="utf-8").write("".join(parts))
    print(f"{len(seen)} pages written")
    if missing:
        print("not in the sidebar, left out:", *missing, sep="\n  ", file=sys.stderr)


if __name__ == "__main__":
    main()
