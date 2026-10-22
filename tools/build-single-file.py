#!/usr/bin/env python3
"""Build the single runnable file php2shell_check.py from the package php2shell_check/.

    python3 tools/build-single-file.py           # write php2shell_check.py
    python3 tools/build-single-file.py --check   # exit 1 if the committed file is out of date

The package is the source (one module per concern, each under 1,000 lines); the single
file is what people run with `curl ... | python3 -` and what the GitHub Action runs. It is
the package's docstring, one set of standard-library imports, then each module's code in
MODULES order with its own docstring and imports taken out (the package's own imports are
not needed once everything is one namespace). A name defined in two modules stops the
build, since one file has one namespace. Standard library only.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "php2shell_check"
OUT = ROOT / "php2shell_check.py"
MODULES = ("safety", "detect", "blocked", "fetch", "advisories", "cards", "cli")   # each after what it uses
MARK = "# GENERATED from php2shell_check/ by tools/build-single-file.py — do not edit"


def defined(tree: ast.Module) -> list:
    """The top-level names a module defines."""
    out = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            out.append(node.name)
        elif isinstance(node, ast.Assign):
            out += [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            out.append(node.target.id)
    return out


def split(text: str) -> tuple:
    """(the code without its docstring and imports, plain imports, {module: names} from-imports)."""
    tree = ast.parse(text)
    lines = text.split("\n")
    drop, plain, froms = set(), set(), {}
    for i, node in enumerate(tree.body):
        is_doc = i == 0 and isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant) \
            and isinstance(node.value.value, str)
        if is_doc or isinstance(node, (ast.Import, ast.ImportFrom)):
            drop.update(range(node.lineno - 1, node.end_lineno))
        if isinstance(node, ast.Import):
            plain.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module != "__future__":
            froms.setdefault(node.module, set()).update(a.name for a in node.names)
    code = "\n".join(line for n, line in enumerate(lines) if n not in drop).strip("\n")
    return code, plain, froms, tree


def build() -> str:
    doc = ast.get_docstring(ast.parse((PACKAGE / "__init__.py").read_text(encoding="utf-8")), clean=False)
    plain, froms, parts, owner = set(), {}, [], {}
    for name in MODULES:
        code, p, f, tree = split((PACKAGE / f"{name}.py").read_text(encoding="utf-8"))
        for d in defined(tree):
            if d in owner and d != "__version__":
                sys.exit(f"{d} is defined in both {owner[d]}.py and {name}.py: one file has one namespace")
            owner[d] = name
        plain |= p
        for module, names in f.items():
            froms.setdefault(module, set()).update(names)
        parts.append(f"# {'-' * 66} {name}.py\n\n{code}")
    imports = [f"import {m}" for m in sorted(plain)]
    imports += [f"from {m} import {', '.join(sorted(n))}" for m, n in sorted(froms.items())]
    return "\n".join(["#!/usr/bin/env python3", MARK, f'"""{doc}"""', "from __future__ import annotations", "",
                      *imports, "", "", "\n\n\n".join(parts), "", "",
                      'if __name__ == "__main__":', "    sys.exit(main())", ""])


def main(argv: list) -> int:
    text = build()
    if "--check" in argv:
        if OUT.exists() and OUT.read_text(encoding="utf-8") == text:
            print(f"{OUT.name} is up to date")
            return 0
        print(f"{OUT.name} is out of date: run python3 tools/build-single-file.py and commit it", file=sys.stderr)
        return 1
    OUT.write_text(text, encoding="utf-8")
    OUT.chmod(0o755)
    print(f"{OUT.name}: {text.count(chr(10))} lines from {len(MODULES)} modules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
