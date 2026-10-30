"""Lex authored AllowIt policy source, derive its standard prefix and compile it against the
std-only `allowit` backend. Standard library only, plus `rustc` for `host_compile`.

`check-policy-bindings.py` and `contract_admin.py` share this module. Comments and literals are
removed with Rust lexing first, so they cannot add, hide or rebind code."""
import atexit
import functools
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWIT = ROOT / "crates/allowit/src"

# Typed Grant fields, which are also the canonical rule names.
GRANT_FIELDS = ("transaction_cap", "spent_cap", "day_spent_cap", "day_total_cap", "call_cap", "recipients", "tokens", "expiry")

# One prefix statement after whitespace removal: `allowit::<rule>(ctx,&ctx.grant.<rule>)?`. rustfmt may add a comma.
PREFIX_CALL = re.compile(r"allowit::([a-z_]+)\(ctx,&ctx\.grant\.([a-z_]+),?\)\?")
EXECUTE = re.compile(r"\bpub\s+fn\s+execute\s*\(\s*ctx\s*:\s*&\s*AllowitContext\s*\)\s*->\s*allowit\s*::\s*Result(?:\s*<\s*\(\s*\)\s*>)?\s*\{")

# Rust literals that can hide code from a plain scan: raw, byte, C and plain strings, then char
# literals. A quote that starts no char literal is a lifetime or label.
RAW_STRING = re.compile(r'(?<![A-Za-z0-9_])[bc]?r(#*)"')
STRING = re.compile(r'(?<![A-Za-z0-9_])[bc]?"(?:\\[\s\S]|[^"\\])*"')
CHAR = re.compile(r"(?<![A-Za-z0-9_])b?'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,8}\}|[^\n])|[^\\'\n])'")

# `allowit` names the canonical crate only as a path root: `allowit::<item>`. Any other use of the
# identifier declares or imports a replacement (`mod allowit`, `use x as allowit`, `fn allowit`,
# `macro_rules! allowit`, `let allowit`) or reaches another module (`self::allowit`).
ALLOWIT_NAME = re.compile(r"\ballowit\b")
# Code that reads other files, the build environment or the including crate, so the one hashed
# file would not be the whole policy, or that can behave differently in `AllowitCustomPolicy` and on
# the host: `#[path]`, `cfg_attr` (which can add `path`), an out-of-line module, `extern` items,
# `unsafe` code and symbol attributes, macro definitions (which can assemble paths that the root
# check below cannot see), conditional compilation, debug-only assertions, mutable statics (which
# keep values across host evaluations but start again in every contract instance), and location,
# type, layout, width, pointer and formatting introspection. File and environment macros are
# checked by `MACRO_NAMES`, and path roots by `path_roots`.
OUTSIDE = (
    (re.compile(r"#\s*\[\s*path\b"), "#[path] attribute"),
    (re.compile(r"\bcfg_attr\b"), "cfg_attr attribute"),
    (re.compile(r"\bmod\s+[^{};]*;"), "out-of-line module"),
    (re.compile(r"\bextern\b"), "extern item"),
    (re.compile(r"\b(?:unsafe|no_mangle|export_name|link_section)\b"), "unsafe code or symbol attribute"),
    (re.compile(r"\bmacro_rules\b"), "macro definition"),
    (re.compile(r"\bcfg\b"), "conditional compilation"),
    (re.compile(r"\bdebug_assert(?:_eq|_ne)?\b"), "debug-only assertion"),
    (re.compile(r"(?<!')\bstatic\b"), "static item"),
    (re.compile(r"\b(?:module_path|type_name|type_name_of_val|Location|caller|TypeId|type_id|size_of|size_of_val|"
                r"align_of|align_of_val|needs_drop|Layout|offset_of|BITS|usize|isize)\b|\bfile\s*!"),
     "location, type, layout or width introspection"),
    (re.compile(r"\*\s*(?:const|mut)\b|\b(?:ptr|addr_of|addr_of_mut|as_ptr|as_mut_ptr|expose_provenance)\b|\.\s*addr\s*\("),
     "pointer introspection"),
    (re.compile(r"\b(?:fmt|write|writeln|format_args)\b"), "formatting"),
    (re.compile(r"\b(?:crate|super|self)\s*::"), "path into the including crate"),
)
# File and environment macros. Their names may appear only as the bare context field read
# `ctx.env`: after a single `.` and not followed by `.`, `(` or `!`, so neither `ctx.env.<method>`
# nor a value's `env()` method, such as the Soroban `Address::env`, passes.
MACRO_NAMES = re.compile(r"\b(?:include|include_str|include_bytes|env|option_env)\b")
# Path roots that name the same thing in every including crate: the canonical crate, `core` and
# the fixed-width primitive types. A capitalized root is a type, trait, enum or generic parameter;
# no crate in the extern prelude of an including crate has a capitalized name. Every other root,
# such as `soroban_sdk`, `std`, `alloc` or `allowit_policy_wallet`, can reach a dependency of the
# including crate, and a lowercase local name cannot be told apart from one lexically.
ROOTS = frozenset(("allowit", "core", "bool", "char", "str", "f32", "f64") + tuple(
    sign + str(bits) for sign in "iu" for bits in (8, 16, 32, 64, 128)))
KEYWORDS = frozenset((
    "as", "async", "await", "box", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "fn",
    "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "self",
    "static", "struct", "super", "trait", "type", "union", "unsafe", "use", "where", "while", "yield"))
TOKEN = re.compile(r"r#[A-Za-z_]\w*|[A-Za-z_]\w*|::|=>|->|\$\w*|'\w+|\d\w*|\S")
IDENT = re.compile(r"(?:r#)?[A-Za-z_]\w*")


def root_error(name):
    """Return why a path root is not allowed, or None."""
    name = name.removeprefix("r#")
    if name in ROOTS or name[:1].isupper():
        return None
    return "path rooted at `{}`; roots must be `allowit`, `core`, a primitive type or a capitalized type".format(name)


def use_roots(tokens, i):
    """Yield the root token of each tree of the `use` declaration whose tree starts at tokens[i]."""
    if i >= len(tokens):
        return
    if tokens[i] != "{":
        yield tokens[i]
        return
    depth, start = 0, i + 1
    for j in range(i, len(tokens)):
        depth += (tokens[j] == "{") - (tokens[j] == "}")
        if depth == 1 and tokens[j] == "," or depth == 0:
            yield from use_roots(tokens, start)
            start = j + 1
        if depth == 0:
            return


def path_roots(code):
    """Raise ValueError when a path or `use` tree starts at a root other than `ROOTS` or a capitalized
    name. A bare `::` root, after a keyword or punctuation other than `>`, reaches the extern prelude."""
    tokens = TOKEN.findall(code)
    for i, token in enumerate(tokens):
        before = tokens[i - 1] if i else ""
        if token == "::":
            if not IDENT.fullmatch(before) and before != ">" or before in KEYWORDS:
                raise ValueError("Policy source must be one self-contained file; it uses a path rooted at ::")
            # A segment after `::` or `.` (method turbofish), or before `<` (turbofish), is no root.
            segment = i >= 2 and tokens[i - 2] in ("::", ".") or tokens[i + 1:i + 2] == ["<"]
            if IDENT.fullmatch(before) and not segment and (error := root_error(before)):
                raise ValueError("Policy source must be one self-contained file; it uses a " + error)
        elif token == "use" and before != ".":
            for root in use_roots(tokens, i + 1):
                if root not in ("::", "}") and (not IDENT.fullmatch(root) or (error := root_error(root))):
                    raise ValueError("Policy source must be one self-contained file; it uses a "
                                     + (error if IDENT.fullmatch(root) else "use tree rooted at " + root))


def rust_code(source):
    """Return source with comments blanked and literals replaced by `0`, so only code remains.
    Block comments nest as in Rust. An unterminated comment or literal is rejected."""
    out, i, n = [], 0, len(source)
    while i < n:
        if source.startswith("//", i):
            end = source.find("\n", i)
            i = n if end < 0 else end
            out.append(" ")
        elif source.startswith("/*", i):
            depth, i = 1, i + 2
            while depth:
                if i >= n:
                    raise ValueError("Policy source has an unterminated block comment")
                step = source[i:i + 2]
                depth += (step == "/*") - (step == "*/")
                i += 2 if step in ("/*", "*/") else 1
            out.append(" ")
        elif raw := RAW_STRING.match(source, i):
            end = source.find('"' + raw[1], raw.end())
            if end < 0:
                raise ValueError("Policy source has an unterminated raw string")
            i = end + 1 + len(raw[1])
            out.append(" 0 ")
        elif literal := STRING.match(source, i) or CHAR.match(source, i):
            i = literal.end()
            out.append(" 0 ")
        elif source[i] == '"' or source.startswith(('b"', 'c"'), i):
            raise ValueError("Policy source has an unterminated string")
        else:
            out.append(source[i])
            i += 1
    return "".join(out)


def checked_code(source):
    """Return the code of one self-contained policy file that binds `allowit` only to the canonical
    crate. Reject inner attributes and doc comments, which the including module cannot accept."""
    if re.search(r"^\s*(//!|/\*!|#\s*!\s*\[)", source, re.M):
        raise ValueError("Policy source must not use inner attributes or inner doc comments")
    code = rust_code(source)
    for found in ALLOWIT_NAME.finditer(code):
        before, after = code[:found.start()].rstrip(), code[found.end():].lstrip()
        if not after.startswith("::") or before.endswith("::"):
            raise ValueError("Policy source must use `allowit` only as the path root `allowit::`; it must not rebind it")
    for found in MACRO_NAMES.finditer(code):
        before, after = code[:found.start()].rstrip(), code[found.end():].lstrip()
        field = before.endswith(".") and not before.endswith("..")
        if not field or after.startswith((".", "(")) or after.startswith("!") and not after.startswith("!="):
            raise ValueError("Policy source must be one self-contained file; it uses file or environment macro")
    for pattern, name in OUTSIDE:
        if pattern.search(code):
            raise ValueError("Policy source must be one self-contained file; it uses " + name)
    path_roots(code)
    return code


def standard_prefix(source):
    """Return the standard prefix of authored policy source: the consecutive leading statements of
    `execute` of the exact form `allowit::<rule>(ctx, &ctx.grant.<rule>)?;`. Any other statement ends it."""
    text = checked_code(source)
    found = list(EXECUTE.finditer(text))
    if len(found) != 1 or len(re.findall(r"\bexecute\b", text)) != 1:
        raise ValueError("Policy source must define pub fn execute(ctx: &AllowitContext) -> allowit::Result once")
    rules = []
    for statement in text[found[0].end():].split(";"):
        call = PREFIX_CALL.fullmatch(re.sub(r"\s+", "", statement))
        if not call or call[1] != call[2] or call[1] not in GRANT_FIELDS:
            break
        rules.append(call[1])
    return rules


@functools.lru_cache(maxsize=None)
def _host_allowit(rustc, digest):
    """Compile `allowit` with only the `std` feature once per process and sources digest."""
    out = Path(tempfile.mkdtemp(prefix="allowit-host-"))
    atexit.register(shutil.rmtree, out, True)
    lib = out / "liballowit.rlib"
    _rustc(rustc, ["--crate-type=rlib", "--crate-name=allowit", "--cfg", 'feature="std"',
                   str(ALLOWIT / "lib.rs"), "-o", str(lib)], "allowit std backend")
    return lib


def _rustc(rustc, args, what):
    command = [rustc, "--edition=2024", "-C", "overflow-checks=on"] + args
    try:
        result = subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError:
        raise ValueError("The std-only policy compile requires rustc (set RUSTC or PATH)") from None
    if result.returncode:
        raise ValueError("Policy source fails the std-only compile of the " + what + ":\n" + result.stderr.strip())


def host_compile(path):
    """Compile authored policy source as the offchain server does: as a module of a `no_std` crate
    whose only dependency is `allowit` with only the `std` feature, with overflow checks on. Raise
    ValueError when it does not compile, for example when it names `soroban_sdk`, calls a Soroban
    `Env` or `Address` method, orders addresses or uses a host-only `std` prelude item."""
    rustc = os.environ.get("RUSTC") or "rustc"
    digest = hashlib.sha256(b"".join((ALLOWIT / name).read_bytes() for name in ("lib.rs", "core.rs"))).hexdigest()
    lib = _host_allowit(rustc, digest)
    source = str(Path(path).resolve())
    if '"#' in source or "\n" in source:
        raise ValueError("Policy source path cannot be named in a Rust raw string")
    with tempfile.TemporaryDirectory(prefix="allowit-policy-") as out:
        crate = Path(out) / "policy_host.rs"
        crate.write_text("#![no_std]\n#[path = r#\"" + source + "\"#]\nmod policy;\n"
                         "pub const EXECUTE: fn(&allowit::AllowitContext) -> allowit::Result = policy::execute;\n")
        _rustc(rustc, ["--crate-type=rlib", "--crate-name=policy_host", "--extern", "allowit=" + str(lib),
                       str(crate), "-o", str(Path(out) / "libpolicy_host.rlib")], "policy")
