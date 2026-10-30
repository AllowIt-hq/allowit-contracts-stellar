"""Lex authored AllowIt policy source and derive its standard prefix. Standard library only.

`check-policy-bindings.py` and `contract_admin.py` share this module. Comments and literals are
removed with Rust lexing first, so they cannot add, hide or rebind code."""
import re

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
ALLOWIT = re.compile(r"\ballowit\b")
# Code that reads other files, the build environment or the including crate, so the one hashed
# file would not be the whole policy, or that can behave differently in CustomPolicy and on the
# host: file and environment macros, `#[path]`, `cfg_attr` (which can add `path`), an out-of-line
# module, `extern crate`, conditional compilation, location and type-name introspection, and paths
# rooted at `crate`, `super`, `self` or a bare `::`.
OUTSIDE = (
    (re.compile(r"\b(?:include|include_str|include_bytes|env|option_env)\b"), "file or environment macro"),
    (re.compile(r"#\s*\[\s*path\b"), "#[path] attribute"),
    (re.compile(r"\bcfg_attr\b"), "cfg_attr attribute"),
    (re.compile(r"\bmod\s+[^{};]*;"), "out-of-line module"),
    (re.compile(r"\bextern\s+crate\b"), "extern crate"),
    (re.compile(r"\bcfg\b"), "conditional compilation"),
    (re.compile(r"\b(?:module_path|type_name|type_name_of_val)\b|\bfile\s*!"), "location or type-name introspection"),
    (re.compile(r"\b(?:crate|super|self)\s*::"), "path into the including crate"),
    (re.compile(r"(?:^|[^\w>\s])\s*::"), "path rooted at ::"),
)


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
    for found in ALLOWIT.finditer(code):
        before, after = code[:found.start()].rstrip(), code[found.end():].lstrip()
        if not after.startswith("::") or before.endswith("::"):
            raise ValueError("Policy source must use `allowit` only as the path root `allowit::`; it must not rebind it")
    for pattern, name in OUTSIDE:
        if pattern.search(code):
            raise ValueError("Policy source must be one self-contained file; it uses " + name)
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
