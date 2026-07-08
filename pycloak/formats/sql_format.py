"""SQL dump processor.

Parses INSERT statements (mysqldump / pg_dump style), masks per-column
values via the anonymizer, and re-emits the statement. Non-INSERT
statements (CREATE TABLE, SET, comments, ...) pass through unchanged.

Supported syntax:
    INSERT INTO `users` (`id`, `email`) VALUES (1, 'a@b.com');
    INSERT INTO "users" ("id", "email") VALUES (1, 'a@b.com'), (2, 'b@c.com');
    INSERT INTO public.users VALUES (1, 'a@b.com');     -- no column list
    INSERT INTO users (id, name) VALUES (1, 'a''b');    -- '' escape
    INSERT INTO users (id, name) VALUES (1, 'a\\'b');   -- MySQL \\' escape

If a statement has no column list, values are left unchanged (we can't
match rules by column name). A warning would be the right behavior in a
verbose mode; for now we silently pass them through.
"""
from __future__ import annotations

import re
from typing import IO, Iterator, List, Optional

from ..anonymizer import Anonymizer

_INSERT_RE = re.compile(
    r"""^(?P<prefix>\s*INSERT\s+INTO\s+
        (?P<table>`[^`]+`|"[^"]+"|[\w.]+)
        \s*
        (?:\((?P<cols>[^)]+)\))?
        \s*VALUES\s*
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def process_sql(input_file: IO, output_file: IO, anonymizer: Anonymizer) -> int:
    """Stream a SQL dump statement-by-statement. Returns rows masked."""
    count = 0
    for stmt in _iter_statements(input_file):
        m = _INSERT_RE.match(stmt)
        if not m:
            output_file.write(stmt)
            if not stmt.rstrip().endswith(";"):
                output_file.write(";")
            output_file.write("\n")
            continue

        prefix = m.group("prefix")
        cols_raw = m.group("cols")
        columns: Optional[List[str]] = (
            [_strip_quotes(c) for c in cols_raw.split(",")] if cols_raw else None
        )

        values_blob = stmt[m.end() :].rstrip().rstrip(";").rstrip()
        tuples = _parse_value_tuples(values_blob)

        masked_tuples: List[List[object]] = []
        for raw_tokens in tuples:
            values = [_decode_sql_literal(t) for t in raw_tokens]
            if columns and len(columns) == len(values):
                record = dict(zip(columns, values))
                masked = anonymizer.process_record(record)
                values = [masked[c] for c in columns]
            masked_tuples.append(values)
            count += 1

        output_file.write(prefix)
        for i, vals in enumerate(masked_tuples):
            if i > 0:
                output_file.write(", ")
            output_file.write("(" + ", ".join(_encode_sql_literal(v) for v in vals) + ")")
        output_file.write(";\n")

    return count


# --- statement splitting ------------------------------------------------------

def _iter_statements(file: IO) -> Iterator[str]:
    """Yield SQL statements (terminated by ';'). Tracks string state so
    semicolons inside strings don't split statements.
    """
    buf: List[str] = []
    state = "OUT"  # OUT | SQ | DQ | BT | LINE_COMMENT | BLOCK_COMMENT
    for line in file:
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            nxt = line[i + 1] if i + 1 < n else ""
            if state == "OUT":
                if ch == "-" and nxt == "-":
                    state = "LINE_COMMENT"
                    buf.append(ch)
                elif ch == "/" and nxt == "*":
                    state = "BLOCK_COMMENT"
                    buf.append(ch)
                elif ch == "'":
                    state = "SQ"
                    buf.append(ch)
                elif ch == '"':
                    state = "DQ"
                    buf.append(ch)
                elif ch == "`":
                    state = "BT"
                    buf.append(ch)
                elif ch == ";":
                    buf.append(ch)
                    stmt = "".join(buf).strip()
                    if stmt:
                        yield stmt
                    buf = []
                else:
                    buf.append(ch)
            elif state == "LINE_COMMENT":
                buf.append(ch)
                if ch == "\n":
                    state = "OUT"
            elif state == "BLOCK_COMMENT":
                buf.append(ch)
                if ch == "*" and nxt == "/":
                    buf.append(nxt)
                    i += 1
                    state = "OUT"
            elif state == "SQ":
                buf.append(ch)
                if ch == "\\" and nxt:
                    buf.append(nxt)
                    i += 1
                elif ch == "'":
                    if nxt == "'":
                        buf.append(nxt)
                        i += 1
                    else:
                        state = "OUT"
            elif state == "DQ":
                buf.append(ch)
                if ch == "\\" and nxt:
                    buf.append(nxt)
                    i += 1
                elif ch == '"':
                    if nxt == '"':
                        buf.append(nxt)
                        i += 1
                    else:
                        state = "OUT"
            elif state == "BT":
                buf.append(ch)
                if ch == "`":
                    state = "OUT"
            i += 1
    tail = "".join(buf).strip()
    if tail:
        yield tail


# --- VALUES tuple parsing -----------------------------------------------------

def _parse_value_tuples(text: str) -> List[List[str]]:
    """Parse '(v1, v2), (v3, v4)' into [['v1','v2'], ['v3','v4']]."""
    tuples: List[List[str]] = []
    n = len(text)
    i = 0
    while i < n:
        while i < n and text[i] != "(":
            i += 1
        if i >= n:
            break
        i += 1  # skip '('
        tokens: List[str] = []
        cur: List[str] = []
        depth = 0
        in_string: Optional[str] = None
        while i < n:
            ch = text[i]
            nxt = text[i + 1] if i + 1 < n else ""
            if in_string:
                cur.append(ch)
                if ch == "\\" and nxt:
                    cur.append(nxt)
                    i += 2
                    continue
                if ch == in_string:
                    if nxt == in_string:
                        cur.append(nxt)
                        i += 2
                        continue
                    in_string = None
                i += 1
                continue
            if ch in ("'", '"'):
                in_string = ch
                cur.append(ch)
            elif ch == "(":
                depth += 1
                cur.append(ch)
            elif ch == ")":
                if depth > 0:
                    depth -= 1
                    cur.append(ch)
                else:
                    tokens.append("".join(cur).strip())
                    i += 1
                    break
            elif ch == "," and depth == 0:
                tokens.append("".join(cur).strip())
                cur = []
            else:
                cur.append(ch)
            i += 1
        if tokens:
            tuples.append(tokens)
    return tuples


# --- literal encoding / decoding ---------------------------------------------

def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("`", '"'):
        return s[1:-1]
    return s


def _decode_sql_literal(s: str):
    s = s.strip()
    upper = s.upper()
    if upper == "NULL":
        return None
    if upper == "TRUE":
        return True
    if upper == "FALSE":
        return False
    if len(s) >= 2 and s[0] == "'" and s[-1] == "'":
        inner = s[1:-1]
        out: List[str] = []
        i = 0
        while i < len(inner):
            ch = inner[i]
            nxt = inner[i + 1] if i + 1 < len(inner) else ""
            if ch == "'" and nxt == "'":
                out.append("'")
                i += 2
            elif ch == "\\" and nxt:
                out.append({"n": "\n", "t": "\t", "r": "\r", "0": "\0"}.get(nxt, nxt))
                i += 2
            else:
                out.append(ch)
                i += 1
        return "".join(out)
    try:
        if "." in s or "e" in s.lower():
            return float(s)
        return int(s)
    except ValueError:
        return s  # leave function calls (NOW(), UUID()) etc. as raw tokens


def _encode_sql_literal(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "TRUE" if v else "FALSE"
    if isinstance(v, (int, float)):
        return str(v)
    s = str(v)
    # Standard SQL: double up single quotes; also escape backslashes for MySQL safety.
    return "'" + s.replace("\\", "\\\\").replace("'", "''") + "'"
