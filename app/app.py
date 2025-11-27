from fastapi import FastAPI, Body
from pydantic import BaseModel
from typing import List, Optional
import re
import json

app = FastAPI(title="ABAP READ TABLE Remediator")

# ------------------------------------------------------------
# REGEX DEFINITIONS
# ------------------------------------------------------------

READ_TABLE_RE = re.compile(
    r"READ\s+TABLE\s+(?P<itab>\w+).*?WITH\s+KEY\s+(?P<keys>.+?)(?:\.|\n)",
    re.IGNORECASE | re.DOTALL,
)

SORT_RE = re.compile(
    r"SORT\s+(?P<itab>\w+)\s+BY\s+(?P<fields>.+?)(?:\.|\n)",
    re.IGNORECASE | re.DOTALL,
)

# ------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------

def extract_sort_statements(txt: str):
    """Find all SORT statements and map fields by ITAB."""
    sort_map = {}
    for m in SORT_RE.finditer(txt or ""):
        itab = m.group("itab").upper()
        fields_raw = m.group("fields")
        fields = [f.strip().upper() for f in re.split(r"[ ,]+", fields_raw) if f.strip()]
        sort_map[itab] = fields
    return sort_map


def fields_match(sort_fields: List[str], key_fields: List[str]) -> bool:
    """
    Check if SORT fields include all READ TABLE key fields in the same order.
    """
    if not sort_fields or not key_fields:
        return False

    if len(sort_fields) < len(key_fields):
        return False

    return sort_fields[:len(key_fields)] == key_fields


def get_line(text: str, pos: int) -> int:
    """Relative line number inside this unit's code."""
    return text.count("\n", 0, pos) + 1


def get_multiline_snippet(text: str, start: int, end: int) -> str:
    """
    Multi-line logical snippet around the READ TABLE:
    full line(s) containing the match span.
    """
    line_start = text.rfind("\n", 0, start)
    if line_start == -1:
        line_start = 0
    else:
        line_start += 1

    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)

    return text[line_start:line_end]


def find_read_table_usage(txt: str):
    """
    Find all READ TABLE statements and determine missing SORT.
    """
    hits = []
    sort_map = extract_sort_statements(txt or "")

    for m in READ_TABLE_RE.finditer(txt or ""):
        itab = m.group("itab")
        keys_raw = m.group("keys")

        key_fields = re.findall(r"(\w+)(?=\s*\+\s*\d+\s*\(\d+\)\s*=|\s*=)", keys_raw, re.IGNORECASE)
        key_fields = [f.upper() for f in key_fields]


        sort_fields = sort_map.get(itab.upper(), [])
        already_sorted = fields_match(sort_fields, key_fields)

        if not already_sorted:
            hits.append({
                "span": m.span(),
                "itab": itab,
                "keys": key_fields,
                "suggestion": f"SORT {itab} BY {', '.join(key_fields)}." if key_fields else None
            })

    return hits

# ------------------------------------------------------------
# MODELS (REFERENCE FORMAT)
# ------------------------------------------------------------

class Finding(BaseModel):
    prog_name: Optional[str] = None
    incl_name: Optional[str] = None
    types: Optional[str] = None
    blockname: Optional[str] = None
    starting_line: Optional[int] = None
    ending_line: Optional[int] = None
    issues_type: Optional[str] = None
    severity: Optional[str] = None
    message: Optional[str] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None


class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = None
    start_line: Optional[int] = 0
    end_line: Optional[int] = 0
    code: Optional[str] = ""
    findings: Optional[List[Finding]] = None


# ------------------------------------------------------------
# CORE SCAN LOGIC
# ------------------------------------------------------------

def scan_unit(unit: Unit):
    src = unit.code or ""
    findings: List[Finding] = []

    base = unit.start_line or 0  # first line of this block in global program

    for m in find_read_table_usage(src):
        span_start, span_end = m["span"]

        # Relative line inside this block
        rel_line = get_line(src, span_start)
        # Absolute line (first line of block = unit.start_line)
        starting_line_abs = base + (rel_line - 1)

        # Multi-line snippet around the READ TABLE
        snippet = get_multiline_snippet(src, span_start, span_end)
        snippet_line_count = snippet.count("\n") + 1
        ending_line_abs = starting_line_abs + snippet_line_count - 1

        findings.append(Finding(
            prog_name=unit.pgm_name,
            incl_name=unit.inc_name,
            types=unit.type,
            blockname=unit.name,
            starting_line=starting_line_abs,
            ending_line=ending_line_abs,
            issues_type="READ_TABLE_Without_SORT",
            severity="error",  # always error
            message=f"READ TABLE on '{m['itab']}' without proper SORT for keys {m['keys']}.",
            suggestion=m["suggestion"],
            snippet=snippet.replace("\n", "\\n")
        ))

    out = unit.model_dump()
    out["findings"] = [f.model_dump() for f in findings]
    return out

# ------------------------------------------------------------
# ENDPOINTS (MB FORMAT)
# ------------------------------------------------------------

@app.post("/remediate-array")
async def remediate_read_array(units: List[Unit] = Body(...)):
    res = []
    for u in units:
        scanned = scan_unit(u)
        if scanned["findings"]:
            res.append(scanned)
    return res


@app.post("/remediate")
async def remediate_read(unit: Unit = Body(...)):
    return scan_unit(unit)
