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
    return text.count("\n", 0, pos) + 1


def extract_line(text: str, pos: int) -> str:
    s = text.rfind("\n", 0, pos) + 1
    e = text.find("\n", pos)
    if e == -1:
        e = len(text)
    return text[s:e].strip()


def find_read_table_usage(txt: str):
    """
    Find all READ TABLE statements and determine missing SORT.
    """
    hits = []
    sort_map = extract_sort_statements(txt or "")

    for m in READ_TABLE_RE.finditer(txt or ""):
        itab = m.group("itab")
        keys_raw = m.group("keys")

        key_fields = re.findall(r"(\w+)\s*=", keys_raw, re.IGNORECASE)
        key_fields = [f.upper() for f in key_fields]

        sort_fields = sort_map.get(itab.upper(), [])
        already_sorted = fields_match(sort_fields, key_fields)

        if not already_sorted:
            hits.append({
                "span": m.span(),
                "itab": itab,
                "keys": key_fields,
                "snippet": extract_line(txt, m.start()),
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
    code: Optional[str] = ""
    findings: Optional[List[Finding]] = None


# ------------------------------------------------------------
# CORE SCAN LOGIC
# ------------------------------------------------------------

def scan_unit(unit: Unit):
    src = unit.code or ""
    findings = []

    for m in find_read_table_usage(src):
        findings.append(Finding(
            prog_name=unit.pgm_name,
            incl_name=unit.inc_name,
            types=unit.type,
            blockname=unit.name,
            starting_line=get_line(src, m["span"][0]),
            ending_line=get_line(src, m["span"][1]),
            issues_type="READ_TABLE_Without_SORT",
            severity="warning",
            message=f"READ TABLE on '{m['itab']}' without proper SORT for keys {m['keys']}.",
            suggestion=m["suggestion"],
            snippet=m["snippet"]
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
