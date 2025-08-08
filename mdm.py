#!/usr/bin/env python3
"""
mdm-exec-builder
----------------
Extracts <Exec> command definitions from Microsoft's latest Windows MDM DDF files.

Main steps:
    1. Scrape Microsoft Learn CSP DDF page to get the latest ZIP download link.
    2. Download and unzip the latest DDF bundle.
    3. Parse each XML in the ZIP to find CSP nodes that allow the "Exec" operation.
    4. Collect each Exec's URI, friendly command name, format, and default value.
    5. Build a clean, multi-line SyncML <Exec> fragment for each.
    6. Save everything as JSON for later integration (Fleet, web UI, etc.).

Why?
    - Exec commands are the "action" endpoints of CSPs — used for things like rebooting, wiping, locking.
    - This script ensures Fleet or other tools have an up-to-date list without manual curation.

Requirements:
    - Python 3.7+ (pure stdlib — no extra installs)
"""

import io
import json
import re
import uuid
import zipfile
import urllib.request
import xml.etree.ElementTree as ET
from typing import Optional, List, Dict

# =============================================================================
# CONFIGURATION
# =============================================================================

# Where to scrape for the latest Windows CSP DDF ZIP file.
LEARN_CSP_DDF_URL = (
    "https://learn.microsoft.com/en-us/windows/client-management/mdm/"
    "configuration-service-provider-ddf"
)

# Where to save the final JSON output.
OUTPUT_FILE = "csp_exec_commands.json"

# Regex to extract the first ZIP download link from the Microsoft Learn page.
ZIP_LINK_RE = re.compile(
    r'href="(https://download\.microsoft\.com/[^"]+\.zip)"',
    re.IGNORECASE
)

# =============================================================================
# LOGGING
# =============================================================================

def log(msg: str) -> None:
    """Unified logging so every line has a consistent prefix."""
    print(f"[mdm-exec-builder] {msg}")

# =============================================================================
# NETWORK HELPERS
# =============================================================================

def download(url: str, retries: int = 3) -> bytes:
    """
    Download content from a URL with simple retry logic.
    Returns raw bytes.
    """
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "mdm-exec-builder/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read()
        except Exception as e:
            log(f"Download failed (attempt {attempt}/{retries}): {e}")
            if attempt == retries:
                raise
    return b""


def find_latest_ddf_zip_url() -> str:
    """
    Scrape the Microsoft Learn CSP DDF page and return the first ZIP URL found.
    This assumes Microsoft keeps the latest ZIP link near the top of the page.
    """
    html = download(LEARN_CSP_DDF_URL).decode("utf-8", errors="ignore")
    m = ZIP_LINK_RE.search(html)
    if not m:
        raise RuntimeError("Could not find a DDF ZIP link on the Microsoft Learn page.")
    return m.group(1)

# =============================================================================
# XML HELPERS
# =============================================================================

def lname(tag: str) -> str:
    """
    Extract the 'local name' from a namespaced XML tag.
    Example: '{urn:some-ns}NodeName' -> 'nodename'
    """
    return tag.split("}", 1)[-1].lower()


def first_child(elem: ET.Element, localname: str) -> Optional[ET.Element]:
    """Find the first direct child element with a given localname."""
    for child in elem:
        if lname(child.tag) == localname.lower():
            return child
    return None


def first_child_text(elem: ET.Element, localname: str) -> Optional[str]:
    """Find first direct child and return its stripped text value."""
    c = first_child(elem, localname)
    if c is None:
        return None
    return (c.text or "").strip() if c.text else None


def has_exec_access(dfprops: ET.Element) -> bool:
    """
    Check if <DFProperties> contains <AccessType><Exec> — which means the node
    supports executing a command via MDM.
    """
    access = first_child(dfprops, "AccessType")
    if access is None:
        return False
    for op in access:
        if lname(op.tag) == "exec":
            return True
    return False


def df_format(dfprops: ET.Element) -> Optional[str]:
    """
    Extract the DFFormat (data type) from DFProperties.
    Example: 'chr', 'int', 'null', etc.
    """
    df = first_child(dfprops, "DFFormat")
    if df is None:
        return None
    for child in df:
        return lname(child.tag)
    txt = (df.text or "").strip()
    return txt.lower() if txt else None


def default_value(dfprops: ET.Element) -> Optional[str]:
    """Get the <DefaultValue> text if present and non-empty."""
    dv = first_child_text(dfprops, "DefaultValue")
    return dv if dv not in (None, "") else None


def join_uri(prefix: str, name: str) -> str:
    """
    Join a CSP path prefix and node name into a full OMA_URI.
    Ensures no duplicate slashes.
    """
    if not prefix:
        return name
    if not name:
        return prefix
    return prefix + name if prefix.endswith("/") else prefix + "/" + name


def must_emit_empty_data(uri: str, eff_fmt: str, default_val: Optional[str]) -> bool:
    """
    Decide whether <Data> should be present in the Exec payload.
    Uses schema data rather than hardcoded command rules.
    """
    if eff_fmt == "null":
        return True
    if default_val is not None:
        return True
    return False


def build_exec_lines(uri: str, fmt: Optional[str], default_val: Optional[str]) -> List[str]:
    """
    Construct a clean, indented <Exec> payload fragment.
    This matches Microsoft's published examples.
    """
    eff_fmt = (fmt or "chr").lower()
    lines = [
        "<Exec>",
        f"  <CmdID>{uuid.uuid4()}</CmdID>",
        "  <Item>",
        "    <Target>",
        f"      <LocURI>{uri.strip()}</LocURI>",
        "    </Target>",
        "    <Meta>",
        f'      <Format xmlns="syncml:metinf">{eff_fmt}</Format>',
        "      <Type>text/plain</Type>",
        "    </Meta>",
    ]

    if must_emit_empty_data(uri, eff_fmt, default_val):
        if default_val is not None and eff_fmt != "null":
            lines.append(f"    <Data>{default_val}</Data>")
        else:
            lines.append("    <Data></Data>")

    lines += [
        "  </Item>",
        "</Exec>",
    ]
    return lines

# =============================================================================
# ZIP PARSER
# =============================================================================

def discover_exec_entries_from_zip(zip_bytes: bytes) -> List[Dict]:
    """
    Unzip the DDF bundle and extract all Exec-capable nodes.
    Returns a list of dicts with:
        - Source      (XML filename)
        - CommandName (from NodeName)
        - OMA_URI
        - DeclaredFormat
        - DefaultValue
    """
    out: List[Dict] = []

    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        for name in zf.namelist():
            if not name.lower().endswith(".xml"):
                continue
            try:
                with zf.open(name) as f:
                    xml_bytes = f.read()
                root = ET.fromstring(xml_bytes)
            except Exception:
                continue

            def walk(node: ET.Element, inherited_path: str, filename: str) -> None:
                if lname(node.tag) != "node":
                    return

                node_name = first_child_text(node, "NodeName") or ""
                path_prefix = first_child_text(node, "Path") or inherited_path
                this_uri = join_uri(path_prefix, node_name)

                dfprops = first_child(node, "DFProperties")
                if dfprops is not None and has_exec_access(dfprops):
                    fmt = df_format(dfprops)
                    default_val = default_value(dfprops)
                    out.append({
                        "Source": filename.split("/")[-1],
                        "CommandName": node_name,
                        "OMA_URI": this_uri,
                        "DeclaredFormat": fmt,
                        "DefaultValue": default_val,
                    })

                for child in node:
                    if lname(child.tag) == "node":
                        walk(child, this_uri, filename)

            # Find the mgmttree root
            mgmt = root if lname(root.tag) == "mgmttree" else None
            if mgmt is None:
                for e in root.iter():
                    if lname(e.tag) == "mgmttree":
                        mgmt = e
                        break
            if mgmt is None:
                continue

            for top in mgmt:
                if lname(top.tag) == "node":
                    walk(top, first_child_text(top, "Path") or "", name)

    return out

# =============================================================================
# MAIN SCRIPT
# =============================================================================

def main() -> None:
    log("Locating latest DDF ZIP on Microsoft Learn…")
    zip_url = find_latest_ddf_zip_url()
    log(f"Found ZIP: {zip_url}")

    log("Downloading DDF ZIP…")
    data = download(zip_url)

    log("Parsing Exec nodes…")
    raw_execs = discover_exec_entries_from_zip(data)

    # Deduplicate by OMA_URI
    seen: Dict[str, Dict] = {}
    for e in raw_execs:
        uri = e["OMA_URI"].strip()
        if uri and uri not in seen:
            seen[uri] = e

    # Sort results
    execs = sorted(seen.values(), key=lambda x: (x["Source"], x["OMA_URI"]))

    # Build final JSON output
    out: List[Dict] = []
    for e in execs:
        lines = build_exec_lines(e["OMA_URI"], e.get("DeclaredFormat"), e.get("DefaultValue"))
        record = {
            "Source": e["Source"],
            "CommandName": e["CommandName"],
            "OMA_URI": e["OMA_URI"],
            "Exec": lines,
        }
        out.append(record)

    # Save JSON
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    log(f"Done. Wrote {len(out)} Exec commands to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()