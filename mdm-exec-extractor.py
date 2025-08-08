#!/usr/bin/env python3
"""
mdm-exec-builder
----------------
Extract <Exec> command fragments from Microsoft's latest Windows MDM DDF bundle.

Outputs JSON records like:
{
  "Source": "RemoteWipe.xml",
  "CommandName": "doWipeProtected",
  "OMA_URI": "./Device/Vendor/MSFT/RemoteWipe/doWipeProtected",
  "MinOSVersion": "10.0.18363",
  "Description": "Exec on this node will …",
  "Exec": ["<Exec>", "  <CmdID>…</CmdID>", ..., "</Exec>"]
}

Key points
- Auto-discovers the latest DDF ZIP from the Learn landing page.
- Walks the CSP tree; only includes nodes with AccessType/Exec.
- Builds multi-line <Exec> payloads (no SyncML envelope).
- CmdID is a fresh UUID every time.
- Inheritance: If a node lacks Description or OsBuildVersion (MinOSVersion),
  it inherits from the closest parent DFProperties (no fabrication).
"""

import io
import json
import re
import uuid
import zipfile
import urllib.request
import xml.etree.ElementTree as ET
from typing import Optional, List, Dict

# --------------------------------------------------------------------
# Config
# --------------------------------------------------------------------
LEARN_CSP_DDF_URL = "https://learn.microsoft.com/en-us/windows/client-management/mdm/configuration-service-provider-ddf"
OUTPUT_FILE = "csp_exec_commands.json"
ZIP_LINK_RE = re.compile(r'href="(https://download\.microsoft\.com/[^"]+\.zip)"', re.IGNORECASE)

# --------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------
def log(msg: str) -> None:
    print(f"[mdm-exec-builder] {msg}")

# --------------------------------------------------------------------
# Network
# --------------------------------------------------------------------
def download(url: str, retries: int = 3) -> bytes:
    """Downloader using stdlib urllib; retries a few times."""
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
    """Scrape the Learn page to find the first Microsoft download ZIP link."""
    html = download(LEARN_CSP_DDF_URL).decode("utf-8", errors="ignore")
    m = ZIP_LINK_RE.search(html)
    if not m:
        raise RuntimeError("Could not find a DDF ZIP link on the Microsoft Learn page.")
    return m.group(1)

# --------------------------------------------------------------------
# XML helpers
# --------------------------------------------------------------------
def lname(tag: str) -> str:
    """Return local (namespace-stripped) lowercase tag name."""
    return tag.split("}", 1)[-1].lower()

def first_child(elem: ET.Element, localname: str) -> Optional[ET.Element]:
    """First direct child with the given local name (case-insensitive)."""
    ln = localname.lower()
    for child in elem:
        if lname(child.tag) == ln:
            return child
    return None

def first_child_text(elem: ET.Element, localname: str) -> Optional[str]:
    """Stripped text content of first direct child with given name, or None."""
    c = first_child(elem, localname)
    if c is None:
        return None
    txt = (c.text or "").strip()
    return txt or None

def has_exec_access(dfprops: ET.Element) -> bool:
    """True if DFProperties/AccessType contains an <Exec/> element."""
    access = first_child(dfprops, "AccessType")
    if access is None:
        return False
    for op in access:
        if lname(op.tag) == "exec":
            return True
    return False

def df_format(dfprops: ET.Element) -> Optional[str]:
    """
    DFFormat is usually:
      <DFFormat><chr/></DFFormat>
    or sometimes text content.
    """
    df = first_child(dfprops, "DFFormat")
    if df is None:
        return None
    for child in df:
        return lname(child.tag)
    txt = (df.text or "").strip()
    return txt.lower() if txt else None

def default_value(dfprops: ET.Element) -> Optional[str]:
    return first_child_text(dfprops, "DefaultValue")

def join_uri(prefix: str, name: str) -> str:
    """Join DDF Path + NodeName into a full OMA_URI."""
    if not prefix:
        return name
    if not name:
        return prefix
    return prefix + name if prefix.endswith("/") else prefix + "/" + name

# --------------------------------------------------------------------
# Inheritance helpers (walk DFProperties chain)
# --------------------------------------------------------------------
def inherited_text_from_chain(dfprops_chain: List[ET.Element], child_name: str) -> Optional[str]:
    """
    Iterate DFProperties from current -> parent -> ... and return first non-empty text
    for the given child tag (e.g., 'Description').
    """
    for dfp in dfprops_chain:
        val = first_child_text(dfp, child_name)
        if val:
            return " ".join(val.split())
    return None

def inherited_osbuild_from_chain(dfprops_chain: List[ET.Element]) -> Optional[str]:
    """Iterate DFProperties chain and return first Applicability/OsBuildVersion."""
    for dfp in dfprops_chain:
        app = first_child(dfp, "Applicability")
        if app is not None:
            val = first_child_text(app, "OsBuildVersion")
            if val:
                return val.strip()
    return None

# --------------------------------------------------------------------
# Exec payload builder
# --------------------------------------------------------------------
def must_emit_data(eff_fmt: str, default_val: Optional[str]) -> bool:
    """
    Emit <Data> when:
      - format is 'null' (empty <Data/> is common in examples), or
      - a DefaultValue exists (we emit that)
    Otherwise omit <Data>.
    """
    if eff_fmt == "null":
        return True
    if default_val is not None:
        return True
    return False

def build_exec_lines(uri: str, fmt: Optional[str], default_val: Optional[str]) -> List[str]:
    eff_fmt = (fmt or "chr").lower()
    lines: List[str] = [
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
    if must_emit_data(eff_fmt, default_val):
        if default_val is not None and eff_fmt != "null":
            lines.append(f"    <Data>{default_val}</Data>")
        else:
            lines.append("    <Data></Data>")
    lines += ["  </Item>", "</Exec>"]
    return lines

# --------------------------------------------------------------------
# DDF ZIP parsing (with inheritance)
# --------------------------------------------------------------------
def discover_exec_entries_from_zip(zip_bytes: bytes) -> List[Dict]:
    """
    Walk all XMLs in the DDF bundle, collect Exec-capable nodes and their details.
    - DFProperties are inherited down the tree (including Description and Applicability).
    - We pass a DFProperties *chain* (list) instead of mutating XML nodes.
    """
    out: List[Dict] = []

    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        for name in zf.namelist():
            if not name.lower().endswith(".xml"):
                continue

            # Parse XML file
            try:
                with zf.open(name) as f:
                    xml_bytes = f.read()
                root = ET.fromstring(xml_bytes)
            except Exception:
                continue

            def walk(node: ET.Element, inherited_path: str, filename: str, dfprops_chain: List[ET.Element]) -> None:
                if lname(node.tag) != "node":
                    return

                node_name = first_child_text(node, "NodeName") or ""
                path_prefix = first_child_text(node, "Path") or inherited_path
                this_uri = join_uri(path_prefix, node_name)

                node_dfprops = first_child(node, "DFProperties")
                # New chain: put current DFProps (if any) at the front
                if node_dfprops is not None:
                    cur_chain = [node_dfprops] + dfprops_chain
                else:
                    cur_chain = dfprops_chain

                # Effective DFProps for format/default/access decisions = current if any, else first of chain (parent)
                eff_dfprops = node_dfprops or (cur_chain[0] if cur_chain else None)

                if eff_dfprops is not None and has_exec_access(eff_dfprops):
                    fmt = df_format(eff_dfprops)
                    default_val = default_value(eff_dfprops)
                    # Inherit Description and OsBuildVersion up the chain if missing
                    desc = inherited_text_from_chain(cur_chain, "Description")
                    min_os = inherited_osbuild_from_chain(cur_chain)

                    out.append({
                        "Source": filename.split("/")[-1],
                        "CommandName": node_name,
                        "OMA_URI": this_uri,
                        "MinOSVersion": min_os,
                        "Description": desc,
                        "DeclaredFormat": fmt,
                        "DefaultValue": default_val,
                    })

                # Recurse into children
                for child in node:
                    if lname(child.tag) == "node":
                        walk(child, this_uri, filename, cur_chain)

            # Find <MgmtTree> root
            mgmt = root if lname(root.tag) == "mgmttree" else None
            if mgmt is None:
                for e in root.iter():
                    if lname(e.tag) == "mgmttree":
                        mgmt = e
                        break
            if mgmt is None:
                continue

            # Start walk for each top-level <Node>
            for top in mgmt:
                if lname(top.tag) == "node":
                    top_dfprops = first_child(top, "DFProperties")
                    top_chain: List[ET.Element] = [top_dfprops] if top_dfprops is not None else []
                    walk(top, first_child_text(top, "Path") or "", name, top_chain)

    return out

# --------------------------------------------------------------------
# Main
# --------------------------------------------------------------------
def main() -> None:
    log("Locating latest DDF ZIP on Microsoft Learn…")
    zip_url = find_latest_ddf_zip_url()
    log(f"Downloading: {zip_url}")
    data = download(zip_url)

    log("Parsing Exec-capable nodes (with inherited Description/MinOS)…")
    raw_execs = discover_exec_entries_from_zip(data)

    # Deduplicate by OMA_URI and sort for stable output
    seen: Dict[str, Dict] = {}
    for e in raw_execs:
        uri = (e.get("OMA_URI") or "").strip()
        if uri and uri not in seen:
            seen[uri] = e
    execs = sorted(seen.values(), key=lambda x: (x["Source"], x["OMA_URI"]))

    # Finalize: render Exec payload and drop internal fields
    out: List[Dict] = []
    for e in execs:
        lines = build_exec_lines(e["OMA_URI"], e.get("DeclaredFormat"), e.get("DefaultValue"))
        out.append({
            "Source": e["Source"],
            "CommandName": e["CommandName"],
            "OMA_URI": e["OMA_URI"],
            "MinOSVersion": e.get("MinOSVersion"),
            "Description": e.get("Description"),
            "Exec": lines,
        })

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    log(f"Done. Wrote {len(out)} Exec commands to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()