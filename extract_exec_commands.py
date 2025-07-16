#!/usr/bin/env python3
"""
Minimal dependency Python script to scrape Microsoft's CSP DDF page, download the DDF v2 ZIP,
extract XMLs, and list only executable commands with accurate OMA_URIs built dynamically.
"""

import urllib.request
import urllib.parse
import zipfile
import io
import re
import json
import xml.etree.ElementTree as ET
import argparse

DDF_DOC_URL = "https://learn.microsoft.com/en-us/windows/client-management/mdm/configuration-service-provider-ddf"

def fetch_ddf_zip_url() -> str:
    with urllib.request.urlopen(DDF_DOC_URL) as resp:
        html = resp.read().decode('utf-8', errors='ignore')
        base_url = resp.geturl()

    match = re.search(
        r'href="([^"]+\.zip)"[^>]*>[^<]*DDF\s*v2\s*Files',
        html,
        re.IGNORECASE
    )

    if not match:
        raise RuntimeError("Could not find DDF v2 Files link.")
    return urllib.parse.urljoin(base_url, match.group(1))

def download_xmls(zip_url: str) -> dict[str, bytes]:
    with urllib.request.urlopen(zip_url) as resp:
        with zipfile.ZipFile(io.BytesIO(resp.read())) as zf:
            return {name: zf.read(name) for name in zf.namelist() if name.lower().endswith('.xml')}

def strip_namespaces(xml_bytes: bytes) -> str:
    text = xml_bytes.decode("utf-8", errors="ignore")
    text = re.sub(r'\s+xmlns(:\w+)?="[^"]+"', "", text)
    text = re.sub(r"<(\/)?\w+:", r"<\1", text)
    return text

def clean_text(text):
    return re.sub(r'\s+', ' ', text or '').strip()

def extract_exec_commands(xmls: dict[str, bytes]) -> list[dict]:
    commands = []
    seen = set()

    for fname, raw_xml in xmls.items():
        try:
            root = ET.fromstring(strip_namespaces(raw_xml))
        except ET.ParseError:
            continue

        def recurse(node, uri_so_far='', inherited_os=''):
            node_name = clean_text(node.findtext('NodeName', ''))
            path_elem = node.find('Path')
            new_uri_base = clean_text(path_elem.text) if path_elem is not None and path_elem.text else uri_so_far
            current_oma_uri = (new_uri_base + '/' + node_name).rstrip('/')
            df_props = node.find('DFProperties')

            min_os = inherited_os
            applicability = df_props.find('Applicability') if df_props is not None else None
            if applicability is not None:
                min_os_candidate = applicability.findtext('OsBuildVersion', '').strip()
                if min_os_candidate:
                    min_os = min_os_candidate

            if df_props is not None and df_props.find('AccessType/Exec') is not None:
                description = clean_text(df_props.findtext('Description', ''))

                key = (current_oma_uri, node_name)
                if key not in seen:
                    seen.add(key)
                    command_info = {
                        "OMA_URI": current_oma_uri,
                        "NodeName": node_name,
                        "Description": description,
                        "MinimumOS": min_os,
                        "SourceFile": fname
                    }
                    commands.append(command_info)

            for child_node in node.findall('Node'):
                recurse(child_node, current_oma_uri, min_os)

        for top_node in root.findall('Node'):
            recurse(top_node)

    return sorted(commands, key=lambda x: (x['OMA_URI'], x['NodeName']))

def main():
    parser = argparse.ArgumentParser(description='Scrape executable CSP commands')
    parser.add_argument('-o', '--output', default='csp_exec_commands.json', help='Output file name')
    args = parser.parse_args()

    print("Fetching ZIP URL...")
    zip_url = fetch_ddf_zip_url()

    print("Downloading XML files...")
    xmls = download_xmls(zip_url)

    print(f"Processing {len(xmls)} XML files...")
    commands = extract_exec_commands(xmls)

    print(f"Found {len(commands)} executable commands.")

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(commands, f, indent=2, ensure_ascii=False)

    print(f"Output written to {args.output}")

if __name__ == '__main__':
    main()
