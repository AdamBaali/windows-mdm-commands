# Windows MDM Commands Extractor

Automatically downloads Microsoft's Configuration Service Provider (CSP) DDF files, extracts available **Exec** commands, and outputs them as structured **JSON** (YAML planned). Useful for building MDM command libraries, documentation, or remediation action catalogs.

---

## Features

- Downloads official Microsoft DDF XML files
- Parses and identifies MDM commands (AccessType: Exec)
- Outputs clean, deduplicated list of commands
- Corrects OMA-URI paths using parent hierarchy
- Includes source XML file reference for each command
- Outputs structured JSON for easy use (YAML planned)

---

## Example Output

```json
[
  {
    "OMA_URI": "./Device/Vendor/MSFT/RemoteWipe/doWipe",
    "NodeName": "doWipe",
    "Description": "Exec on this node will perform a remote wipe on the device.",
    "MinimumOS": "10.0.10586",
    "SourceFile": "RemoteWipe.xml"
  }
]
