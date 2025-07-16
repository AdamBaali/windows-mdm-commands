Here’s a cleaned and professional version of your markdown for the project:

# Windows MDM CSP Command Extractor

A Python script to automatically fetch and parse Microsoft’s latest Windows MDM Configuration Service Provider (CSP) DDF files, extracting all available executable commands (`AccessType: Exec`).  
The output is a structured JSON file listing each command’s OMA_URI, description, minimum OS version, and source XML file.

---

## Why This Project?

Microsoft does not publish a clear, consolidated list of Windows MDM commands. These commands are hidden within individual XML DDF files.  
This project automates the discovery and listing of all executable Windows MDM actions — helpful for MDM engineers, developers, and documentation writers.

---

## Features

- Fetches the latest official DDF ZIP from Microsoft automatically  
- Parses all CSP XML files inside the ZIP  
- Detects executable (`AccessType: Exec`) commands only  
- Dynamically constructs OMA_URIs using XML structure  
- Outputs a clean JSON list of all available Windows MDM commands  
- Pure Python (no dependencies)

---

## Requirements

- Python 3.7 or newer  
- No third-party libraries required

---

## Usage

```bash
python3 csp_command_extractor.py

Example output:

[
  {
    "OMA_URI": "./Device/Vendor/MSFT/RemoteWipe/doWipe",
    "NodeName": "doWipe",
    "Description": "Exec on this node will perform a remote wipe on the device. The return status code shows whether the device accepted the Exec command.",
    "MinimumOS": "10.0.10586",
    "SourceFile": "RemoteWipe.xml"
  },
  {
    "OMA_URI": "./Device/Vendor/MSFT/BitLocker/RotateRecoveryPasswords",
    "NodeName": "RotateRecoveryPasswords",
    "Description": "Allows admin to push one-time rotation of all numeric recovery passwords...",
    "MinimumOS": "10.0.18363",
    "SourceFile": "BitLocker.xml"
  }
]


⸻

Roadmap
	•	JSON output
	•	YAML output (planned)
	•	Optional output filename support
	•	Filter by CSP or keyword (future)

Let me know if you'd like this styled for a more technical audience (e.g., adding badges, contributing sections, etc.).
