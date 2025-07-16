# Windows MDM Commands Extractor

This script extracts actionable Windows MDM commands from official Microsoft Configuration Service Provider (CSP) XML files.

## Purpose

Microsoft's CSP DDF files describe both configuration settings and commands. This tool parses those XMLs to generate a clean, structured list of actual **Exec commands** that can be executed via MDM.

Ideal for:
- Building remediation libraries (e.g., Fleet's /remediations page)
- Creating structured reference documentation of available MDM actions
- Automating CSP command extraction

## How It Works

- Scans XML files in the `ddf_files/` directory.
- Identifies nodes with `<AccessType>` set to `Exec`.
- Reconstructs full OMA-URIs using parent/child relationships.
- Extracts descriptions, minimum OS versions, and source file names.
- Outputs a deduplicated list of MDM commands as JSON.

## Usage

```bash
python extract_exec_commands.py
