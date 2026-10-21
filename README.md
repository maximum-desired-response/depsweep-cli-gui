# DepSweep 🔍

**DepSweep** is a high-performance, cross-platform dependency vulnerability and binary threat auditor. Designed to safeguard immutable system architectures and deployment pipelines, it recursively scans filesystems, packaging environments, manifest lockfiles, and compiled standalone application bundles to reveal outdated or compromised components. 

It runs as a responsive graphical dashboard using **PySide6 (Qt6)** or headlessly via a streamlined **Command-Line Interface (CLI)**.

---

## ⚡ The Catalyst: The eMudhra Root Certificate Debacle

Trust models on modern operating systems assume that root certificate authority validation layers remain secure. The compromised **eMudhra root certificate incident** shattered this assumption. When a root CA is revoked or compromised, the vulnerability isn't restricted to your system's global certificate store—compromised certificates and old metadata routinely slip downstream, bundled deep inside local virtual environment caches, nested project lockfiles, and static standalone app bundles.

If you are building an **immutable Live OS** or container environment, a lurking vulnerability inside a sealed file system image is a ticking time bomb. Once burned to an ISO or image layer, it remains a permanent fixture of that environment until the next deployment loop. **DepSweep** was built to sweep staging environments, sanitize packaging pipelines, and catch hidden security threats *before* the filesystem is sealed.

---

## 🛠️ Key Capabilities & Target Auditing

DepSweep analyzes your environment across multiple development frameworks simultaneously:

* ⚙️ **AppImages & Standalone Binaries:** Uses a zero-copy memory-mapped structure (`mmap`) to scan compiled binary layers for hardcoded threat signatures (such as compromised eMudhra CA chains) without causing out-of-memory (OOM) overhead or system freezings on multi-gigabyte files.
* 🐍 **Python Environments:** Audits local development sandboxes, unpacked Wheel archives, and structural site-packages metadata layers (`METADATA`, `PKG-INFO`) for vulnerable dependencies like outdated `certifi` bundles.
* 📦 **Node.js (Lockfiles):** Recursively inspects nested dependency graphs inside modern `package-lock.json` manifests and legacy tree configurations.
* 🦀 **Rust (Cargo.lock):** Decodes project lockfiles natively using `tomllib` (with an integrated regex fallback parser if executed on systems running older Python runtimes).
* 🐹 **Go Modules:** Scans `go.mod` and `go.sum` manifests to trace vulnerable packages.

---

## 🚀 Usage

### 1. Graphical Interface Mode (Default)
Simply execute the script without any parameters to launch the interactive audit control panel:
```bash
./depsweep.py
```
* **"Open File Location" Feature:** The dashboard includes an action-oriented remediation pipeline. Highlight any flagged vulnerability row in the interface and click **Open File Location** to instantly jump right to the target directory inside your OS file manager (*Dolphin, Nautilus, Finder, or Windows Explorer*).

### 2. Headless CLI Mode
For integration into automated CI/CD build scripts or Live OS compiler pipelines, use the terminal interface flags:
```bash
./depsweep.py --cli --path "/path/to/scan" --python --node --cargo --go --progress --json "./report.json"
```

### CLI Parameters

| Flag | Description |
| :--- | :--- |
| `--cli` | Enables headless command-line terminal scan mode. |
| `--path <path>` | Specifies the absolute or relative root path to sweep recursively. |
| `--progress` | Displays a live file counter spinner in the terminal pane during execution. |
| `--certifi-date <YYYY-MM-DD>` | Flag versions of `certifi` older than this release date. |
| `--binary-regex <pattern>` | Provide a custom regex sequence to scan binary data layers for. |
| `--python`, `--node`, `--appimages` | Toggle scanning configurations for Python, Node, or Binaries. |
| `--cargo`, `--go` | Toggle scanning configurations for Rust or Go manifests. |
| `--json <path>`, `--csv <path>` | Automatically write structured audit data frames to disk on completion. |

---

## 📦 Building from Source (Standalone Executable)

If you are distributing DepSweep to end-users who do not have Python or PySide6 installed on their machines, you can compile it into a single, fully portable standalone binary file.

To protect your host development environment, the repository includes an automated compilation script that spins up an isolated Python Virtual Environment (`venv`), upgrades the toolchain, builds the optimized app bundle via Nuitka, and cleans up after itself.

### Compilation Steps:
1. Ensure your system has the standard Python 3 development utilities installed.
2. Mark the build script as executable and run it:
   ```bash
   chmod +x compile_depsweep.sh
   ./compile_depsweep.sh
   ```
3. Once completed, a single-file executable named `depsweep` will be created in your root directory. You can copy this executable anywhere—even onto an air-gapped environment—and run it instantly with no external packages required.

---

## 📄 License & Disclaimer

Copyright (c) 2026 Don Prince (aka tru.ai).  
This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License** as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
