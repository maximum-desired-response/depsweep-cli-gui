#!/usr/bin/env python3
"""
DepSweep CLI & GUI — Dependency Vulnerability Auditor

Purpose:
This tool scans local file systems, Python environments (wheels and site-packages),
Node.js lockfiles, Rust Cargo.lock files, Go modules, and standalone binaries or AppImages
to discover outdated or vulnerable dependencies that carry revoked/compromised TLS root certificates
or metadata. It runs as a responsive graphical window using PySide6 or headlessly via the terminal.

Usage:
1. Graphical Interface Mode (Default):
   $ python depsweep.py
2. Headless CLI Mode:
   $ python depsweep.py --cli --path "/path/to/scan" --python --node --cargo --go --progress --json "./report.json"

License & Disclaimer:
Copyright (c) 2026 Don Prince
This program is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.
"""

import os
import sys
import re
import json
import csv
import argparse
import fnmatch
import mmap
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any, Callable
from PySide6.QtCore import Qt, QThread, Signal, QDate, QDateTime
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QFileDialog, QCheckBox,
    QTableWidget, QTableWidgetItem, QProgressBar, QGroupBox, QMessageBox,
    QDateEdit
)

__version__ = "2026.1.0"


def setup_persistent_logging() -> logging.Logger:
    """Configures a rolling file logger in the user's home path directory."""
    log_dir = Path("~/depsweep/logs").expanduser()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "depsweep.log"

    logger = logging.getLogger("DepSweep")
    logger.setLevel(logging.INFO)

    # Avoid duplicate handler stack attachment loops
    if not logger.handlers:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger


class SweepWorker(QThread):
    """Background worker thread for scanning directories."""

    progress_signal: Signal = Signal(str)
    warning_signal: Signal = Signal(str)  # Registered for cross-thread GUI status sync
    skipped_file_signal: Signal = Signal(str, str)  # Path, Reason
    found_vulnerability_signal: Signal = Signal(str, str, str, str)  # Target Type, Details, Remediation, Path
    finished_signal: Signal = Signal(int)

    root_dir: str
    targets: List[str]
    certifi_threshold: Tuple[int, int, int]
    vuln_count: int
    whl_version_rx: re.Pattern
    emudhra_bin_rx: re.Pattern
    ignore_rules: Dict[Path, List[str]]
    logger: logging.Logger

    def __init__(
        self,
        root_dir: str,
        targets: List[str],
        certifi_threshold: Tuple[int, int, int],
        binary_pattern_str: str
    ) -> None:
        super().__init__()
        self.root_dir = root_dir
        self.targets = targets
        self.certifi_threshold = certifi_threshold
        self.vuln_count = 0
        self.logger = setup_persistent_logging()

        # Compile regex for wheel version extraction
        self.whl_version_rx = re.compile(r"certifi-([\d\.]+)-")

        # Compile regex safely with explicit error reporting and fallback
        try:
            if binary_pattern_str:
                self.emudhra_bin_rx = re.compile(binary_pattern_str.encode('utf-8'))
            else:
                raise ValueError("Empty pattern provided")
        except re.error as e:
            print(
                f"[WARNING] Invalid custom regex pattern provided ('{binary_pattern_str}'): {e}. "
                f"Falling back to default eMudhra signature matching.",
                file=sys.stderr
            )
            self.emudhra_bin_rx = re.compile(b"eMudhra|eMudhra Premium|eMudhra Sub-CA")
        except Exception as e:
            print(
                f"[WARNING] Regex configuration error: {e}. "
                f"Falling back to default eMudhra signature matching.",
                file=sys.stderr
            )
            self.emudhra_bin_rx = re.compile(b"eMudhra|eMudhra Premium|eMudhra Sub-CA")

        self.ignore_rules: Dict[Path, List[str]] = {}

    def parse_gitignore(self, gitignore_path: Path) -> List[str]:
        """Parse .gitignore file into a list of rules."""
        rules: List[str] = []
        try:
            with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if line.endswith("/"):
                            line = line[:-1]
                        rules.append(line)
        except Exception:
            pass
        return rules

    def is_ignored(self, file_path: Path, root_path: Path) -> bool:
        """Check if a file matches any .gitignore rules relative to the root."""
        try:
            relative_path: Path = file_path.relative_to(root_path)
            path_parts: Tuple[str, ...] = relative_path.parts

            current_check: Path = Path(file_path)
            while current_check != root_path.parent:
                if current_check in self.ignore_rules:
                    for rule in self.ignore_rules[current_check]:
                        if (
                            any(fnmatch.fnmatch(part, rule) for part in path_parts)
                            or fnmatch.fnmatch(str(relative_path), rule)
                        ):
                            return True
                current_check = current_check.parent
        except ValueError:
            pass

        return False

    def run(self) -> None:
        """Main scanning logic."""
        root_path: Path = Path(self.root_dir).resolve()
        if not root_path.exists():
            self.finished_signal.emit(0)
            return

        for current_path, dirs, files in os.walk(root_path):
            current_dir: Path = Path(current_path).resolve()

            if ".gitignore" in files:
                self.ignore_rules[current_dir] = self.parse_gitignore(current_dir / ".gitignore")

            # Filter directories to avoid descending into ignored ones
            dirs[:] = [d for d in dirs if not d.startswith(".") and not self.is_ignored(current_dir / d, root_path)]

            for file in files:
                file_path: Path = current_dir / file

                if file.startswith(".") or self.is_ignored(file_path, root_path):
                    continue

                file_lower: str = file.lower()
                self.progress_signal.emit(str(file_path))

                # 1. Python Target Sweeps
                if "python" in self.targets:
                    if file_lower.endswith(".whl") and "certifi" in file_lower:
                        match: Optional[re.Match] = self.whl_version_rx.search(file)
                        if match:
                            version_str: str = match.group(1)
                            if self.is_certifi_vulnerable(version_str, self.certifi_threshold):
                                self.report_vuln(
                                    "Python (Wheel)",
                                    f"Vulnerable certifi Wheel archive found (v{version_str}).",
                                    "Delete file and run 'pip download certifi' to fetch a modern secure build.",
                                    str(file_path)
                                )

                    elif file in ("METADATA", "PKG-INFO") and "certifi" in current_path.lower():
                        version_str_opt: Optional[str] = self.parse_metadata_version(file_path)
                        if version_str_opt and self.is_certifi_vulnerable(version_str_opt, self.certifi_threshold):
                            # Determine remediation based on environment (Snap vs Standard)
                            if "/snap/" in str(file_path):
                                remediation_msg = "Immutable Read-Only System Asset. Run 'sudo snap refresh' or contact the upstream bundle maintainer to push a patched revision."
                            else:
                                remediation_msg = "Run 'pip install --upgrade certifi' inside the active virtual environment toolchain."

                            self.report_vuln(
                                "Python (Installed)",
                                f"Vulnerable site-packages certifi instance found (v{version_str_opt}).",
                                remediation_msg,
                                str(file_path)
                            )

                # 2. Node.js Target Sweeps
                if "node" in self.targets and file == "package-lock.json":
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            lock_data: Dict[str, Any] = json.load(f)

                        packages: Dict[str, Any] = lock_data.get("packages", {})
                        dependencies: Dict[str, Any] = lock_data.get("dependencies", {})

                        # Determine remediation based on environment
                        if "/snap/" in str(file_path):
                            remedy_modern = "Immutable System Wrapper. Upstream package update required via package manager."
                            remedy_legacy = "Immutable System Wrapper. Maintainer build environment regeneration required."
                        else:
                            remedy_modern = "Run 'npm update certifi' or force dependency tree alignment with 'npm audit fix'."
                            remedy_legacy = "Regenerate lockfile layer or declare a safe target override inside package.json resolutions."

                        for pkg_path, pkg_info in packages.items():
                            if "node_modules/certifi" in pkg_path or pkg_path.endswith("certifi"):
                                version_str: str = pkg_info.get("version", "")
                                if self.is_certifi_vulnerable(version_str, self.certifi_threshold):
                                    self.report_vuln(
                                        "Node.js (Lockfile)",
                                        f"Vulnerable nested certifi dependency (v{version_str}).",
                                        remedy_modern,
                                        str(file_path)
                                    )

                        if "certifi" in dependencies:
                            version_str = dependencies["certifi"].get("version", "")
                            if self.is_certifi_vulnerable(version_str, self.certifi_threshold):
                                self.report_vuln(
                                    "Node.js (Legacy Lockfile)",
                                    f"Vulnerable certifi dependency configuration found (v{version_str}).",
                                    remedy_legacy,
                                    str(file_path)
                                )
                    except Exception:
                        pass

                # 3. Binaries & AppImages Target Sweeps
                if "appimages" in self.targets:
                    is_executable = os.access(file_path, os.X_OK) and not file_path.is_dir()
                    is_binary_ext = file_lower.endswith((".appimage", ".bin", ".exe"))

                    if is_binary_ext or is_executable:
                        if self.scan_binary_for_signatures(file_path):
                            path_str = str(file_path)
                            # Determine remediation based on system path
                            if any(path_str.startswith(p) for p in ["/opt/", "/usr/bin/", "/usr/lib/", "/usr/local/", "/snap/"]):
                                remediation_msg = (
                                    "System or proprietary binary path. Update via system package manager "
                                    "(apt/snap) or replace with an officially patched vendor distribution."
                                )
                            else:
                                remediation_msg = (
                                    "Re-compile bundle using an updated system base patch or contact "
                                    "upstream software developer for an updated binary."
                                )

                            self.report_vuln(
                                "AppImage / Binary Payload",
                                "Embedded custom root CA signature sequences matched inside compiled data layers.",
                                remediation_msg,
                                path_str
                            )

                # 4. Rust Cargo Target Sweeps
                if "cargo" in self.targets and file == "Cargo.lock":
                    try:
                        import tomllib
                        with open(file_path, "rb") as f:
                            lock_data = tomllib.load(f)
                        packages = lock_data.get("package", [])
                        for pkg in packages:
                            name = pkg.get("name", "")
                            version = pkg.get("version", "")
                            if name == "openssl" and version.startswith("0.10."):
                                self.report_vuln(
                                    "Rust (Cargo.lock)",
                                    f"Vulnerable crate found: {name} v{version}.",
                                    "Run 'cargo update -p openssl' to pull a secure upstream patch.",
                                    str(file_path)
                                )
                    except ImportError:
                        # Fallback regex scanning if run on Python versions older than 3.11 without tomllib
                        try:
                            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read()
                            package_blocks = re.findall(
                                r'\[\[package\]\]\n(name\s*=\s*"[^"]+"\nversion\s*=\s*"[^"]+")',
                                content
                            )
                            for block in package_blocks:
                                name_match = re.search(r'name\s*=\s*"([^"]+)"', block)
                                ver_match = re.search(r'version\s*=\s*"([^"]+)"', block)
                                if name_match and ver_match:
                                    name = name_match.group(1)
                                    version = ver_match.group(1)
                                    if name == "openssl" and version.startswith("0.10."):
                                        self.report_vuln(
                                            "Rust (Cargo.lock - Fallback)",
                                            f"Vulnerable crate found: {name} v{version}.",
                                            "Run 'cargo update -p openssl' to pull a secure upstream patch.",
                                            str(file_path)
                                        )
                        except Exception:
                            pass
                    except Exception:
                        pass

                # 5. Go Module Target Sweeps
                if "go" in self.targets and file in ("go.mod", "go.sum"):
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        if (
                            "golang.org/x/net" in content
                            and ("v0.0." in content or "v0.7." in content)
                        ):
                            self.report_vuln(
                                "Go (Module Manifest)",
                                f"Potentially vulnerable Go module version referenced in {file}.",
                                "Run 'go get -u golang.org/x/net' to update the dependency tree.",
                                str(file_path)
                            )
                    except Exception:
                        pass

        self.finished_signal.emit(self.vuln_count)

    def scan_binary_for_signatures(self, path: Path) -> bool:
        """Zero-copy memory-mapped implementation with integrated safety skips and UI alerting."""
        try:
            file_size = path.stat().st_size
            if file_size == 0:
                return False

            if file_size > 500_000_000:
                reason = f"Exceeds 500MB safety threshold ({file_size / 1_000_000:.1f} MB)"
                print(f"[PIPELINE-WARN] Skipped large file: {path.name} ({file_size / 1_000_000:.1f} MB)", file=sys.stderr)
                self.logger.warning(f"Skipped large file: {path} ({file_size / 1_000_000:.1f} MB)")
                self.warning_signal.emit(f"Skipped large file: {path.name}")
                self.skipped_file_signal.emit(str(path), reason)
                return False

            with open(path, "rb") as f:
                with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                    if self.emudhra_bin_rx.search(mm):
                        return True
        except (PermissionError, FileNotFoundError, OSError) as e:
            reason = f"Environmental access constraint ({e})"
            print(f"[PIPELINE-WARN] Skipped unreadable file: {path.name} ({e})", file=sys.stderr)
            self.logger.warning(f"Skipped unreadable file: {path} ({e})")
            self.warning_signal.emit(f"Unscanned file: {path.name}")
            self.skipped_file_signal.emit(str(path), reason)
        except Exception as e:
            reason = f"General processing failure ({e})"
            print(f"[PIPELINE-WARN] Error processing file: {path.name} ({e})", file=sys.stderr)
            self.logger.error(f"Error processing file: {path} ({e})")
            self.warning_signal.emit(f"Error on file: {path.name}")
            self.skipped_file_signal.emit(str(path), reason)

        return False

    def report_vuln(
        self, target_type: str, details: str, remediation: str, path: str
    ) -> None:
        """Emit signal for new vulnerability."""
        self.vuln_count += 1
        self.logger.info(f"VULNERABILITY FLAGS: [{target_type}] {path}")
        self.found_vulnerability_signal.emit(target_type, details, remediation, path)

    def parse_metadata_version(self, metadata_path: Path) -> Optional[str]:
        """Extract version string from METADATA file."""
        try:
            with open(metadata_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("Version:"):
                        return str(line.split(":", 1)[1].strip())
        except Exception:
            pass
        return None

    def is_certifi_vulnerable(
        self, version_str: str, threshold_tuple: Tuple[int, int, int]
    ) -> bool:
        """Compare semantic version against threshold."""
        try:
            parts: List[int] = [int(p) for p in version_str.split(".")]
            if len(parts) >= 3:
                return tuple(parts[:3]) < threshold_tuple
            return True
        except ValueError:
            return True


class AuditSweeperWindow(QMainWindow):
    """Main GUI Window."""

    path_input: QLineEdit
    date_edit: QDateEdit
    binary_input: QLineEdit
    chk_python: QCheckBox
    chk_node: QCheckBox
    chk_appimages: QCheckBox
    chk_cargo: QCheckBox
    chk_go: QCheckBox
    chk_export_json: QCheckBox
    chk_export_csv: QCheckBox
    start_btn: QPushButton
    open_dir_btn: QPushButton
    progress_bar: QProgressBar
    table: QTableWidget
    skipped_table: QTableWidget
    status_label: QLabel
    worker: SweepWorker
    skipped_cache_list: List[Dict[str, str]]

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"DepSweep CLI & GUI v{__version__} — Dependency Vulnerability Auditor")
        self.resize(1100, 850)
        self.skipped_cache_list = []
        self.init_ui()

    def init_ui(self) -> None:
        central_widget: QWidget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout: QVBoxLayout = QVBoxLayout(central_widget)

        # 1. Root Folder Selection Group
        dir_group: QGroupBox = QGroupBox("1. Select Root Directory to Sweep")
        dir_layout: QHBoxLayout = QHBoxLayout(dir_group)
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Choose directory (e.g., home directory, project folder)...")
        browse_btn: QPushButton = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_folder)
        dir_layout.addWidget(self.path_input)
        dir_layout.addWidget(browse_btn)
        main_layout.addWidget(dir_group)

        # 2. Configurable Dynamic Rules Selection
        rule_group: QGroupBox = QGroupBox("2. Advanced Vulnerability Rule Definition")
        rule_layout: QHBoxLayout = QHBoxLayout(rule_group)
        certifi_label: QLabel = QLabel("Certifi Release Threshold (Vulnerable Before):")
        self.date_edit = QDateEdit()
        self.date_edit.setCalendarPopup(True)
        self.date_edit.setDate(QDate(2024, 7, 4))
        binary_label: QLabel = QLabel("Binary Targets Regex Pattern:")
        self.binary_input = QLineEdit("eMudhra|eMudhra Premium|eMudhra Sub-CA")
        rule_layout.addWidget(certifi_label)
        rule_layout.addWidget(self.date_edit)
        rule_layout.addWidget(binary_label)
        rule_layout.addWidget(self.binary_input)
        main_layout.addWidget(rule_group)

        # 3. Target Selection Group
        target_group: QGroupBox = QGroupBox("3. Select Targets to Scan")
        target_layout: QHBoxLayout = QHBoxLayout(target_group)
        self.chk_python = QCheckBox("Python (certifi / Wheels)")
        self.chk_python.setChecked(True)
        self.chk_node = QCheckBox("Node.js (Lockfiles)")
        self.chk_node.setChecked(True)
        self.chk_appimages = QCheckBox("AppImages & Binaries")
        self.chk_appimages.setChecked(True)
        self.chk_cargo = QCheckBox("Rust (Cargo.lock)")
        self.chk_cargo.setChecked(True)
        self.chk_go = QCheckBox("Go (go.mod / go.sum)")
        self.chk_go.setChecked(True)
        target_layout.addWidget(self.chk_python)
        target_layout.addWidget(self.chk_node)
        target_layout.addWidget(self.chk_appimages)
        target_layout.addWidget(self.chk_cargo)
        target_layout.addWidget(self.chk_go)
        main_layout.addWidget(target_group)

        # 4. Report Export Settings Group
        export_group: QGroupBox = QGroupBox("4. Export Report Options (Prompts on Completion)")
        export_layout: QHBoxLayout = QHBoxLayout(export_group)
        self.chk_export_json = QCheckBox("Export JSON Report")
        self.chk_export_csv = QCheckBox("Export CSV Report")
        export_layout.addWidget(self.chk_export_json)
        export_layout.addWidget(self.chk_export_csv)
        main_layout.addWidget(export_group)

        # Action & Progress Layout
        action_layout: QHBoxLayout = QHBoxLayout()
        self.start_btn = QPushButton("Start Audit Sweep")
        self.start_btn.setStyleSheet(
            "background-color: #2b5b84; color: white; font-weight: bold; padding: 8px;"
        )
        self.start_btn.clicked.connect(self.start_sweep)

        self.open_dir_btn = QPushButton("Open File Location")
        self.open_dir_btn.setStyleSheet(
            "background-color: #4a5568; color: white; font-weight: bold; padding: 8px;"
        )
        self.open_dir_btn.clicked.connect(self.open_selected_location)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.hide()

        action_layout.addWidget(self.start_btn)
        action_layout.addWidget(self.open_dir_btn)
        action_layout.addWidget(self.progress_bar)
        main_layout.addLayout(action_layout)

        # Report / Results Table
        report_group: QGroupBox = QGroupBox("5. Audit Report & Remediation Findings")
        report_layout: QVBoxLayout = QVBoxLayout(report_group)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels([
            "Target Type",
            "Vulnerability Details",
            "Remediation Required",
            "File Path (Where)"
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 140)
        self.table.setColumnWidth(1, 240)
        self.table.setColumnWidth(2, 320)
        report_layout.addWidget(self.table)
        main_layout.addWidget(report_group)

        # Skipped Artifacts View Layout Panel Group
        skipped_group: QGroupBox = QGroupBox("6. Skipped / Unscanned Artifacts (Audit Trail Boundaries)")
        skipped_layout: QVBoxLayout = QVBoxLayout(skipped_group)
        self.skipped_table = QTableWidget(0, 3)
        self.skipped_table.setHorizontalHeaderLabels([
            "Artifact Location Path",
            "Estimated Size",
            "Skipped Reason Boundary Exception"
        ])
        self.skipped_table.horizontalHeader().setStretchLastSection(True)
        self.skipped_table.setColumnWidth(0, 480)
        self.skipped_table.setColumnWidth(1, 120)
        skipped_layout.addWidget(self.skipped_table)
        main_layout.addWidget(skipped_group)

        # Status Summary Label with Copyright & Version display info
        self.status_label = QLabel(f"DepSweep v{__version__} | Copyright (c) 2026 Don Prince — Ready to scan.")
        main_layout.addWidget(self.status_label)

    def handle_pipeline_warning(self, message: str) -> None:
        """Updates the status bar label with a temporarily highlighted skip warning."""
        self.status_label.setText(f"⚠️ {message}")

    def handle_skipped_artifact(self, path: str, reason: str) -> None:
        """Appends unexamined build layers into the secondary data log table layout."""
        # Cache memory values for file generation pipelines later
        try:
            size_bytes = os.path.getsize(path)
            size_str = f"{size_bytes / 1_000_000:.1f} MB" if size_bytes > 0 else "0.0 MB"
        except Exception:
            size_str = "UNKNOWN"

        self.skipped_cache_list.append({
            "file_path": path,
            "size": size_str,
            "reason": reason
        })

        row_position = self.skipped_table.rowCount()
        self.skipped_table.insertRow(row_position)

        # Apply structured formatting elements
        path_item = QTableWidgetItem(path)
        size_item = QTableWidgetItem(size_str)
        reason_item = QTableWidgetItem(reason)

        # Soft amber color overlay indicators mapping
        reason_item.setForeground(Qt.GlobalColor.darkYellow)

        self.skipped_table.setItem(row_position, 0, path_item)
        self.skipped_table.setItem(row_position, 1, size_item)
        self.skipped_table.setItem(row_position, 2, reason_item)

    def browse_folder(self) -> None:
        dir_path: str = QFileDialog.getExistingDirectory(self, "Select Root Directory")
        if dir_path:
            self.path_input.setText(dir_path)

    def open_selected_location(self) -> None:
        """Extracts the file path from the highlighted row and displays it inside the OS manager."""
        # Fall back gracefully to check the skipped table if the active row selection falls within it
        current_row: int = self.table.currentRow()
        active_table = self.table
        col_idx = 3

        if current_row == -1:
            current_row = self.skipped_table.currentRow()
            active_table = self.skipped_table
            col_idx = 0

        if current_row == -1:
            QMessageBox.information(
                self, "No Selection",
                "Please click on an active target row inside either table first."
            )
            return

        path_item = active_table.item(current_row, col_idx)
        if not path_item:
            return

        target_file_path = Path(path_item.text())
        target_dir = target_file_path.parent if target_file_path.is_file() else target_file_path

        if not target_dir.exists():
            QMessageBox.warning(
                self, "Path Not Found",
                f"The directory profile no longer exists locally:\n{target_dir}"
            )
            return

        try:
            if sys.platform == "win32":
                os.startfile(target_dir)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(target_dir)])
            else:
                subprocess.Popen(["xdg-open", str(target_dir)])
        except Exception as e:
            QMessageBox.critical(
                self, "Execution Failure",
                f"Could not launch native file manager context wrapper:\n{e}"
            )

    def start_sweep(self) -> None:
        root_dir: str = self.path_input.text().strip()
        if not root_dir or not Path(root_dir).exists():
            QMessageBox.warning(
                self, "Invalid Path",
                "Please select a valid root directory before starting the sweep."
            )
            return

        targets: List[str] = []
        if self.chk_python.isChecked():
            targets.append("python")
        if self.chk_node.isChecked():
            targets.append("node")
        if self.chk_appimages.isChecked():
            targets.append("appimages")
        if self.chk_cargo.isChecked():
            targets.append("cargo")
        if self.chk_go.isChecked():
            targets.append("go")

        if not targets:
            QMessageBox.warning(
                self, "No Targets",
                "Please select at least one scan target option."
            )
            return

        selected_date: QDate = self.date_edit.date()
        certifi_threshold: Tuple[int, int, int] = (
            selected_date.year(),
            selected_date.month(),
            selected_date.day()
        )
        binary_pattern_str: str = self.binary_input.text().strip()

        if not binary_pattern_str:
            QMessageBox.warning(
                self, "Empty Pattern",
                "Please provide a valid text/regex pattern string."
            )
            return

        # Reset UI structures
        self.table.setRowCount(0)
        self.skipped_table.setRowCount(0)
        self.skipped_cache_list.clear()

        self.start_btn.setEnabled(False)
        self.progress_bar.show()
        self.status_label.setText("Sweeping directories recursively...")

        # Initialize and start worker
        self.worker = SweepWorker(root_dir, targets, certifi_threshold, binary_pattern_str)
        self.worker.found_vulnerability_signal.connect(self.add_vulnerability_row)
        self.worker.warning_signal.connect(self.handle_pipeline_warning)
        self.worker.skipped_file_signal.connect(self.handle_skipped_artifact)
        self.worker.finished_signal.connect(self.sweep_finished)

        self.worker.progress_signal.connect(lambda p: self.status_label.setText(f"Analyzing: {Path(p).name}"))
        self.worker.start()

    def add_vulnerability_row(
        self, target_type: str, details: str, remediation: str, path: str
    ) -> None:
        row_position: int = self.table.rowCount()
        self.table.insertRow(row_position)
        self.table.setItem(row_position, 0, QTableWidgetItem(target_type))
        self.table.setItem(row_position, 1, QTableWidgetItem(details))
        self.table.setItem(row_position, 2, QTableWidgetItem(remediation))
        self.table.setItem(row_position, 3, QTableWidgetItem(path))

    def sweep_finished(self, total_count: int) -> None:
        self.progress_bar.hide()
        self.start_btn.setEnabled(True)

        skipped_count = len(self.skipped_cache_list)
        self.status_label.setText(
            f"Sweep complete. Flagged: {total_count} | Skipped/Unscanned boundaries: {skipped_count}"
        )

        if total_count == 0 and skipped_count == 0:
            QMessageBox.information(
                self, "Scan Complete",
                "No vulnerabilities or skipped target boundaries discovered."
            )
            return

        # Collect findings for export
        findings = []
        for row in range(self.table.rowCount()):
            findings.append({
                "target_type": self.table.item(row, 0).text(),
                "details": self.table.item(row, 1).text(),
                "remediation": self.table.item(row, 2).text(),
                "file_path": self.table.item(row, 3).text()
            })

        default_log_dir = Path("~/depsweep/logs").expanduser()
        default_log_dir.mkdir(parents=True, exist_ok=True)

        timestamp_str = QDateTime.currentDateTime().toString("yyyyMMdd-HHmmss")

        if self.chk_export_json.isChecked():
            json_path_str, _ = QFileDialog.getSaveFileName(
                self,
                "Save JSON Audit Report",
                str(default_log_dir / f"depsweep_audit_{timestamp_str}.json"),
                "JSON Files (.json);;All Files (*)"
            )
            if json_path_str:
                export_json(json_path_str, total_count, findings, self.skipped_cache_list)

        if self.chk_export_csv.isChecked():
            csv_path_str, _ = QFileDialog.getSaveFileName(
                self,
                "Save CSV Audit Report",
                str(default_log_dir / f"depsweep_audit_{timestamp_str}.csv"),
                "CSV Files (.csv);;All Files (*)"
            )
            if csv_path_str:
                export_csv(csv_path_str, findings, self.skipped_cache_list)


def export_json(path: str, total_count: int, findings: List[Dict[str, str]], skipped: List[Dict[str, str]]) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "generated_by": f"DepSweep v{__version__} CLI & GUI",
                "copyright": "Copyright (c) 2026 Don Prince",
                "total_flagged": total_count,
                "total_skipped": len(skipped),
                "results": findings,
                "skipped_artifacts": skipped
            }, f, indent=4)
        print(f"\n[SUCCESS] JSON Report saved to: {path}")
    except Exception as e:
        print(f"\n[ERROR] Failed to save JSON report: {e}", file=sys.stderr)


def export_csv(path: str, findings: List[Dict[str, str]], skipped: List[Dict[str, str]]) -> None:
    try:
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Report Generated By:", f"DepSweep v{__version__} CLI & GUI"])
            writer.writerow(["Copyright:", "Copyright (c) 2026 Don Prince"])
            writer.writerow([])

            # Section A: Flagged Core Vulnerabilities Matrix
            writer.writerow(["=== SECTION 1: FLAGGED VULNERABILITY FINDINGS ==="])
            writer.writerow(["Target Type", "Vulnerability Details", "Remediation Required", "File Path (Where)"])
            for item in findings:
                writer.writerow([item["target_type"], item["details"], item["remediation"], item["file_path"]])
            writer.writerow([])

            # Section B: Audit Trail Skipped Asset Boundaries Manifest
            writer.writerow(["=== SECTION 2: SKIPPED UNEXAMINED ARTIFACTS MANIFEST ==="])
            writer.writerow(["Artifact Location Path", "Estimated Size", "Skipped Reason Boundary Exception"])
            for item in skipped:
                writer.writerow([item["file_path"], item["size"], item["reason"]])

        print(f"\n[SUCCESS] CSV Report saved to: {path}")
    except Exception as e:
        print(f"\n[ERROR] Failed to save CSV report: {e}", file=sys.stderr)


def run_cli_mode(args: argparse.Namespace) -> None:
    """Headless CLI execution logic."""
    print(f"=== Starting DepSweep CLI v{__version__} ===")
    print("Copyright (c) 2026 Don Prince")
    print(f"Scanning Target Directory: {args.path}")

    logger = setup_persistent_logging()

    try:
        parts: List[int] = [int(x) for x in args.certifi_date.split("-")]
        if len(parts) != 3:
            raise ValueError()
        certifi_threshold: Tuple[int, int, int] = (parts[0], parts[1], parts[2])
    except Exception:
        print("[ERROR] --certifi-date must follow the specific YYYY-MM-DD pattern syntax.", file=sys.stderr)
        sys.exit(1)

    targets = []
    if args.python:
        targets.append("python")
    if args.node:
        targets.append("node")
    if args.appimages:
        targets.append("appimages")
    if args.cargo:
        targets.append("cargo")
    if args.go:
        targets.append("go")

    if not targets:
        print("[ERROR] No target scan profiles selected. Enable --python, --node, --appimages, --cargo, or --go.", file=sys.stderr)
        sys.exit(1)

    worker = SweepWorker(args.path, targets, certifi_threshold, args.binary_regex)
    findings_list = []
    skipped_list = []
    scanned_files_count = 0
    spinner_chars = ['|', '/', '-', '\\']

    def handle_progress(file_path: str) -> None:
        nonlocal scanned_files_count
        scanned_files_count += 1
        if args.progress:
            display_path = file_path if len(file_path) < 55 else f"...{file_path[-52:]}"
            spinner = spinner_chars[scanned_files_count % 4]
            sys.stdout.write(f"\r [{spinner}] Scanned items: {scanned_files_count} | Analyzing: {display_path}")
            sys.stdout.flush()

    def handle_finding(target_type: str, details: str, remediation: str, file_path: str) -> None:
        if args.progress:
            sys.stdout.write("\r" + " " * 90 + "\r")

        print(f" 📌 [{target_type}] -> {details}")
        print(f" 🔧 Action: {remediation}")
        print(f" 📍 Location: {file_path}\n")

        findings_list.append({
            "target_type": target_type,
            "details": details,
            "remediation": remediation,
            "file_path": file_path
        })

    def handle_cli_skip(path: str, reason: str) -> None:
        try:
            size_bytes = os.path.getsize(path)
            size_str = f"{size_bytes / 1_000_000:.1f} MB" if size_bytes > 0 else "0.0 MB"
        except Exception:
            size_str = "UNKNOWN"

        skipped_list.append({
            "file_path": path,
            "size": size_str,
            "reason": reason
        })

    worker.progress_signal.connect(handle_progress)
    worker.found_vulnerability_signal.connect(handle_finding)
    worker.skipped_file_signal.connect(handle_cli_skip)
    worker.run()

    total_found = worker.vuln_count
    total_skipped = len(skipped_list)

    if args.progress:
        sys.stdout.write("\r" + " " * 90 + "\r")

    print(f"========================================")
    print(f"DepSweep CLI Task Finished. Evaluated {scanned_files_count} total files.")
    print(f"Vulnerabilities Flagged: {total_found} | Skipped Assets: {total_skipped}")

    if total_found > 0 or total_skipped > 0:
        if args.json:
            try:
                with open(args.json, "w", encoding="utf-8") as f:
                    json.dump({
                        "generated_by": f"DepSweep v{__version__} CLI",
                        "copyright": "Copyright (c) 2026 Don Prince",
                        "total_flagged": total_found,
                        "total_skipped": total_skipped,
                        "results": findings_list,
                        "skipped_artifacts": skipped_list
                    }, f, indent=4)
                print(f"\n[SUCCESS] CLI JSON Report saved to: {args.json}")
            except Exception as e:
                print(f"[ERROR] Failed to save CLI JSON report: {e}", file=sys.stderr)

        if args.csv:
            try:
                with open(args.csv, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Report Generated By:", f"DepSweep v{__version__} CLI"])
                    writer.writerow(["Copyright:", "Copyright (c) 2026 Don Prince"])
                    writer.writerow([])

                    writer.writerow(["=== SECTION 1: FLAGGED VULNERABILITY FINDINGS ==="])
                    writer.writerow(["Target Type", "Vulnerability Details", "Remediation Required", "File Path (Where)"])
                    for item in findings_list:
                        writer.writerow([item["target_type"], item["details"], item["remediation"], item["file_path"]])
                    writer.writerow([])

                    writer.writerow(["=== SECTION 2: SKIPPED UNEXAMINED ARTIFACTS MANIFEST ==="])
                    writer.writerow(["Artifact Location Path", "Estimated Size", "Skipped Reason Boundary Exception"])
                    for item in skipped_list:
                        writer.writerow([item["file_path"], item["size"], item["reason"]])

                print(f"\n[SUCCESS] CLI CSV Report saved to: {args.csv}")
            except Exception as e:
                print(f"[ERROR] Failed to save CLI CSV report: {e}", file=sys.stderr)

    sys.exit(1 if total_found > 0 else 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "DepSweep CLI & GUI — High-Performance Dependency Vulnerability & Binary Threat Auditor.\n\n"
            "Recursively sweeps local filesystems, Python site-packages/wheels, Node.js lockfiles, "
            "Rust Cargo.lock files, Go modules, and standalone AppImages or ELF binaries to "
            "flag revoked/compromised TLS root certificates (e.g., eMudhra) and outdated metadata. "
            "Supports responsive PySide6 GUI dashboard execution and headless CI/CD pipeline automation."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Version action runtime argument
    parser.add_argument(
        "--version",
        action="version",
        version=f"DepSweep v{__version__}\nCopyright (c) 2026 Don Prince. Licensed under the GNU GPL v3.",
    )

    parser.add_argument("--cli", action="store_true", help="Enable headless command line terminal scan mode.")
    parser.add_argument("--path", type=str, help="Path to the directory root you want to sweep.")
    parser.add_argument("--progress", action="store_true", help="Display terminal counter spinner in CLI.")
    parser.add_argument(
        "--certifi-date",
        type=str,
        default="2024-07-04",
        help="Flag certifi versions older than this date (YYYY-MM-DD)."
    )
    parser.add_argument(
        "--binary-regex",
        type=str,
        default="eMudhra|eMudhra Premium|eMudhra Sub-CA",
        help="Custom signature pattern to match in binaries."
    )

    # Target Toggles
    parser.add_argument("--python", action="store_true", help="Scan Python virtual environments and wheels.")
    parser.add_argument("--node", action="store_true", help="Scan Node.js lockfiles and packages.")
    parser.add_argument("--appimages", action="store_true", help="Scan raw binary bundles and AppImages.")
    parser.add_argument("--cargo", action="store_true", help="Scan Rust Cargo.lock files.")
    parser.add_argument("--go", action="store_true", help="Scan Go go.mod and go.sum manifests.")

    # Output Exporters
    parser.add_argument("--json", type=str, help="File destination path to save a JSON report.")
    parser.add_argument("--csv", type=str, help="File destination path to save a CSV report.")

    parsed_args = parser.parse_args()

    if parsed_args.cli:
        if not parsed_args.path:
            parser.error("--path is required when running in --cli mode.")
        run_cli_mode(parsed_args)
    else:
        app = QApplication(sys.argv)
        app.setStyle("Fusion")
        window = AuditSweeperWindow()
        window.show()
        sys.exit(app.exec())
