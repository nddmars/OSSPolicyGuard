"""OPG-053 — Install-script and binary inventory without execution.

Scans NPM tarballs and PyPI wheel archives to surface lifecycle hooks,
native binaries, obfuscated code, and network-capable files — no code is
executed during the scan.
"""
from __future__ import annotations

import io  # noqa: F401  (part of declared stdlib surface)
import json
import os  # noqa: F401  (part of declared stdlib surface)
import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NPM_LIFECYCLE: frozenset[str] = frozenset([
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "uninstall",
    "postuninstall",
    "prepublish",
    "prepare",
    "prepack",
    "postpack",
])

BINARY_EXTS: frozenset[str] = frozenset([
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".node",
    ".bin",
    ".elf",
    ".wasm",
    ".pyd",
    ".a",
    ".lib",
])

# Detects outbound-network API usage in source files.
# Unescaped dots are intentional (broad matching).
_NETWORK_RE = re.compile(
    r"socket\.|http\.request|urllib\.request|requests\.|fetch\("
    r"|XMLHttpRequest|net\.connect|http\.get|https\.get"
    r"|require\(['\"]https?['\"]",
    re.I,
)

# Detects common obfuscation primitives and dense hex-escape sequences.
# The hex-escape branch requires 4+ consecutive \xNN sequences in source text.
_OBFUSC_RE = re.compile(
    r"eval\s*\(|atob\s*\(|Buffer\.from[^)]*base64|(?:\\x[0-9a-fA-F]{2}){4,}",
    re.I,
)

MAX_ARCHIVE_SIZE: int = 50 * 1024 * 1024  # 50 MB
MAX_FILE_COUNT: int = 5_000

# Maximum bytes read per file for regex-based content checks.
_READ_CHUNK: int = 64 * 1024  # 64 KB

# File suffixes eligible for content-based analysis inside PyPI wheels.
_TEXT_SUFFIXES: frozenset[str] = frozenset([
    ".py", ".pyw", ".js", ".ts", ".sh", ".bash", ".rb", ".pl",
])


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ArtifactInventory:
    """Structured result of a static package inventory scan."""

    lifecycle_scripts: list[dict]       # [{name, command, source_file}]
    native_binaries: list[str]
    obfuscated_files: list[str]
    network_capable_files: list[str]
    new_executables: list[str]
    file_count: int = 0
    total_size_bytes: int = 0
    warnings: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Return a plain-dict representation including the computed risk level."""
        return {
            "lifecycle_scripts": self.lifecycle_scripts,
            "native_binaries": self.native_binaries,
            "obfuscated_files": self.obfuscated_files,
            "network_capable_files": self.network_capable_files,
            "new_executables": self.new_executables,
            "file_count": self.file_count,
            "total_size_bytes": self.total_size_bytes,
            "warnings": self.warnings,
            "risk_level": self.risk_level(),
        }

    def risk_level(self) -> str:
        """Compute a four-tier risk rating from the collected indicators.

        CRITICAL — obfuscated code combined with network calls, or lifecycle
                   scripts combined with native binaries (both escalation paths
                   suggest supply-chain compromise).
        HIGH     — any one of: lifecycle scripts, native binaries, obfuscated files.
        MEDIUM   — network-capable files only.
        LOW      — no indicators detected.
        """
        has_obfuscated = bool(self.obfuscated_files)
        has_network = bool(self.network_capable_files)
        has_lifecycle = bool(self.lifecycle_scripts)
        has_natives = bool(self.native_binaries)

        if (has_obfuscated and has_network) or (has_lifecycle and has_natives):
            return "CRITICAL"

        if has_lifecycle or has_natives or has_obfuscated:
            return "HIGH"

        if has_network:
            return "MEDIUM"

        return "LOW"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_obfuscated(content: bytes) -> bool:
    """Return True if *content* appears to be obfuscated or otherwise suspicious.

    Decision criteria (any one is sufficient to return True):

    1. The bytes cannot be decoded as UTF-8 — a binary blob masquerading as a
       text file is treated as suspicious.
    2. The content matches the obfuscation pattern regex (_OBFUSC_RE).
    3. Any single line exceeds 500 characters (minified/packed code heuristic).
    """
    try:
        text = content.decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        # Binary blob in a text-position file is suspicious.
        return True

    if _OBFUSC_RE.search(text):
        return True

    for line in text.splitlines():
        if len(line) > 500:
            return True

    return False


def _has_network(content: bytes) -> bool:
    """Return True if *content* contains network-related API calls."""
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover
        return False
    return bool(_NETWORK_RE.search(text))


def _is_executable(mode: int) -> bool:
    """Return True if *mode* has any executable permission bit set."""
    return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def _safe_path(name: str) -> bool:
    """Return True when *name* is free of path-traversal sequences."""
    if name.startswith("/"):
        return False
    # Check each segment individually to catch both "foo/../bar" and "..".
    if ".." in name.replace("\\", "/").split("/"):
        return False
    return True


def _extract_npm_lifecycle(scripts: object, source_file: str) -> list[dict]:
    """Return lifecycle-script dicts from a *scripts* mapping."""
    results: list[dict] = []
    if not isinstance(scripts, dict):
        return results
    for script_name, command in scripts.items():
        if script_name in NPM_LIFECYCLE:
            results.append({
                "name": script_name,
                "command": command,
                "source_file": source_file,
            })
    return results


# ---------------------------------------------------------------------------
# NPM package inventory
# ---------------------------------------------------------------------------

def inventory_npm_package(
    package_json: Optional[dict] = None,
    archive_path: Optional[str] = None,
    size_limit: int = MAX_ARCHIVE_SIZE,
) -> ArtifactInventory:
    """Inventory an NPM package without executing any code.

    Args:
        package_json: Parsed *package.json* dict (optional).  Lifecycle
            scripts are extracted directly from ``package_json["scripts"]``.
        archive_path: Path to a ``.tgz`` / ``.tar.gz`` archive (optional).
            Files are classified by extension and inspected for obfuscation
            and network-API usage (up to 64 KB per file).
        size_limit: Maximum total uncompressed bytes to process before
            halting.  Defaults to :data:`MAX_ARCHIVE_SIZE` (50 MB).

    Returns:
        An :class:`ArtifactInventory` populated with detected indicators.
    """
    lifecycle_scripts: list[dict] = []
    native_binaries: list[str] = []
    obfuscated_files: list[str] = []
    network_capable_files: list[str] = []
    new_executables: list[str] = []
    warnings: list[str] = []
    file_count: int = 0
    total_size_bytes: int = 0

    # ------------------------------------------------------------------
    # 1. Lifecycle scripts from the supplied package.json dict
    # ------------------------------------------------------------------
    if package_json is not None:
        lifecycle_scripts.extend(
            _extract_npm_lifecycle(
                package_json.get("scripts", {}),
                "package.json",
            )
        )

    # ------------------------------------------------------------------
    # 2. Archive scan
    # ------------------------------------------------------------------
    if archive_path is not None:
        archive_path_obj = Path(archive_path)

        if not archive_path_obj.exists():
            warnings.append(f"Archive not found: {archive_path}")
        elif not tarfile.is_tarfile(str(archive_path_obj)):
            warnings.append(f"Not a valid tar archive: {archive_path}")
        else:
            try:
                with tarfile.open(str(archive_path_obj), mode="r:gz") as tf:
                    for member in tf:
                        if file_count >= MAX_FILE_COUNT:
                            warnings.append(
                                f"File count limit ({MAX_FILE_COUNT}) reached; "
                                "remaining members skipped."
                            )
                            break

                        # Path-traversal guard
                        if not _safe_path(member.name):
                            warnings.append(
                                f"Skipping dangerous path: {member.name}"
                            )
                            continue

                        # Only process regular files
                        if not member.isreg():
                            continue

                        file_count += 1

                        if total_size_bytes + member.size > size_limit:
                            warnings.append(
                                f"Size limit ({size_limit} bytes) reached; "
                                f"skipping {member.name} and remaining files."
                            )
                            break
                        total_size_bytes += member.size

                        suffix = Path(member.name).suffix.lower()

                        # Executable-bit check (non-zero mode only)
                        if member.mode and _is_executable(member.mode):
                            new_executables.append(member.name)

                        # Native binary by extension — skip content scan
                        if suffix in BINARY_EXTS:
                            native_binaries.append(member.name)
                            continue

                        # Read up to 64 KB for content-based checks
                        chunk: bytes = b""
                        try:
                            fobj = tf.extractfile(member)
                            if fobj is not None:
                                chunk = fobj.read(_READ_CHUNK)
                        except (tarfile.TarError, OSError) as exc:
                            warnings.append(
                                f"Could not read {member.name}: {exc}"
                            )
                            continue

                        # Opportunistically harvest lifecycle scripts from any
                        # package.json found inside the archive.
                        if Path(member.name).name == "package.json" and chunk:
                            try:
                                inner_pkg = json.loads(
                                    chunk.decode("utf-8", errors="replace")
                                )
                                lifecycle_scripts.extend(
                                    _extract_npm_lifecycle(
                                        inner_pkg.get("scripts", {}),
                                        member.name,
                                    )
                                )
                            except (json.JSONDecodeError, AttributeError):
                                pass

                        if chunk:
                            if _check_obfuscated(chunk):
                                obfuscated_files.append(member.name)
                            if _has_network(chunk):
                                network_capable_files.append(member.name)

            except tarfile.TarError as exc:
                warnings.append(f"Error reading archive {archive_path}: {exc}")

    return ArtifactInventory(
        lifecycle_scripts=lifecycle_scripts,
        native_binaries=native_binaries,
        obfuscated_files=obfuscated_files,
        network_capable_files=network_capable_files,
        new_executables=new_executables,
        file_count=file_count,
        total_size_bytes=total_size_bytes,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# PyPI package inventory
# ---------------------------------------------------------------------------

def inventory_pypi_package(
    wheel_path: Optional[str] = None,
    metadata: Optional[dict] = None,
    size_limit: int = MAX_ARCHIVE_SIZE,
) -> ArtifactInventory:
    """Inventory a PyPI wheel package without executing any code.

    Args:
        wheel_path: Path to a ``.whl`` file (optional).  ``.pyd`` and ``.so``
            members are recorded as native binaries; ``.py`` files and other
            text-like sources are inspected for obfuscation and network calls.
        metadata: Parsed metadata dict (optional; reserved for future use).
        size_limit: Maximum total uncompressed bytes to process before
            halting.  Defaults to :data:`MAX_ARCHIVE_SIZE` (50 MB).

    Returns:
        An :class:`ArtifactInventory` populated with detected indicators.
    """
    lifecycle_scripts: list[dict] = []
    native_binaries: list[str] = []
    obfuscated_files: list[str] = []
    network_capable_files: list[str] = []
    new_executables: list[str] = []
    warnings: list[str] = []
    file_count: int = 0
    total_size_bytes: int = 0

    if wheel_path is not None:
        wheel_path_obj = Path(wheel_path)

        if not wheel_path_obj.exists():
            warnings.append(f"Wheel not found: {wheel_path}")
        elif not zipfile.is_zipfile(str(wheel_path_obj)):
            warnings.append(f"Not a valid zip/wheel archive: {wheel_path}")
        else:
            try:
                with zipfile.ZipFile(str(wheel_path_obj), mode="r") as zf:
                    for info in zf.infolist():
                        if file_count >= MAX_FILE_COUNT:
                            warnings.append(
                                f"File count limit ({MAX_FILE_COUNT}) reached; "
                                "remaining entries skipped."
                            )
                            break

                        name = info.filename

                        # Path-traversal guard
                        if not _safe_path(name):
                            warnings.append(f"Skipping dangerous path: {name}")
                            continue

                        # Skip directory entries
                        if name.endswith("/"):
                            continue

                        file_count += 1

                        if total_size_bytes + info.file_size > size_limit:
                            warnings.append(
                                f"Size limit ({size_limit} bytes) reached; "
                                f"skipping {name} and remaining files."
                            )
                            break
                        total_size_bytes += info.file_size

                        suffix = Path(name).suffix.lower()

                        # Executable-bit check from Unix external attributes
                        unix_mode = info.external_attr >> 16
                        if unix_mode and _is_executable(unix_mode):
                            new_executables.append(name)

                        # Native binary by extension — skip content scan
                        if suffix in BINARY_EXTS:
                            native_binaries.append(name)
                            continue

                        # Only perform content checks on text-like source files
                        if suffix not in _TEXT_SUFFIXES:
                            continue

                        # Read up to 64 KB for content-based checks
                        chunk: bytes = b""
                        try:
                            with zf.open(info) as fobj:
                                chunk = fobj.read(_READ_CHUNK)
                        except (zipfile.BadZipFile, KeyError, OSError) as exc:
                            warnings.append(f"Could not read {name}: {exc}")
                            continue

                        if chunk:
                            if _check_obfuscated(chunk):
                                obfuscated_files.append(name)
                            if _has_network(chunk):
                                network_capable_files.append(name)

            except zipfile.BadZipFile as exc:
                warnings.append(f"Error reading wheel {wheel_path}: {exc}")

    return ArtifactInventory(
        lifecycle_scripts=lifecycle_scripts,
        native_binaries=native_binaries,
        obfuscated_files=obfuscated_files,
        network_capable_files=network_capable_files,
        new_executables=new_executables,
        file_count=file_count,
        total_size_bytes=total_size_bytes,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "ArtifactInventory",
    "inventory_npm_package",
    "inventory_pypi_package",
]
