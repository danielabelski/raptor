"""SCA parser for binary import tables.

Converts an REDatabase's import list into SCA :class:`Dependency` records
with ``ecosystem="native"`` and ``source_kind="binary_import_table"``.
Matches imported symbols to known library names (libc, libssl, libz, etc.)
and creates one Dependency per detected library.

This catches dependencies that manifest-based SCA misses: vendored,
statically linked, or build-system-injected libraries.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Confidence, Dependency, PinStyle

_LIBRARY_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "openssl": {
        "symbols": frozenset({
            "SSL_read", "SSL_write", "SSL_CTX_new", "SSL_new",
            "SSL_connect", "SSL_accept", "SSL_shutdown",
            "SSL_get_error", "SSL_library_init",
            "EVP_EncryptInit", "EVP_DecryptInit", "EVP_DigestInit",
            "RSA_public_encrypt", "RSA_private_decrypt",
        }),
        "soname_pattern": re.compile(r"libssl\.so\.(\d+)"),
        "min_match": 2,
    },
    "zlib": {
        "symbols": frozenset({
            "deflate", "inflate", "deflateInit", "inflateInit",
            "deflateEnd", "inflateEnd", "compress", "uncompress",
            "gzopen", "gzread", "gzwrite", "gzclose",
        }),
        "soname_pattern": re.compile(r"libz\.so\.(\d+)"),
        "min_match": 2,
    },
    "libcurl": {
        "symbols": frozenset({
            "curl_easy_init", "curl_easy_perform", "curl_easy_setopt",
            "curl_easy_cleanup", "curl_multi_init",
            "curl_global_init", "curl_url",
        }),
        "soname_pattern": re.compile(r"libcurl\.so\.(\d+)"),
        "min_match": 2,
    },
    "libxml2": {
        "symbols": frozenset({
            "xmlParseFile", "xmlParseMemory", "xmlReadFile",
            "xmlReadMemory", "xmlDocGetRootElement", "xmlFreeDoc",
            "xmlXPathEvalExpression", "xmlSAXParseFile",
        }),
        "soname_pattern": re.compile(r"libxml2\.so\.(\d+)"),
        "min_match": 2,
    },
    "sqlite3": {
        "symbols": frozenset({
            "sqlite3_open", "sqlite3_close", "sqlite3_exec",
            "sqlite3_prepare_v2", "sqlite3_step", "sqlite3_finalize",
            "sqlite3_bind_text", "sqlite3_column_text",
        }),
        "soname_pattern": re.compile(r"libsqlite3\.so"),
        "min_match": 2,
    },
    "libpng": {
        "symbols": frozenset({
            "png_create_read_struct", "png_create_write_struct",
            "png_read_image", "png_write_image",
            "png_set_IHDR", "png_get_IHDR",
        }),
        "soname_pattern": re.compile(r"libpng\d*\.so"),
        "min_match": 2,
    },
    "libjpeg": {
        "symbols": frozenset({
            "jpeg_CreateDecompress", "jpeg_CreateCompress",
            "jpeg_read_header", "jpeg_start_decompress",
            "jpeg_read_scanlines", "jpeg_finish_decompress",
        }),
        "soname_pattern": re.compile(r"libjpeg\.so"),
        "min_match": 2,
    },
}


def parse_binary_imports(
    db,
    *,
    binary_path: Optional[Path] = None,
) -> List[Dependency]:
    """Extract library dependencies from REDatabase imports.

    Parameters
    ----------
    db:
        An REDatabase instance with populated ``imports`` list.
    binary_path:
        Path to the binary (for ``declared_in``). Defaults to
        ``db.binary_path``.

    Returns
    -------
    list[Dependency]
        One Dependency per detected library.
    """
    bp = Path(binary_path or db.binary_path or "unknown")

    import_names = set()
    for imp in db.imports or []:
        name = imp.get("name", "")
        if name:
            import_names.add(name.split("@")[0])

    deps: List[Dependency] = []
    for lib_name, sig in _LIBRARY_SIGNATURES.items():
        matched = import_names & sig["symbols"]
        if len(matched) >= sig["min_match"]:
            version = _detect_version_from_soname(
                db, sig.get("soname_pattern"),
            )
            deps.append(Dependency(
                ecosystem="native",
                name=lib_name,
                version=version,
                declared_in=bp,
                scope="main",
                is_lockfile=False,
                pin_style=PinStyle.UNKNOWN,
                direct=True,
                purl="pkg:native/%s%s" % (
                    lib_name,
                    "@%s" % version if version else "",
                ),
                parser_confidence=Confidence(level="medium", reason="symbol-set match"),
                source_kind="binary_import_table",
                source_extra={
                    "matched_symbols": sorted(matched)[:5],
                    "match_count": len(matched),
                    "total_signatures": len(sig["symbols"]),
                },
            ))

    return deps


def _detect_version_from_soname(db, pattern) -> Optional[str]:
    """Try to extract a version from NEEDED sonames in metadata."""
    if pattern is None or not db.metadata:
        return None
    for key in ("needed", "sonames", "libraries"):
        libs = db.metadata.get(key, [])
        if isinstance(libs, list):
            for lib in libs:
                m = pattern.search(str(lib))
                if m:
                    # Some library patterns have no capture group
                    # (identity only, no version component).
                    if not m.groups():
                        return None
                    return m.group(1) + ".x"
    return None
