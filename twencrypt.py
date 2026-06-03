#!/usr/bin/env python3
"""
twencrypt.py — Encrypt a folder of .tid files into a TiddlyWiki HTML file,
using an existing encrypted TiddlyWiki as the template.

Layout expected in <input_folder> (matches twdecrypt.py's output):
    <root>/*.tid          ordinary (user) tiddlers
    <root>/system/*.tid   system tiddlers
    <root>/plugin/*.tid   plugin tiddlers (text body is the raw JSON payload)

Usage:
    python3 twencrypt.py <input_folder> <template.html> <output.html>

The password is requested twice on the terminal (no echo, no shell history)
and must match. Output file must not already exist. The template file is
read once and its <pre id="encryptedStoreArea"> contents are replaced with
freshly encrypted ciphertext; everything else in the template is preserved.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import html
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --------------------------------------------------------------------------
# SJCL-compatible AES-CCM encryption
# --------------------------------------------------------------------------
# SJCL stores a 16-byte IV but uses only the first (15 - L) bytes as the CCM
# nonce, where L is the smallest value in [2, 8] such that the plaintext
# length fits in L bytes. The `cryptography` library's AESCCM hardcodes
# L = 15 - len(nonce), which caps payloads to ~64 KiB when nonce is 13
# bytes, so we implement CCM by hand on top of raw AES-ECB.


def _aes_ecb_block(key: bytes, block: bytes) -> bytes:
    """Encrypt one 16-byte block with AES (the CCM primitive)."""
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _sjcl_ccm_encrypt(
    key: bytes, iv16: bytes, plaintext: bytes, adata: bytes, tag_len: int
) -> bytes:
    """Returns ciphertext || tag (the form SJCL packs into `ct`)."""
    pt_len = len(plaintext)

    L = 2
    while pt_len >= (1 << (8 * L)) and L < 8:
        L += 1
    nonce_len = 15 - L
    nonce = iv16[:nonce_len]

    # --- CBC-MAC over B_0 || formatted_adata || padded_plaintext ---
    has_adata = len(adata) > 0
    M = tag_len
    flags_b0 = (0x40 if has_adata else 0) | (((M - 2) // 2) << 3) | (L - 1)
    b0 = bytearray(16)
    b0[0] = flags_b0
    b0[1 : 1 + nonce_len] = nonce
    b0[16 - L : 16] = pt_len.to_bytes(L, "big")

    formatted_adata = b""
    if has_adata:
        la = len(adata)
        if la < 0xFF00:
            la_enc = la.to_bytes(2, "big")
        elif la < (1 << 32):
            la_enc = b"\xff\xfe" + la.to_bytes(4, "big")
        else:
            la_enc = b"\xff\xff" + la.to_bytes(8, "big")
        formatted_adata = la_enc + adata
        if len(formatted_adata) % 16:
            formatted_adata += b"\x00" * (16 - len(formatted_adata) % 16)

    pt_padded = plaintext
    if len(pt_padded) % 16:
        pt_padded += b"\x00" * (16 - len(pt_padded) % 16)

    mac_input = bytes(b0) + formatted_adata + pt_padded
    state = b"\x00" * 16
    for o in range(0, len(mac_input), 16):
        block = bytes(s ^ b for s, b in zip(state, mac_input[o : o + 16]))
        state = _aes_ecb_block(key, block)
    raw_tag = state[:tag_len]

    # --- CTR encryption + tag XOR with A_0 keystream ---
    flags_a = L - 1
    a0 = bytearray(16)
    a0[0] = flags_a
    a0[1 : 1 + nonce_len] = nonce
    s0 = _aes_ecb_block(key, bytes(a0))
    enc_tag = bytes(t ^ k for t, k in zip(raw_tag, s0[:tag_len]))

    ciphertext = bytearray()
    offset = 0
    counter = 1
    while offset < pt_len:
        a = bytearray(16)
        a[0] = flags_a
        a[1 : 1 + nonce_len] = nonce
        a[16 - L : 16] = counter.to_bytes(L, "big")
        keystream = _aes_ecb_block(key, bytes(a))
        chunk = plaintext[offset : offset + 16]
        ciphertext.extend(b ^ k for b, k in zip(chunk, keystream[: len(chunk)]))
        offset += 16
        counter += 1

    return bytes(ciphertext) + enc_tag


# Defaults match what TiddlyWiki itself produces.
_DEFAULT_KS = 256  # AES key size, bits
_DEFAULT_ITER = 10000  # PBKDF2 iterations
_DEFAULT_TS = 64  # tag size, bits
_DEFAULT_SALT_BYTES = 8
_DEFAULT_IV_BYTES = 16


def sjcl_encrypt(password: str, plaintext: str) -> dict[str, Any]:
    """Encrypt a string and return the SJCL JSON blob (as a dict)."""
    salt = os.urandom(_DEFAULT_SALT_BYTES)
    iv = os.urandom(_DEFAULT_IV_BYTES)

    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=_DEFAULT_KS // 8,
        salt=salt,
        iterations=_DEFAULT_ITER,
    )
    key = kdf.derive(password.encode("utf-8"))

    ct = _sjcl_ccm_encrypt(key, iv, plaintext.encode("utf-8"), b"", _DEFAULT_TS // 8)

    return {
        "iv": base64.b64encode(iv).decode("ascii"),
        "v": 1,
        "iter": _DEFAULT_ITER,
        "ks": _DEFAULT_KS,
        "ts": _DEFAULT_TS,
        "mode": "ccm",
        "adata": "",
        "cipher": "aes",
        "salt": base64.b64encode(salt).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }


# --------------------------------------------------------------------------
# .tid parsing
# --------------------------------------------------------------------------
_HEADER_LINE_RE = re.compile(r"^([A-Za-z0-9_\-\.]+):\s?(.*)$")


def parse_tid(text: str) -> dict[str, Any]:
    """
    Parse a .tid file. Header is `field: value` lines, then a blank line,
    then the rest of the file is the `text` field. If no blank line is
    found, the whole file is treated as header (with empty text).
    """
    # Normalize line endings so the header/body split is stable.
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    lines = text.split("\n")
    header: dict[str, str] = {}
    body_start = len(lines)  # default: no body

    for i, line in enumerate(lines):
        if line == "":
            body_start = i + 1
            break
        m = _HEADER_LINE_RE.match(line)
        if not m:
            # First non-header line with no preceding blank line — treat as
            # start of body. This matches TiddlyWiki's lenient behavior.
            body_start = i
            break
        header[m.group(1)] = m.group(2)

    body = "\n".join(lines[body_start:]) if body_start < len(lines) else ""
    header["text"] = body
    return header


def filename_to_title(filename: str) -> str:
    """
    Best-effort fallback used only when a .tid file is missing a `title:`
    header. The underscore substitution from twdecrypt.py is not
    reversible, so this just strips the .tid extension and returns the
    stem unchanged.
    """
    return filename[:-4] if filename.endswith(".tid") else filename


# --------------------------------------------------------------------------
# Folder scan
# --------------------------------------------------------------------------
def collect_tiddlers(folder: Path) -> dict[str, dict[str, Any]]:
    """
    Walk <folder>, parse every *.tid file into a tiddler dict, and return
    a {title: tiddler} mapping. Files in system/ and plugin/ subfolders
    are included; deeper nesting is not.
    """
    store: dict[str, dict[str, Any]] = {}
    seen_files: dict[str, Path] = {}

    candidates: list[Path] = list(folder.glob("*.tid"))
    for sub in ("system", "plugin"):
        subdir = folder / sub
        if subdir.is_dir():
            candidates.extend(subdir.glob("*.tid"))

    for path in candidates:
        try:
            raw = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as e:
            raise ValueError(f"{path}: not valid UTF-8 ({e})") from e

        tid = parse_tid(raw)
        # If the header has a `title`, trust it; otherwise derive from filename.
        title = tid.get("title") or filename_to_title(path.name)
        tid["title"] = title

        if title in store:
            raise ValueError(
                f"duplicate title {title!r}: both {seen_files[title]} and {path}"
            )
        store[title] = tid
        seen_files[title] = path

    return store


# --------------------------------------------------------------------------
# Template surgery
# --------------------------------------------------------------------------
_STORE_RE = re.compile(
    r'(<pre[^>]*id\s*=\s*["\']encryptedStoreArea["\'][^>]*>)(.*?)(</pre>)',
    re.DOTALL | re.IGNORECASE,
)


def render_into_template(template_html: str, blob: dict[str, Any]) -> str:
    payload = json.dumps(blob, separators=(",", ":"))
    # Match what TiddlyWiki itself emits: escape the JSON for HTML so that
    # quotes and angle brackets don't break the surrounding markup.
    payload_escaped = html.escape(payload, quote=True)

    def _sub(m: re.Match[str]) -> str:
        return m.group(1) + "\n" + payload_escaped + "\n" + m.group(3)

    new_html, n = _STORE_RE.subn(_sub, template_html, count=1)
    if n == 0:
        raise ValueError(
            "template has no <pre id='encryptedStoreArea'>; is it an encrypted TiddlyWiki?"
        )
    return new_html


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Encrypt a folder of .tid files into a TiddlyWiki HTML file."
    )
    parser.add_argument("input", type=Path, help="Folder containing .tid files")
    parser.add_argument(
        "template", type=Path, help="Encrypted TiddlyWiki HTML to use as template"
    )
    parser.add_argument("output", type=Path, help="Output HTML file (must not exist)")
    args = parser.parse_args(argv)

    if not args.input.is_dir():
        print(f"error: input folder does not exist: {args.input}", file=sys.stderr)
        return 2
    if not args.template.is_file():
        print(f"error: template file not found: {args.template}", file=sys.stderr)
        return 2
    if args.output.exists():
        print(f"error: output file already exists: {args.output}", file=sys.stderr)
        return 2

    # Parse tiddlers and read template up front, so any structural error
    # surfaces before the user types a password.
    try:
        store = collect_tiddlers(args.input)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if not store:
        print(f"error: no .tid files found in {args.input}", file=sys.stderr)
        return 1

    template_html = args.template.read_text(encoding="utf-8")
    # Validate the template before asking for a password.
    if not _STORE_RE.search(template_html):
        print(
            "error: template has no <pre id='encryptedStoreArea'>; "
            "is it an encrypted TiddlyWiki?",
            file=sys.stderr,
        )
        return 1

    # Prompt for password twice; confirm match.
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("error: passwords do not match", file=sys.stderr)
        return 1
    if not password:
        print("error: password may not be empty", file=sys.stderr)
        return 1
    del confirm

    plaintext = json.dumps(store, separators=(",", ":"), ensure_ascii=False)

    try:
        blob = sjcl_encrypt(password, plaintext)
    finally:
        del password

    new_html = render_into_template(template_html, blob)

    # Write atomically: write to a temp file in the same folder, then rename.
    tmp = args.output.with_suffix(args.output.suffix + ".tmp")
    tmp.write_text(new_html, encoding="utf-8")
    tmp.replace(args.output)

    print(f"Encrypted {len(store)} tiddlers to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
