#!/usr/bin/env python3
"""
twdecrypt.py — Decrypt an encrypted TiddlyWiki HTML file and dump its
tiddlers as .tid files into an output folder.

Layout produced in <output_folder>:
    <root>/*.tid          ordinary (user) tiddlers
    <root>/system/*.tid   system tiddlers (title starts with '$:/') that
                          are NOT plugins
    <root>/plugin/*.tid   plugin tiddlers (plugin-type == 'plugin'),
                          with their raw JSON payload as the .tid text body

Usage:
    python3 twdecrypt.py <encrypted.html> <output_folder>

The password is read from the terminal with getpass (no echo, no shell
history). The output folder must either not exist or be empty.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import html
import json
import re
import sys
from pathlib import Path
from typing import Any

import time
from datetime import timedelta

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --------------------------------------------------------------------------
# SJCL-compatible AES-CCM decryption
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


def _sjcl_ccm_decrypt(
    key: bytes, iv16: bytes, ct_with_tag: bytes, adata: bytes, tag_len: int
) -> bytes:
    ct = ct_with_tag[:-tag_len]
    tag = ct_with_tag[-tag_len:]
    pt_len = len(ct)

    # Smallest L in [2, 8] that holds pt_len
    L = 2
    while pt_len >= (1 << (8 * L)) and L < 8:
        L += 1
    nonce_len = 15 - L
    nonce = iv16[:nonce_len]

    # --- CTR-mode decryption ---
    flags_a = L - 1
    plaintext = bytearray()
    offset = 0
    counter = 1
    while offset < pt_len:
        a = bytearray(16)
        a[0] = flags_a
        a[1 : 1 + nonce_len] = nonce
        a[16 - L : 16] = counter.to_bytes(L, "big")
        keystream = _aes_ecb_block(key, bytes(a))
        chunk = ct[offset : offset + 16]
        plaintext.extend(b ^ k for b, k in zip(chunk, keystream[: len(chunk)]))
        offset += 16
        counter += 1
    plaintext_bytes = bytes(plaintext)

    # --- Recover the transmitted MAC tag (XOR with A_0 keystream) ---
    a0 = bytearray(16)
    a0[0] = flags_a
    a0[1 : 1 + nonce_len] = nonce
    s0 = _aes_ecb_block(key, bytes(a0))
    received_tag = bytes(t ^ k for t, k in zip(tag, s0[:tag_len]))

    # --- Recompute the expected CBC-MAC tag and compare ---
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

    pt_padded = plaintext_bytes
    if len(pt_padded) % 16:
        pt_padded += b"\x00" * (16 - len(pt_padded) % 16)

    mac_input = bytes(b0) + formatted_adata + pt_padded
    state = b"\x00" * 16
    for o in range(0, len(mac_input), 16):
        block = bytes(s ^ b for s, b in zip(state, mac_input[o : o + 16]))
        state = _aes_ecb_block(key, block)

    if state[:tag_len] != received_tag:
        raise ValueError("MAC check failed (wrong password or corrupted data)")
    return plaintext_bytes


def sjcl_decrypt(password: str, blob: dict[str, Any]) -> str:
    """Decrypt one SJCL blob (the dict parsed from JSON) and return text."""
    salt = base64.b64decode(blob["salt"])
    iv = base64.b64decode(blob["iv"])
    ct = base64.b64decode(blob["ct"])
    adata = blob.get("adata", "").encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=blob["ks"] // 8,
        salt=salt,
        iterations=blob["iter"],
    )
    key = kdf.derive(password.encode("utf-8"))
    pt = _sjcl_ccm_decrypt(key, iv, ct, adata, blob["ts"] // 8)
    return pt.decode("utf-8")


# --------------------------------------------------------------------------
# Tiddler I/O
# --------------------------------------------------------------------------
_STORE_RE = re.compile(
    r'<pre[^>]*id\s*=\s*["\']encryptedStoreArea["\'][^>]*>(.*?)</pre>',
    re.DOTALL | re.IGNORECASE,
)


def extract_encrypted_blob(html_text: str) -> dict[str, Any]:
    m = _STORE_RE.search(html_text)
    if not m:
        raise ValueError("No <pre id='encryptedStoreArea'> found in input file")
    return json.loads(html.unescape(m.group(1)).strip())


def title_to_filename(title: str) -> str:
    """
    Replace filesystem-unsafe characters with underscores, one-for-one,
    matching the TiddlyWiki Node-edition style where `$:/foo/bar`
    becomes `$__foo_bar.tid`. Characters that pass through unchanged:
    letters, digits, space, '-', '_', '.', and '$'. Everything else
    (including the reserved < > : " / \\ | ? * and control chars) is
    replaced with a single '_' per character. Runs of underscores are
    NOT collapsed, so the original structure is preserved.
    """
    safe = re.sub(r"[^A-Za-z0-9 \-_.$]", "_", title)
    # Avoid filenames that are problematic on some filesystems.
    if safe in ("", ".", ".."):
        safe = "untitled"
    return safe + ".tid"


# Fields that always go in the header block, in this order. Anything else
# (and `text`) is also a header field, but we order the well-known ones
# first for readability, then alphabetize the rest.
_HEADER_PRIORITY = [
    "title",
    "creator",
    "modifier",
    "created",
    "modified",
    "type",
    "tags",
]


def tiddler_to_tid(tid: dict[str, Any]) -> str:
    """Serialize a tiddler dict to .tid file format."""
    text = tid.get("text", "")
    fields = {k: v for k, v in tid.items() if k != "text"}

    ordered_keys = [k for k in _HEADER_PRIORITY if k in fields]
    ordered_keys += sorted(k for k in fields if k not in _HEADER_PRIORITY)

    lines = []
    for k in ordered_keys:
        v = fields[k]
        if not isinstance(v, str):
            v = json.dumps(v) if not isinstance(v, (int, float)) else str(v)
        # .tid headers are one line; collapse any newlines defensively.
        v = v.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
        lines.append(f"{k}: {v}")

    return (
        "\n".join(lines)
        + "\n\n"
        + (text if isinstance(text, str) else json.dumps(text))
    )


def classify(title: str, tid: dict[str, Any]) -> str:
    """Return 'plugin', 'system', or 'user' for a tiddler."""
    if tid.get("plugin-type") == "plugin":
        return "plugin"
    if title.startswith("$:/"):
        return "system"
    return "user"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decrypt an encrypted TiddlyWiki and write its tiddlers as .tid files."
    )
    parser.add_argument("input", type=Path, help="Path to encrypted TiddlyWiki .html")
    parser.add_argument(
        "output", type=Path, help="Output folder (must not exist or be empty)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args(argv)

    if not args.input.is_file():
        print(f"error: input file not found: {args.input}", file=sys.stderr)
        return 2

    # Output folder rule: must not exist OR exist and be empty.
    if args.output.exists():
        if not args.output.is_dir():
            print(
                f"error: output path exists and is not a directory: {args.output}",
                file=sys.stderr,
            )
            return 2
        if any(args.output.iterdir()):
            print(f"error: output folder is not empty: {args.output}", file=sys.stderr)
            return 2

    if args.verbose:
        start_time = time.perf_counter()
    html_text = args.input.read_text(encoding="utf-8")
    try:
        blob = extract_encrypted_blob(html_text)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    # Read password without echoing or saving to shell history.
    password = getpass.getpass("Password: ")

    try:
        plaintext = sjcl_decrypt(password, blob)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    finally:
        # Drop the password reference promptly. Python doesn't guarantee
        # zeroing, but at least we don't hold it longer than needed.
        del password

    try:
        store = json.loads(plaintext)
    except json.JSONDecodeError as e:
        print(f"error: decrypted payload is not JSON: {e}", file=sys.stderr)
        return 1

    if not isinstance(store, dict):
        print("error: decrypted payload is not a tiddler store object", file=sys.stderr)
        return 1

    # Make sure the output dirs exist.
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "system").mkdir(exist_ok=True)
    (args.output / "plugin").mkdir(exist_ok=True)

    counts = {"user": 0, "system": 0, "plugin": 0}
    # Track filenames per destination directory to disambiguate collisions
    # caused by the underscore substitution.
    used: dict[Path, set[str]] = {}

    for title, tid in store.items():
        if not isinstance(tid, dict):
            print(f"warning: skipping non-object tiddler {title!r}", file=sys.stderr)
            continue
        # Ensure the tiddler carries its own title (some stores keep it in the key only).
        tid.setdefault("title", title)

        kind = classify(title, tid)
        if kind == "user":
            dest_dir = args.output
        elif kind == "system":
            dest_dir = args.output / "system"
        else:  # plugin
            dest_dir = args.output / "plugin"

        filename = title_to_filename(title)
        dir_used = used.setdefault(dest_dir, set())
        if filename in dir_used:
            # Disambiguate with a numeric suffix. Since the tiddler's own
            # `title:` header preserves the original, this only affects
            # the on-disk filename.
            stem = filename[:-4]
            n = 2
            while f"{stem}_{n}.tid" in dir_used:
                n += 1
            filename = f"{stem}_{n}.tid"
        dir_used.add(filename)

        dest = dest_dir / filename
        dest.write_text(tiddler_to_tid(tid), encoding="utf-8")
        counts[kind] += 1

    print(
        f"Wrote {counts['user']} user, {counts['system']} system, "
        f"{counts['plugin']} plugin tiddlers to {args.output}"
    )
    if args.verbose:
        end_time = time.perf_counter()
        elapsed_seconds = end_time - start_time
        formatted_time = str(timedelta(seconds=int(elapsed_seconds)))
        print(f"Execution time: {formatted_time}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
