# twencryption

Python command-line tools for converting between an encrypted single-file
[TiddlyWiki](https://tiddlywiki.com/) and a folder of plain `.tid` files —
without needing a browser or any JavaScript runtime.

- `twdecrypt.py` — decrypts an encrypted TiddlyWiki HTML file and writes
  every tiddler out as a `.tid` file.
- `twencrypt.py` — re-encrypts a folder of `.tid` files back into an
  encrypted TiddlyWiki HTML file, using an existing encrypted wiki as
  the template.

## Why this exists

This started as a response to a request on the TiddlyWiki forum for
non-JavaScript tools that can read and write encrypted TiddlyWikis:

> [Fitness for purpose and the cool factor](https://talk.tiddlywiki.org/t/fitness-for-purpose-and-the-cool-factor/15042)

It's posted here for anyone who finds it useful. **No support is offered
and no warranty of any kind is implied** — see `LICENSE`. If something
doesn't work for you, you're welcome to read the code, fix it, and fork
it.

## Requirements

- Python 3.9 or newer
- The [`cryptography`](https://pypi.org/project/cryptography/) package
  (used only for raw AES-ECB and PBKDF2; the AES-CCM mode is implemented
  by hand to match SJCL's wire format — see below)

Install the one dependency:

```
pip install cryptography
```

## Try it

A sample encrypted TiddlyWiki, `encrypted.html`, is included in the
repo. The password is `password`. Use it to take both tools for a spin:

```
python3 twdecrypt.py encrypted.html ./sample-unpacked
python3 twencrypt.py ./sample-unpacked encrypted.html sample-roundtrip.html
```

The same file also works as the template argument to `twencrypt.py`
when you want to package your own folder of `.tid` files into a fresh
encrypted wiki.

## Usage

### Decrypt an encrypted TiddlyWiki

```
python3 twdecrypt.py <encrypted.html> <output_folder>
```

The password is read from the terminal with no echo. The output folder
must either not exist or be empty. Tiddlers are written into three
subfolders:

```
<output_folder>/*.tid          ordinary (user) tiddlers
<output_folder>/system/*.tid   system tiddlers (titles starting with $:/)
<output_folder>/plugin/*.tid   plugin tiddlers (their JSON payload as the body)
```

Filenames are derived from the tiddler title by replacing filesystem-unsafe
characters with underscores (e.g. `$:/core/ui/Buttons` becomes
`$__core_ui_Buttons.tid`). The tiddler's real title is preserved in the
`title:` header inside the file, so the on-disk filename is only a
convenience.

### Re-encrypt a folder back to a TiddlyWiki

```
python3 twencrypt.py <input_folder> <template.html> <output.html>
```

- `<input_folder>` must follow the layout produced by `twdecrypt.py`
  (root, `system/`, `plugin/`).
- `<template.html>` is any existing **encrypted** TiddlyWiki — its
  `<pre id="encryptedStoreArea">` block is replaced with the freshly
  encrypted ciphertext and everything else (TiddlyWiki core, boot
  scripts, CSS, etc.) is preserved.
- `<output.html>` must not already exist.

The password is asked for twice and must match. The output is written
atomically (to a temporary file, then renamed).

A typical round-trip:

```
python3 twdecrypt.py mywiki.html ./unpacked
# ... edit .tid files however you like ...
python3 twencrypt.py ./unpacked mywiki.html mywiki-new.html
```

### Verbose outout

Both `twdecrypt.py` and `twencrypt.py` support an optional `-v | --verbose`
parameter, which makes them display additional info about execution when
enabled. This is useful for processing big wiki files on old slow hardware.

## How it works

TiddlyWiki encrypts its store using [SJCL](https://github.com/bitwiseshiftleft/sjcl):

- AES-CCM with a 256-bit key and 64-bit tag
- PBKDF2-HMAC-SHA256 with 10 000 iterations
- 8-byte salt, 16-byte IV
- The encrypted blob is a JSON object base64-embedded inside a
  `<pre id="encryptedStoreArea">` element in the HTML.

These tools reproduce SJCL's exact CCM framing by hand on top of raw
AES-ECB. The reason for not using `cryptography.hazmat`'s `AESCCM` is
that SJCL stores a full 16-byte IV but only uses the first `15 - L` bytes
as the CCM nonce (where `L` grows with plaintext size). The library's
high-level `AESCCM` hardcodes `L = 15 - len(nonce)`, which would cap
payloads at ~64 KiB for a 13-byte nonce — too small for any real wiki.
The hand-rolled CCM in `_sjcl_ccm_encrypt` / `_sjcl_ccm_decrypt` matches
SJCL byte-for-byte instead.

The `.tid` parser is intentionally lenient and matches TiddlyWiki's own
behaviour: header is `field: value` lines, then a blank line, then the
rest of the file is the `text` field.

## Caveats

- Tested against TiddlyWiki 5.x encrypted output. If TiddlyWiki ever
  changes its SJCL parameters (different KDF, key size, tag size, mode),
  these scripts will need to be updated to match.
- The password is held in a Python string while in use. CPython doesn't
  guarantee that string memory is zeroed when the reference is dropped,
  so don't rely on these tools in a threat model where in-process memory
  inspection matters.
- The filename mapping is not perfectly reversible — two distinct titles
  can collapse to the same filename. Collisions are disambiguated with a
  numeric suffix on decrypt, and `twencrypt.py` uses each tiddler's
  `title:` header (not its filename) when re-encrypting.

## License

Public domain — see `LICENSE` ([The Unlicense](https://unlicense.org/)).
Do whatever you want with it. No warranty. No support.
