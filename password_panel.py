#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
password_panel.py - A console-based password vault (Python 3.9+), ASCII-box TUI

Dependencies:
    pip install cryptography pyfiglet

How to run:
    python password_panel.py

What's inside:
- AES-GCM authenticated encryption via cryptography
- PBKDF2-HMAC-SHA256 KDF with 200,000 iterations and a 16-byte random salt
- Single vault file "vault.dat"
  Format:
    - First line: UTF-8 JSON header with base64 "salt", "version", "kdf", "iterations"
    - Remaining bytes: binary ciphertext blob = nonce(12 bytes) || AES-GCM ciphertext (with tag)
- Master key creation/unlock flow on startup
- ASCII-art banner using pyfiglet ("KAKAN PASSWORDPANEL")
- ASCII box-style TUI for menus, prompts, and listings
- Only the master key uses getpass.getpass() for input (per requirement).
  Entry-specific passwords use plain input() so users can see what they type.
- All changes are re-encrypted and saved immediately.

Data model (encrypted JSON):
{
  "version": 1,
  "categories": [...],
  "entries": [
    {
      "id": "uuid4",
      "title": "Example",
      "url": "https://example.com",
      "username": "user",
      "password": "secret",        # in-memory / encrypted at rest
      "description": "Notes",
      "category": "Personal",
      "created_at": "ISO8601Z",
      "updated_at": "ISO8601Z"
    }
  ],
  "meta": {"created_at": "ISO8601Z","updated_at": "ISO8601Z"}
}
"""

import base64
import getpass
import json
import os
import secrets
import shutil
import sys
import textwrap
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# Third-party dependencies
try:
    from pyfiglet import Figlet
except ImportError as e:
    print("Missing dependency 'pyfiglet'. Please install with:")
    print("    pip install pyfiglet")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("Missing dependency 'cryptography'. Please install with:")
    print("    pip install cryptography")
    sys.exit(1)


# -----------------------------
# Configuration / Constants
# -----------------------------

VAULT_PATH = "vault.dat"
HEADER_VERSION = 1
KDF_NAME = "PBKDF2-HMAC-SHA256"
KDF_ITERATIONS = 200_000  # >= 100,000 as required
SALT_SIZE = 16            # 128-bit salt
AES_KEY_SIZE = 32         # 256-bit key for AES-256-GCM
NONCE_SIZE = 12           # 96-bit nonce for AES-GCM
MAX_LOGIN_ATTEMPTS = 3


# -----------------------------
# Utilities (time, base64, terminal, TUI rendering)
# -----------------------------

def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO8601 format with 'Z' suffix."""
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _b64e(data: bytes) -> str:
    """Base64-url encode to str without newlines."""
    return base64.urlsafe_b64encode(data).decode("utf-8")


def _b64d(data_str: str) -> bytes:
    """Base64-url decode from str."""
    return base64.urlsafe_b64decode(data_str.encode("utf-8"))


def _term_size() -> Tuple[int, int]:
    """Return current terminal (columns, rows) with sensible fallback."""
    ts = shutil.get_terminal_size(fallback=(100, 24))
    return ts.columns, ts.lines


def _center_lines(lines: List[str], width: int) -> List[str]:
    """Center each line within width."""
    return [line.center(width) for line in lines]


def _wrap_lines(text: str, width: int) -> List[str]:
    """Wrap plaintext into lines with given width, keeping words when possible."""
    wrapper = textwrap.TextWrapper(width=width, replace_whitespace=False, drop_whitespace=False)
    result: List[str] = []
    for para in text.splitlines() or [""]:
        if not para:
            result.append("")
        else:
            result.extend(wrapper.wrap(para) or [""])
    return result


def _draw_box(title: Optional[str], body_lines: List[str], box_width: Optional[int] = None, center: bool = True) -> str:
    """
    Draw an ASCII box with a title and body lines.

    title: appears in the top border like: +-- title --+
    body_lines: list of strings to be placed inside the box (wrapped as needed)
    box_width: total width of the box (including borders). If None, auto based on content and terminal.
    center: if True, horizontally center the box within the terminal width.
    """
    term_w, _ = _term_size()
    # Compute content width: try to respect longest line and title
    longest = max([len(line) for line in body_lines] + [len(title) if title else 0, 20])
    max_box_width = max(40, min(term_w - 2, 120))  # clamp to terminal (a bit margin)
    content_width = min(longest, max_box_width - 4)  # inner width between vertical bars

    # Re-wrap lines if they exceed content width
    wrapped_lines: List[str] = []
    for line in body_lines:
        if len(line) <= content_width:
            wrapped_lines.append(line)
        else:
            wrapped_lines.extend(_wrap_lines(line, content_width))

    # Recompute content width against wrapped lines and title
    content_width = max([len(line) for line in wrapped_lines] + [len(title) if title else 0, 20])
    content_width = min(content_width, max_box_width - 4)
    total_width = content_width + 4  # '+ ' + content + ' +'

    # Build border with title centered in the top line if provided
    if title:
        title_str = f" {title} "
        # Compute dashes left and right around title within border
        dash_total = total_width - 2 - len(title_str)
        dash_left = dash_total // 2
        dash_right = dash_total - dash_left
        top = "+" + "-" * dash_left + title_str + "-" * dash_right + "+"
    else:
        top = "+" + "-" * (total_width - 2) + "+"

    # Body
    body = []
    for line in wrapped_lines:
        padded = line + " " * (content_width - len(line))
        body.append(f"| {padded} |")

    bottom = "+" + "-" * (total_width - 2) + "+"

    lines = [top] + body + [bottom]

    # Center horizontally if required
    if center:
        pad = max(0, (term_w - total_width) // 2)
        lines = [(" " * pad) + ln for ln in lines]

    return "\n".join(lines)


def _prompt_in_box(prompt: str, allow_empty: bool = True, default: Optional[str] = None) -> str:
    """
    Show a boxed prompt and capture input.
    Input is read via input() (never hidden). Returns entered string.
    """
    box = _draw_box("INPUT", [prompt])
    print(box)
    while True:
        val = input("> ").strip()
        if val:
            return val
        if default is not None and not val:
            return default
        if allow_empty:
            return val
        print("Please enter a non-empty value.")


def _prompt_yes_no_boxed(prompt: str, default: Optional[bool] = None) -> bool:
    """
    Yes/No prompt rendered with a box. Returns True for yes, False for no.
    """
    suffix = " [y/n]"
    if default is True:
        suffix = " [Y/n]"
    elif default is False:
        suffix = " [y/N]"
    box = _draw_box("CONFIRM", [prompt + suffix])
    print(box)
    while True:
        s = input("> ").strip().lower()
        if not s and default is not None:
            return default
        if s in ("y", "yes"):
            return True
        if s in ("n", "no"):
            return False
        print("Please answer with 'y' or 'n'.")


def _prompt_int_boxed(title: str, options: List[str], allow_zero_cancel: bool = False) -> int:
    """
    Render a selection menu in a box and return the chosen index (1..len(options)).
    If allow_zero_cancel is True, also accept 0 for cancel and return 0.
    """
    lines = [f"{i+1}. {opt}" for i, opt in enumerate(options)]
    if allow_zero_cancel:
        lines.append("0. Cancel")
    print(_draw_box(title, lines))
    lo = 0 if allow_zero_cancel else 1
    hi = len(options)
    while True:
        s = input("> ").strip()
        try:
            v = int(s)
        except ValueError:
            print("Please enter a number.")
            continue
        if v < lo or v > hi:
            if allow_zero_cancel:
                print(f"Please enter a number between 0 and {hi}.")
            else:
                print(f"Please enter a number between 1 and {hi}.")
            continue
        return v


def _render_banner() -> None:
    """Print the ASCII art banner for 'KAKAN PASSWORDPANEL' centered."""
    term_w, _ = _term_size()
    fig = Figlet(font="slant")  # use a readable font
    banner = fig.renderText("KAKAN PASSWORDPANEL")
    # Center each banner line
    lines = banner.rstrip("\n").splitlines()
    for ln in lines:
        pad = max(0, (term_w - len(ln)) // 2)
        print(" " * pad + ln)
    print(_draw_box("WELCOME", ["Secure local vault with AES-GCM and PBKDF2"], center=True))


def _table_box(title: str, headers: List[str], rows: List[List[str]]) -> str:
    """
    Render a boxed ASCII table with a header row and rows of data.
    Column widths are computed to fit terminal width; cell contents are cropped.
    """
    term_w, _ = _term_size()
    max_table_width = max(60, min(term_w - 2, 120))
    # Columns: compute relative percentages to allocate width
    n = len(headers)
    # Default percentages for common 5-col layout; otherwise distribute evenly
    if n == 5:
        perc = [6, 38, 18, 20, 18]  # No., Title, Category, Username, URL
    else:
        base = 100 // n
        perc = [base] * n
        for i in range(100 - base * n):
            perc[i] += 1

    inner_width = max_table_width - (n + 1) - 1  # borders and plus signs; simplify
    col_widths = [max(3, (inner_width * p) // 100) for p in perc]

    def crop(s: str, w: int) -> str:
        if len(s) <= w:
            return s
        if w <= 1:
            return s[:w]
        return s[: max(0, w - 1)] + "…"

    # Build table lines
    def sep(char: str = "-") -> str:
        cells = [char * (w + 2) for w in col_widths]
        return "+" + "+".join(cells) + "+"

    def row(cells: List[str]) -> str:
        padded = [f" {crop(c, w).ljust(w)} " for c, w in zip(cells, col_widths)]
        return "|" + "|".join(padded) + "|"

    lines = [sep("-"), row(headers), sep("=")]
    for r in rows:
        # pad or trim to n cells
        c = (r + [""] * n)[:n]
        lines.append(row(c))
    lines.append(sep("-"))

    # Wrap into a titled outer box
    content = "\n".join(lines)
    content_lines = content.splitlines()
    return _draw_box(title, content_lines, center=True)


# -----------------------------
# Crypto primitives (required)
# -----------------------------

def derive_key(passphrase: str, salt: bytes) -> bytes:
    """
    Derive a symmetric key from a passphrase and salt using PBKDF2-HMAC-SHA256.
    Returns 32-byte key suitable for AES-256-GCM.
    """
    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("Passphrase must be a non-empty string.")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
        raise ValueError("Salt must be bytes and at least 8 bytes long.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(data: bytes, key: bytes) -> bytes:
    """
    Encrypt bytes with AES-GCM.
    Returns ciphertext blob: nonce(12 bytes) || ciphertext(with GCM tag).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("Data must be bytes.")
    if not isinstance(key, (bytes, bytearray)) or len(key) != AES_KEY_SIZE:
        raise ValueError("Key must be 32 bytes.")

    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)
    return nonce + ciphertext


def decrypt(ciphertext_blob: bytes, key: bytes) -> bytes:
    """
    Decrypt a ciphertext blob of format: nonce(12 bytes) || ciphertext(with tag).
    Returns plaintext bytes.
    Raises InvalidTag if authentication fails (wrong key or corrupted file).
    """
    if not isinstance(ciphertext_blob, (bytes, bytearray)) or len(ciphertext_blob) < NONCE_SIZE + 16:
        raise ValueError("Ciphertext blob is too short or invalid.")
    if not isinstance(key, (bytes, bytearray)) or len(key) != AES_KEY_SIZE:
        raise ValueError("Key must be 32 bytes.")

    nonce = ciphertext_blob[:NONCE_SIZE]
    ciphertext = ciphertext_blob[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


# -----------------------------
# Vault I/O (required)
# -----------------------------

def load_vault(path: str) -> Tuple[Dict[str, Any], bytes]:
    """
    Load the vault file header and ciphertext blob.

    Returns:
      - header (dict) with at least {"version": int, "salt": str}
      - ciphertext_blob (bytes) = nonce || ciphertext
    """
    with open(path, "rb") as f:
        header_line = f.readline()
        if not header_line:
            raise ValueError("Vault file is empty or missing header.")
        try:
            header = json.loads(header_line.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Failed to parse vault header JSON: {e}")

        ciphertext_blob = f.read()
        if not ciphertext_blob:
            raise ValueError("Vault file missing ciphertext content.")
    return header, ciphertext_blob


def _write_atomic(path: str, data: bytes) -> None:
    """Write bytes atomically to file to reduce risk of corruption."""
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)


def save_vault(path: str, vault_dict: Dict[str, Any], key: bytes, salt: Optional[bytes] = None) -> None:
    """
    Save (re-encrypt) the vault to disk.

    - Uses a fresh random nonce for every write.
    - Writes a single-line JSON header followed by the binary ciphertext blob.
    """
    if salt is None:
        # Reuse existing salt from file
        try:
            header, _ = load_vault(path)
            salt_b64 = header.get("salt")
            if not salt_b64:
                raise ValueError("Existing header missing salt.")
            salt = _b64d(salt_b64)
        except FileNotFoundError:
            raise FileNotFoundError("Vault file not found; cannot auto-reuse salt. Provide salt for initial save.")

    # Ensure categories reflect entries (dedupe)
    _sync_categories_with_entries(vault_dict)

    # Update vault meta timestamp
    vault_dict.setdefault("meta", {})
    vault_dict["meta"]["updated_at"] = _utc_now_iso()

    # Serialize and encrypt
    plaintext = json.dumps(vault_dict, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext_blob = encrypt(plaintext, key)

    # Build header (single-line JSON)
    header = {
        "version": HEADER_VERSION,
        "salt": _b64e(salt),
        "kdf": KDF_NAME,
        "iterations": KDF_ITERATIONS,
        "ciphertext_format": "nonce+ciphertext",
    }
    header_line = json.dumps(header, separators=(",", ":")).encode("utf-8") + b"\n"

    # Write header + ciphertext atomically
    _write_atomic(path, header_line + ciphertext_blob)


# -----------------------------
# Vault helpers and validation
# -----------------------------

def _new_empty_vault() -> Dict[str, Any]:
    """Create a new empty vault structure."""
    now = _utc_now_iso()
    return {
        "version": HEADER_VERSION,
        "categories": [],
        "entries": [],
        "meta": {"created_at": now, "updated_at": now},
    }


def _sync_categories_with_entries(vault: Dict[str, Any]) -> None:
    """Ensure categories list includes all categories used by entries, deduplicated, sorted."""
    entries = vault.get("entries", [])
    cats_from_entries = {e.get("category") for e in entries if e.get("category")}
    existing = set(vault.get("categories", []))
    combined = sorted(cats_from_entries.union(existing))
    vault["categories"] = combined


def _find_entry_by_id(vault: Dict[str, Any], entry_id: str) -> Optional[Dict[str, Any]]:
    for e in vault.get("entries", []):
        if e.get("id") == entry_id:
            return e
    return None


# -----------------------------
# Initialization / Unlock flow (master key uses getpass)
# -----------------------------

def initialize_new_vault(path: str) -> Tuple[Dict[str, Any], bytes, bytes]:
    """
    Guide the user to create a new vault and master passphrase.

    Returns: (vault, key, salt)
    """
    print(_draw_box("NEW VAULT", ["No existing vault found. Let's create one."]))
    while True:
        pw1 = getpass.getpass("Create a master passphrase: ")
        if len(pw1) < 8:
            print("Passphrase should be at least 8 characters.")
            continue
        pw2 = getpass.getpass("Confirm master passphrase: ")
        if pw1 != pw2:
            print("Passphrases do not match. Please try again.")
            continue
        break

    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(pw1, salt)

    vault = _new_empty_vault()
    save_vault(path, vault, key, salt=salt)
    print(_draw_box("SUCCESS", [f"New vault created at: {path}"]))
    return vault, key, salt


def unlock_existing_vault(path: str) -> Tuple[Dict[str, Any], bytes, bytes]:
    """
    Prompt user for passphrase up to MAX_LOGIN_ATTEMPTS times to unlock.

    Returns: (vault, key, salt)
    """
    try:
        header, ciphertext_blob = load_vault(path)
    except FileNotFoundError:
        print(_draw_box("ERROR", ["Vault file not found." ]))
        raise
    except Exception as e:
        print(_draw_box("ERROR", [f"Error loading vault: {e}"]))
        raise

    if not isinstance(header, dict) or "salt" not in header:
        print(_draw_box("ERROR", ["Vault header is invalid or missing salt."]))
        raise SystemExit(1)

    try:
        salt = _b64d(header["salt"])
    except Exception:
        print(_draw_box("ERROR", ["Vault header contains invalid salt encoding."]))
        raise SystemExit(1)

    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        print(_draw_box("UNLOCK", [f"Enter master passphrase (attempt {attempt}/{MAX_LOGIN_ATTEMPTS})"]))
        passphrase = getpass.getpass("> ")
        try:
            key = derive_key(passphrase, salt)
            plaintext = decrypt(ciphertext_blob, key)
            vault = json.loads(plaintext.decode("utf-8"))
            if not isinstance(vault, dict) or "entries" not in vault:
                raise ValueError("Decrypted vault is malformed.")
            print(_draw_box("UNLOCKED", ["Vault unlocked successfully."]))
            return vault, key, salt
        except InvalidTag:
            remaining = MAX_LOGIN_ATTEMPTS - attempt
            print(_draw_box("FAILED", [f"Incorrect passphrase or data corrupted. Attempts remaining: {remaining}"]))
            if remaining == 0:
                print(_draw_box("EXIT", ["Maximum attempts exceeded. Exiting."]))
                raise SystemExit(1)
        except Exception as e:
            remaining = MAX_LOGIN_ATTEMPTS - attempt
            print(_draw_box("FAILED", [f"Failed to unlock vault: {e}", f"Attempts remaining: {remaining}"]))
            if remaining == 0:
                print(_draw_box("EXIT", ["Maximum attempts exceeded. Exiting."]))
                raise SystemExit(1)

    raise SystemExit(1)


# -----------------------------
# ASCII Boxed Menus and Actions
# -----------------------------

def _show_main_menu() -> int:
    """Render the main menu as a centered boxed list and return the selected option."""
    options = [
        "Add new entry",
        "List categories",
        "List entries (all or by category)",
        "View entry",
        "Edit entry",
        "Delete entry",
        "Change master key",
        "Export entries to plaintext JSON",
        "Lock / Logout",
        "Exit",
    ]
    print(_draw_box("MAIN MENU", [f"{i+1}. {opt}" for i, opt in enumerate(options)]))
    while True:
        s = input("> ").strip()
        try:
            v = int(s)
        except ValueError:
            print("Please enter a number between 0 and 10 (0 for Exit).")
            continue
        if v == 0:
            return 10  # map 0 to Exit (option 10)
        if 1 <= v <= 10:
            return v
        print("Please enter a valid menu number.")


def add_entry(vault: Dict[str, Any]) -> None:
    """Add a new entry to the vault. Entry password uses input() (visible), not getpass()."""
    print(_draw_box("ADD NEW ENTRY", ["Enter details below. Fields marked (optional) can be left blank."]))
    title = _prompt_in_box("Title:", allow_empty=False)
    url = _prompt_in_box("URL (optional):")
    username = _prompt_in_box("Username (optional):")

    # Per requirement: do NOT use getpass for entry-specific passwords
    while True:
        pw1 = _prompt_in_box("Password (visible input):", allow_empty=True)
        pw2 = _prompt_in_box("Confirm Password:", allow_empty=True)
        if pw1 != pw2:
            print(_draw_box("NOTICE", ["Passwords do not match. Please try again."]))
            continue
        break

    # Category selection/creation
    categories = vault.get("categories", [])
    if categories:
        cat_lines = [f"{i+1}. {c}" for i, c in enumerate(categories)]
    else:
        cat_lines = ["(No categories yet)"]
    cat_lines.append("0. Create new category")
    print(_draw_box("SELECT CATEGORY", cat_lines))
    max_choice = len(categories)
    while True:
        s = input("> ").strip()
        try:
            v = int(s)
        except ValueError:
            print("Please enter a number.")
            continue
        if v < 0 or v > max_choice:
            print(f"Please enter a number between 0 and {max_choice}.")
            continue
        break

    if v == 0:
        category = _prompt_in_box("New category name:", allow_empty=False)
    else:
        category = categories[v - 1] if categories else _prompt_in_box("New category name:", allow_empty=False)

    description = _prompt_in_box("Description (optional):")

    now = _utc_now_iso()
    entry = {
        "id": str(uuid.uuid4()),
        "title": title,
        "url": url,
        "username": username,
        "password": pw1,
        "description": description,
        "category": category,
        "created_at": now,
        "updated_at": now,
    }
    vault.setdefault("entries", []).append(entry)
    _sync_categories_with_entries(vault)
    print(_draw_box("SUCCESS", ["Entry added."]))


def list_categories(vault: Dict[str, Any]) -> None:
    """Show categories in a boxed list with entry counts."""
    categories = vault.get("categories", [])
    if not categories:
        print(_draw_box("CATEGORIES", ["(No categories)"]))
        return
    counts = {cat: 0 for cat in categories}
    for e in vault.get("entries", []):
        cat = e.get("category")
        if cat in counts:
            counts[cat] += 1
    lines = [f"{i+1}. {cat} ({counts.get(cat,0)} entries)" for i, cat in enumerate(categories)]
    print(_draw_box("CATEGORIES", lines))


def _list_entries_internal(vault: Dict[str, Any], by_category: Optional[str] = None) -> List[Dict[str, Any]]:
    """Render entries list (optionally filtered by category) as a boxed table. Returns sorted list."""
    entries = vault.get("entries", [])
    if by_category:
        entries = [e for e in entries if e.get("category") == by_category]
    entries_sorted = sorted(entries, key=lambda e: (e.get("title") or "").lower())
    if not entries_sorted:
        title = f"ENTRIES - {by_category}" if by_category else "ENTRIES - ALL"
        print(_draw_box(title, ["(No entries found.)"]))
        return []

    headers = ["No", "Title", "Category", "Username", "URL"]
    rows = []
    for idx, e in enumerate(entries_sorted, start=1):
        rows.append([
            str(idx),
            e.get("title") or "",
            e.get("category") or "",
            e.get("username") or "",
            e.get("url") or "",
        ])
    title = f"ENTRIES - {by_category}" if by_category else "ENTRIES - ALL"
    print(_table_box(title, headers, rows))
    return entries_sorted


def list_entries(vault: Dict[str, Any]) -> None:
    """Show a menu for listing entries (all or by category) and render a table."""
    choice = _prompt_int_boxed("LIST ENTRIES", ["All entries", "Filter by category"], allow_zero_cancel=True)
    if choice == 0:
        return
    if choice == 1:
        _list_entries_internal(vault, None)
        return
    # Filter by category
    categories = vault.get("categories", [])
    if not categories:
        print(_draw_box("INFO", ["No categories available."]))
        return
    cat_idx = _prompt_int_boxed("SELECT CATEGORY", categories, allow_zero_cancel=True)
    if cat_idx == 0:
        return
    chosen = categories[cat_idx - 1]
    _list_entries_internal(vault, by_category=chosen)


def _select_entry(vault: Dict[str, Any], scope_category: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Show entries (optionally filtered) and let user select one. Returns the selected entry or None."""
    entries_scope = _list_entries_internal(vault, by_category=scope_category)
    if not entries_scope:
        return None
    print(_draw_box("SELECT ENTRY", ["Enter the 'No' column number to select an entry.", "0 to Cancel"]))
    while True:
        s = input("> ").strip()
        try:
            v = int(s)
        except ValueError:
            print("Please enter a number.")
            continue
        if v == 0:
            return None
        if 1 <= v <= len(entries_scope):
            return entries_scope[v - 1]
        print(f"Please enter a number between 1 and {len(entries_scope)}.")


def view_entry(vault: Dict[str, Any]) -> None:
    """View an entry; password masked by default with option to reveal temporarily."""
    entry = _select_entry(vault)
    if not entry:
        return

    # Build details lines
    masked_pw = "******" if entry.get("password") else ""
    lines = [
        f"Title      : {entry.get('title') or ''}",
        f"URL        : {entry.get('url') or ''}",
        f"Username   : {entry.get('username') or ''}",
        f"Password   : {masked_pw} (masked)",
        f"Description: {entry.get('description') or ''}",
        f"Category   : {entry.get('category') or ''}",
        f"Created at : {entry.get('created_at') or ''}",
        f"Updated at : {entry.get('updated_at') or ''}",
    ]
    print(_draw_box("ENTRY DETAILS", lines))

    if entry.get("password"):
        if _prompt_yes_no_boxed("Reveal password temporarily?", default=False):
            print(_draw_box("PASSWORD", [entry["password"]]))
            _prompt_in_box("Press Enter to continue and re-mask...", allow_empty=True)


def edit_entry(vault: Dict[str, Any]) -> None:
    """Edit an existing entry. Entry password uses input() and can be left blank to keep unchanged."""
    entry = _select_entry(vault)
    if not entry:
        return

    print(_draw_box("EDIT ENTRY", ["Leave fields blank to keep current value."]))

    new_title = _prompt_in_box(f"Title [{entry.get('title') or ''}]:")
    new_url = _prompt_in_box(f"URL [{entry.get('url') or ''}]:")
    new_username = _prompt_in_box(f"Username [{entry.get('username') or ''}]:")
    # Per requirement: DO NOT use getpass here; use input (via _prompt_in_box)
    print(_draw_box("PASSWORD", ["Leave blank to keep current password."]))
    new_pw = _prompt_in_box("New Password (visible input):")
    if new_pw:
        confirm = _prompt_in_box("Confirm New Password:")
        if new_pw != confirm:
            print(_draw_box("NOTICE", ["Passwords do not match. Aborting edit."]))
            return

    new_description = _prompt_in_box(f"Description [{entry.get('description') or ''}]:")

    # Category selection
    categories = vault.get("categories", [])
    cat_lines = [f"{i+1}. {c}" for i, c in enumerate(categories)] if categories else ["(No categories yet)"]
    cat_lines += ["0. Keep current", "N. Create new category"]
    print(_draw_box("CATEGORY", cat_lines))
    cat_choice = input("> ").strip().lower()

    # Apply changes
    if new_title:
        entry["title"] = new_title
    if new_url:
        entry["url"] = new_url
    if new_username:
        entry["username"] = new_username
    if new_pw:
        entry["password"] = new_pw
    if new_description:
        entry["description"] = new_description

    if cat_choice == "n":
        new_cat = _prompt_in_box("New category name:", allow_empty=False)
        entry["category"] = new_cat
    elif cat_choice.isdigit():
        n = int(cat_choice)
        if n == 0:
            pass  # keep current
        elif 1 <= n <= len(categories):
            entry["category"] = categories[n - 1]
        else:
            print(_draw_box("NOTICE", ["Invalid category selection. Keeping current category."]))

    entry["updated_at"] = _utc_now_iso()
    _sync_categories_with_entries(vault)
    print(_draw_box("SUCCESS", ["Entry updated."]))


def delete_entry(vault: Dict[str, Any]) -> None:
    """Delete an entry after confirmation."""
    entry = _select_entry(vault)
    if not entry:
        return
    title = entry.get("title") or "(untitled)"
    if not _prompt_yes_no_boxed(f"Are you sure you want to delete '{title}'?", default=False):
        print(_draw_box("CANCELLED", ["Deletion cancelled."]))
        return
    entries = vault.get("entries", [])
    vault["entries"] = [e for e in entries if e.get("id") != entry.get("id")]
    _sync_categories_with_entries(vault)
    print(_draw_box("SUCCESS", ["Entry deleted."]))


def change_master_key(path: str, vault: Dict[str, Any]) -> bytes:
    """
    Re-encrypt the vault with a new master passphrase and salt.
    Returns the new key (bytes).
    """
    print(_draw_box("CHANGE MASTER KEY", ["Enter a NEW master passphrase (hidden input)."]))
    while True:
        pw1 = getpass.getpass("New master passphrase: ")
        if len(pw1) < 8:
            print("Passphrase should be at least 8 characters.")
            continue
        pw2 = getpass.getpass("Confirm new master passphrase: ")
        if pw1 != pw2:
            print("Passphrases do not match. Try again.")
            continue
        break

    new_salt = secrets.token_bytes(SALT_SIZE)
    new_key = derive_key(pw1, new_salt)
    save_vault(path, vault, new_key, salt=new_salt)
    print(_draw_box("SUCCESS", ["Master key changed and vault re-encrypted."]))
    return new_key


def export_plaintext_json(vault: Dict[str, Any]) -> None:
    """
    Export entries to a plaintext JSON file (unencrypted).
    Warn the user before exporting.
    """
    print(_draw_box("EXPORT WARNING", [
        "This will export ALL entries in PLAINTEXT JSON.",
        "Anyone with access to the file can read your passwords."
    ]))
    if not _prompt_yes_no_boxed("Proceed with export?", default=False):
        print(_draw_box("CANCELLED", ["Export cancelled."]))
        return

    default_path = "vault_export.json"
    out_path = _prompt_in_box(f"Output file path [{default_path}]:") or default_path

    export_obj = {
        "exported_at": _utc_now_iso(),
        "entries": vault.get("entries", []),
    }
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(export_obj, f, ensure_ascii=False, indent=2)
        print(_draw_box("SUCCESS", [f"Exported to {out_path} (PLAINTEXT)."]))
    except Exception as e:
        print(_draw_box("ERROR", [f"Failed to export: {e}"]))


# -----------------------------
# Main loop / Orchestrator
# -----------------------------

def run_menu(path: str, vault: Dict[str, Any], key: bytes) -> Optional[Tuple[Dict[str, Any], bytes]]:
    """
    Main menu loop. Returns either:
      - (vault, key) on "Lock / Logout" to re-prompt login, or
      - None on exit.
    """
    while True:
        choice = _show_main_menu()

        if choice == 1:
            add_entry(vault)
            try:
                save_vault(path, vault, key)
            except Exception as e:
                print(_draw_box("ERROR", [f"Error saving vault: {e}"]))
        elif choice == 2:
            list_categories(vault)
        elif choice == 3:
            list_entries(vault)
        elif choice == 4:
            view_entry(vault)
        elif choice == 5:
            edit_entry(vault)
            try:
                save_vault(path, vault, key)
            except Exception as e:
                print(_draw_box("ERROR", [f"Error saving vault: {e}"]))
        elif choice == 6:
            delete_entry(vault)
            try:
                save_vault(path, vault, key)
            except Exception as e:
                print(_draw_box("ERROR", [f"Error saving vault: {e}"]))
        elif choice == 7:
            try:
                key = change_master_key(path, vault)
            except Exception as e:
                print(_draw_box("ERROR", [f"Failed to change master key: {e}"]))
        elif choice == 8:
            export_plaintext_json(vault)
        elif choice == 9:
            print(_draw_box("LOCK", ["Locking vault and returning to login screen..."]))
            return vault, key
        elif choice == 10:
            print(_draw_box("EXIT", ["Exiting. Goodbye."]))
            return None


def create_sample_vault_for_testing() -> Dict[str, Any]:
    """
    Create a sample vault in memory for local testing.

    WARNING: This is for testing only. Not used by default.
    Example (disabled by default):
        vault = create_sample_vault_for_testing()
        key = derive_key("test-passphrase", b"0"*16)
        save_vault(VAULT_PATH, vault, key, salt=b"0"*16)
    """
    now = _utc_now_iso()
    vault = {
        "version": HEADER_VERSION,
        "categories": ["Personal", "Work"],
        "entries": [
            {
                "id": str(uuid.uuid4()),
                "title": "Email",
                "url": "https://mail.example.com",
                "username": "alice",
                "password": "alice-pass-123",
                "description": "Primary email account",
                "category": "Personal",
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": str(uuid.uuid4()),
                "title": "Company VPN",
                "url": "",
                "username": "alice.work",
                "password": "vpn-secret!",
                "description": "VPN credentials",
                "category": "Work",
                "created_at": now,
                "updated_at": now,
            },
        ],
        "meta": {"created_at": now, "updated_at": now},
    }
    return vault


def main() -> None:
    # Banner first (before any login/create flow)
    _render_banner()

    # On startup: create new vault if missing, otherwise unlock with retries.
    if not os.path.exists(VAULT_PATH):
        try:
            vault, key, _salt = initialize_new_vault(VAULT_PATH)
        except Exception as e:
            print(_draw_box("ERROR", [f"Failed to initialize vault: {e}"]))
            sys.exit(1)
    else:
        try:
            vault, key, _salt = unlock_existing_vault(VAULT_PATH)
        except SystemExit:
            raise
        except Exception as e:
            print(_draw_box("ERROR", [f"Fatal error opening vault: {e}"]))
            sys.exit(1)

    # Menu loop with support for Lock/Logout re-auth
    while True:
        result = run_menu(VAULT_PATH, vault, key)
        if result is None:
            break  # Exit selected
        # Lock/Logout: re-prompt for passphrase
        try:
            vault, key, _salt = unlock_existing_vault(VAULT_PATH)
        except SystemExit:
            break  # user failed attempts or chose to exit
        except Exception as e:
            print(_draw_box("ERROR", [f"Fatal error unlocking vault: {e}"]))
            break


if __name__ == "__main__":
    main()