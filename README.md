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