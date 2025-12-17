# Cyber Lockbox Pro (Text-Encryption)

A simple desktop GUI tool to **encrypt and decrypt files** using **AES-256 in GCM mode** with a key derived from your password via **PBKDF2-HMAC-SHA256**.

The main app is a Tkinter GUI implemented in `cyber-lockbox.py`.

## Features

- **AES-256-GCM authenticated encryption** (confidentiality + integrity)
- **Password-based key derivation** using PBKDF2 (SHA-256)
- **GUI interface** (Tkinter)
- **One-click encrypt/decrypt** with output saved to the same folder as the input file

## How it works (file format)

When encrypting, the tool writes the following bytes into the output `.enc` file:

- `salt` (16 bytes)
- `iv` (12 bytes)
- `tag` (16 bytes, GCM authentication tag)
- `ciphertext` (remaining bytes)

Decryption reads the same structure and restores the original plaintext.

## Requirements

- Python **3.9+** (recommended)
- `cryptography` library
- Tkinter (usually included with Python on Windows)

## Run from source

1. Create and activate a virtual environment (optional but recommended).
2. Install dependencies:

```bash
pip install cryptography
```

3. Run the application:

```bash
python cyber-lockbox.py
```

## Using the app

- **Select File**: Choose any file to encrypt or decrypt.
- **Output Name**:
  - Encrypt: the tool creates `<Output Name>.enc`
  - Decrypt: the tool creates `<Output Name>.txt`
- **Password**: Must be the same password used during encryption to decrypt successfully.

### Example

- Encrypt `notes.txt` with output name `notes_secure`
  - Output: `notes_secure.enc`
- Decrypt `notes_secure.enc` with output name `notes_restored`
  - Output: `notes_restored.txt`

## Executable build

This repo contains:

- `cyber-lockbox.spec` (PyInstaller spec)
- `dist/` (built output)
- `build/` (build artifacts)

If you already have the executable in `dist/`, you can run it directly (no Python required).

## Notes / Limitations

- Decryption always saves as `*.txt` (even if the original file was not a text file).
- Encrypted files are saved next to the original input file.
- If you forget the password, the data **cannot be recovered**.

## Project structure

- `cyber-lockbox.py` — main GUI + encryption/decryption logic
- `cyber-lockbox.spec` — PyInstaller configuration
- `dist/` — packaged application output
- `build/` — build artifacts
- `test files/` — sample files for testing

## Author

Developed by **g0utam**.
