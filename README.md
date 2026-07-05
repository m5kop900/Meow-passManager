# Meow PassManager

A simple terminal-based password manager written in Python.

## Features

- AES-256-GCM encryption
- Argon2id key derivation
- Master password protection
- Store service, username, password, notes and URL
- Password generator
- Search by service, username, URL, password or notes
- Change master password
- Export and import encrypted vault files
- Automatic vault locking after inactivity
- Clipboard support

## Requirements

- Python 3.11+
- cryptography
- colorama
- pyperclip

Install dependencies:

```bash
pip install -r requirements.txt
```

## Installation

### From GitHub (recommended)

```bash
pip install git+https://github.com/m5kop900/Meow-passManager.git
```

If you prefer using pipx:

```bash
pipx install git+https://github.com/m5kop900/Meow-passManager.git
```

### For Development

```bash
git clone https://github.com/m5kop900/Meow-passManager.git
cd Meow-passManager
pip install -e .
```

## Running

```bash
pm
```

or

```bash
python main.py
```
## Usage 
CLI format
pm [command]

pm            → Interactive menu mode
pm add        → Add a new password entry
pm show       → Show a specific password (by id/service)
pm list       → List all saved passwords
pm search     → Advanced search (service/username/url/notes/password)
pm remove     → Delete a password entry
pm edit       → Edit an existing entry
pm copy       → Copy a password to clipboard
pm changepassword → Change master password and re-encrypt vault
pm generate [n]   → Generate random password (default: 16 chars)
pm export [file]  → Export encrypted vault to file
pm import [file]  → Import vault from exported file

## Project Structure

```text
.
├── main.py
├── pm
│   ├── __init__.py
│   ├── crypto.py
│   ├── manager.py
│   └── validator.py
├── requirements.txt
└── README.md
```

## Export Format

Exported vaults are encrypted with a password chosen during export. Each export contains its own random salt, allowing it to be imported on a different machine without depending on the original database.

## Notes

- Vault auto-locks after inactivity
- No recovery if master password is lost

This project was created as a learning project. While reasonable effort was made to use modern cryptographic primitives, it has not been professionally audited and should not be considered production-ready for storing highly sensitive data.

---

Meow~
