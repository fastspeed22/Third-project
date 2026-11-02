from collections import Counter
import getpass
import hashlib
import hmac
import json
import os
import re
import string
import sys


def check_password():
    while True:
        print("\n--- Password Checker ---")
        print("1. Enter a password to check")
        print("2. Go back to the menu")
        choice = input("Select an option: ").strip().lower()

        if choice in ("2", "back"):
            break
        elif choice == "1":
            password = input("Enter a password to check: ")

            missing = []
            if len(password) < 8:
                missing.append("at least 8 characters")
            if not any(c.isupper() for c in password):
                missing.append("an uppercase letter")
            if not any(c.isdigit() for c in password):
                missing.append("a number")
            if not any(c in string.punctuation for c in password):
                missing.append("a special character")

            if not missing:
                print("\nStrong password!")
            elif len(missing) >= 3:
                print("\nWeak password. You need: " + ", ".join(missing))
            else:
                print("\nAlmost there! Add: " + ", ".join(missing))
        else:
            print("Enter one of the above options.")

    
PHISHING_WORDS = ["urgent", "immediately", "act now", "final notice", "last chance", "expires today", "within 24 hours", "respond", "limited time", "suspended", "locked", "unusual activity", "unauthorized", "security", "alert", "verify your account", "confirm your identity", "account closed", "deactivated", "ssn", "password", "pin", "social security", "bank", "payment", "credit card", "cvv", "verification code", "one-time code", "login", "username", "wire transfer", "gift card", "bitcoin", "crypto", "invoice", "refund", "overdue", "billing", "direct deposit", "you've won", "lottery", "prize", "congratulations", "inheritance", "free", "claim your reward", "selected", "dear customer", "dear user", "valued customer", "dear member", "click here", "click the link", "open attachment", "download", "update your information", "log in"]


def check_phishing():
    while True:
        print("\n--- Phishing Checker ---")
        print("1. Enter message to analyze")
        print("2. Go back to the menu")
        choice = input("\nSelect an option: ").lower()

        if choice in ("2", "back"):
            break
        elif choice == "1":
            message = input("Enter a possible Phishing: ").lower()
            
            # \b matches whole words only ("pin" won't match "shipping")
            found = [w for w in PHISHING_WORDS if re.search(rf"\b{re.escape(w)}\b", message)]
            if found:
                print("Warning: possible phishing. Suspicious words found: " + ", ".join(found))
            else:
                print("No red flags found. Still be careful of suspicious links and unknown senders.")
        else:
            print("Enter one of the above options.")

# Save next to the program. Inside a PyInstaller .exe, __file__ points at a temporary
# folder that is deleted on exit, so use the .exe's own folder instead.
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HASH_FILE = os.path.join(BASE_DIR, "hashes.json")


def hash_file(path):
    """Return the SHA-256 hash of a file (read in chunks so big files are fine)."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def load_hashes():
    if os.path.exists(HASH_FILE):
        try:
            with open(HASH_FILE) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            print("Warning: hashes.json is unreadable, starting with no saved hashes.")
    return {}


def save_hashes(hashes):
    with open(HASH_FILE, "w") as f:
        json.dump(hashes, f, indent=2)


def file_integrity_checker():
    while True:
        print("\n--- File Integrity Checker ---")
        print("1. Save a file's hash")
        print("2. Check a file against its saved hash")
        print("3. Back")
        choice = input("Select an option: ").strip().lower()

        if choice in ("3", "back"):
            break
        if choice not in ("1", "2"):
            print("Enter one of the above options.")
            continue

        path = input("Enter the file path: ").strip().strip('"')
        if not os.path.isfile(path):
            print("File not found.")
            continue

        key = os.path.abspath(path)
        try:
            current = hash_file(path)
        except OSError as e:
            print(f"Could not read file: {e}")
            continue

        hashes = load_hashes()

        if choice == "1":
            hashes[key] = current
            save_hashes(hashes)
            print(f"Saved hash: {current}")
        elif key not in hashes:
            print("No saved hash for this file yet. Use option 1 first.")
        elif hashes[key] == current:
            print("OK: file is unchanged.")
        else:
            print("WARNING: file has CHANGED since its hash was saved!")

LEVEL_PATTERN = re.compile(r"\b(ERROR|WARNING|INFO)\b", re.IGNORECASE)
IP_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
BRUTE_FORCE_THRESHOLD = 5  # number of failed attempts to consider an IP suspicious


def log_analyzer():
    while True:
        print("\n--- Log Analyzer ---")
        print("1. enter a log file for analysis")
        print("2. go back to the menu")
        choice = input("Select an option: ").strip().lower()

        if choice in ("2", "back"):
            break
        elif choice == "1":
            path = input("Enter the log file path: ").strip().strip('"')
            if not os.path.isfile(path):
                print("\nFile not found.")
                continue

            levels = Counter()
            failed_ips = Counter()
            total = 0

            try:
                with open(path, errors="ignore") as f:
                    for line in f:
                        total += 1

                        level = LEVEL_PATTERN.search(line)
                        if level:
                            levels[level.group(1).upper()] += 1


                        if "failed" in line.lower():
                            for ip in IP_PATTERN.findall(line):
                                failed_ips[ip] += 1
            except OSError as e:
                print(f"\nCould not read file: {e}")
                continue
            print(f"\n--- Log Analysis Report: {total} lines ---")
            for name in ("ERROR", "WARNING", "INFO"):
                print(f"{name}: {levels[name]}")

            print(f"\nFailed Attempts: {sum(failed_ips.values())}")
            for ip, count in failed_ips.most_common(3):
                print(f"  {ip}: {count}")

            suspicious = [ip for ip, count in failed_ips.items() if count >= BRUTE_FORCE_THRESHOLD]
            
            if suspicious:
                print("\nWARNING: possible brute-force attack detected from: "+", ".join(suspicious))
            else:
                print("\nNo brute-force attack patterns found.")
        else:
            print("Enter one of the above options.")


# Encryption built only from Python's standard library (no extra packages to install,
# so it works inside a PyInstaller .exe). The design:
#   password --PBKDF2-HMAC-SHA256--> two keys (one to encrypt, one to authenticate)
#   encrypt: XOR the file with a keystream made from HMAC-SHA256(key, nonce + counter)
#   authenticate: HMAC-SHA256 tag over everything (encrypt-then-MAC), checked BEFORE decrypting
# File layout: MAGIC | salt | nonce | ciphertext | tag
MAGIC = b"CBE1"
SALT_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 32
KDF_ITERATIONS = 600_000  # more iterations = slower for attackers guessing passwords
CHUNK_SIZE = 1 << 20      # process 1 MiB at a time (must be a multiple of 32)


class DecryptionError(Exception):
    """Wrong password, a damaged file, or a file not made by this tool."""


def derive_keys(password, salt):
    """Turn a password + random salt into two independent 32-byte keys."""
    material = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, KDF_ITERATIONS, dklen=64)
    return material[:32], material[32:]


def apply_keystream(data, enc_key, nonce):
    """XOR data with the keystream. The same call encrypts and decrypts."""
    base = hmac.new(enc_key, nonce, hashlib.sha256)
    out = bytearray()
    for offset in range(0, len(data), CHUNK_SIZE):
        chunk = data[offset:offset + CHUNK_SIZE]
        first_block = offset // 32
        blocks = []
        for i in range((len(chunk) + 31) // 32):
            block = base.copy()
            block.update((first_block + i).to_bytes(8, "big"))
            blocks.append(block.digest())
        stream = b"".join(blocks)[:len(chunk)]
        out += (int.from_bytes(chunk, "big") ^ int.from_bytes(stream, "big")).to_bytes(len(chunk), "big")
    return bytes(out)


def encrypt_file(path, password):
    """Write an encrypted copy of the file (path + '.enc') and return its name."""
    with open(path, "rb") as f:
        data = f.read()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    enc_key, mac_key = derive_keys(password, salt)

    body = MAGIC + salt + nonce + apply_keystream(data, enc_key, nonce)
    tag = hmac.new(mac_key, body, hashlib.sha256).digest()

    out_path = path + ".enc"
    with open(out_path, "wb") as f:
        f.write(body + tag)
    return out_path


def decrypt_file(path, password):
    """Write a decrypted copy of an .enc file and return its name.
    Raises DecryptionError if the password is wrong or the file was changed."""
    with open(path, "rb") as f:
        blob = f.read()

    header_size = len(MAGIC) + SALT_SIZE + NONCE_SIZE
    if len(blob) < header_size + TAG_SIZE or not blob.startswith(MAGIC):
        raise DecryptionError("not an encrypted file made by this tool")

    salt = blob[len(MAGIC):len(MAGIC) + SALT_SIZE]
    nonce = blob[len(MAGIC) + SALT_SIZE:header_size]
    body, tag = blob[:-TAG_SIZE], blob[-TAG_SIZE:]
    ciphertext = blob[header_size:-TAG_SIZE]

    enc_key, mac_key = derive_keys(password, salt)
    expected = hmac.new(mac_key, body, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):  # checked before any decrypting happens
        raise DecryptionError("wrong password or the file was modified")

    data = apply_keystream(ciphertext, enc_key, nonce)

    out_path = path[:-4] if path.endswith(".enc") else path + ".dec"
    if os.path.exists(out_path):  # never overwrite an existing file
        base, ext = os.path.splitext(out_path)
        out_path = f"{base}_decrypted{ext}"
    with open(out_path, "wb") as f:
        f.write(data)
    return out_path


def encryption_tool():
    while True:
        print("\n--- Encryption Tool ---")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Go back to the menu")
        choice = input("Select an option: ").strip().lower()

        if choice in ("3", "back"):
            break
        if choice not in ("1", "2"):
            print("Enter one of the above options.")
            continue

        path = input("Enter the file path: ").strip().strip('"')
        if not os.path.isfile(path):
            print("File not found.")
            continue

        password = getpass.getpass("Enter password: ")
        if not password:
            print("Password can't be empty.")
            continue

        try:
            if choice == "1":
                if password != getpass.getpass("Confirm password: "):
                    print("Passwords don't match.")
                    continue
                if os.path.exists(path + ".enc") and input("Encrypted copy already exists. Overwrite? (yes/no): ").strip().lower() != "yes":
                    continue
                print(f"Encrypted! Saved as: {encrypt_file(path, password)}")
                print("Your original file was NOT deleted. Remember your password; it can't be recovered.")
            else:
                print(f"Decrypted! Saved as: {decrypt_file(path, password)}")
        except DecryptionError as e:
            print(f"Decryption failed: {e}.")
        except OSError as e:
            print(f"Could not read or write file: {e}")


def menu():
    while True:
        print("\n=== Welcome to Cyber Build ===")
        print("1. Password Strength Checker")
        print("2. Phishing Detector")
        print("3. File Integrity Checker")
        print("4. Log Analyzer")
        print("5. Encryption Tool")
        print("6. Quit")

        choice = input("\nSelect an option: ").strip().lower()

        if choice in ("1", "password"):
            check_password()
        elif choice in ("2", "phishing"):
            check_phishing()
        elif choice in ("3", "file integrity checker"):
            file_integrity_checker()
        elif choice in ("4", "log analyzer"):
            log_analyzer()
        elif choice in ("5", "encryption tool", "encryption"):
            encryption_tool()
        elif choice in ("6", "quit"):
            break
        else:
            print("Enter one of the above options.")


if __name__ == "__main__":
    menu()
