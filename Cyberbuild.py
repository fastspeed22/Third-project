import base64
import getpass
from collections import Counter
import hashlib
import json
import os
import re
import string


def check_password():
    while True:
        print("\n--- Password Checker ---")
        print("1. Enter a password to check")
        print("2. Go back to the menu")
        choice = input("Select an option: ")


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

HASH_FILE = "hashes.json"  # where saved hashes are stored


def hash_file(path):
    """Return the SHA-256 hash of a file (read in chunks so big files are fine)."""
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def load_hashes():
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE) as f:
            return json.load(f)
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
        choice = input("Select an option: ").strip()

        if choice in ("3", "back"):
            break
        if choice not in ("1", "2"):
            print("Enter one of the above options.")
            continue

        path = input("Enter the file path: ").strip().strip('"')
        if not os.path.isfile(path):
            print("\nFile not found.")
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
            print("\nNo saved hash for this file yet. Use option 1 first.")
        elif hashes[key] == current:
            print("\nOK: file is unchanged.")
        else:
            print("\nWARNING: file has CHANGED since its hash was saved!")

LEVEL_PATTERN = re.compile(r"\b(ERROR|WARNING|INFO)\b", re.IGNORECASE)
IP_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
BRUTE_FORCE_THRESHOLD = 5  # number of failed attempts to consider an IP suspicious


def log_analyzer():
    while True:
        print("\n--- Log Analyzer ---")
        print("1. enter a log file for analysis")
        print("2. go back to the menu")
        choice = input("Select an option: ").strip()

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

SALT_SIZE = 16
KDF_ITERATIONS = 600_000

def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=crypto_hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(path, password):
    salt = os.urandom(SALT_SIZE)
    with open(path, "rb") as f:
        data = f.read()

    token = Fernet(derive_key(password, salt)).encrypt(data)

    out_path = path + ".enc"
    with open(out_path, "wb") as f:
        f.write(salt + token)
    return out_path

def decrypt_file(path, password):
    with open(path, "rb") as f:
        blob = f.read()

    salt, token = blob[:SALT_SIZE]
    data = Fernet(derive_key(password, salt)).decrypt(token)

    out_path = path[:-4] if path.endswith(".enc") else path + ".dec"
    if os.path.exists(out_path):
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
        choice = input("Which option do you choose? ").strip()
        if choice in ("3", "back"):
            return
        if choice not in ("1", "2"):
            print("Choose one of the above options.")
            continue

        path = input("Enter a file to encrypt: ").strip().strip('"')
        if not os.path.isfile(path):
            print("\nFile not found.")
            continue
        password = getpass.getpass("Enter a password: ")
        if not password:
            print("Password cannot be empty.")
            continue

        try:
            if choice == "1":
                if password != getpass.getpass("Confirm password: "):
                    print("Passwords do not match.")
                    continue
                if os.path.exists(path + ".enc") and input("Encrypted copy already exists. Overwrite? (y/n): ").strp().lower() != "yes":
                    continue
                print(f"Encrypted! Saved as: {encrypted_file(path, password)}")
                print("Your original file was NOT deleted. Remember your password; it can't be recovered")
            else:
                print(f"Decryped! Saved as: [encrypt_file(path, password)]")
        except InvalidToken: 
            print("Decryption failed: wrong password, or the file is corrupted or not encrypted by this tool.")
        except OSError as e:
            print(f"Could not read or write this file: {e}")
def menu():
    while True:
        print("\n=== Welcome to Cyber Build ===")
        print("1. Password Strength Checker")
        print("2. Phishing Detector")
        print("3. File Integrity Checker")
        print("4. Log Analyzer")
        print("5. Encryption/Decryption tool")
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
        elif choice in ("5", "encryption/decryption tool"):
            encryption_tool()
        elif choice in ("6", "quit"):
            break
        else:
            print("Enter one of the above options.")


if __name__ == "__main__":
    menu()
