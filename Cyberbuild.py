import hashlib
import json
import os
import re
import string


def check_password():
    while True:
        print("\n--- Pasword Checker ---")
        print("1. Enter a pasword to check")
        print("2. Go back to the menu")
        choice = input("Select an option: ")


        if choice in ("2", "back"):
            break
        elif choice == "1":
            password = input("Enter a pasword to check: ")

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

        # \b makes sure we match whole words ("pin" won't match "shipping")
        
        elif choice == "1":
            message = input("Enter a possible Phishing: ")
            
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

def log_analyzer():
    print("not finished yet")
def menu():
    while True:
        print("\n=== Welcome to Cyber Build ===")
        print("1. Password Strength Checker")
        print("2. Phishing Detector")
        print("3. File Integrity Checker")
        print("4. Log Analyzer")
        print("5. Quit")

        choice = input("\nSelect an option: ").strip().lower()

        if choice in ("1", "password"):
            check_password()
        elif choice in ("2", "phishing"):
            check_phishing()
        elif choice in ("3", "file integrity checker"):
            file_integrity_checker()
        elif choice in ("4", "log analyzer"):
            log_analyzer()
        elif choice in ("5", "quit"):
            break
        else:
            print("Enter one of the above options.")


if __name__ == "__main__":
    menu()
