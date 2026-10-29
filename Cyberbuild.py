import re
import string


def check_password():
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
        print("Strong password!")
    elif len(missing) >= 3:
        print("Weak password. You need: " + ", ".join(missing))
    else:
        print("Almost there! Add: " + ", ".join(missing))


PHISHING_WORDS = ["urgent", "immediately", "act now", "final notice", "last chance", "expires today", "within 24 hours", "respond", "limited time", "suspended", "locked", "unusual activity", "unauthorized", "security", "alert", "verify your account", "confirm your identity", "account closed", "deactivated", "ssn" "password", "pin", "social security", "bank", "payment", "credit card", "cvv", "verification code", "one-time code", "login", "username", "wire transfer", "gift card", "bitcoin", "crypto", "invoice", "refund", "overdue", "billing", "direct deposit", "you've won", "lottery", "prize", "congratulations", "inheritance", "free", "claim your reward", "selected", "dear customer", "dear user", "valued customer", "dear member", "click here", "click the link", "open attachment", "download", "update your information", "log in"]

print("this shit is so annting i am going to kill someone")

def check_phishing():
    while True:
        message = input("\nEnter a message to analyze (or 'back' to return to the menu): ").lower()

        if message.strip() == "back":
            break

        # \b makes sure we match whole words ("pin" won't match "shipping")
        found = [w for w in PHISHING_WORDS if re.search(rf"\b{w}\b", message)]

        if found:
            print("Warning: possible phishing. Suspicious words found: " + ", ".join(found))
        else:
            print("No red flags found. Still be careful of suspicious links and unknown senders.")

def file_integrity_checker():
    print("startung")

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
