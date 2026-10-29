import string
import re

#Fix loops

def check_password():
    password = input("Enter a password to check: ")
    length_ok = len(password) >= 8
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)
 
    if length_ok and has_upper and has_digit and has_symbol:
        print("Strong password!")
    elif length_ok and (has_symbol or has_digit or has_upper):
        missing = []

        if not has_upper:
            missing.append("an uppercase letter")
        if not has_digit:
            missing.append("an number")
        if not has_symbol:
            missing.append("a special character")
        print("Almost there! Add: "+", ".join(missing))
    
    else:
        print("Son you're really using THAT password. Worst passwords of all time. You need ATLEAST 8 characters,an uppercase letter, number, and special character")   


def password_checker():
    
    while True:
        print("\n=== This is password strength checker ===")
        ans = input("Would you like to check your password?(yes/no)").lower()
        if ans == "yes":
            check_password()
        elif ans == "no":
            break
        else:
            print("Enter required input")
            password_checker

PHISHING_WORDS = ["urgent", "password", "pin", "social security", "bank", "payment", "act now", "final notice", "last chance", "expires today", "within 24 hours", "asap", "limited time", "suspended", "locked", "unusual activity", "unauthorized", "security alert", "verify your account", "confirm your identity", "deactivated", "passcode", "credit card", "ssn", "routing number", "account number", "cvv", "verification code", "login", "username", "wire transfer", "gift card", "bitcoin", "crypto", "invoice", "refund", "overdue", "billing", "direct deposit", "you've won", "lottery", "prize", "congratulations", "inheritance", "free", "claim", "selected"]

def phishing_dectector():
    while True:
        message = input("/nPlease enter a message to analyze (or 'back' to return to the menu): ").lower()
        if message.strip() == "back":
            break
        found = [w for w in PHISHING_WORDS if re.search(rf"\b{w}\b", message)]

        if found:
            print("Warning: Possible phishing. suspicous words dectected: " + ", ".join(found))
        else:
            print("No anomalies dectected. Still be careful of suspicous links and unknown senders.")

   
    
        

def menu():
    while True:
        print("\n=== Welcome to cyber build ===")
        print("1. Password Checker")
        print("2. Phishing Dectector")
        print("3. File Integrity Checker")
        print("4. Log Analyzer")
        print("5. Quit")

        choice = input("\nSelect an option: ").lower()
        if choice in ("1", "password checker", "password"):
            password_checker()
        elif choice in ("2", "phishing", "phishing dectector" ):
            phishing_dectector()
        elif choice in ("3"):
            print("not finished")
        elif choice in ("5", "quit"):
            break
        else:
            print("Enter one of the above options")

menu()