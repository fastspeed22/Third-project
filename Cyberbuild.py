import string

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
                
        
        

def menu():
    while True:
        print("\n=== Welcome to cyber build ===")
        ans = input("\nWould you like to 1) password checker 2) Phishing dectector 3) File integrity checker 4) log analyzer 5) quit: ").lower()
        if ans in ("1", "password checker", "password"):
            password_checker()
        elif ans in ("2", "phishing", "phishing dectector" ):
            print("not finished")
        elif ans in ("3"):
            print("not finished")
        elif ans in ("5", "quit"):
            break
        else:
            print("Enter one of the above options")

menu()
