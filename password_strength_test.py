import re

def load_common_passwords(filepath="common_passwords.txt"):
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            return set(line.strip() for line in file)
    except FileNotFoundError:
        print("⚠️ Common password list not found. Skipping dictionary check.")
        return set()

def check_strength(password, common_passwords):
    score = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password too short (min 8 characters).")

    # Character variety
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add at least one number.")
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        feedback.append("Add at least one special character (e.g. !, @, #).")

    # Common password check
    if password.lower() in common_passwords:
        feedback.append("This password is too common.")
        score = 0

    # Final rating
    rating = {
        0: "Very Weak",
        1: "Weak",
        2: "Fair",
        3: "Good",
        4: "Strong",
        5: "Very Strong",
        6: "Excellent"
    }.get(score, "Unknown")

    return rating, feedback

def main():
    print("🔐 Password Strength Checker")
    common_passwords = load_common_passwords()

    password = input("Enter a password to check: ").strip()
    rating, feedback = check_strength(password, common_passwords)

    print(f"\nStrength: {rating}")
    if feedback:
        print("\nSuggestions:")
        for tip in feedback:
            print(f" - {tip}")

if __name__ == "__main__":
    main()
