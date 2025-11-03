# password_checker.py
import math
import re
import sys
from collections import Counter

COMMON_PASSWORDS = {
    "123456","password","123456789","qwerty","abc123","password1","111111","iloveyou",
    "123123","dragon","monkey","letmein","admin","welcome","football","qwerty123"
}

SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "0123456789",
    "qwertyuiop","asdfghjkl","zxcvbnm",
    "QWERTYUIOP","ASDFGHJKL","ZXCVBNM"
]

def estimate_entropy_bits(pw: str) -> float:
    """Upper-bound Shannon-ish estimate: log2(charset_size^length)."""
    if not pw:
        return 0.0
    charset = 0
    if re.search(r"[a-z]", pw): charset += 26
    if re.search(r"[A-Z]", pw): charset += 26
    if re.search(r"[0-9]", pw): charset += 10
    if re.search(r"[^A-Za-z0-9]", pw): charset += 33  
    return len(pw) * math.log2(charset or 1)

def has_sequence(pw: str, run_len: int = 4) -> bool:
    """Detect easy sequential runs (abcd, 1234, qwer…)."""
    if len(pw) < run_len:
        return False
    for base in SEQUENCES:
        for i in range(len(base) - run_len + 1):
            chunk = base[i:i+run_len]
            if chunk in pw or chunk[::-1] in pw:
                return True
    return False

def has_repeats(pw: str, max_repeat: int = 3) -> bool:
    """Detect long runs of same char (aaaa, 1111…)."""
    return re.search(r"(.)\1{" + str(max_repeat) + ",}", pw) is not None

def category_count(pw: str) -> int:
    cats = [
        bool(re.search(r"[a-z]", pw)),
        bool(re.search(r"[A-Z]", pw)),
        bool(re.search(r"[0-9]", pw)),
        bool(re.search(r"[^A-Za-z0-9]", pw)),
    ]
    return sum(cats)

def dictionary_like(pw: str) -> bool:
    """Very light heuristic: password in common set or mostly one word."""
    lower = pw.lower()
    if lower in COMMON_PASSWORDS:
        return True
    return bool(re.fullmatch(r"[A-Za-z]{8,}", pw))

def score_password(pw: str) -> dict:
    issues = []
    suggestions = []

    # Basic signals
    length = len(pw)
    cats = category_count(pw)
    entropy = estimate_entropy_bits(pw)

    # Start from entropy-based baseline (cap at 100)
    # 0–30 bits = weak, 30–50 = okay, 50–70 = strong-ish, 70+ = great
    base = min(100, max(0, (entropy / 70) * 100))

    # Penalties
    penalty = 0
    if length < 8:
        penalty += 30
        issues.append("Too short (< 8 chars).")
        suggestions.append("Use at least 12–16 characters.")
    elif length < 12:
        penalty += 10
        suggestions.append("Bump length toward 12–16 characters.")

    if cats < 2:
        penalty += 25
        issues.append("Low variety (only one character type).")
        suggestions.append("Mix upper/lowercase, digits, and a symbol.")

    if has_sequence(pw):
        penalty += 20
        issues.append("Contains obvious sequences (e.g., abcd, 1234, qwerty).")
        suggestions.append("Avoid keyboard runs or simple sequences.")

    if has_repeats(pw):
        penalty += 15
        issues.append("Contains long repeated characters (e.g., aaaa).")
        suggestions.append("Break up repeated characters.")

    if dictionary_like(pw):
        penalty += 20
        issues.append("Looks like a common or dictionary-style word.")
        suggestions.append("Use unrelated words or add noise (digits/symbols).")

    # Bonus for variety + length combo
    if length >= 14 and cats >= 3:
        base += 5

    score = int(max(0, min(100, base - penalty)))

    # Grade buckets
    if score < 35:
        grade = "VERY WEAK"
    elif score < 60:
        grade = "WEAK"
    elif score < 80:
        grade = "FAIR"
    elif score < 90:
        grade = "STRONG"
    else:
        grade = "EXCELLENT"

    # De-duplicate suggestions, keep top 4
    dedup_suggestions = []
    for s in suggestions:
        if s not in dedup_suggestions:
            dedup_suggestions.append(s)
    dedup_suggestions = dedup_suggestions[:4]

    # Minimal hints for building better passwords
    tips = [
        "Passphrases are king: 3–4 random words + separators (e.g., 'tuna|orbit|7!mud').",
        "Length beats complexity past a point; aim for 14+ characters.",
        "Avoid personal info, dates, and site names.",
        "Use a password manager to generate and store unique passwords."
    ]

    return {
        "password_length": length,
        "categories_used": cats,
        "entropy_bits_est": round(entropy, 1),
        "score": score,
        "grade": grade,
        "issues": issues,
        "suggestions": dedup_suggestions,
        "tips": tips
    }

def explain(result: dict, pw_preview: str) -> str:
    bar = "█" * (result["score"] // 5) + "░" * (20 - result["score"] // 5)
    lines = [
        f"[{bar}] {result['score']}/100 — {result['grade']}",
        f"Length: {result['password_length']} | Categories: {result['categories_used']} | Entropy≈{result['entropy_bits_est']} bits",
    ]
    if result["issues"]:
        lines.append("Issues:")
        for i in result["issues"]:
            lines.append(f"  - {i}")
    if result["suggestions"]:
        lines.append("Suggestions:")
        for s in result["suggestions"]:
            lines.append(f"  • {s}")
    lines.append("Tips:")
    for t in result["tips"]:
        lines.append(f"  • {t}")
    lines.append(f"(You entered: {pw_preview})")
    return "\n".join(lines)

def mask_preview(pw: str) -> str:
    """Show only first & last char to avoid printing secrets."""
    if not pw:
        return "<empty>"
    if len(pw) <= 2:
        return pw[0] + "*"
    return pw[0] + "*" * (len(pw) - 2) + pw[-1]

def main():
    # Usage:
    #   python password_checker.py           # interactive
    #   python password_checker.py "MyPass"  # one-shot
    if len(sys.argv) > 1:
        pw = sys.argv[1]
    else:
        try:
            pw = input("Enter a password to check (will be echoed): ").strip()
        except KeyboardInterrupt:
            print("\nCanceled.")
            return
    result = score_password(pw)
    print(explain(result, mask_preview(pw)))

if __name__ == "__main__":
    main()
