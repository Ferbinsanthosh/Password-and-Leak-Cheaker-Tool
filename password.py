import time
import sys
import hashlib
import requests
import os
import math
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ⚠ VirusTotal API key placeholder (not used here)
VT_API_KEY = "your_api_key_here"

try:
    from zxcvbn import zxcvbn
    HAS_ZXCVBN = True
except ImportError:
    HAS_ZXCVBN = False


def shield_banner():
    """Print a cool colored ASCII shield banner."""
    shield = f"""
{Fore.CYAN}
              .-=========-.
              \\'-=======-'/
              _|   .=.   |_
             ((|  {{ 1 }}  |))
              \|   /|\\   |/
               \\__ '`' __/
                 _`) (`_
               _/_______\\_
              /___________\\

{Fore.YELLOW}       🛡️  PASSWORD SECURITY TOOL  🛡️
{Fore.WHITE}───────────────────────────────────────────────
"""
    print(shield)


def spinner_animation(duration=2, message="Checking"):
    """Show a spinning animation."""
    chars = ['|', '/', '-', '\\']
    for i in range(int(duration / 0.1)):
        sys.stdout.write(f"\r{message}... {chars[i % len(chars)]}")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * (len(message) + 5) + "\r")


def rule_based_score(pw):
    """Simple entropy-based password scoring."""
    length = len(pw)
    lower = any(c.islower() for c in pw)
    upper = any(c.isupper() for c in pw)
    digits = any(c.isdigit() for c in pw)
    symbols = any(not c.isalnum() for c in pw)

    pool = 0
    if lower: pool += 26
    if upper: pool += 26
    if digits: pool += 10
    if symbols: pool += 32

    entropy = length * math.log2(pool) if pool > 0 else 0
    if entropy < 28: score = 1
    elif entropy < 36: score = 2
    elif entropy < 60: score = 3
    else: score = 4

    return score, entropy


def analyze_password(pw):
    """Analyze password strength."""
    if not pw:
        return {"score": 0, "entropy": 0, "feedback": ["Empty password."]}
    if HAS_ZXCVBN:
        res = zxcvbn(pw)
        score = res["score"]
        entropy = res["entropy"]
        feedback = []
        if res["feedback"]["warning"]:
            feedback.append(res["feedback"]["warning"])
        feedback += res["feedback"]["suggestions"]
        return {"score": score, "entropy": entropy, "feedback": feedback}
    else:
        score, entropy = rule_based_score(pw)
        return {"score": score, "entropy": entropy, "feedback": ["Rule-based scoring."]}


def show_suggestions(pw):
    """Give suggestions to make the password stronger."""
    suggestions = []
    if len(pw) < 8:
        suggestions.append("➡️ Make your password at least 8 characters long.")
    if not any(c.islower() for c in pw):
        suggestions.append("➡️ Add some lowercase letters.")
    if not any(c.isupper() for c in pw):
        suggestions.append("➡️ Add some uppercase letters.")
    if not any(c.isdigit() for c in pw):
        suggestions.append("➡️ Include numbers (0-9).")
    if not any(not c.isalnum() for c in pw):
        suggestions.append("➡️ Add special characters like !, @, #, $, %.")
    if len(pw) >= 8 and len(pw) < 12:
        suggestions.append("➡️ Try making your password even longer for extra strength.")
    return suggestions


def progress_bar(score, pw):
    """Show a colored progress bar, label, and suggestions."""
    length = 30
    filled = int((score / 4) * length)

    # Decide color and label
    if score >= 3:
        color = Fore.GREEN
        label = "GOOD"
    elif score == 2:
        color = Fore.YELLOW
        label = "MEDIUM"
    else:
        color = Fore.RED
        label = "POOR"

    bar = color + "█" * filled + Fore.WHITE + "-" * (length - filled)
    print(f"[{bar}] {score}/4 Strength")
    print(color + f"→ Password Strength: {label}\n" + Fore.RESET)

    if score < 3:
        print(Fore.LIGHTBLACK_EX + "Suggestions to make your password stronger:")
        for tip in show_suggestions(pw):
            print(Fore.WHITE + tip)
        print()


def hibp_password_pwned(password):
    """Check if password was exposed in known data breaches."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        spinner_animation(2, "Checking Breaches")
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return -1
        for line in r.text.splitlines():
            suf, count = line.split(":")
            if suf == suffix:
                return int(count)
        return 0
    except Exception:
        return -1


def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    shield_banner()
    print(Fore.CYAN + Style.BRIGHT + "=== PASSWORD STRENGTH + LEAK CHECK TOOL ===\n")

    pw = input(Fore.YELLOW + "Enter your password: " + Style.RESET_ALL)
    spinner_animation(1.5, "Analyzing")

    # Analyze strength
    result = analyze_password(pw)
    score = result["score"]
    feedback = result["feedback"]
    entropy = result["entropy"]

    print(Fore.CYAN + "\nPassword Strength Result:")
    progress_bar(score, pw)
    print(Fore.WHITE + f"Entropy: {entropy:.2f} bits")
    for f in feedback:
        print(Fore.LIGHTBLACK_EX + " - " + f)

    # Check breach status
    count = hibp_password_pwned(pw)
    if count == -1:
        print(Fore.RED + "\n⚠  Could not contact HIBP API.")
    elif count == 0:
        print(Fore.GREEN + "\n✅ This password was NOT found in known breaches.")
    else:
        print(Fore.RED + f"\n❌ WARNING: This password appeared in {count} known breaches!")

    print(Fore.CYAN + "\nDone. Stay secure 🔐")


if __name__ == "__main__":
    main()
