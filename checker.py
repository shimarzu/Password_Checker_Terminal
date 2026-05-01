"""
Password Strength Checker
A cybersecurity tool to analyze password strength, check for data breaches,
and estimate how long a brute-force attack would take to crack it.
"""

import re
import math
import hashlib
import requests
import getpass


# ── Terminal colors ──────────────────────────────────────────────────────────
class Color:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


# ── Common weak passwords to block ───────────────────────────────────────────
COMMON_PASSWORDS = [
    "password", "123456", "123456789", "12345678", "12345",
    "1234567", "qwerty", "abc123", "password1", "iloveyou",
    "admin", "letmein", "monkey", "1234567890", "000000",
    "dragon", "master", "sunshine", "princess", "welcome",
]


# ── Brute-force time estimation ───────────────────────────────────────────────

# How many guesses per second different attackers can try.
# These are real-world benchmarks based on hardware commonly used in attacks.
ATTACK_SPEEDS = {
    "Online attack (web login, ~100/s)"    : 100,
    "Slow hash (bcrypt, ~10K/s)"           : 10_000,
    "Fast hash (MD5/SHA1, ~10B/s)"         : 10_000_000_000,
    "GPU cluster (top-end, ~100B/s)"       : 100_000_000_000,
}

def calculate_charset_size(password: str) -> int:
    """
    Works out how many possible characters the attacker must consider.
    Bigger charset = exponentially harder to brute-force.
    """
    size = 0
    if re.search(r"[a-z]", password): size += 26   # lowercase letters
    if re.search(r"[A-Z]", password): size += 26   # uppercase letters
    if re.search(r"\d", password):    size += 10   # digits 0-9
    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", password): size += 32  # special chars
    return size if size > 0 else 26  # default to lowercase if nothing matched


def format_time(seconds: float) -> str:
    """
    Converts a raw number of seconds into a human-readable string.
    e.g. 3_153_600_000 -> "100 years"
    """
    if seconds < 1:
        return "less than a second"

    MINUTE = 60
    HOUR   = 60 * MINUTE
    DAY    = 24 * HOUR
    YEAR   = 365 * DAY
    MILLENNIUM = 1000 * YEAR

    if seconds < MINUTE:
        v = int(seconds)
        return f"{v} second{'s' if v != 1 else ''}"
    elif seconds < HOUR:
        v = int(seconds / MINUTE)
        return f"{v} minute{'s' if v != 1 else ''}"
    elif seconds < DAY:
        v = int(seconds / HOUR)
        return f"{v} hour{'s' if v != 1 else ''}"
    elif seconds < YEAR:
        v = int(seconds / DAY)
        return f"{v} day{'s' if v != 1 else ''}"
    elif seconds < MILLENNIUM:
        v = int(seconds / YEAR)
        return f"{v:,} year{'s' if v != 1 else ''}"
    elif seconds < MILLENNIUM * 1_000_000:
        v = int(seconds / MILLENNIUM)
        return f"{v:,} thousand years"
    else:
        exp = int(math.log10(seconds / YEAR))
        return f"10^{exp} years (practically uncrackable)"


def estimate_bruteforce(password: str) -> dict:
    """
    Calculates the total keyspace and estimates crack time for each
    attack scenario using the formula:
        total_combinations = charset_size ^ password_length
        time = total_combinations / guesses_per_second / 2
    We divide by 2 because on average an attacker finds the password
    halfway through the search space.
    """
    charset_size = calculate_charset_size(password)
    length       = len(password)

    log_combinations = length * math.log10(charset_size)
    combinations     = 10 ** log_combinations

    results = {
        "charset_size"  : charset_size,
        "combinations"  : combinations,
        "log_combos"    : log_combinations,
        "scenarios"     : {}
    }

    for scenario, speed in ATTACK_SPEEDS.items():
        seconds = (combinations / speed) / 2
        results["scenarios"][scenario] = format_time(seconds)

    return results


def print_bruteforce(bf: dict):
    """
    Prints the brute-force estimation section in the terminal.
    """
    c = Color
    print(f"  {c.BOLD}Brute-force crack time estimate:{c.RESET}")
    print(f"  Charset size : {bf['charset_size']} possible characters")

    if bf["log_combos"] < 15:
        print(f"  Keyspace     : {int(bf['combinations']):,} combinations")
    else:
        exp = int(bf["log_combos"])
        print(f"  Keyspace     : ~10^{exp} combinations")

    print()

    for scenario, time_str in bf["scenarios"].items():
        if "second" in time_str or "minute" in time_str or "hour" in time_str:
            color = c.RED
        elif "day" in time_str or ("year" in time_str and "thousand" not in time_str and "^" not in time_str):
            color = c.YELLOW
        else:
            color = c.GREEN

        print(f"  {c.CYAN}▸{c.RESET} {scenario}")
        print(f"      → {color}{c.BOLD}{time_str}{c.RESET}")

    print()
    print(f"  {c.YELLOW}Note: This assumes a pure brute-force attack (no dictionary).{c.RESET}")
    print(f"  {c.YELLOW}Dictionary/hybrid attacks on simple words are much faster.{c.RESET}")
    print("─" * 45 + "\n")


# ── Breach check via HaveIBeenPwned API (k-anonymity) ────────────────────────
def check_breach(password: str) -> int:
    """
    Checks if the password appears in known data breaches.
    Uses k-anonymity — only the first 5 chars of the SHA1 hash are sent.
    The full password is NEVER sent over the internet.
    Returns the number of times it was found (0 = safe).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5
        )
        response.raise_for_status()
    except requests.RequestException:
        # If the API is unreachable, skip the check gracefully
        return -1

    # Each line is  HASH_SUFFIX:COUNT
    for line in response.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)

    return 0  # Not found in any breach


# ── Core strength analysis ────────────────────────────────────────────────────
def analyze_password(password: str) -> dict:
    """
    Runs all checks and returns a results dictionary.
    """
    results = {
        "length"          : len(password),
        "has_upper"       : bool(re.search(r"[A-Z]", password)),
        "has_lower"       : bool(re.search(r"[a-z]", password)),
        "has_digit"       : bool(re.search(r"\d", password)),
        "has_special"     : bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)),
        "is_common"       : password.lower() in COMMON_PASSWORDS,
        "breach_count"    : check_breach(password),
    }

    # ── Scoring ──────────────────────────────────────────────────────────────
    score = 0

    if results["length"] >= 8:  score += 1
    if results["length"] >= 12: score += 1
    if results["length"] >= 16: score += 1
    if results["has_upper"]:    score += 1
    if results["has_lower"]:    score += 1
    if results["has_digit"]:    score += 1
    if results["has_special"]:  score += 1

    # Penalties
    if results["is_common"]:       score = 0
    if results["breach_count"] > 0: score = min(score, 1)

    results["score"] = score

    # ── Strength label ────────────────────────────────────────────────────────
    if score <= 1:
        results["strength"] = "Weak"
        results["color"]    = Color.RED
    elif score <= 3:
        results["strength"] = "Fair"
        results["color"]    = Color.YELLOW
    elif score <= 5:
        results["strength"] = "Strong"
        results["color"]    = Color.GREEN
    else:
        results["strength"] = "Very Strong"
        results["color"]    = Color.CYAN

    return results


# ── Display results ───────────────────────────────────────────────────────────
def print_results(results: dict):
    c = Color
    print("\n" + "─" * 45)

    # Strength banner
    strength_line = f"  Strength: {results['color']}{c.BOLD}{results['strength']}{c.RESET}"
    score_line    = f"  Score:    {results['score']} / 7"
    print(strength_line)
    print(score_line)
    print("─" * 45)

    # Individual checks
    def check_line(label, passed, good_msg, bad_msg):
        icon = f"{c.GREEN}✔{c.RESET}" if passed else f"{c.RED}✘{c.RESET}"
        msg  = good_msg if passed else f"{c.RED}{bad_msg}{c.RESET}"
        print(f"  {icon}  {label}: {msg}")

    check_line("Length",          results["length"] >= 12,
               f"{results['length']} chars",
               f"{results['length']} chars (use 12+)")

    check_line("Uppercase",       results["has_upper"],
               "Present", "Missing")

    check_line("Lowercase",       results["has_lower"],
               "Present", "Missing")

    check_line("Number",          results["has_digit"],
               "Present", "Missing")

    check_line("Special char",    results["has_special"],
               "Present", "Missing (!@#$...)")

    check_line("Not common",      not results["is_common"],
               "OK", "This is a very common password!")

    # Breach check output
    bc = results["breach_count"]
    if bc == -1:
        print(f"  {c.YELLOW}⚠{c.RESET}  Breach check: Could not reach API (check your internet)")
    elif bc == 0:
        print(f"  {c.GREEN}✔{c.RESET}  Breach check: Not found in any known breach")
    else:
        print(f"  {c.RED}✘{c.RESET}  Breach check: {c.RED}Found {bc:,} times in data breaches!{c.RESET}")

    print("─" * 45 + "\n")


# ── Tips ──────────────────────────────────────────────────────────────────────
def print_tips(results: dict):
    tips = []

    if results["length"] < 12:
        tips.append("Use at least 12 characters.")
    if not results["has_upper"]:
        tips.append("Add uppercase letters (A-Z).")
    if not results["has_lower"]:
        tips.append("Add lowercase letters (a-z).")
    if not results["has_digit"]:
        tips.append("Add numbers (0-9).")
    if not results["has_special"]:
        tips.append("Add special characters like !@#$%.")
    if results["is_common"]:
        tips.append("Avoid extremely common passwords.")
    if results["breach_count"] > 0:
        tips.append("This password has been leaked — change it immediately.")

    if tips:
        print(f"  {Color.BOLD}Tips to improve:{Color.RESET}")
        for tip in tips:
            print(f"    • {tip}")
        print()
    else:
        print(f"  {Color.CYAN}{Color.BOLD}Excellent password! Keep it safe.{Color.RESET}\n")


# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    print(f"\n{Color.BOLD}{'='*45}")
    print("   Password Strength Checker")
    print(f"{'='*45}{Color.RESET}")
    print("  Your password is never stored or transmitted.")
    print("  Breach check uses k-anonymity (safe).\n")

    while True:
        # getpass hides input — password won't show on screen
        try:
            password = getpass.getpass("  Enter password (hidden): ")
        except KeyboardInterrupt:
            print("\n\n  Exited. Stay secure!\n")
            break

        if not password:
            print(f"  {Color.YELLOW}Please enter a password.{Color.RESET}\n")
            continue

        print(f"\n  {Color.CYAN}Checking...{Color.RESET}")
        results = analyze_password(password)
        print_results(results)
        print_tips(results)

        print("─" * 45)
        bf = estimate_bruteforce(password)
        print_bruteforce(bf)

        again = input("  Check another password? (y/n): ").strip().lower()
        if again != "y":
            print(f"\n  {Color.GREEN}Stay secure!{Color.RESET}\n")
            break


if __name__ == "__main__":
    main()
