# Password Strength Checker

A command-line cybersecurity tool that analyzes password strength and checks if your password has appeared in real-world data breaches.

---

## Features

- Checks password length, uppercase, lowercase, digits, and special characters
- Scores passwords from **Weak** to **Very Strong**
- Detects common/dictionary passwords
- Checks against **580M+ breached passwords** via the [HaveIBeenPwned API](https://haveibeenpwned.com/API/v3)
- Uses **k-anonymity** — your full password is *never* sent over the internet
- **Brute-force crack time estimation** across 4 real-world attack scenarios
- Color-coded terminal output (red = danger, yellow = warning, green = safe)
- Password input is hidden while typing

---

## How k-anonymity works

When checking for breaches, the tool:
1. Hashes your password with SHA-1
2. Sends only the **first 5 characters** of the hash to the API
3. The API returns all hashes that start with those 5 chars
4. The comparison happens **locally on your machine**

Your actual password never leaves your computer.

---

## Setup

**Requirements:** Python 3.7+

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/password-strength-checker.git
cd password-strength-checker

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the tool
python checker.py
```

---

## Usage

```
=============================================
   Password Strength Checker
=============================================
  Your password is never stored or transmitted.
  Breach check uses k-anonymity (safe).

  Enter password (hidden):

  Checking...

─────────────────────────────────────────────
  Strength: Very Strong
  Score:    7 / 7
─────────────────────────────────────────────
  ✔  Length: 17 chars
  ✔  Uppercase: Present
  ✔  Lowercase: Present
  ✔  Number: Present
  ✔  Special char: Present
  ✔  Not common: OK
  ✔  Breach check: Not found in any known breach
─────────────────────────────────────────────

  Excellent password! Keep it safe.
```

---

## Project Structure

```
password-strength-checker/
├── checker.py        # Main script
├── requirements.txt  # Python dependencies
└── README.md         # This file
```

---

## What I Learned

- How password entropy and complexity scoring works
- How the HaveIBeenPwned k-anonymity model protects user privacy
- How brute-force keyspace math works (charset size ^ length)
- Real-world attacker speed benchmarks (online vs GPU cluster)
- SHA-1 hashing in Python
- Making HTTP API requests with the `requests` library
- Building a clean CLI tool with color output

---

## Disclaimer

This tool is for **educational purposes**. Never test passwords you don't own.

---

## Author

Your Name — Zuhair Al Midani Shimar 
