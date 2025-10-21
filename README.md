A Python-based password strength analyzer and data breach checker that helps you evaluate the security of your passwords locally and safely.
It combines entropy-based scoring, pattern analysis (via zxcvbn), and the Have I Been Pwned (HIBP) API to detect if your password has ever appeared in known data breaches.

Features!!!!!!!!!!!
1. Real-time password strength analysis (using zxcvbn if available, otherwise fallback to entropy rules)
2. Colorful progress bar and feedback for better visualization
3. Live breach check via the official Have I Been Pwned API (anonymous k-anonymity model — your password never leaves your device directly)
4. Helpful suggestions to improve weak passwords
5. Cross-platform support (Windows, macOS, Linux)
6. No external dependencies required beyond colorama and requests (and optionally zxcvbn)

Requirements!!!!!!!
1. Python 3.7+
2. pip install colorama requests
3. (Optional) pip install zxcvbn
