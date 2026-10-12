# Phase 4: example ML-only scores

Hand-written example URLs (not from the training data; never fetched).

**`https://www.google.com/search?q=weather`**

- Score: 6.4/10 | Type: Phishing (56%) | Reasons: Uses HTTPS (raises risk by 2.4); URL has 2 special characters (lowers risk by 0.4); Query string is 9 characters long (lowers risk by 0.3); URL has 1 query parameters (lowers risk by 0.3); Top-level domain is 3 characters long (lowers risk by 0.2)
- Probabilities: {'benign': 0.245, 'phishing': 0.563, 'malware': 0.076, 'defacement': 0.115}
- Time: 3.00s

**`en.wikipedia.org/wiki/Machine_learning`**

- Score: 0.9/10 | Type: Benign (90%) | Reasons: URL has 2 dots (lowers risk by 0.7); URL has 1 special characters (lowers risk by 0.6); Top-level domain is 3 characters long (lowers risk by 0.5); Path is 22 characters long (lowers risk by 0.4); Domain has 1 subdomain level(s) (lowers risk by 0.4)
- Probabilities: {'benign': 0.899, 'phishing': 0.1, 'malware': 0.0, 'defacement': 0.0}
- Time: 1.07s

**`github.com/scikit-learn/scikit-learn/blob/main/README.rst`**

- Score: 0.5/10 | Type: Benign (93%) | Reasons: Domain name is 10 characters long (lowers risk by 1.1); Top-level domain is 3 characters long (lowers risk by 0.5); URL has 2 hyphens (lowers risk by 0.5); Path is 47 characters long (lowers risk by 0.5); Does not use HTTPS (lowers risk by 0.3)
- Probabilities: {'benign': 0.927, 'phishing': 0.017, 'malware': 0.006, 'defacement': 0.051}
- Time: 1.04s

**`https://docs.python.org/3/library/urllib.parse.html`**

- Score: 8.2/10 | Type: Phishing (83%) | Reasons: Uses HTTPS (raises risk by 2.0); URL has 4 dots (raises risk by 0.6); Top-level domain is 3 characters long (lowers risk by 0.2); URL has 0 hyphens (raises risk by 0.2); Uses a domain name, not an IP address (lowers risk by 0.2)
- Probabilities: {'benign': 0.092, 'phishing': 0.83, 'malware': 0.077, 'defacement': 0.0}
- Time: 1.02s

**`http://paypal-account-verify.secure-login.tk/signin/update.php?id=88231`**

- Score: 3.6/10 | Type: Benign (61%) | Reasons: Uses a top-level domain often abused by attackers (raises risk by 0.5); URL has 3 dots (raises risk by 0.2); Uses a domain name, not an IP address (lowers risk by 0.2); Contains 6 suspicious keyword(s) (raises risk by 0.2); Top-level domain is 2 characters long (raises risk by 0.2)
- Probabilities: {'benign': 0.606, 'phishing': 0.337, 'malware': 0.056, 'defacement': 0.001}
- Time: 0.95s

**`http://192.168.43.10/bins/mozi.arm7`**

- Score: 10.0/10 | Type: Malware (100%) | Reasons: Uses a raw IP address instead of a domain name (raises risk by 1.1); Top-level domain is 0 characters long (raises risk by 1.0); URL has 4 dots (raises risk by 0.6); 39% of the URL's characters are digits (raises risk by 0.6); URL contains 11 digits (raises risk by 0.2)
- Probabilities: {'benign': 0.0, 'phishing': 0.0, 'malware': 1.0, 'defacement': 0.0}
- Time: 0.99s

**`http://198.51.100.23:8080/Photo.scr`**

- Score: 10.0/10 | Type: Malware (100%) | Reasons: Uses a raw IP address instead of a domain name (raises risk by 1.0); Top-level domain is 0 characters long (raises risk by 1.0); URL has 4 dots (raises risk by 0.6); 50% of the URL's characters are digits (raises risk by 0.5); URL contains 14 digits (raises risk by 0.2)
- Probabilities: {'benign': 0.0, 'phishing': 0.004, 'malware': 0.996, 'defacement': 0.0}
- Time: 0.98s

**`bit.ly/3xYz9Ab`**

- Score: 3.1/10 | Type: Benign (65%) | Reasons: URL has 1 dots (lowers risk by 1.1); Top-level domain is 2 characters long (raises risk by 0.7); Domain name is 6 characters long (lowers risk by 0.6); Does not use HTTPS (lowers risk by 0.4); URL is 14 characters long (raises risk by 0.4)
- Probabilities: {'benign': 0.654, 'phishing': 0.342, 'malware': 0.004, 'defacement': 0.001}
- Time: 0.97s

**`http://www.example-school.edu/index.php?option=com_content&view=article&id=48&Itemid=55`**

- Score: 5.0/10 | Type: Defacement (100%) | Reasons: URL has 3 dots (raises risk by 0.5); Top-level domain is 3 characters long (lowers risk by 0.2); Uses a domain name, not an IP address (lowers risk by 0.2); URL has 9 special characters (lowers risk by 0.2); Query string is 47 characters long (lowers risk by 0.2)
- Probabilities: {'benign': 0.001, 'phishing': 0.0, 'malware': 0.0, 'defacement': 0.999}
- Time: 0.98s

**`secure-bankofamerica.com-verify-account.info/login/confirm/password.html`**

- Score: 4.7/10 | Type: Phishing (51%) | Reasons: URL has 3 dots (raises risk by 0.5); Contains 7 suspicious keyword(s) (raises risk by 0.4); Domain name is 44 characters long (raises risk by 0.3); Path is 28 characters long (lowers risk by 0.3); URL is 72 characters long (lowers risk by 0.3)
- Probabilities: {'benign': 0.483, 'phishing': 0.513, 'malware': 0.003, 'defacement': 0.001}
- Time: 0.99s
