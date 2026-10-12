# Phase 4: example ML-only scores

Hand-written example URLs (not from the training data; never fetched). Model: v2-no-https.

**`https://www.google.com/search?q=weather`**

- Score: 2.8/10 | Type: Benign (54%) | Reasons: URL has 2 special characters (lowers risk by 0.7); URL has 1 query parameters (lowers risk by 0.4); Top-level domain is 3 characters long (lowers risk by 0.4); Query string is 9 characters long (lowers risk by 0.3); Uses a domain name, not an IP address (lowers risk by 0.2)
- Probabilities: {'benign': 0.542, 'phishing': 0.124, 'malware': 0.002, 'defacement': 0.331}
- Time: 3.14s

**`en.wikipedia.org/wiki/Machine_learning`**

- Score: 1.1/10 | Type: Benign (88%) | Reasons: URL has 2 dots (lowers risk by 0.7); URL has 1 special characters (lowers risk by 0.7); Top-level domain is 3 characters long (lowers risk by 0.6); Path is 22 characters long (lowers risk by 0.5); Domain has 1 subdomain level(s) (lowers risk by 0.4)
- Probabilities: {'benign': 0.881, 'phishing': 0.119, 'malware': 0.0, 'defacement': 0.0}
- Time: 1.03s

**`github.com/scikit-learn/scikit-learn/blob/main/README.rst`**

- Score: 0.7/10 | Type: Benign (90%) | Reasons: Domain name is 10 characters long (lowers risk by 1.0); URL has 2 hyphens (lowers risk by 0.6); Path is 47 characters long (lowers risk by 0.5); Top-level domain is 3 characters long (lowers risk by 0.5); URL has 2 dots (lowers risk by 0.3)
- Probabilities: {'benign': 0.898, 'phishing': 0.013, 'malware': 0.037, 'defacement': 0.052}
- Time: 1.01s

**`https://docs.python.org/3/library/urllib.parse.html`**

- Score: 6.1/10 | Type: Phishing (68%) | Reasons: URL has 4 dots (raises risk by 1.3); Top-level domain is 3 characters long (lowers risk by 0.3); URL has 0 hyphens (raises risk by 0.3); Path is 28 characters long (lowers risk by 0.3); Uses a domain name, not an IP address (lowers risk by 0.2)
- Probabilities: {'benign': 0.32, 'phishing': 0.677, 'malware': 0.002, 'defacement': 0.0}
- Time: 1.00s

**`http://paypal-account-verify.secure-login.tk/signin/update.php?id=88231`**

- Score: 4.1/10 | Type: Benign (55%) | Reasons: Uses a top-level domain often abused by attackers (raises risk by 0.4); URL has 3 dots (raises risk by 0.3); Contains 6 suspicious keyword(s) (raises risk by 0.2); Top-level domain is 2 characters long (raises risk by 0.2); URL has 3 hyphens (lowers risk by 0.2)
- Probabilities: {'benign': 0.553, 'phishing': 0.408, 'malware': 0.037, 'defacement': 0.002}
- Time: 0.92s

**`http://192.168.43.10/bins/mozi.arm7`**

- Score: 10.0/10 | Type: Malware (100%) | Reasons: Top-level domain is 0 characters long (raises risk by 1.2); Uses a raw IP address instead of a domain name (raises risk by 0.8); 39% of the URL's characters are digits (raises risk by 0.6); URL has 4 dots (raises risk by 0.5); URL contains 11 digits (raises risk by 0.3)
- Probabilities: {'benign': 0.0, 'phishing': 0.002, 'malware': 0.998, 'defacement': 0.0}
- Time: 0.98s

**`http://198.51.100.23:8080/Photo.scr`**

- Score: 10.0/10 | Type: Malware (100%) | Reasons: Top-level domain is 0 characters long (raises risk by 1.1); Uses a raw IP address instead of a domain name (raises risk by 0.8); 50% of the URL's characters are digits (raises risk by 0.6); URL has 4 dots (raises risk by 0.6); URL contains 14 digits (raises risk by 0.3)
- Probabilities: {'benign': 0.0, 'phishing': 0.005, 'malware': 0.995, 'defacement': 0.0}
- Time: 0.93s

**`bit.ly/3xYz9Ab`**

- Score: 6.0/10 | Type: Phishing (65%) | Reasons: Top-level domain is 2 characters long (raises risk by 0.9); URL has 1 dots (lowers risk by 0.7); URL is 14 characters long (raises risk by 0.7); Domain name is 6 characters long (lowers risk by 0.3); Uses a domain name, not an IP address (lowers risk by 0.2)
- Probabilities: {'benign': 0.334, 'phishing': 0.654, 'malware': 0.011, 'defacement': 0.0}
- Time: 0.97s

**`http://www.example-school.edu/index.php?option=com_content&view=article&id=48&Itemid=55`**

- Score: 5.0/10 | Type: Defacement (100%) | Reasons: URL has 3 dots (raises risk by 0.5); URL has 9 special characters (lowers risk by 0.3); Top-level domain is 3 characters long (lowers risk by 0.2); Query string is 47 characters long (lowers risk by 0.2); Uses a domain name, not an IP address (lowers risk by 0.2)
- Probabilities: {'benign': 0.001, 'phishing': 0.0, 'malware': 0.0, 'defacement': 0.999}
- Time: 1.03s

**`secure-bankofamerica.com-verify-account.info/login/confirm/password.html`**

- Score: 4.7/10 | Type: Phishing (52%) | Reasons: Contains 7 suspicious keyword(s) (raises risk by 0.4); URL has 3 dots (raises risk by 0.4); Path is 28 characters long (lowers risk by 0.3); Domain name is 44 characters long (raises risk by 0.3); URL has 3 hyphens (lowers risk by 0.3)
- Probabilities: {'benign': 0.473, 'phishing': 0.521, 'malware': 0.004, 'defacement': 0.002}
- Time: 0.93s
