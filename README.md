# Public Wi-Fi Risk Analyzer (HTTPS-Based),
This tool detects potentially unsafe public Wi-Fi networks using only HTTPS-level observations. It performs a series of secure connection checks to trusted websites and calculates a risk score based on anomalies found in SSL/TLS behavior.

---

Features:
- Verifies SSL certificate validity and issuer
- Detects TLS version downgrade attempts
- Flags failed HTTPS handshakes
- Detects unexpected HTTP/HTTPS redirections
- Computes a final risk score (Low / Medium / High)

---

How It Works
The script connects to a list of well-known secure websites and applies a set of heuristics to analyze network behavior:

| Check | Description | Risk Level |
|-------|-------------|------------|
| Invalid or self-signed certificates | May indicate MITM | High |
| TLS version below 1.2 | Potential downgrade attack | Medium |
| HTTPS connection failures | Likely interception or blocking | High |
| Redirects to unknown domains | Could be phishing/captive portal | Medium |
| Certificate issuer mismatch | Suspicious certificate injection | Medium–High |

---
