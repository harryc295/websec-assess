# Security Assessment Report: demo.example.com

- **Target:** https://demo.example.com
- **Profile:** standard
- **Status:** completed
- **Started:** 2026-06-20 09:00:00+00:00
- **Finished:** 2026-06-20 09:04:12+00:00

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 2 |
| LOW | 1 |
| INFO | 1 |

Total findings: **7** &nbsp;&nbsp; Total assets discovered: **6**

## Findings

### [CRITICAL] Unauthenticated Docker daemon API exposed
- **Plugin:** cloud_infra.container_exposure (cloud_infra)
- **Confidence:** high
- **Affected URL:** `http://demo.example.com:2375/version`
- **CWE:** CWE-306
- **OWASP:** A05:2021-Security Misconfiguration

The Docker Engine API on port 2375 responds without authentication.

**Remediation:** Never expose the Docker daemon over plain TCP without TLS client-cert auth.

### [HIGH] SQL injection indicator on parameter 'id'
- **Plugin:** injection.sqli_indicators (injection)
- **Confidence:** medium
- **Affected URL:** `https://demo.example.com/products?id=1'`
- **CWE:** CWE-89
- **OWASP:** A03:2021-Injection

Appending a quote character to 'id' produced a database error message not present in the baseline response, suggesting unsanitised input reaches a SQL query.

**Evidence:**
- New error signature vs. baseline
  - matched: `you have an error in your sql syntax`

**Remediation:** Use parameterised queries/prepared statements exclusively.

**References:**
- https://owasp.org/www-community/attacks/SQL_Injection

### [HIGH] Potential secret exposed in JavaScript: AWS Access Key ID
- **Plugin:** content_discovery.secret_detection (content_discovery)
- **Confidence:** low
- **Affected URL:** `https://demo.example.com/static/app.js`
- **CWE:** CWE-798
- **OWASP:** A07:2021-Identification and Authentication Failures

A pattern matching 'AWS Access Key ID' was found in a publicly served JavaScript file.

**Evidence:**
- AWS Access Key ID
  - matched: `AKIA****************MNOP`

**Remediation:** Remove hardcoded secrets from client-side code; rotate immediately.

### [MEDIUM] Missing security header: content-security-policy
- **Plugin:** vuln_assessment.security_headers (vuln_assessment)
- **Confidence:** high
- **Affected URL:** `https://demo.example.com`
- **CWE:** CWE-1021
- **OWASP:** A05:2021-Security Misconfiguration

No Content-Security-Policy header, so the browser has no defence-in-depth against injected scripts.

**Remediation:** Define a restrictive CSP.

### [MEDIUM] Cookie 'session' missing HttpOnly flag
- **Plugin:** vuln_assessment.cookie_analysis (vuln_assessment)
- **Confidence:** high
- **Affected URL:** `https://demo.example.com`
- **CWE:** CWE-1004
- **OWASP:** A05:2021-Security Misconfiguration

Cookie is readable from JavaScript, increasing impact if an XSS is found elsewhere.

**Remediation:** Set the HttpOnly attribute.

### [LOW] Version disclosure via server header
- **Plugin:** recon.http_fingerprint (recon)
- **Confidence:** high
- **Affected URL:** `https://demo.example.com`
- **CWE:** CWE-200

The 'server' response header discloses specific software version information.

**Evidence:**
- server: nginx/1.18.0
  - matched: `nginx/1.18.0`

**Remediation:** Suppress version information in server response headers.

### [INFO] Subdomain enumeration summary
- **Plugin:** recon.subdomain_enum (recon)
- **Confidence:** high
- **Affected URL:** `https://demo.example.com`

Discovered 6 candidate subdomain(s) via certificate transparency and DNS brute-force.

## Asset Inventory

### subdomain (2)
- api.demo.example.com  _(via recon.subdomain_enum)_
- staging.demo.example.com  _(via recon.subdomain_enum)_

### url (1)
- https://demo.example.com/products  _(via recon.endpoint_discovery)_

### technology (2)
- nginx  _(via recon.tech_detection)_
- React  _(via recon.tech_detection)_

### api_endpoint (1)
- GET /api/v1/products  _(via content_discovery.api_endpoint_id)_
