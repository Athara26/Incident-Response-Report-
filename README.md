# Incident-Response-Report-
Premium House Lights – Incident Response Report
Prepared by: Athar Ahmed
Date of Incident: February 19, 2022

 1. Executive Summary

On February 19, 2022, Premium House Lights received a threatening email from an attacker claiming to have stolen the company’s customer database. The attacker attached proof of the stolen data and demanded 10 BTC in ransom.

Analysis of server access logs confirmed malicious activity, including active probing of sensitive endpoints, brute-force attempts, and suspicious file access patterns. The attacker ultimately uploaded a malicious PHP file (shell.php), indicating a successful compromise.

Critical weaknesses identified:

Exposed sensitive endpoints

Lack of rate-limiting

Insufficient monitoring or intrusion detection

Immediate containment actions included blocking malicious IPs and auditing exposed endpoints. Long-term recommendations focused on improved authentication, SIEM monitoring, and enhanced perimeter security.

 2. Incident Timeline
[19/Feb/2022:21:56:11 -0500]
Event: Repeated GET requests from 136.243.111.17 (SiteCheckerBotCrawler).
Analysis: Automated scanning, possible reconnaissance.

[19/Feb/2022:21:58:22 -0500]
Event: IP 138.68.92.163 attempts accessing invalid URLs (/nonexistent, /admin).
Analysis: Directory enumeration.

[19/Feb/2022:21:58:24 -0500]
Event: Same IP scans /register, /content, /docs.
Analysis: Application enumeration.

[19/Feb/2022:21:58:40 -0500]
Event: Attacker discovers upload page (upload.php).
Analysis: Poorly secured functionality exposed.

[19/Feb/2022:21:59:04 -0500]
Event: POST request uploads shell.php using curl/7.68.0.
Impact: Possible remote command execution or backdoor access.


This timeline shows a structured attack — reconnaissance → discovery → exploitation — enabled by weak endpoint security.

 3. Technical Analysis
Attack Origin

Malicious IPs: 138.68.92.163, 46.101.123.114

Automated scans from 136.243.111.17

High interaction with sensitive endpoints: /admin, /wp-login.php, /login.php

Impact

Attackers mapped endpoint structure

Brute-force attempts detected

Successful upload of a malicious PHP script

Potential foothold gained for deeper exploitation

How Access Was Gained

Automated bots + manual actors scanned endpoints

Login attempts indicate brute-force behavior

Lack of lockout/CAPTCHA enabled repeated access attempts

Weaknesses Identified

Exposed endpoints: /admin, /wp-login.php, public upload page

Weak IP filtering: No rate-limiting or automated blocking

No IDS/IPS: No detection of unusual traffic patterns

Unmonitored logs: Reconnaissance continued without alerts

 4. Incident Response
Containment Actions

Block malicious IPs

138.68.92.163

46.101.123.114

Enable rate-limiting to stop automated bot traffic

Geofencing administrative endpoints

Restrict admin access using IP whitelisting

Remediation Steps

Audit all exposed public endpoints

Enforce MFA for administrative logins

Apply all security patches (CMS, plugins, server software)

Deploy IDS/IPS and integrate logs into SIEM

Conduct full penetration testing to identify remaining weaknesses

 5. Post-Incident Recommendations
A. Protecting Against Future Attacks
1. Perimeter Security

Install a Web Application Firewall (WAF)

Block known malicious IPs using threat intelligence

Restrict admin areas with IP whitelisting

2. Harden Endpoint Security

Rename sensitive endpoints (/wp-login.php, /admin)

Enable MFA + CAPTCHA

Disable unused services/pages

3. Monitoring & Detection

Integrate logs into a SIEM (Splunk, ELK, Wazuh)

Deploy IDS/IPS for real-time alerting

Review logs regularly

4. Vulnerability Management

Perform regular vulnerability scans (OpenVAS, Nessus)

Conduct periodic penetration tests

Patch third-party software immediately

5. Incident Response Readiness

Maintain an IR plan

Conduct IR drills

Document lessons learned

B. Security Policy Adjustments

Enforce role-based access control (RBAC)

Strong password policy + MFA

Rate-limiting and bot protection

Staff training on phishing & social engineering

 6. Appendix – Key Logs & Evidence
Suspicious IP Activity

138.68.92.163 and 46.101.123.114 repeatedly targeted sensitive endpoints

/wp-login.php brute-force evidence

Multiple 404/403 responses from probing attempts

Reconnaissance Indicators

Attempts to access: /randomfile1, /register, /admin

Multiple scans suggest directory enumeration

Tools Used

Log analysis of phl_access_log.txt

OWASP security guidelines

Recommended solutions: Cloudflare WAF, Splunk SIEM, Nessus

 7. References

NIST Incident Handling Guide (SP 800-61)

Lighthouse Labs Cybersecurity Curriculum

OWASP Secure Coding Practices
