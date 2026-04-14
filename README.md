# Whitelist-check

Python script for checking whitelisted domains in Virustotal environment via API

---

Actually this is my first script ever made in 2019 for checking whitelisted domains in Virustotal API. I had several generation of this project:

---

## Version 0.1
Cleans a list of domains and checks each one against the VirusTotal API to identify and print out any that are flagged as malicious.

```
ready_list (raw)
     ↓
Strip prefixes (*.  ^.  www.  etc.)
     ↓
cleaned_file.txt
     ↓
Send each domain → VirusTotal API
     ↓
Check response for threat indicators
     ↓
Print flagged malicious domains
```

---

## Version 0.2
This code differs by adding a two API calls per domain, rate limiting and an extra threat check

```
whitelist.txt (raw)
     ↓
Remove empty lines & blank characters
     ↓
Strip URL paths (split on "/")
     ↓
Remove prefixes (*. ^. www. etc.)
     ↓
domain.txt
     ↓
Send each domain → VirusTotal Domain API
     ↓  (wait 15s)
Send each domain → VirusTotal URL API
     ↓  (wait 15s)
Check response for 4 threat indicators
     ↓
Print flagged malicious domains
```

---

## Version 1.0
This is the production version — cleaner code and automated reporting

```
domains.txt
     ↓
Remove prefixes (*. ^. via regex)
     ↓
Remove \n from each line
     ↓
Send domain → VirusTotal Domain API
     ↓  (wait 30s)
Check 4 threat indicators:
  - Webutation verdict
  - detected_downloaded_samples
  - detected_urls
  - detected_communicating_samples
     ↓
Domain flagged as vulnerable?
  ├── YES → In exceptions.txt?
  │           ├── YES → Skip
  │           └── NO  → Add to vuln_list
  └── NO  → Has subdomains?
              ├── YES → Recurse into subdomains ↩
              └── NO  → Move to next domain
     ↓
Remove duplicates from vuln_list
     ↓
Send vuln_list → Slack webhook
```
