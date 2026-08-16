# Authorized OSINT Collection Tool

A modular, Python 3 command-line tool for **lawful, authorized** open-source
intelligence (OSINT) gathering in support of cybersecurity investigations,
digital forensics, and threat intelligence work.

> **This tool only ever touches information that is already public, or that
> is returned by an officially authorized API/credential you supply.** It
> never bypasses authentication, CAPTCHAs, rate limits, or any other access
> control, and it never attempts to discover private contact details,
> passwords, tokens, or hidden accounts.

---

## 1. Legal / Ethical Notice

This software is provided for **authorized security research, digital
forensics, and lawful investigative work only**. By using it you agree that:

- You have the legal right/authorization to investigate the target
  identifiers you supply.
- You will not use this tool to harass, stalk, dox, or otherwise harm any
  individual.
- You will comply with the Terms of Service of every platform and API you
  query, and with all applicable local, national, and international law
  (including data-protection law such as GDPR where relevant).
- You understand this tool **does not** and **will not**:
  - bypass authentication, CAPTCHAs, rate limits, or privacy controls
  - access private posts, private profiles, or private messages
  - guess, enumerate, or "reverse" private emails/phone numbers
  - perform credential attacks, brute forcing, or account takeover
  - perform port scanning or any intrusive network probing
  - store or print API secrets/tokens

The banner below is displayed every time the tool starts and cannot be
suppressed:

```
AUTHORIZED OSINT TOOL
Use only for lawful investigations and systems/data you are authorized to access.
This tool does not bypass privacy controls or retrieve private information.
```

---

## 2. What counts as "public" here

| Category | Allowed | Not allowed |
|---|---|---|
| Social media | Public bio, public posts, public profile image, follower counts exposed by an official API | Private/locked accounts, DMs, content behind login |
| Email | Syntax validation, domain/MX lookup, provider identification, checking a **breach-notification API** for an address the investigator already has | Guessing addresses, mailbox access, password reset abuse |
| Phone | Normalizing a number the investigator/API already supplied, carrier/region lookup via `phonenumbers` | Reverse-lookup of a private number from a username or leaked DB |
| Domain/DNS | A/AAAA/MX/NS/TXT/CNAME, reverse DNS, WHOIS/RDAP | Vulnerability scanning, port scanning |
| Username | Checking whether a username exists on public, allow-listed sites and reporting a confidence level | Claiming identity match without evidence |

---

## 3. Project layout

```
osint_tool/
    main.py                 CLI entry point
    config.py                Configuration & environment loading
    models.py                 Dataclasses shared across modules
    collectors/
        social.py              Social-media collectors (pluggable per platform)
        email.py                Email validation / DNS / breach-API check
        phone.py                 Phone normalization / metadata
        dns.py                     Domain / DNS / WHOIS recon
        username.py                Username availability / correlation search
    reporting/
        json_report.py           JSON case export
        csv_report.py              CSV case export
        html_report.py              Human-readable HTML report
    utils/
        logging_utils.py         Logging setup (never logs secrets)
        validation.py              Input validation & sanitization
        networking.py               Shared HTTP session, timeouts, rate limiting
    tests/                      Unit tests
cases/                        Created at runtime, one folder per case ID
```

Each collector implements a small common interface (`BaseCollector` in
`models.py`) so new **authorized** data sources can be added later without
touching the CLI or reporting code.

---

## 4. Installation

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # then fill in any API keys you actually have
```

Python 3.9+ is recommended.

---

## 5. Usage examples

```bash
# Domain / DNS recon
python main.py --case CASE001 --domain example.com --html --json

# Username correlation search across allow-listed public platforms
python main.py --case CASE001 --username exampleuser --json --csv

# Email the investigator already has (syntax, domain, optional breach check)
python main.py --case CASE001 --email public@example.com --html

# Phone number the investigator already has, normalize + metadata
python main.py --case CASE001 --phone "+31612345678"

# Public profile URL
python main.py --case CASE001 --profile "https://example.com/public-profile"

# Combine several identifiers in one run, with a reference note
python main.py --case CASE001 --username exampleuser --domain example.com \
    --reference "Insider-threat investigation, legal ref #123" \
    --json --csv --html --verbose
```

Outputs are written to `cases/<CASE_ID>/{raw,reports,evidence,logs}/`.

---

## 6. Which sources require credentials

| Source | Credential needed? | Env var | Notes |
|---|---|---|---|
| DNS resolution (A/AAAA/MX/NS/TXT/CNAME) | No | – | Uses `dnspython`, public resolvers |
| RDAP/WHOIS | No (public RDAP) | – | Falls back gracefully if unavailable |
| Breach-notification lookup | **Yes** | `HIBP_API_KEY` | Uses an authorized breach-notification API (e.g. Have I Been Pwned) only if a key is configured; skipped otherwise |
| GitHub username lookup | No (unauthenticated works, higher limits with token) | `GITHUB_TOKEN` (optional) | Uses GitHub's public REST API |
| Social platform official APIs | **Yes**, per platform | e.g. `TWITTER_BEARER_TOKEN` | Collector cleanly skips/reports "not configured" if the key is absent — it never falls back to scraping private content |

If a credential is not supplied, the relevant collector logs a clear
"skipped: no credentials configured" result rather than attempting any
workaround.

---

## 7. Public vs. restricted information — explicit distinction

**Collected (public):** usernames, public display names, public bios, public
profile images, public post URLs/captions/timestamps exposed by an official
API, public engagement counts, publicly listed links, DNS/WHOIS records for
domains, syntax/domain/provider info for an email you already have, and
formatting/region/carrier info for a phone number you already have.

**Never collected, never attempted:** private posts or DMs, passwords or
auth tokens, hidden/private phone numbers or emails not already supplied or
not published by the subject, results of credential attacks, or anything
obtained by defeating a CAPTCHA, login wall, or rate limit.

---

## 8. Running tests

```bash
python -m pytest tests/ -v
```

## 9. Disclaimer

This is a research/utility scaffold. Confidence scoring, especially for
username correlation, is heuristic and must be reviewed by a qualified
investigator before being relied upon. Nothing produced by this tool is a
substitute for a properly authorized legal process (e.g. a subpoena) where
one is required.
"# OSINT_TOOL" 
"# OSINT_TOOL" 
