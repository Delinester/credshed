# Credshed — DFIR Investigator Guide

This guide covers the DFIR enhancements added on top of upstream credshed. It is
written for an **authorized** investigator triaging credential-exposure data
during an incident-response or threat-intel engagement.

> ⚠️ Operate only on data you are authorized to possess and process. Credential
> dumps frequently contain third-party personal data; handle under your
> engagement's legal and data-handling rules.

---

## What changed vs. upstream

| Area | Upstream credshed | DFIR-enhanced |
|------|-------------------|---------------|
| Parser | email-centric; dropped ~52% of a stealer log (username/phone-only rows) and discarded the service URL | `SmartParse`: format-aware, captures ~99.8% of ULP data **with** service + phone |
| Formats | colon combos + opportunistic email absorb | ULP (`url:login:pass`), combo, `email:hash`, CSV+header, SQL `INSERT`, JSON-lines, pipe/tab, and heterogeneous "dirty" files |
| Identity fields | email, username, password, hash, misc | **+ phone, + service (breached site)** |
| Search by | email, domain, username | **+ password, phone, service, TLD/domain-zone** |
| Regional view | none | **per-region / per-country statistics** (victim geography and breached-platform geography) |
| Indexing | commented out (username search = full scan) | explicit, on-demand secondary indexes (`idx_u/p/t/v`) |
| Python 3.12 | broken (`File` path bug) | fixed |

---

## The data model

Each account is one MongoDB document. Short keys keep 100M+ collections small:

| key | field | notes |
|-----|-------|-------|
| `_id` | compound index | `<reversed-email-domain>\|<emailhash><accounthash>` — makes email, email-domain and email-**zone** searches use the primary index |
| `e` | email local-part | domain lives (reversed) in `_id` |
| `u` | username | |
| `p` | password (plaintext) | |
| `h` | hashes | list; a hash-looking password is moved here |
| `m` | misc | free context |
| `t` | phone | bare digits, country code preserved (`+1 (555) 123-4567` → `15551234567`) |
| `v` | service host | **stored reversed** (e.g. `moc.xebew` for `webex.com`) so service + service-zone searches use a prefix index, exactly like the email domain trick |
| `s` | source IDs | which ingested file(s) this account came from |

The same login on two different services is kept as two accounts (different
credentials/context); identical rows across files dedupe and merge their `s`.

---

## Searching

```
./credshed-cli.py [-q TYPE] [--limit N] [--json|--colons] TERM [TERM ...]
```

`-q`/`--query-type` is auto-detected when omitted. Supported types (+ aliases):

| `-q` | searches | example |
|------|----------|---------|
| `email` | a specific address | `./credshed-cli.py bob@example.com` |
| `domain` | all emails at a domain | `./credshed-cli.py -q domain example.com` |
| `tld` (`zone`, `region`) | all emails in a domain **zone** | `./credshed-cli.py -q tld .ru` |
| `username` (`user`) | exact username | `./credshed-cli.py -q username jsmith` |
| `password` (`pass`, `pw`) | **reverse search** — who used a password | `./credshed-cli.py -q password 'Summer2024!'` |
| `phone` (`tel`, `msisdn`) | a phone number (any format) | `./credshed-cli.py -q phone +15551234567` |
| `service` (`url`, `site`) | a breached platform (host + subdomains) | `./credshed-cli.py -q service webex.com` |
| `service` + leading dot | breached platforms in a zone | `./credshed-cli.py -q service .ru` |

Auto-detection: `bob@x.com`→email, `.ru`→tld, `example.com`→domain, `+1555...`→phone.
A bare word (e.g. a username, or a bare `ru`) is ambiguous and is **not** guessed —
pass `-q username`, or use a leading dot (`.ru`) for a zone.

Notes:
- **`domain`** matches the domain *and its subdomains* (`gmail.com` also returns
  `mail.gmail.com`) but never siblings (`notgmail.com`); same for **`service`**.
- A purely numeric login (e.g. a forum user-ID) is stored as a username, and a
  phone needs a `+` or separators to be treated as a phone — so `-q phone` and
  `-q username` both also check the other field, and numeric pivots never silently miss.

Output formats: default is a readable labeled line; `--json` for JSON-lines
(machine parsing / piping into jq); `--colons` for the legacy
`email:user:pass:hash:misc:phone:service`; `--print0` for NUL-delimited bytes.

### Investigator examples

```bash
# Everyone in the dump with a Russian-zone email address
./credshed-cli.py -q tld .ru --limit 50

# Which of our users had an account on a specific SaaS platform?
./credshed-cli.py -q service webex.com

# Password reuse: everyone who used a weak/known password
./credshed-cli.py -q password 'P@ssw0rd'

# Pivot a known phone number
./credshed-cli.py -q phone +447700900123

# Pipe to jq: pull just service+password for a domain's users
./credshed-cli.py -q domain acme.com --json | jq -r '[.v,.p]|@tsv'
```

---

## Regional / zone statistics

```bash
./credshed-cli.py --tld-stats            # email-domain zones  = victim geography
./credshed-cli.py --tld-stats service    # service zones       = breached-platform geography
./credshed-cli.py --db-stats             # totals + per-source + top regions
```

Zones are rolled up to **country** (ccTLD → country) and **region** (e.g.
*Eastern Europe / CIS*, *Middle East / Gulf*, *Central Asia*). Generic TLDs
(`.com`, `.net`, …) are grouped as *Generic (gTLD)* so they don't drown out the
country signal; ccTLDs commonly sold worldwide (`.io`, `.co`, `.me`, …) are
tagged *(often generic)*.

Stats are computed from **per-source histograms** recorded at ingest time, so
`--tld-stats` is instant even on a billion-row database (it never scans the
accounts collection).

---

## Ingest

```bash
# One file or a whole directory tree (recurses, auto-detects format + encoding)
./credshed-cli.py --unattended --ingest /path/to/leaks

# Parallelism: one worker per file
./credshed-cli.py --unattended --threads 6 --ingest /path/to/leaks
```

Each source records its detected format, login-type split, phone count and
TLD/service histograms (visible in `--db-stats`).

### Performance workflow (bulk load, then index)

Secondary indexes slow bulk writes, so the fast path is **load first, index
after** — build only the dimensions the engagement needs:

```bash
./credshed-cli.py --unattended --ingest /path/to/leaks   # fast, no secondary indexes
./credshed-cli.py --build-indexes                        # all of u,p,t,v
./credshed-cli.py --build-indexes u v                    # or just username + service
./credshed-cli.py --drop-indexes                         # reclaim space before the next big load
```

Which searches use an index:

| search | index used |
|--------|-----------|
| email, domain, tld (email zone) | `_id` (always present) — anchored prefix regex |
| service, service-zone | `idx_v` (reversed host) — anchored prefix regex |
| username / password / phone | `idx_u` / `idx_p` / `idx_t` — exact match |

Without the relevant secondary index, those three fall back to a collection
scan (still correct, just slower) — build the index for repeated queries.

---

## Generating synthetic test data

`tools/gen_test_formats.py` writes **fake** fixtures in 13 real-world leak
formats (combo, ULP, CSV, SQL, JSON-lines, pipe/tab, dirty/mixed, …) for
exercising the parser:

```bash
python3 tools/gen_test_formats.py tests/fixtures/leak_formats --rows 500
python3 tools/test_parser_formats.py tests/fixtures/leak_formats   # coverage report
```

All generated content is randomly synthesized and must never be treated as real.
