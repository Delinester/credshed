#!/usr/bin/env python3

# by TheTechromancer

import re
import sys
import unicodedata
from .errors import *
from base64 import b64decode
from binascii import Error as Base64Error

# for checking if string is an email
email_regex = re.compile(r'^([A-Z0-9][A-Z0-9_\-\.\+]{,100})@([A-Z0-9][A-Z0-9_\-\.]{,100})\.([A-Z]{2,8})$', re.I)
# for searching for email in string
email_regex_search = re.compile(r'[A-Z0-9][A-Z0-9_\-\.\+]{,100}@[A-Z0-9][A-Z0-9_\-\.]{,100}\.[A-Z]{2,8}', re.I)
# less-strict version
fuzzy_email_regex = re.compile(r'^(.+)@(.+)\.(.+)')
# domain
domain_regex = re.compile(r'^([A-Z0-9_\-\.]*)\.([A-Z]{2,24})$', re.I)
# a bare TLD / domain-zone query, e.g. ".ru", "ru", ".co.uk"
tld_query_regex = re.compile(r'^\.?([a-z0-9]{2,24}(?:\.[a-z0-9]{2,24})?)$', re.I)
# host / url-ish first field of a ULP (URL:login:password) line
url_scheme_regex = re.compile(r'^[a-z][a-z0-9+.\-]{0,15}://', re.I)
host_split_regex = re.compile(r'[/?#\\ ]')
# phone number (optionally +, digits with common separators), 7-15 significant digits
phone_regex = re.compile(r'^\+?[\d][\d\-\s().]{5,20}$')
# characters that are NOT part of a phone number
phone_strip_regex = re.compile(r'[^\d+]')
# control characters incl. NUL (illegal in Mongo field names, and nonsense in a host)
control_chars_re = re.compile(r'[\x00-\x1f\x7f]')
# for finding base words in password
word_regex = re.compile(r'[a-z]{1}[a-z13450@$]{1,18}[a-z]{1}', re.I)

# bounded memo for baseword extraction: passwords repeat heavily in breach data
# ("123456", "password", ...), so caching the (lowercased) base-word tuple turns
# most password/misc tallies into a dict hit instead of a regex scan + lower().
_baseword_cache = {}
_BASEWORD_CACHE_CAP = 100000   # common passwords dominate the hit rate; cap to bound RAM

def basewords_lower(s):
    '''lowercased base words of a string, memoized. Pure -> identical output.'''
    cached = _baseword_cache.get(s)
    if cached is not None:
        return cached
    result = tuple(w.lower() for w in word_regex.findall(s))
    if len(_baseword_cache) < _BASEWORD_CACHE_CAP:
        _baseword_cache[s] = result
    return result
# for checking for hashed passwords
# matches 227/240 (95%) of hashcat's example passwords

hash_regexes = [
    # {smd5}a5/yTL/u$VfvgyHx1xUlXZYBocQpQY0
    r'{[a-z0-9-]{3,15}}[a-z0-9/\.\$+]{20,1000}={0,2}',
    # $P$984478476IagS59wHZvyQMArzfx58u.
    r'\${0,1}[a-z0-9_-]{1,16}\$[a-z0-9/\.\*\$+=]{20,1000}',
    # AK1AAECAwQFBgcICRARNGqgeC3is8gv2xWWRony9NJnDgE=
    r'[a-z0-9/+]{20,1000}={1,2}',
    # 8743b52063cd84097a65d1633f5c74f5
    r'[a-f0-9]{1}[a-f0-9:]{30,1000}[a-f0-9]{1}',
]

hash_regexes_str   = [re.compile(r, re.I) for r in hash_regexes]

# valid characters for email addresses
email_chars_re = re.compile(r'[^abcdefghijklmnopqrstuvwxyz0123456789\.@_\-\+]')

all_chars = (chr(i) for i in range(sys.maxunicode))
categories = {'L', 'M', 'N', 'P', 'S'}
good_chars = ''.join(c for c in all_chars if unicodedata.category(c) in categories)
utf_chars_re = re.compile(f'^[ {re.escape(good_chars)}]')
sep_chars_re = re.compile(r'\s+')
def clean_utf(s, allow_whitespace=True):
    '''
    Remove all non-printable characters and all whitespace except for spaces
    '''
    if not s:                      # fast path: empty field (very common) -> no regex
        return s
    if allow_whitespace:
        return utf_chars_re.sub('', sep_chars_re.sub(' ', s))
    else:
        return utf_chars_re.sub('', sep_chars_re.sub('', s))


def clean_email(s):

    return email_chars_re.sub('', s)


def is_domain(domain):

    if domain_regex.match(domain):
        return True
    return False


def is_email(email):

    # abort if value is too long
    if len(email) >= 256:
        return False

    if email_regex.match(email):
        return True

    return False


def is_fuzzy_email(email):

    if len(email) > 128:
        return False

    if fuzzy_email_regex.match(email):
        return True


    return False


def is_hash(s):

    # fast reject: the shortest possible match across all hash patterns is 21
    # chars (base64 run of 20 + '='), so anything shorter cannot be a hash and
    # we skip four regex probes.  Output-identical to the loop below.
    if len(s) < 21:
        return False
    # go in reverse
    for i in range(len(hash_regexes)-1, -1, -1):
        if hash_regexes_str[i].match(s):
            return True
    return False


def find_hashes(s):

    for hash_regex in hash_regexes_str:
        for match in hash_regex.findall(s):
            yield match


def strip_hashes(s):

    for hash_regex in hash_regexes_str:
        s = re.sub(hash_regex, '', s)

    return s


def strip_emails(s):

    s = re.sub(email_regex_search, '', s)

    return s


def is_phone(s):
    '''
    True if the string looks like a phone number (8-15 digits).  Requires a
    leading '+' OR a separator (space / dash / dot / parens) so that a bare run
    of digits -- which is far more likely a numeric user-ID than a phone -- is
    NOT misclassified as a phone.  A bare numeric login therefore stays a
    username and remains findable via `-q username` (and `-q phone` also checks
    the username field, see db._build_query).
    '''
    if not s:
        return False
    s = s.strip()
    if not phone_regex.match(s):
        return False
    digits = phone_strip_regex.sub('', s).lstrip('+')
    if not (8 <= len(digits) <= 15):
        return False
    return s.startswith('+') or any(c in s for c in ' -.()')


def normalize_phone(s):
    '''
    Normalize a phone number to a bare digit string (country code preserved,
    leading '+' and separators removed) so that "+1 (555) 123-4567",
    "+15551234567" and "15551234567" all match.  Returns '' if not phone-like.
    '''
    if not s:
        return ''
    s = s.strip()
    digits = phone_strip_regex.sub('', s).lstrip('+')
    if 7 <= len(digits) <= 15:
        return digits
    return ''


def is_url_like(s):
    '''
    True if the field looks like a URL / hostname / reverse-DNS app id
    (the "service" field of a URL:login:password line).
    '''
    if not s or '@' in s:
        return False
    if url_scheme_regex.match(s):
        return True
    # a hostname needs a dot; extract_host only ever removes characters, so a
    # dotless string can never yield a dotted host -> skip the costly extract.
    if '.' not in s:
        return False
    host = extract_host(s)
    # a dotted host with a plausible label, or an android-style package (a.b.c)
    return bool(host) and ('.' in host) and not host.replace('.', '').isdigit()


def extract_host(s):
    '''
    Extract a normalized hostname from a URL-ish service field.
    Strips scheme, path, query, port and a leading 'www.'.
    e.g. "https://www.Example.com:443/login?x=1" -> "example.com"
         "com.instagram.android"                 -> "com.instagram.android"
         "github.com/session"                    -> "github.com"
    '''
    if not s:
        return ''
    s = control_chars_re.sub('', s.strip().lower())
    s = url_scheme_regex.sub('', s)
    # userinfo@host -> host (rare in service fields, but be safe)
    if '@' in s:
        s = s.split('@', 1)[-1]
    # cut at first path/query/fragment/space/backslash
    s = host_split_regex.split(s, 1)[0]
    # strip port
    s = s.split(':', 1)[0]
    # strip leading www.
    if s.startswith('www.'):
        s = s[4:]
    return s.strip('.')


# small bounded memo: during ingest tld_of() is called once per account on the
# email domain and the service host, both of which are extremely repetitive
# (gmail.com, google.com, ...), so caching turns most calls into a dict hit.
# Pure function => the cache can never change a result.
_tld_cache = {}
_TLD_CACHE_CAP = 100000   # hot domains/hosts repeat heavily; a small cache covers most hits

def tld_of(host):
    '''
    Return the top-level label (zone) of a hostname, lowercased, or '' if none.
    Understands a short list of multi-part public suffixes (e.g. co.uk).
    '''
    cached = _tld_cache.get(host)
    if cached is not None:
        return cached
    raw = host
    host = (host or '').strip().lower().strip('.')
    if not host or '.' not in host:
        result = ''
    else:
        labels = host.split('.')
        # common two-label public suffixes worth grouping by
        if len(labels) >= 3 and '.'.join(labels[-2:]) in multi_part_suffixes:
            result = '.'.join(labels[-2:])
        else:
            result = labels[-1]
    if raw is not None and len(_tld_cache) < _TLD_CACHE_CAP:
        _tld_cache[raw] = result
    return result


# selected multi-part public suffixes so e.g. foo.co.uk groups under "co.uk"
multi_part_suffixes = {
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk',
    'com.au', 'net.au', 'org.au', 'gov.au', 'edu.au', 'id.au',
    'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
    'co.kr', 'or.kr', 'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in',
    'co.za', 'org.za', 'gov.za', 'com.mx', 'com.ar', 'com.tr', 'com.cn',
    'com.tw', 'com.hk', 'com.sg', 'com.my', 'com.ua', 'com.pk', 'com.ng',
    'co.id', 'co.nz', 'co.il', 'co.th',
}


def validate_query_type(query, query_type='auto'):
    '''
    returns valid query type, autodetects if needed

    Supported explicit types:
      email, domain, username, password, phone, service, tld (a.k.a. zone)
    '''

    if query is None or not str(query).strip():
        raise CredShedValidationError('Empty search term')

    query_type = (query_type or 'auto').strip().lower()

    # aliases
    aliases = {
        'zone': 'tld', 'region': 'tld', 'ccTLD'.lower(): 'tld',
        'user': 'username', 'u': 'username',
        'pass': 'password', 'pw': 'password', 'p': 'password',
        'tel': 'phone', 'mobile': 'phone', 'msisdn': 'phone',
        'url': 'service', 'site': 'service', 'host': 'service', 'domain_service': 'service',
        'mail': 'email', 'e': 'email', 'd': 'domain',
        'md5': 'hash', 'sha1': 'hash', 'sha256': 'hash', 'bcrypt': 'hash', 'ntlm': 'hash', 'h': 'hash',
    }
    query_type = aliases.get(query_type, query_type)

    explicit_types = {'email', 'domain', 'username', 'password', 'phone', 'service', 'tld', 'hash'}

    # honor a valid explicit choice (these fields can hold almost anything,
    # so trust the operator rather than re-detecting)
    if query_type in explicit_types:
        if query_type == 'email' and not is_email(query):
            # fall through to autodetect only if it clearly isn't an email
            if is_domain(query) or is_phone(query):
                pass
            else:
                return 'email'
        else:
            return query_type

    # ---- auto-detect ----
    if is_email(query):
        return 'email'
    # a leading-dot token is unambiguously a domain-zone query (".ru", ".co.uk")
    if query.startswith('.') and tld_query_regex.match(query):
        return 'tld'
    if is_phone(query):
        return 'phone'
    if is_domain(query):
        return 'domain'

    # NB: a bare token ("ru", "me", "admin") is intentionally NOT auto-routed to
    # a zone search - too many real usernames/words collide with TLDs. Use a
    # leading dot (".ru") or an explicit -q tld / -q username / -q password.
    raise CredShedValidationError(
        f'Ambiguous term "{query}" - specify -q username|password|service|tld '
        f'(or use ".{query}" for a domain zone)')
