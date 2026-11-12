#!/usr/bin/env python3

# Credshed DFIR enhancement
#
# SmartParse: a robust, format-aware, dirty-data-tolerant replacement for the
# email-centric absorb parser.  Built for real-world credential dumps,
# especially modern **stealer logs / ULP (URL:Login:Password) combolists**, but
# also handles plain combos, CSV database dumps, SQL INSERTs and JSON-lines.
#
# Design goals:
#   * Never silently drop a whole class of rows.  The legacy parser dropped
#     every username- or phone-only record (~50% of a typical stealer log).
#   * Route each login by *type per row* (email | phone | username) instead of
#     forcing one column type across the whole file.
#   * Preserve the breached *service* (the ULP "URL") which is high-value for
#     DFIR ("which of our users had an account on X?").
#   * Degrade gracefully on malformed rows (absorb any email/hash it can find).

import re
import json
import logging
import statistics
from .file import File
from ..errors import *
from ..account import Account
from .. import validation


log = logging.getLogger('credshed.smartparse')


# delimiter candidates, in rough priority order (space is last-resort, for
# whitespace-separated dumps that use no real delimiter)
_DELIMS = [':', ';', '|', '\t', ',', ' ']

# header-name synonyms -> canonical field, for CSV / JSON-lines dumps
_FIELD_SYNONYMS = {
    'email':    {'email', 'e-mail', 'mail', 'emailaddress', 'email_address', 'e_mail'},
    'username': {'username', 'user', 'login', 'user_name', 'login_name', 'nick',
                 'nickname', 'screenname', 'handle', 'account', 'uid', 'userid'},
    'password': {'password', 'pass', 'passwd', 'pwd', 'plaintext', 'plain',
                 'clear', 'cleartext', 'pwd_plain', 'secret', 'credential', 'passphrase'},
    'hash':     {'hash', 'passhash', 'password_hash', 'pwdhash', 'md5', 'sha1',
                 'sha256', 'bcrypt', 'hashed_password', 'pass_hash'},
    'phone':    {'phone', 'tel', 'telephone', 'mobile', 'msisdn', 'phone_number',
                 'phonenumber', 'cell', 'cellphone'},
    'service':  {'url', 'domain', 'host', 'hostname', 'site', 'website', 'service',
                 'app', 'application', 'origin', 'target'},
    'misc':     {'name', 'fullname', 'full_name', 'ip', 'ip_address', 'ipaddress',
                 'address', 'city', 'country', 'dob', 'notes', 'firstname',
                 'lastname', 'first_name', 'last_name'},
}
_HEADER_LOOKUP = {}
for _canon, _syns in _FIELD_SYNONYMS.items():
    for _s in _syns:
        _HEADER_LOOKUP[_s] = _canon

_STRIP = ' \t\'"'
# hard cap on a single line we will try to parse — protects against a
# pathologically long line in a huge dump blowing up memory/CPU
MAX_LINE = 65536

# SQL dump scaffolding that File.sql_split_insert leaves behind between value
# rows - skip it so the actual `(...)` value tuples parse as clean tabular data.
_SQL_NOISE = ('insert into', 'values (', 'values(', '/*', '*/', '-- ',
              'create table', 'drop table', 'lock tables', 'unlock tables', 'set ')


# stealer-log "Key: value" block fields (RedLine / Vidar / Raccoon style records)
_BLOCK_KEY = re.compile(r'^\s*(soft|application|url|host|link|login|user(?:name)?|e-?mail|'
                        r'pass(?:word)?|pwd|hash)\s*[:=]\s*(.*)$', re.I)
_BLOCK_SEP = re.compile(r'^\s*[=\-*_~#.]{3,}\s*$')
_BLOCK_CANON = {
    'url': 'service', 'host': 'service', 'link': 'service',
    'login': 'login', 'user': 'login', 'username': 'login', 'email': 'login', 'e-mail': 'login',
    'pass': 'password', 'password': 'password', 'pwd': 'password',
    'hash': 'hash',
    # 'soft'/'application' intentionally dropped (not a credential field)
}


def _is_sql_noise(line):
    s = line.strip().lower()
    if s in ('', ',', ';', 'values', ')', '(', '();'):
        return True
    return s.startswith(_SQL_NOISE)


# canonical fields a custom format spec may assign to a column
_SPEC_FIELDS = {'email', 'username', 'password', 'hash', 'phone', 'service', 'misc'}
# tokens that mean "ignore this column"
_SPEC_SKIP = {'', '-', '_', 'x', 'skip', 'ignore', 'null', 'none', 'na'}


def build_presniff_from_spec(spec, delimiter=None):
    '''
    DFIR scalability feature: let an investigator declare a file's layout instead
    of relying on auto-detection, for odd/ambiguous dumps.

    `spec` lists the columns in order, e.g.:
        "service:email:password"      URL:login:password (routed to the ULP parser)
        "username,password"           CSV user/pass
        "email|hash|-|phone"          '-' (or skip/ignore) drops a column
    Field names accept the same synonyms as CSV headers (url/host->service,
    user/login->username, pass->password, tel->phone, md5/sha1->hash, ...).
    The delimiter defaults to the spec's own separator but can be overridden
    (e.g. a tab) via `delimiter`.

    A classic 3-field "service:<identity>:password" colon spec is handled by the
    real scheme/port-aware ULP parser (so "https://host:443:user:pass" parses
    correctly); any other layout uses the positional generic parser (which peels a
    leading URL scheme but is not :port-aware — for messy scheme+port URL:login:
    password data, just let auto-detect pick 'ulp').

    Returns a presniff dict consumable by SmartParse(..., presniff=...).
    '''
    if not spec or not str(spec).strip():
        raise ValueError('empty format spec')
    spec = str(spec).strip()

    # The spec's OWN separator is always inferred from the spec text (first
    # non-identifier char).  `delimiter`, when given, overrides only the DATA
    # delimiter, so e.g. a comma-written spec can target tab-delimited data.
    spec_sep = None
    for ch in spec:
        if not (ch.isalnum() or ch == '_'):
            spec_sep = ch
            break
    if spec_sep is None:
        spec_sep = ':'          # single-field spec, no separator present
    tokens = [t.strip().lower() for t in spec.split(spec_sep)]

    column_map = {}
    for i, tok in enumerate(tokens):
        if tok in _SPEC_SKIP:
            continue
        canon = _HEADER_LOOKUP.get(tok, tok)
        if canon not in _SPEC_FIELDS:
            raise ValueError(f'unknown field {tok!r} in format spec (col {i}); '
                             f'use one of {sorted(_SPEC_FIELDS)} or a skip token')
        column_map[i] = canon

    if not column_map:
        raise ValueError('format spec assigns no usable columns')
    # a credential needs at least one identity or secret to be meaningful
    if not ({'email', 'username', 'phone'} & set(column_map.values())) and \
       not ({'password', 'hash'} & set(column_map.values())):
        raise ValueError('format spec needs at least an identity (email/username/'
                         'phone) or a secret (password/hash)')

    data_delim = delimiter if delimiter is not None else spec_sep

    # the classic URL:login:password shape is best handled by the real ULP parser
    # (scheme peeling + :port folding + login-type anchoring), which the naive
    # generic column splitter cannot do; detect it and route there.
    is_ulp_shape = (data_delim == ':' and len(tokens) == 3 and
                    column_map.get(0) == 'service' and column_map.get(2) == 'password'
                    and column_map.get(1) in ('email', 'username', 'phone'))

    return {
        'format': 'ulp' if is_ulp_shape else 'generic',
        'delimiter': data_delim,
        'num_fields': len(tokens),
        'header': None,
        'column_map': column_map,
    }


def _mode(values, default=0):
    try:
        return statistics.mode(values)
    except statistics.StatisticsError:
        return default


class SmartParse:
    '''
    Usage:
        p = SmartParse(file_or_path)
        for account in p:
            ...
    Exposes:
        .file     - the underlying File
        .format   - detected format ('ulp','combo','csv','jsonl','generic','mixed')
        .stats    - dict of counters filled in during iteration
    '''

    # formats whose rows are self-contained (one line == independent record), so
    # the file can be split into byte ranges and parsed by workers in parallel.
    # 'blocks' is excluded (multi-line stateful records); 'empty' has no rows.
    PARALLEL_SAFE_FORMATS = ('ulp', 'combo', 'mixed', 'csv', 'generic', 'jsonl')

    def __init__(self, file, unattended=True, force_ascii=False, sample_lines=2000,
                 presniff=None, line_source=None):

        # coerce to a File (which knows how to decode + SQL-split while iterating)
        if isinstance(file, File):
            self.file = file
        else:
            self.file = File(file)

        self.unattended = unattended
        self.sample_lines = sample_lines

        # detected parameters
        self.format = 'generic'
        self.delimiter = ':'
        self.num_fields = 2
        self.header = None
        self.column_map = {}   # index -> canonical field name (csv / generic)

        # DFIR enhancement (parallel ingest): when a worker parses one byte range
        # of a file, iterate this injected line source instead of the whole file.
        self._line_source = line_source

        # runtime counters
        self.stats = {
            'lines_total': 0,
            'lines_blank': 0,
            'lines_junk': 0,
            'accounts': 0,
            'absorbed': 0,
            'login_email': 0,
            'login_username': 0,
            'login_phone': 0,
        }

        if presniff is not None:
            # reuse a format detected once by the parent (all workers parse
            # identically, and nobody re-samples the file).
            self.format = presniff.get('format', 'generic')
            self.delimiter = presniff.get('delimiter', ':')
            self.num_fields = presniff.get('num_fields', 2)
            self.header = presniff.get('header')
            self.column_map = {int(k): v for k, v in (presniff.get('column_map') or {}).items()}
        else:
            self._sniff()

    def sniff_params(self):
        '''the detected parameters, as a picklable dict to hand to parallel workers'''
        return {
            'format': self.format,
            'delimiter': self.delimiter,
            'num_fields': self.num_fields,
            'header': self.header,
            'column_map': dict(self.column_map),
        }

    def _lines(self):
        '''whole file (normal) or the injected byte-range iterator (parallel worker)'''
        return self.file if self._line_source is None else self._line_source


    # ------------------------------------------------------------------ sniff

    def _sample(self):
        sample = []
        for line in self.file:
            if not line.strip() or _is_sql_noise(line):
                continue
            sample.append(line)
            if len(sample) >= self.sample_lines:
                break
        return sample

    def _split(self, line, delimiter=None, maxsplit=-1):
        d = self.delimiter if delimiter is None else delimiter
        # Scheme-safe ':' split: a URL scheme ("https://") anywhere in a
        # colon-delimited line must not be torn apart on the ':' of "://".
        # Shield it with a sentinel for the split, then restore — so sniffing,
        # column detection AND parsing all see the URL as one field (fixes
        # url-first, url-middle and url-last layouts alike).
        if d == ':' and '://' in line:
            prot = line.replace('://', '\x01')
            parts = prot.split(':') if maxsplit < 0 else prot.split(':', maxsplit)
            return [p.replace('\x01', '://') for p in parts]
        if maxsplit < 0:
            return line.split(d)
        return line.split(d, maxsplit)

    def _peel_scheme(self, line):
        '''
        Peel only the URL scheme marker (http://, https://, android://, ...) so
        the embedded "://" doesn't get mistaken for a field delimiter.  Returns
        (scheme_prefix, remainder); scheme_prefix is '' when there is no scheme.
        The host/port/path stays in the remainder and is resolved by _ulp_split.
        '''
        m = validation.url_scheme_regex.match(line)
        if m:
            return (line[:m.end()], line[m.end():])
        return ('', line)

    def _ulp_split(self, parts, scheme_prefix=''):
        '''
        Resolve a URL:LOGIN:PASSWORD row into (service, login, password),
        tolerant of two things that break naive positional splitting:
          * the URL may carry a ":port" (and "/path"), adding colons, and
          * the password may itself contain the delimiter.
        Strategy: anchor on the login's *type* - the first field after the
        service that is an email or phone is the login (everything before is the
        service, everything after is the password).  When the login is a bare
        username (no email/phone to anchor on), fall back to position but fold a
        leading numeric ":port" into the service.  Returns None if unusable.
        '''
        n = len(parts)
        # 1) type anchor: first email/phone after the service
        for i in range(1, n):
            p = parts[i].strip(_STRIP)
            if validation.is_email(p) or validation.is_phone(p):
                service = scheme_prefix + self.delimiter.join(parts[:i])
                return (service, p, self.delimiter.join(parts[i + 1:]))
        # 2) username login: fold a leading ":port" into the service only when
        #    there are still both a login and a password left afterwards
        svc_end = 1
        if n >= 4:
            p1 = parts[1].strip(_STRIP)
            if p1.isdigit() and 0 < len(p1) <= 5 and int(p1) <= 65535:
                svc_end = 2
        if n > svc_end:
            service = scheme_prefix + self.delimiter.join(parts[:svc_end])
            return (service, parts[svc_end].strip(_STRIP), self.delimiter.join(parts[svc_end + 1:]))
        return None

    def _best_delimiter(self, sample):
        '''pick the delimiter with the most consistent, non-zero per-line count'''
        best = (':', 0, 1)  # (delim, consistency, mode_count)
        for d in _DELIMS:
            # ignore the "://" of schemes when scoring ':'
            counts = [(line.replace('://', '')).count(d) if d == ':' else line.count(d)
                      for line in sample]
            nonzero = [c for c in counts if c > 0]
            if not nonzero:
                continue
            m = _mode(nonzero, 0)
            if m <= 0:
                continue
            consistency = counts.count(m)
            if consistency > best[1]:
                best = (d, consistency, m)
        return best[0]

    def _sniff(self):
        sample = self._sample()
        if not sample:
            # empty / whitespace-only / all-noise file: don't crash a bulk
            # directory import, just parse to zero accounts
            self.format = 'empty'
            log.info(f'No parseable lines in {self.file}')
            return

        # --- JSON-lines ---
        head = sample[:200]
        jlike = sum(1 for l in head if l.lstrip()[:1] in '{[')
        if jlike / len(head) > 0.8:
            ok = 0
            for l in head:
                try:
                    json.loads(l)
                    ok += 1
                except Exception:
                    pass
            if ok / len(head) > 0.6:
                self.format = 'jsonl'
                log.info(f'Detected format: JSON-lines in {self.file}')
                return

        # --- stealer-log "Key: value" blocks (multi-line records) ---
        bhits = sum(1 for l in sample if _BLOCK_KEY.match(l))
        if bhits / len(sample) > 0.5:
            self.format = 'blocks'
            log.info(f'Detected format: stealer-log key/value blocks in {self.file}')
            return

        # --- delimiter ---
        self.delimiter = self._best_delimiter(sample)
        n = len(sample)

        # --- per-line shape stats (scheme-aware) ---
        counts = []
        url0 = email0 = 0
        for l in sample:
            scheme, rest = self._peel_scheme(l)
            parts = self._split(rest)          # scheme-safe: a url in any column counts as one field
            counts.append(len(parts))
            first = parts[0].strip(_STRIP)
            if scheme or validation.is_url_like(first):
                url0 += 1
            elif validation.is_email(first):
                email0 += 1
        self.num_fields = max(2, _mode([c for c in counts if c >= 2], 2))
        modal_frac = counts.count(_mode(counts, 2)) / n

        # --- CSV with a recognizable header ---
        if self.delimiter in (',', ';', '\t', '|'):
            header = [h.strip(_STRIP).lower() for h in self._split(sample[0])]
            known = {i: _HEADER_LOOKUP[h] for i, h in enumerate(header) if h in _HEADER_LOOKUP}
            if len(known) >= 2:
                self.format = 'csv'
                self.header = header
                self.column_map = known
                log.info(f'Detected format: CSV ({header}) in {self.file}')
                return

        # --- ULP (URL:login:password), incl. scheme-prefixed ---
        if url0 / n > 0.5:
            self.format = 'ulp'
            log.info(f'Detected format: ULP url:login:password '
                     f'(delim {self.delimiter!r}) in {self.file}')
            return

        # --- uniform field count ---
        if modal_frac >= 0.6:
            if self.num_fields == 2:
                self.format = 'combo'
                log.info(f'Detected format: combo login:password '
                         f'(delim {self.delimiter!r}) in {self.file}')
            else:
                self.format = 'generic'
                self.column_map = self._detect_columns(sample)
                log.info(f'Detected format: generic tabular (delim {self.delimiter!r}, '
                         f'map {self.column_map}) in {self.file}')
            return

        # --- col0 mostly email but ragged field count => email-combo w/ delim in password ---
        if email0 / n > 0.6:
            self.format = 'combo'
            log.info(f'Detected format: email-combo (ragged, delim {self.delimiter!r}) '
                     f'in {self.file}')
            return

        # --- heterogeneous / dirty: parse each line adaptively ---
        self.format = 'mixed'
        log.info(f'Detected format: mixed/dirty (delim {self.delimiter!r}) in {self.file}')

    def _detect_columns(self, sample):
        '''heuristically label columns of a uniform delimited file'''
        n = self.num_fields
        colmap = {}
        cols = [[] for _ in range(n)]
        for line in sample:
            parts = self._split(line)
            for i in range(n):
                cols[i].append(parts[i].strip(_STRIP) if i < len(parts) else '')
        col_nonblank = {i: [c for c in col if c] for i, col in enumerate(cols)}
        nonblank_idx = [i for i in range(n) if col_nonblank[i]]
        last_present = nonblank_idx[-1] if nonblank_idx else -1
        skip = set()
        for i in nonblank_idx:
            nonblank = col_nonblank[i]

            def frac(pred):
                return sum(1 for c in nonblank if pred(c)) / len(nonblank)
            if frac(validation.is_email) > 0.6:
                colmap[i] = 'email'
            elif frac(validation.is_phone) > 0.6:
                colmap[i] = 'phone'
            elif frac(validation.is_url_like) > 0.6:
                colmap[i] = 'service'
            elif frac(lambda c: validation.is_hash(c)) > 0.6:
                colmap[i] = 'hash'
            elif frac(lambda c: c.isdigit()) > 0.8 and i != last_present:
                # numeric id / timestamp / row counter in a non-final column -
                # skip it; but never skip the final column (may be a numeric PIN)
                skip.add(i)

        # assign the remaining untyped columns by position
        typed_vals = set(colmap.values())
        has_identity = bool({'email', 'phone'} & typed_vals)
        untyped = [i for i in nonblank_idx if i not in colmap and i not in skip]
        if untyped:
            if len(untyped) == 1:
                # a lone extra column is a password if we already have an identity,
                # otherwise treat it as the username/login
                colmap[untyped[0]] = 'password' if (has_identity or 'hash' in typed_vals) else 'username'
            else:
                colmap[untyped[0]] = 'username'
                colmap[untyped[-1]] = 'password'
                for mid in untyped[1:-1]:
                    colmap.setdefault(mid, 'misc')
        return colmap


    # ----------------------------------------------------------------- parse

    def _route_login(self, login):
        '''classify a login value by type and return Account kwargs'''
        login = login.strip(_STRIP)
        if not login:
            return {}
        if validation.is_email(login):
            self.stats['login_email'] += 1
            return {'email': login}
        if validation.is_phone(login):
            self.stats['login_phone'] += 1
            return {'phone': login}
        self.stats['login_username'] += 1
        return {'username': login}

    def _parse_delimited(self, line):
        '''
        Adaptive per-line router used for ulp / combo / mixed formats.
        Handles scheme URLs, URL[:port][/path]:login:password, login:password,
        2-field service:identity, and passwords that contain the delimiter.
        '''
        scheme, rest = self._peel_scheme(line)
        parts = rest.split(self.delimiter)
        if len(parts) < 2:
            yield from self._absorb(line)
            return

        first = parts[0].strip(_STRIP)
        # hash-first (e.g. a hashcat potfile  <hash>:<cracked plaintext>)
        if not scheme and validation.is_hash(first):
            secret = self.delimiter.join(parts[1:]).strip()
            yield Account(hashes=[first], password=secret)
            return

        # URL:login:password  (service URL may carry :port and /path)
        if scheme or validation.is_url_like(first):
            r = self._ulp_split(parts, scheme)
            if r:
                service, login, password = r
                kw = self._route_login(login)
                if kw:
                    yield Account(service=service, password=password, **kw)
                    return
            yield from self._absorb(line)
            return

        # identity:secret  (secret may contain the delimiter -> keep it whole)
        login = first
        secret = self.delimiter.join(parts[1:])
        kw = self._route_login(login)
        if kw:
            yield Account(password=secret, **kw)
            return
        yield from self._absorb(line)

    def _parse_generic(self, line):
        '''uniform delimited file with detected column types; absorb on mismatch'''
        if not self.column_map:
            yield from self._parse_delimited(line)
            return
        # _split is scheme-safe for ':', so a URL in any column stays intact.
        parts = self._split(line)
        fields = {'email': '', 'username': '', 'password': '', 'phone': '', 'service': '', 'misc': ''}
        hashes = []
        for i, canon in self.column_map.items():
            if i >= len(parts):
                continue
            val = parts[i].strip(_STRIP)
            if not val or val.upper() == 'NULL':
                continue
            if canon == 'hash':
                hashes.append(val)
            elif canon == 'misc':
                fields['misc'] = (fields['misc'] + ' ' + val).strip()
            else:
                fields[canon] = val
        try:
            yield Account(hashes=hashes, **fields)
        except AccountCreationError:
            yield from self._absorb(line)

    def _parse_csv(self, line):
        parts = self._split_csv(line)
        fields = {'email': '', 'username': '', 'password': '', 'phone': '', 'service': '', 'misc': ''}
        hashes = []
        for i, canon in self.column_map.items():
            if i >= len(parts):
                continue
            val = parts[i].strip(_STRIP)
            if not val or val.upper() == 'NULL':
                continue
            if canon == 'hash':
                hashes.append(val)
            elif canon == 'misc':
                fields['misc'] = (fields['misc'] + ' ' + val).strip()
            else:
                fields[canon] = val
        try:
            yield Account(hashes=hashes, **fields)
        except AccountCreationError:
            yield from self._absorb(line)

    def _split_csv(self, line):
        '''minimal quoted-CSV split (handles "a,b",c without a full csv parser per line)'''
        if '"' not in line:
            return self._split(line)
        out, cur, inq = [], [], False
        d = self.delimiter
        for ch in line:
            if ch == '"':
                inq = not inq
            elif ch == d and not inq:
                out.append(''.join(cur))
                cur = []
            else:
                cur.append(ch)
        out.append(''.join(cur))
        return out

    def _parse_jsonl(self, line):
        try:
            obj = json.loads(line)
        except Exception:
            yield from self._absorb(line)
            return
        if isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    yield from self._account_from_dict(item)
            return
        if isinstance(obj, dict):
            yield from self._account_from_dict(obj)

    def _account_from_dict(self, obj):
        fields = {'email': '', 'username': '', 'password': '', 'phone': '', 'service': '', 'misc': ''}
        hashes = []
        for k, v in obj.items():
            if v is None:
                continue
            canon = _HEADER_LOOKUP.get(str(k).strip().lower())
            if canon is None:
                continue
            v = str(v)
            if canon == 'hash':
                hashes.append(v)
            elif canon == 'misc':
                fields['misc'] = (fields['misc'] + ' ' + v).strip()
            else:
                fields[canon] = v
        try:
            yield Account(hashes=hashes, **fields)
        except AccountCreationError:
            return

    def _emit_block(self, cur):
        '''build an Account from an accumulated {service,login,password,hash} record'''
        if not cur:
            return None
        login = cur.get('login', '')
        kw = self._route_login(login) if login else {}
        try:
            return Account(service=cur.get('service', ''), password=cur.get('password', ''),
                           hashes=[cur['hash']] if cur.get('hash') else [], **kw)
        except AccountCreationError:
            return None

    def _parse_blocks(self):
        '''
        Stateful parser for multi-line stealer-log records, e.g.:
            URL: https://site.com/login
            Username: bob@x.com
            Password: hunter2
            =====================
        A record ends at a blank line, a separator line, or when a new URL/host
        field starts while the current record already has a secret.
        '''
        cur = {}
        for line in self._lines():
            self.stats['lines_total'] += 1
            s = line.strip()
            if not s or _BLOCK_SEP.match(s):
                acc = self._emit_block(cur)
                cur = {}
                if acc:
                    self.stats['accounts'] += 1
                    yield acc
                continue
            m = _BLOCK_KEY.match(line)
            if not m:
                continue
            canon = _BLOCK_CANON.get(m.group(1).strip().lower())
            val = m.group(2).strip()
            if not canon or not val:
                continue
            if canon == 'service' and cur.get('service') and (cur.get('password') or cur.get('login') or cur.get('hash')):
                acc = self._emit_block(cur)
                cur = {}
                if acc:
                    self.stats['accounts'] += 1
                    yield acc
            cur[canon] = val
        acc = self._emit_block(cur)
        if acc:
            self.stats['accounts'] += 1
            yield acc

    def _absorb(self, line):
        '''
        last-resort salvage: pull every email out of the line (with nearby
        context as misc), and recover hashes.  Only used when structured
        parsing fails, so nothing is silently lost.
        '''
        self.stats['absorbed'] += 1
        matches = [(0, 0)] + [m.span() for m in validation.email_regex_search.finditer(line)] + [(len(line), 0)]
        found_any = False
        for i in range(1, len(matches) - 1):
            found_any = True
            startpos, endpos = matches[i]
            email = line[startpos:endpos]
            context_start = matches[i - 1][-1]
            context_end = matches[i + 1][0]
            left_side = line[context_start:startpos][-250:]
            right_side = line[endpos:context_end][:250]
            misc = ''
            found_hashes = []
            if len(left_side) > 1 or len(right_side) > 1:
                misc = (left_side + ' ' + right_side).strip(' :;|,\t')
                found_hashes = sorted(set(validation.find_hashes(misc)), key=len)
                for h in found_hashes:
                    misc = misc.replace(h, '')
                misc = validation.strip_emails(misc).strip(' :;|,\t')
            try:
                yield Account(email=email, hashes=found_hashes, misc=misc[:200])
            except AccountCreationError:
                continue
        if not found_any:
            self.stats['lines_junk'] += 1

    # ------------------------------------------------------------------ iter

    def __iter__(self):

        dispatch = {
            'ulp': self._parse_delimited,
            'combo': self._parse_delimited,
            'mixed': self._parse_delimited,
            'csv': self._parse_csv,
            'jsonl': self._parse_jsonl,
            'generic': self._parse_generic,
        }
        if self.format == 'empty':
            return
        # stealer-log blocks need a stateful, multi-line parser
        if self.format == 'blocks':
            yield from self._parse_blocks()
            return

        parse = dispatch.get(self.format, self._parse_delimited)
        skip_header = (self.format == 'csv')
        # SQL scaffolding only appears in files parsed as generic/combo/mixed;
        # skip the per-line check for the big uniform formats (ulp/csv/jsonl)
        sql_possible = self.format in ('generic', 'combo', 'mixed')

        for line in self._lines():
            self.stats['lines_total'] += 1
            if not line.strip():
                self.stats['lines_blank'] += 1
                continue
            if len(line) > MAX_LINE:
                line = line[:MAX_LINE]
            if sql_possible and _is_sql_noise(line):
                self.stats['lines_blank'] += 1
                continue
            if skip_header:
                skip_header = False
                if any(h in _HEADER_LOOKUP for h in
                       [x.strip(_STRIP).lower() for x in self._split(line)]):
                    continue
            try:
                for account in parse(line):
                    self.stats['accounts'] += 1
                    yield account
            except AccountCreationError:
                continue
            except Exception as e:
                log.debug(f'parse error on line: {str(e)[:100]}')
                continue
